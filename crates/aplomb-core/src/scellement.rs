//! **Scellement** du journal (EF-I1) et **ancrage** hors de la machine (EF-I2).
//!
//! Les sessions ont chacune leur chaîne de hachage : on peut y ajouter en parallèle, et
//! toute modification d'une entrée se voit. Mais une chaîne seule ne voit ni qu'on l'a
//! **tronquée** (dernières entrées supprimées), ni qu'on a **supprimé** toute une session,
//! ni qu'on l'a **réécrite** entièrement.
//!
//! Un **scellé** fige périodiquement la tête (dernier numéro et dernière empreinte) de
//! chaque session dans une **racine de Merkle**. Il est signé par la clé du superviseur et
//! chaîné au scellé précédent. Une copie de la chaîne de scellés hors de la machine (un
//! autre disque, une clé USB, une autre machine) et une empreinte courte notée à part
//! (« témoin ») rendent détectable même une réécriture complète par quelqu'un qui aurait
//! tous les droits sur la machine.
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::journal::{self, Entree};

/// Tête d'une session au moment du scellé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tete {
    pub fichier: String,
    pub seq: u64,
    pub empreinte: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scelle {
    pub seq: u64,
    pub horodatage: u64,
    pub sessions: Vec<Tete>,
    /// Racine de Merkle des têtes (permet de prouver l'inclusion d'une session).
    pub racine: String,
    /// Empreinte de la ligne du scellé précédent.
    pub precedent: String,
    /// Signature ed25519 (hex) du scellé, ce champ vide.
    #[serde(default)]
    pub signature: String,
}

fn sha256_hex(o: &[u8]) -> String {
    hex::encode(Sha256::digest(o))
}

fn feuille(t: &Tete) -> String {
    sha256_hex(format!("{}\n{}\n{}", t.fichier, t.seq, t.empreinte).as_bytes())
}

/// Racine de Merkle (SHA-256, nœud impair remonté tel quel).
pub fn racine_merkle(feuilles: &[String]) -> String {
    if feuilles.is_empty() {
        return sha256_hex(b"");
    }
    let mut niveau: Vec<String> = feuilles.to_vec();
    while niveau.len() > 1 {
        niveau = niveau
            .chunks(2)
            .map(|p| if p.len() == 2 { sha256_hex(format!("{}{}", p[0], p[1]).as_bytes()) } else { p[0].clone() })
            .collect();
    }
    niveau.remove(0)
}

impl Scelle {
    fn octets_signes(&self) -> Vec<u8> {
        let mut s = self.clone();
        s.signature.clear();
        serde_json::to_vec(&s).expect("sérialisation JSON")
    }

    fn signature_valide(&self, cle: &VerifyingKey) -> bool {
        let Some(tab) = hex::decode(&self.signature).ok().and_then(|o| <[u8; 64]>::try_from(o).ok()) else {
            return false;
        };
        cle.verify(&self.octets_signes(), &Signature::from_bytes(&tab)).is_ok()
    }
}

/// Têtes de toutes les sessions du dossier, après vérification de chaque chaîne.
pub fn tetes(dossier: &Path) -> Result<Vec<Tete>, String> {
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(dossier)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    fichiers.sort();
    let mut res = Vec::new();
    for f in fichiers {
        let nom = f.file_name().unwrap_or_default().to_string_lossy().to_string();
        if let Some(e) = journal::verifier(&f).map_err(|e| format!("{nom} : {e}"))? {
            res.push(Tete { fichier: nom, seq: e.seq, empreinte: e.empreinte });
        }
    }
    Ok(res)
}

/// Chemin de la chaîne de scellés d'un journal (sous-dossier, hors des sessions).
pub fn chemin_chaine(dossier_journal: &Path) -> PathBuf {
    dossier_journal.join("scelles").join("chaine.jsonl")
}

fn lire_chaine(chemin: &Path) -> Result<Vec<(String, Scelle)>, String> {
    let Ok(texte) = std::fs::read_to_string(chemin) else { return Ok(Vec::new()) };
    texte
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l).map(|s| (l.to_string(), s)).map_err(|e| format!("scellé {} illisible : {e}", i + 1))
        })
        .collect()
}

/// Ajoute un scellé si l'état du journal a changé depuis le dernier. Rend le scellé créé.
pub fn sceller(dossier_journal: &Path, cle: &SigningKey, horodatage: u64) -> Result<Option<Scelle>, String> {
    let chemin = chemin_chaine(dossier_journal);
    let chaine = lire_chaine(&chemin)?;
    let sessions = tetes(dossier_journal)?;
    if chaine.last().is_some_and(|(_, s)| s.sessions == sessions) {
        return Ok(None);
    }
    let racine = racine_merkle(&sessions.iter().map(feuille).collect::<Vec<_>>());
    let (seq, precedent) = match chaine.last() {
        Some((ligne, s)) => (s.seq + 1, sha256_hex(ligne.as_bytes())),
        None => (1, journal::GENESE.to_string()),
    };
    let mut s = Scelle { seq, horodatage, sessions, racine, precedent, signature: String::new() };
    s.signature = hex::encode(cle.sign(&s.octets_signes()).to_bytes());
    std::fs::create_dir_all(chemin.parent().expect("sous-dossier")).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&chemin).map_err(|e| e.to_string())?;
    let mut ligne = serde_json::to_vec(&s).expect("sérialisation JSON");
    ligne.push(b'\n');
    f.write_all(&ligne).map_err(|e| e.to_string())?;
    f.sync_data().map_err(|e| e.to_string())?;
    Ok(Some(s))
}

/// Empreinte courte du dernier scellé, à noter hors de la machine (« témoin »).
pub fn temoin(dossier_journal: &Path) -> Result<Option<(u64, String)>, String> {
    Ok(lire_chaine(&chemin_chaine(dossier_journal))?
        .last()
        .map(|(ligne, s)| (s.seq, sha256_hex(ligne.as_bytes())[..16].to_string())))
}

#[derive(Debug, Default)]
pub struct Rapport {
    pub scelles: u64,
    pub dernier_horodatage: Option<u64>,
    pub sessions_scellees: usize,
    /// Sessions apparues depuis le dernier scellé (normal entre deux scellés).
    pub sessions_nouvelles: usize,
    pub temoin: Option<String>,
    /// Sessions scellées puis archivées (registre de rétention, EF-I5).
    pub sessions_archivees: usize,
}

/// Session du journal qui tient le registre des archivages (EF-I5) : chaînée et scellée
/// comme les autres, elle prouve qu'une session absente a été archivée, et dans quel état.
pub const SESSION_RETENTION: &str = "_retention";

/// Sessions archivées : fichier → (dernier numéro, dernière empreinte).
fn archivees(dossier_journal: &Path) -> std::collections::HashMap<String, (u64, String)> {
    let mut m = std::collections::HashMap::new();
    let chemin = dossier_journal.join(journal::nom_fichier(SESSION_RETENTION));
    for l in std::fs::read_to_string(chemin).unwrap_or_default().lines() {
        let Ok(e) = serde_json::from_str::<Entree>(l) else { continue };
        let c = &e.contenu;
        if c.get("action").and_then(|x| x.as_str()) == Some("archivage") {
            let s = |k: &str| c.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
            m.insert(s("fichier"), (c.get("seq").and_then(|x| x.as_u64()).unwrap_or(0), s("empreinte")));
        }
    }
    m
}

/// Bilan d'un archivage.
#[derive(Debug, Default)]
pub struct BilanArchivage {
    pub archivees: Vec<String>,
    /// Sessions assez anciennes mais pas encore couvertes par un scellé : au prochain passage.
    pub non_scellees: usize,
}

/// Archive les sessions dont la dernière entrée est antérieure à `avant_ms` et que le
/// dernier scellé couvre (EF-I5) : copie vérifiée vers `vers`, inscription au registre de
/// rétention, puis retrait du journal actif. Le journal reste vérifiable, et les scellés
/// restent valables même après destruction de l'archive.
pub fn archiver(dossier_journal: &Path, vers: &Path, avant_ms: u64, maintenant: u64) -> Result<BilanArchivage, String> {
    let chaine = lire_chaine(&chemin_chaine(dossier_journal))?;
    let scelle: Vec<Tete> = chaine.last().map(|(_, s)| s.sessions.clone()).unwrap_or_default();
    let registre = journal::nom_fichier(SESSION_RETENTION);
    let mut j = journal::Journal::ouvrir(dossier_journal).map_err(|e| e.to_string())?;
    let mut bilan = BilanArchivage::default();
    for t in tetes(dossier_journal)? {
        if t.fichier == registre {
            continue;
        }
        let chemin = dossier_journal.join(&t.fichier);
        let Some(der) = journal::verifier(&chemin).map_err(|e| format!("{} : {e}", t.fichier))? else { continue };
        if der.horodatage >= avant_ms {
            continue;
        }
        if !scelle.contains(&t) {
            bilan.non_scellees += 1;
            continue;
        }
        std::fs::create_dir_all(vers).map_err(|e| format!("{} : {e}", vers.display()))?;
        let copie = vers.join(&t.fichier);
        std::fs::copy(&chemin, &copie).map_err(|e| format!("{} : {e}", copie.display()))?;
        std::fs::File::open(&copie).and_then(|f| f.sync_all()).map_err(|e| e.to_string())?;
        match journal::verifier(&copie) {
            Ok(Some(e)) if e.empreinte == t.empreinte => {}
            _ => return Err(format!("copie de {} incorrecte : archivage arrêté, rien n'est retiré", t.fichier)),
        }
        let detail = serde_json::json!({"action": "archivage", "fichier": t.fichier, "seq": t.seq, "empreinte": t.empreinte, "derniere_entree": der.horodatage});
        j.ajouter(SESSION_RETENTION, "administration", detail, maintenant).map_err(|e| e.to_string())?;
        std::fs::remove_file(&chemin).map_err(|e| format!("{} : {e}", chemin.display()))?;
        bilan.archivees.push(t.fichier);
    }
    Ok(bilan)
}

fn entree_a(chemin: &Path, seq: u64) -> Option<Entree> {
    let texte = std::fs::read_to_string(chemin).ok()?;
    let ligne = texte.lines().filter(|l| !l.trim().is_empty()).nth(seq.checked_sub(1)? as usize)?;
    serde_json::from_str(ligne).ok()
}

/// Vérifie la chaîne de scellés (signatures, liens) puis le journal contre le dernier
/// scellé : aucune session scellée ne doit avoir disparu, été tronquée ou réécrite.
pub fn verifier(dossier_journal: &Path, cle: &VerifyingKey) -> Result<Rapport, String> {
    let chaine = lire_chaine(&chemin_chaine(dossier_journal))?;
    let mut precedent = journal::GENESE.to_string();
    for (i, (ligne, s)) in chaine.iter().enumerate() {
        let n = i as u64 + 1;
        if s.seq != n || s.precedent != precedent {
            return Err(format!("chaîne de scellés rompue au scellé {n}"));
        }
        if !s.signature_valide(cle) {
            return Err(format!("scellé {n} : signature invalide"));
        }
        if s.racine != racine_merkle(&s.sessions.iter().map(feuille).collect::<Vec<_>>()) {
            return Err(format!("scellé {n} : racine de Merkle incohérente"));
        }
        precedent = sha256_hex(ligne.as_bytes());
    }
    let mut r = Rapport { scelles: chaine.len() as u64, ..Default::default() };
    let Some((ligne, dernier)) = chaine.last() else { return Ok(r) };
    let archives = archivees(dossier_journal);
    for t in &dernier.sessions {
        let chemin = dossier_journal.join(&t.fichier);
        if !chemin.exists() {
            match archives.get(&t.fichier) {
                Some((seq, emp)) if *seq > t.seq || (*seq == t.seq && *emp == t.empreinte) => {
                    r.sessions_archivees += 1;
                    continue;
                }
                _ => return Err(format!("session {} scellée puis supprimée", t.fichier)),
            }
        }
        match entree_a(&chemin, t.seq) {
            Some(e) if e.empreinte == t.empreinte => {}
            Some(_) => return Err(format!("session {} réécrite depuis le scellé {}", t.fichier, dernier.seq)),
            None => return Err(format!("session {} tronquée depuis le scellé {}", t.fichier, dernier.seq)),
        }
    }
    let actuelles = tetes(dossier_journal)?;
    r.dernier_horodatage = Some(dernier.horodatage);
    r.sessions_scellees = dernier.sessions.len();
    r.sessions_nouvelles = actuelles.iter().filter(|a| !dernier.sessions.iter().any(|t| t.fichier == a.fichier)).count();
    r.temoin = Some(sha256_hex(ligne.as_bytes())[..16].to_string());
    Ok(r)
}

/// Vérifie qu'une copie d'ancrage est un **préfixe** de la chaîne locale : si la chaîne
/// locale a été réécrite, les scellés ancrés n'y figurent plus à l'identique.
pub fn verifier_ancre(dossier_journal: &Path, ancre: &Path) -> Result<u64, String> {
    let locale = lire_chaine(&chemin_chaine(dossier_journal))?;
    let copie = lire_chaine(ancre)?;
    if copie.is_empty() {
        return Err("ancre vide".into());
    }
    for (i, (ligne, _)) in copie.iter().enumerate() {
        match locale.get(i) {
            Some((l, _)) if l == ligne => {}
            Some(_) => return Err(format!("scellé {} différent de l'ancre : chaîne locale réécrite", i + 1)),
            None => return Err(format!("scellé {} présent dans l'ancre mais absent localement : chaîne tronquée", i + 1)),
        }
    }
    Ok(copie.len() as u64)
}

/// Copie la chaîne de scellés vers un dossier d'ancrage, sans jamais écraser une ancre
/// qui ne serait pas un préfixe de la chaîne locale (elle serait la preuve d'une
/// réécriture).
pub fn ancrer(dossier_journal: &Path, dossier_ancre: &Path) -> Result<PathBuf, String> {
    let source = chemin_chaine(dossier_journal);
    if !source.exists() {
        return Err("aucun scellé à ancrer (le superviseur scelle toutes les minutes)".into());
    }
    std::fs::create_dir_all(dossier_ancre).map_err(|e| e.to_string())?;
    let cible = dossier_ancre.join("aplomb-ancre.jsonl");
    if cible.exists() {
        verifier_ancre(dossier_journal, &cible).map_err(|e| format!("ancre existante incompatible, conservée : {e}"))?;
    }
    std::fs::copy(&source, &cible).map_err(|e| e.to_string())?;
    Ok(cible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;
    use serde_json::json;

    fn dossier(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aplomb-scelle-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn cle() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn journal(d: &Path) -> Journal {
        let mut j = Journal::ouvrir(d).unwrap();
        for s in ["a", "b", "c"] {
            for t in 1..=3 {
                j.ajouter(s, "decision", json!({"t": t}), t).unwrap();
            }
        }
        j
    }

    #[test]
    fn archivage_sans_perte_de_verifiabilite() {
        let d = std::env::temp_dir().join(format!("aplomb-retention-{}", std::process::id()));
        let a = d.with_extension("archive");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&a);
        let mut j = journal::Journal::ouvrir(&d).unwrap();
        j.ajouter("vieille", "decision", serde_json::json!({}), 1_000).unwrap();
        j.ajouter("recente", "decision", serde_json::json!({}), 9_000).unwrap();
        sceller(&d, &cle(), 9_500).unwrap();
        j.ajouter("pas-scellee", "decision", serde_json::json!({}), 1_000).unwrap();
        let b = archiver(&d, &a, 5_000, 10_000).unwrap();
        assert_eq!(b.archivees, vec![journal::nom_fichier("vieille")]);
        assert_eq!(b.non_scellees, 1, "une session non scellée attend le prochain scellé");
        assert!(a.join(journal::nom_fichier("vieille")).exists());
        let r = verifier(&d, &cle().verifying_key()).unwrap();
        assert_eq!(r.sessions_archivees, 1);
        // L'archive détruite plus tard (purge) : le journal reste vérifiable.
        std::fs::remove_dir_all(&a).unwrap();
        sceller(&d, &cle(), 11_000).unwrap();
        assert!(verifier(&d, &cle().verifying_key()).is_ok());
        // Une suppression hors registre reste détectée.
        std::fs::remove_file(d.join(journal::nom_fichier("recente"))).unwrap();
        assert!(verifier(&d, &cle().verifying_key()).unwrap_err().contains("supprimée"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn merkle() {
        let f: Vec<String> = ["x", "y", "z"].iter().map(|s| s.to_string()).collect();
        assert_eq!(racine_merkle(&f), racine_merkle(&f));
        assert_ne!(racine_merkle(&f), racine_merkle(&f[..2]));
        assert_eq!(racine_merkle(&f[..1]), "x");
    }

    #[test]
    fn scelle_puis_verifie() {
        let d = dossier("ok");
        let mut j = journal(&d);
        assert!(sceller(&d, &cle(), 10).unwrap().is_some());
        // Rien n'a changé : pas de nouveau scellé.
        assert!(sceller(&d, &cle(), 11).unwrap().is_none());
        j.ajouter("a", "decision", json!({"t": 4}), 12).unwrap();
        j.ajouter("d", "decision", json!({"t": 1}), 12).unwrap();
        let r = verifier(&d, &cle().verifying_key()).unwrap();
        assert_eq!((r.scelles, r.sessions_scellees, r.sessions_nouvelles), (1, 3, 1));
        assert_eq!(sceller(&d, &cle(), 13).unwrap().unwrap().seq, 2);
        assert!(verifier(&d, &cle().verifying_key()).is_ok());
        assert!(verifier(&d, &SigningKey::from_bytes(&[8u8; 32]).verifying_key()).unwrap_err().contains("signature"));
    }

    #[test]
    fn troncature_et_suppression_detectees() {
        let d = dossier("tronc");
        let j = journal(&d);
        sceller(&d, &cle(), 10).unwrap();
        // Tronquer la session a : sa chaîne reste valide, mais le scellé la contredit.
        let f = j.chemin("a");
        let lignes: Vec<String> = std::fs::read_to_string(&f).unwrap().lines().map(String::from).collect();
        std::fs::write(&f, format!("{}\n", lignes[0])).unwrap();
        assert!(journal::verifier(&f).is_ok());
        assert!(verifier(&d, &cle().verifying_key()).unwrap_err().contains("tronquée"));
        std::fs::remove_file(&f).unwrap();
        assert!(verifier(&d, &cle().verifying_key()).unwrap_err().contains("supprimée"));
    }

    #[test]
    fn reecriture_complete_detectee_par_l_ancre() {
        let d = dossier("reecr");
        let ancre = dossier("reecr-ancre");
        let j = journal(&d);
        sceller(&d, &cle(), 10).unwrap();
        let copie = ancrer(&d, &ancre).unwrap();
        assert_eq!(verifier_ancre(&d, &copie).unwrap(), 1);
        // Un attaquant qui a la clé réécrit tout : session et scellés recalculés.
        drop(j);
        std::fs::remove_dir_all(&d).unwrap();
        let mut j = Journal::ouvrir(&d).unwrap();
        j.ajouter("a", "decision", json!({"t": "falsifié"}), 1).unwrap();
        sceller(&d, &cle(), 20).unwrap();
        assert!(verifier(&d, &cle().verifying_key()).is_ok(), "localement, tout semble cohérent");
        assert!(verifier_ancre(&d, &copie).unwrap_err().contains("réécrite"));
        // Et la nouvelle chaîne ne peut pas écraser l'ancre qui la contredit.
        assert!(ancrer(&d, &ancre).is_err());
    }
}
