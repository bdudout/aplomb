//! **Vue gouvernance** (J6, EF-P3, EF-P6) : indicateurs agrégés d'un journal, signés par
//! l'instance, fédérables entre instances.
//!
//! Un agrégat ne lit que les métadonnées en clair du journal (verdicts, règles, moniteurs,
//! modes de branchement, jetons) : il n'ouvre aucun contenu scellé et n'a besoin d'aucune
//! clé de session. Il ne contient **aucun indicateur nominatif** : ni identifiant de
//! session, ni utilisateur, ni compte, ni ressource. Les ventilations par règle, moniteur
//! et outil ne montrent que les catégories vues au moins `seuil_k` fois ; les autres sont
//! regroupées sous « autres », pour qu'un cas rare ne désigne personne.
//!
//! **Agrégat signé** : l'instance signe l'agrégat avec sa clé de signature des réponses ;
//! l'identifiant d'instance par défaut dérive de cette clé (rien du nom de la machine).
//! **Fédération** : un fichier d'instances (identifiant, clé publique) fait foi ; un agrégat
//! non signé par une instance connue, ou deux agrégats d'une même instance sur des périodes
//! qui se recouvrent (double compte), sont refusés.
use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::journal::{self, Entree};

/// Version du format d'agrégat.
pub const FORMAT: u32 = 1;
/// Seuil de publication d'une catégorie (EF-P3).
pub const SEUIL_K_DEFAUT: u64 = 5;
/// Catégorie qui regroupe les cas trop rares pour être montrés.
pub const AUTRES: &str = "autres";
/// Sessions techniques : elles portent les actions des passerelles et du proxy LLM ; ce ne
/// sont pas des sessions d'agents.
const TECHNIQUES: &[&str] = &["modele", "passerelle", "_administration"];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Periode {
    /// Millisecondes depuis l'époque Unix, bornes comprises.
    pub debut: u64,
    pub fin: u64,
}

impl Periode {
    fn recouvre(&self, autre: &Periode) -> bool {
        self.debut <= autre.fin && autre.debut <= self.fin
    }
}

/// Version d'un mandat (système d'IA) vue dans la période.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VersionMandat {
    pub id: String,
    pub version: u64,
    /// Empreinte du mandat (16 premiers caractères).
    pub empreinte: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Decisions {
    pub allow: u64,
    pub review: u64,
    pub deny: u64,
    pub gel: u64,
    /// Décisions qu'un moniteur a durcies (EF-K1 : un moniteur ne fait que durcir).
    pub durcies: u64,
}

impl Decisions {
    pub fn total(&self) -> u64 {
        self.allow + self.review + self.deny + self.gel
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Juge {
    pub consultations: u64,
    pub indisponibles: u64,
    /// Somme des latences, pour recalculer la moyenne après fédération.
    pub latence_totale_ms: u64,
}

/// Issues des revues humaines (passerelles, dans Aplomb Watch).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Revues {
    pub approuvees: u64,
    pub refusees: u64,
    pub expirees: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Administration {
    pub gels: u64,
    pub degels: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Integrite {
    /// Fichiers de session dont la chaîne de hachage est intacte.
    pub sessions_intactes: u64,
    /// Fichiers de session dont la chaîne est rompue : leurs entrées ne sont pas comptées.
    pub sessions_rompues: u64,
}

/// Indicateurs agrégés d'une instance sur une période (aucun indicateur nominatif).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Agregat {
    pub format: u32,
    /// Identifiant de l'instance (dérivé de sa clé publique par défaut).
    pub instance: String,
    /// Système d'IA retenu (identifiant de mandat), ou tous.
    pub systeme: Option<String>,
    pub periode: Periode,
    pub seuil_k: u64,
    pub mandats: Vec<VersionMandat>,
    /// Sessions d'agents actives dans la période.
    pub sessions: u64,
    /// Sessions d'agents par mode de branchement et niveau d'assurance (« hook-claude-code/1 »).
    pub branchements: BTreeMap<String, u64>,
    pub decisions: Decisions,
    /// Décisions non Allow par règle de la politique.
    pub regles: BTreeMap<String, u64>,
    /// Avis suspects ou critiques par moniteur.
    pub moniteurs: BTreeMap<String, u64>,
    /// Décisions par outil.
    pub outils: BTreeMap<String, u64>,
    pub juge: Juge,
    pub revues: Revues,
    pub administration: Administration,
    /// Jetons du modèle relayés par le proxy LLM (entrée + sortie).
    pub jetons: u64,
    pub echanges_modele: u64,
    pub integrite: Integrite,
}

/// Taux dérivés d'un agrégat (affichage).
pub fn taux(a: &Agregat) -> BTreeMap<&'static str, f64> {
    let total = a.decisions.total().max(1) as f64;
    let mut t = BTreeMap::new();
    t.insert("revue", a.decisions.review as f64 / total);
    t.insert("refus", (a.decisions.deny + a.decisions.gel) as f64 / total);
    t.insert("gel", a.decisions.gel as f64 / total);
    t.insert("durcies", a.decisions.durcies as f64 / total);
    let juge = a.juge.consultations.max(1) as f64;
    t.insert("juge_indisponible", a.juge.indisponibles as f64 / juge);
    let revues = (a.revues.approuvees + a.revues.refusees + a.revues.expirees).max(1) as f64;
    t.insert("revues_expirees", a.revues.expirees as f64 / revues);
    t
}

fn incrementer(m: &mut BTreeMap<String, u64>, cle: &str) {
    *m.entry(cle.to_string()).or_default() += 1;
}

/// Regroupe sous « autres » les catégories vues moins de `k` fois (EF-P3).
fn masquer(m: BTreeMap<String, u64>, k: u64) -> BTreeMap<String, u64> {
    let mut res = BTreeMap::new();
    for (c, n) in m {
        if n >= k && c != AUTRES {
            res.insert(c, n);
        } else {
            *res.entry(AUTRES.to_string()).or_default() += n;
        }
    }
    res
}

/// Identifiant d'instance par défaut : dérivé de la clé publique, rien de la machine.
pub fn identifiant_instance(cle: &VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    format!("aplomb-{}", &hex::encode(Sha256::digest(cle.to_bytes()))[..12])
}

/// Paramètres du calcul d'un agrégat.
pub struct Calcul<'a> {
    pub instance: &'a str,
    pub systeme: Option<&'a str>,
    pub periode: Periode,
    pub seuil_k: u64,
}

fn lire(chemin: &Path) -> Result<Vec<Entree>, journal::ErreurJournal> {
    journal::verifier(chemin)?;
    let texte = std::fs::read_to_string(chemin)?;
    texte
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| serde_json::from_str(l).map_err(|e| journal::ErreurJournal::Format(i + 1, e.to_string())))
        .collect()
}

/// Calcule l'agrégat d'un dossier de journal. Une session dont la chaîne est rompue est
/// comptée comme telle et ses entrées sont écartées (on n'agrège pas un journal falsifié).
pub fn calculer(dossier: &Path, c: &Calcul) -> Result<Agregat, String> {
    let mut fichiers: Vec<_> = std::fs::read_dir(dossier)
        .map_err(|e| format!("{} : {e}", dossier.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    fichiers.sort();
    let mut a = Agregat {
        format: FORMAT,
        instance: c.instance.into(),
        systeme: c.systeme.map(String::from),
        periode: c.periode.clone(),
        seuil_k: c.seuil_k,
        ..Default::default()
    };
    let (mut regles, mut moniteurs, mut outils, mut branchements) = Default::default();
    let mut mandats = std::collections::BTreeSet::new();
    for f in fichiers {
        let Ok(entrees) = lire(&f) else {
            a.integrite.sessions_rompues += 1;
            continue;
        };
        a.integrite.sessions_intactes += 1;
        agreger_session(&entrees, c, &mut a, &mut regles, &mut moniteurs, &mut outils, &mut branchements, &mut mandats);
    }
    a.regles = masquer(regles, c.seuil_k);
    a.moniteurs = masquer(moniteurs, c.seuil_k);
    a.outils = masquer(outils, c.seuil_k);
    // Les branchements ne sont pas masqués : le niveau d'assurance de chaque mode doit être
    // affiché dans la vue gouvernance (contrat de mode de branchement), et il ne désigne
    // personne.
    a.branchements = branchements;
    a.mandats = mandats.into_iter().collect();
    Ok(a)
}

#[allow(clippy::too_many_arguments)]
fn agreger_session(
    entrees: &[Entree],
    c: &Calcul,
    a: &mut Agregat,
    regles: &mut BTreeMap<String, u64>,
    moniteurs: &mut BTreeMap<String, u64>,
    outils: &mut BTreeMap<String, u64>,
    branchements: &mut BTreeMap<String, u64>,
    mandats: &mut std::collections::BTreeSet<VersionMandat>,
) {
    let tete = entrees.iter().find(|e| e.type_ == "session").map(|e| &e.contenu);
    let systeme = tete.and_then(|t| t["mandat"].as_str());
    if c.systeme.is_some() && systeme != c.systeme {
        return;
    }
    let dans = |e: &&Entree| e.horodatage >= c.periode.debut && e.horodatage <= c.periode.fin;
    let actives: Vec<&Entree> = entrees.iter().filter(dans).collect();
    if actives.is_empty() {
        return;
    }
    let session = entrees[0].session.as_str();
    if let Some(t) = tete {
        let empreinte: String = t["empreinte_mandat"].as_str().unwrap_or_default().chars().take(16).collect();
        if let Some(id) = t["mandat"].as_str() {
            mandats.insert(VersionMandat { id: id.into(), version: t["version"].as_u64().unwrap_or(0), empreinte });
        }
        if !TECHNIQUES.contains(&session) {
            let mode = t["mode"].as_str().unwrap_or("?");
            incrementer(branchements, &format!("{mode}/{}", t["niveau_assurance"].as_u64().unwrap_or(0)));
        }
    }
    if !TECHNIQUES.contains(&session) {
        a.sessions += 1;
    }
    for e in actives {
        let v = &e.contenu;
        match e.type_.as_str() {
            "decision" => {
                match v["verdict"].as_str() {
                    Some("allow") => a.decisions.allow += 1,
                    Some("review") => a.decisions.review += 1,
                    Some("deny") => a.decisions.deny += 1,
                    Some("gel") => a.decisions.gel += 1,
                    _ => continue,
                }
                if v["durci"].as_bool() == Some(true) {
                    a.decisions.durcies += 1;
                }
                if v["verdict"] != "allow" {
                    if let Some(r) = v["regle"].as_str() {
                        incrementer(regles, r);
                    }
                }
                incrementer(outils, v["outil"].as_str().unwrap_or("?"));
                for avis in v["avis"].as_array().into_iter().flatten() {
                    if matches!(avis["niveau"].as_str(), Some("suspect" | "critique")) {
                        incrementer(moniteurs, avis["moniteur"].as_str().unwrap_or("?"));
                    }
                }
                if v["juge"].get("latence_ms").is_some() {
                    a.juge.consultations += 1;
                    a.juge.latence_totale_ms += v["juge"]["latence_ms"].as_u64().unwrap_or(0);
                    if v["juge"]["issue"] == "indisponible" {
                        a.juge.indisponibles += 1;
                    }
                }
            }
            "observation" => {
                match v["revue"].as_str() {
                    Some("approuvée") => a.revues.approuvees += 1,
                    Some("refusée") => a.revues.refusees += 1,
                    Some("expirée") => a.revues.expirees += 1,
                    _ => {}
                }
                let jetons = ["jetons_entree", "jetons_sortie"].iter().filter_map(|k| v[*k].as_u64()).sum::<u64>();
                if v["verbe"] == "modele" && jetons > 0 {
                    a.echanges_modele += 1;
                    a.jetons += jetons;
                }
            }
            "administration" => match v["action"].as_str() {
                Some("gel") => a.administration.gels += 1,
                Some("degel") => a.administration.degels += 1,
                _ => {}
            },
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------------------
// Signature et fédération
// ---------------------------------------------------------------------------------------

/// Agrégat signé par une instance (EF-P6 : la fédération ne remonte que cela).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgregatSigne {
    pub agregat: Agregat,
    pub cle_publique: String,
    pub signature: String,
}

fn octets(a: &Agregat) -> Vec<u8> {
    // Sérialisation déterministe : champs dans l'ordre de la structure, tables triées.
    serde_json::to_vec(a).expect("sérialisation JSON")
}

pub fn signer(a: Agregat, cle: &SigningKey) -> AgregatSigne {
    let signature = hex::encode(cle.sign(&octets(&a)).to_bytes());
    AgregatSigne { agregat: a, cle_publique: hex::encode(cle.verifying_key().to_bytes()), signature }
}

/// Instance connue de la fédération.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub id: String,
    pub cle_publique: String,
}

/// Fichier des instances de la fédération (ancre de confiance, gérée hors bande).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FichierInstances {
    pub instances: Vec<Instance>,
}

impl AgregatSigne {
    /// Vérifie la signature contre la clé publique déclarée pour l'instance.
    pub fn verifier(&self, instances: &FichierInstances) -> Result<(), String> {
        let id = &self.agregat.instance;
        let inst = instances.instances.iter().find(|i| &i.id == id).ok_or_else(|| format!("instance {id} inconnue de la fédération"))?;
        if inst.cle_publique.trim() != self.cle_publique.trim() {
            return Err(format!("instance {id} : clé publique différente de celle de la fédération"));
        }
        let cle = crate::mandat::cle_publique(&inst.cle_publique).map_err(|e| format!("instance {id} : {e}"))?;
        verifier_signature(&cle, &self.agregat, &self.signature).map_err(|e| format!("instance {id} : {e}"))
    }

    /// Vérifie la signature contre la clé que l'agrégat déclare (contrôle d'intégrité seul).
    pub fn verifier_seul(&self) -> Result<(), String> {
        let cle = crate::mandat::cle_publique(&self.cle_publique).map_err(|e| e.to_string())?;
        verifier_signature(&cle, &self.agregat, &self.signature)
    }
}

fn verifier_signature(cle: &VerifyingKey, a: &Agregat, signature: &str) -> Result<(), String> {
    let o = hex::decode(signature.trim()).map_err(|_| "signature illisible".to_string())?;
    let tab: [u8; 64] = o.try_into().map_err(|_| "signature de longueur invalide".to_string())?;
    cle.verify(&octets(a), &Signature::from_bytes(&tab)).map_err(|_| "signature invalide (agrégat modifié ?)".to_string())
}

/// Vue consolidée de plusieurs instances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Federation {
    /// Instances et périodes agrégées.
    pub sources: Vec<(String, Periode)>,
    pub total: Agregat,
}

fn fusionner(dest: &mut BTreeMap<String, u64>, src: &BTreeMap<String, u64>) {
    for (k, n) in src {
        *dest.entry(k.clone()).or_default() += n;
    }
}

/// Vérifie et additionne des agrégats signés. Seuil k du total : le plus exigeant des
/// sources, réappliqué après la somme.
pub fn federer(agregats: &[AgregatSigne], instances: &FichierInstances) -> Result<Federation, String> {
    if agregats.is_empty() {
        return Err("aucun agrégat à fédérer".into());
    }
    let mut f = Federation::default();
    let t = &mut f.total;
    t.format = FORMAT;
    t.instance = "federation".into();
    t.periode = Periode { debut: u64::MAX, fin: 0 };
    let mut mandats = std::collections::BTreeSet::new();
    for (i, s) in agregats.iter().enumerate() {
        s.verifier(instances)?;
        let a = &s.agregat;
        if a.format != FORMAT {
            return Err(format!("agrégat de {} : format {} non pris en charge", a.instance, a.format));
        }
        if agregats[..i].iter().any(|x| x.agregat.instance == a.instance && x.agregat.periode.recouvre(&a.periode)) {
            return Err(format!("instance {} : deux agrégats sur des périodes qui se recouvrent (double compte)", a.instance));
        }
        if i == 0 {
            t.systeme = a.systeme.clone();
        } else if t.systeme != a.systeme {
            t.systeme = None;
        }
        f.sources.push((a.instance.clone(), a.periode.clone()));
        t.periode.debut = t.periode.debut.min(a.periode.debut);
        t.periode.fin = t.periode.fin.max(a.periode.fin);
        t.seuil_k = t.seuil_k.max(a.seuil_k);
        mandats.extend(a.mandats.iter().cloned());
        t.sessions += a.sessions;
        fusionner(&mut t.branchements, &a.branchements);
        t.decisions.allow += a.decisions.allow;
        t.decisions.review += a.decisions.review;
        t.decisions.deny += a.decisions.deny;
        t.decisions.gel += a.decisions.gel;
        t.decisions.durcies += a.decisions.durcies;
        fusionner(&mut t.regles, &a.regles);
        fusionner(&mut t.moniteurs, &a.moniteurs);
        fusionner(&mut t.outils, &a.outils);
        t.juge.consultations += a.juge.consultations;
        t.juge.indisponibles += a.juge.indisponibles;
        t.juge.latence_totale_ms += a.juge.latence_totale_ms;
        t.revues.approuvees += a.revues.approuvees;
        t.revues.refusees += a.revues.refusees;
        t.revues.expirees += a.revues.expirees;
        t.administration.gels += a.administration.gels;
        t.administration.degels += a.administration.degels;
        t.jetons += a.jetons;
        t.echanges_modele += a.echanges_modele;
        t.integrite.sessions_intactes += a.integrite.sessions_intactes;
        t.integrite.sessions_rompues += a.integrite.sessions_rompues;
    }
    let k = t.seuil_k;
    for m in [&mut t.regles, &mut t.moniteurs, &mut t.outils] {
        *m = masquer(std::mem::take(m), k);
    }
    t.mandats = mandats.into_iter().collect();
    Ok(f)
}

/// Champs d'un agrégat qui ne doivent jamais apparaître (test de non-nominativité).
pub const CHAMPS_INTERDITS: &[&str] = &["session", "utilisateur", "compte", "ressource", "ref", "prompt", "scelle", "approbateur", "demandeur"];

/// Vrai si une valeur JSON contient une clé interdite, à quelque profondeur que ce soit.
pub fn contient_champ_interdit(v: &Value) -> bool {
    match v {
        Value::Object(o) => o.iter().any(|(k, x)| CHAMPS_INTERDITS.contains(&k.as_str()) || contient_champ_interdit(x)),
        Value::Array(a) => a.iter().any(contient_champ_interdit),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn journal_type(dossier: &Path) {
        let mut j = journal::Journal::ouvrir(dossier).unwrap();
        for s in ["s1", "s2"] {
            j.ajouter(s, "session", json!({"mandat": "code", "version": 3, "empreinte_mandat": "abcdef0123456789ffff", "mode": "hook-claude-code", "niveau_assurance": 1}), 10).unwrap();
        }
        for i in 0..6 {
            j.ajouter("s1", "decision", json!({"outil": "Bash", "verdict": "allow", "ressource": "secret", "regle": "lire"}), 20 + i).unwrap();
        }
        j.ajouter("s1", "decision", json!({"outil": "Write", "verdict": "deny", "regle": "rare", "durci": false}), 30).unwrap();
        j.ajouter("s2", "decision", json!({"outil": "Bash", "verdict": "review", "regle": "revue-bash", "durci": true,
            "avis": [{"moniteur": "juge", "niveau": "suspect"}], "juge": {"latence_ms": 40, "niveau": "suspect"}}), 31).unwrap();
        j.ajouter("s2", "decision", json!({"outil": "Bash", "verdict": "allow", "juge": {"latence_ms": 10, "issue": "indisponible"}}), 5000).unwrap();
        j.ajouter("_administration", "administration", json!({"action": "gel", "session": "s2", "compte": "alice"}), 32).unwrap();
        j.ajouter("modele", "session", json!({"mandat": "code", "version": 3, "empreinte_mandat": "abcdef0123456789ffff", "mode": "proxy-llm", "niveau_assurance": 2}), 11).unwrap();
        j.ajouter("modele", "observation", json!({"verbe": "modele", "jetons_entree": 100, "jetons_sortie": 20, "utilisateur": "brice"}), 33).unwrap();
        j.ajouter("passerelle", "observation", json!({"verbe": "revue", "revue": "expirée"}), 34).unwrap();
    }

    fn dossier(nom: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("aplomb-indicateurs-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn calcul(k: u64, fin: u64) -> Calcul<'static> {
        Calcul { instance: "i1", systeme: None, periode: Periode { debut: 0, fin }, seuil_k: k }
    }

    #[test]
    fn agregat_compte_et_masque() {
        let d = dossier("compte");
        journal_type(&d);
        let a = calculer(&d, &calcul(2, 1000)).unwrap();
        assert_eq!(a.sessions, 2);
        assert_eq!(a.decisions, Decisions { allow: 6, review: 1, deny: 1, gel: 0, durcies: 1 });
        // « rare » et « revue-bash » vus une fois : regroupés.
        assert_eq!(a.regles, BTreeMap::from([(AUTRES.to_string(), 2)]));
        assert_eq!(a.outils.get("Bash"), Some(&7));
        assert_eq!(a.branchements.get("hook-claude-code/1"), Some(&2));
        assert_eq!(a.juge.consultations, 1);
        assert_eq!(a.administration.gels, 1);
        assert_eq!((a.jetons, a.echanges_modele), (120, 1));
        assert_eq!(a.revues.expirees, 1);
        assert_eq!(a.mandats, vec![VersionMandat { id: "code".into(), version: 3, empreinte: "abcdef0123456789".into() }]);
        // La décision à t = 5000 est hors période.
        let b = calculer(&d, &calcul(1, u64::MAX)).unwrap();
        assert_eq!(b.juge.indisponibles, 1);
        assert_eq!(b.regles.get("rare"), Some(&1));
    }

    #[test]
    fn aucun_champ_nominatif() {
        let d = dossier("nominatif");
        journal_type(&d);
        let a = calculer(&d, &calcul(1, u64::MAX)).unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert!(!contient_champ_interdit(&v), "{v}");
        let texte = v.to_string();
        for interdit in ["s1", "s2", "alice", "brice", "secret"] {
            assert!(!texte.contains(&format!("\"{interdit}\"")), "{interdit} dans {texte}");
        }
    }

    #[test]
    fn journal_rompu_ecarte() {
        let d = dossier("rompu");
        journal_type(&d);
        let f = &d.join(journal::nom_fichier("s1"));
        let t = std::fs::read_to_string(&f).unwrap().replace("\"deny\"", "\"allow\"");
        std::fs::write(&f, t).unwrap();
        let a = calculer(&d, &calcul(1, u64::MAX)).unwrap();
        assert_eq!(a.integrite.sessions_rompues, 1);
        assert_eq!(a.decisions.deny, 0);
    }

    #[test]
    fn signature_et_federation() {
        let d = dossier("federation");
        journal_type(&d);
        let (k1, k2) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let (id1, id2) = (identifiant_instance(&k1.verifying_key()), identifiant_instance(&k2.verifying_key()));
        let mut c = calcul(1, 1000);
        c.instance = &id1;
        let a1 = signer(calculer(&d, &c).unwrap(), &k1);
        c.instance = &id2;
        let a2 = signer(calculer(&d, &c).unwrap(), &k2);
        let instances = FichierInstances {
            instances: vec![
                Instance { id: id1.clone(), cle_publique: hex::encode(k1.verifying_key().to_bytes()) },
                Instance { id: id2.clone(), cle_publique: hex::encode(k2.verifying_key().to_bytes()) },
            ],
        };
        let f = federer(&[a1.clone(), a2.clone()], &instances).unwrap();
        assert_eq!(f.total.sessions, 4);
        assert_eq!(f.total.decisions.allow, 12);
        assert_eq!(f.total.regles.get("rare"), Some(&2));
        // Double compte, agrégat modifié, instance inconnue : refus.
        assert!(federer(&[a1.clone(), a1.clone()], &instances).unwrap_err().contains("recouvrent"));
        let mut falsifie = a2.clone();
        falsifie.agregat.decisions.deny = 0;
        assert!(federer(&[a1.clone(), falsifie], &instances).unwrap_err().contains("signature invalide"));
        let seule = FichierInstances { instances: instances.instances[..1].to_vec() };
        assert!(federer(&[a1, a2], &seule).unwrap_err().contains("inconnue"));
    }
}
