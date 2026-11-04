//! **Journal** probatoire (EF-I) : une chaîne de hachage SHA-256 **par session**
//! (pas de sérialisation globale des écritures, revue critique S2), en JSONL.
//!
//! `empreinte = SHA-256(precedent || JSON{seq, horodatage, session, type, contenu})`.
//! La première entrée d'une session (`type = "session"`) porte l'empreinte du mandat,
//! le mode de branchement et son niveau d'assurance (EF-G3).
//!
//! Limites J1 : entrées non signées, pas d'ancrage hors machine (J2).
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const GENESE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum ErreurJournal {
    #[error("E/S journal : {0}")]
    Io(#[from] std::io::Error),
    #[error("entrée illisible ligne {0} : {1}")]
    Format(usize, String),
    #[error("chaîne rompue ligne {ligne} : {raison}")]
    Rompue { ligne: usize, raison: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entree {
    pub seq: u64,
    /// Millisecondes depuis l'époque Unix.
    pub horodatage: u64,
    pub session: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub contenu: Value,
    pub precedent: String,
    pub empreinte: String,
}

fn calculer_empreinte(precedent: &str, seq: u64, horodatage: u64, session: &str, type_: &str, contenu: &Value) -> String {
    let corps = json!({"seq": seq, "horodatage": horodatage, "session": session, "type": type_, "contenu": contenu});
    let mut h = Sha256::new();
    h.update(precedent.as_bytes());
    h.update(serde_json::to_vec(&corps).expect("sérialisation JSON"));
    hex::encode(h.finalize())
}

/// Nom de fichier sûr pour un identifiant de session (aucune traversée de chemin).
pub fn nom_fichier(session: &str) -> String {
    let propre: String = session
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(96)
        .collect();
    format!("{}-{}.jsonl", propre, &hex::encode(Sha256::digest(session.as_bytes()))[..8])
}

struct Etat {
    seq: u64,
    dernier: String,
}

/// Journal multi-sessions sur disque.
pub struct Journal {
    dossier: PathBuf,
    sessions: HashMap<String, Etat>,
}

impl Journal {
    pub fn ouvrir(dossier: impl Into<PathBuf>) -> Result<Self, ErreurJournal> {
        let dossier = dossier.into();
        std::fs::create_dir_all(&dossier)?;
        Ok(Self { dossier, sessions: HashMap::new() })
    }

    pub fn chemin(&self, session: &str) -> PathBuf {
        self.dossier.join(nom_fichier(session))
    }

    pub fn dossier(&self) -> &Path {
        &self.dossier
    }

    /// Vrai si la session a déjà au moins une entrée (en mémoire ou sur disque).
    pub fn connait(&mut self, session: &str) -> Result<bool, ErreurJournal> {
        Ok(self.etat(session)?.seq > 0)
    }

    fn etat(&mut self, session: &str) -> Result<&mut Etat, ErreurJournal> {
        if !self.sessions.contains_key(session) {
            // Reprise après redémarrage : la chaîne existante est vérifiée avant de la prolonger.
            let chemin = self.chemin(session);
            let etat = if chemin.exists() {
                match verifier(&chemin)? {
                    Some(der) => Etat { seq: der.seq, dernier: der.empreinte },
                    None => Etat { seq: 0, dernier: GENESE.into() },
                }
            } else {
                Etat { seq: 0, dernier: GENESE.into() }
            };
            self.sessions.insert(session.to_string(), etat);
        }
        Ok(self.sessions.get_mut(session).expect("inséré ci-dessus"))
    }

    pub fn ajouter(&mut self, session: &str, type_: &str, contenu: Value, horodatage: u64) -> Result<Entree, ErreurJournal> {
        let chemin = self.chemin(session);
        let etat = self.etat(session)?;
        let seq = etat.seq + 1;
        let empreinte = calculer_empreinte(&etat.dernier, seq, horodatage, session, type_, &contenu);
        let entree = Entree {
            seq,
            horodatage,
            session: session.to_string(),
            type_: type_.to_string(),
            contenu,
            precedent: etat.dernier.clone(),
            empreinte: empreinte.clone(),
        };
        let mut f = OpenOptions::new().create(true).append(true).open(&chemin)?;
        let mut ligne = serde_json::to_vec(&entree).expect("sérialisation JSON");
        ligne.push(b'\n');
        f.write_all(&ligne)?;
        f.sync_data()?;
        etat.seq = seq;
        etat.dernier = empreinte;
        Ok(entree)
    }

    /// Vérifie toutes les sessions du dossier ; renvoie (fichier, nombre d'entrées).
    pub fn verifier_tout(&self) -> Result<Vec<(String, u64)>, (String, ErreurJournal)> {
        let mut res = Vec::new();
        let lecture = std::fs::read_dir(&self.dossier).map_err(|e| (String::new(), e.into()))?;
        let mut fichiers: Vec<PathBuf> = lecture
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        fichiers.sort();
        for f in fichiers {
            let nom = f.file_name().unwrap_or_default().to_string_lossy().to_string();
            let n = verifier(&f).map_err(|e| (nom.clone(), e))?.map_or(0, |d| d.seq);
            res.push((nom, n));
        }
        Ok(res)
    }
}

/// Vérifie la chaîne d'un fichier de session ; renvoie la dernière entrée.
pub fn verifier(chemin: &Path) -> Result<Option<Entree>, ErreurJournal> {
    let lecteur = BufReader::new(File::open(chemin)?);
    let mut precedent = GENESE.to_string();
    let mut dernier = None;
    let mut session: Option<String> = None;
    for (i, ligne) in lecteur.lines().enumerate() {
        let n = i + 1;
        let ligne = ligne?;
        if ligne.trim().is_empty() {
            continue;
        }
        let e: Entree = serde_json::from_str(&ligne).map_err(|err| ErreurJournal::Format(n, err.to_string()))?;
        let rompue = |raison: &str| ErreurJournal::Rompue { ligne: n, raison: raison.into() };
        if e.seq != n as u64 {
            return Err(rompue("numéro de séquence inattendu"));
        }
        if e.precedent != precedent {
            return Err(rompue("lien vers l'entrée précédente invalide"));
        }
        if session.get_or_insert_with(|| e.session.clone()) != &e.session {
            return Err(rompue("session différente dans le même fichier"));
        }
        let calcul = calculer_empreinte(&e.precedent, e.seq, e.horodatage, &e.session, &e.type_, &e.contenu);
        if calcul != e.empreinte {
            return Err(rompue("empreinte invalide (contenu modifié)"));
        }
        precedent = e.empreinte.clone();
        dernier = Some(e);
    }
    Ok(dernier)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aplomb-journal-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn chaine_valide_et_reprise() {
        let d = dossier("ok");
        let mut j = Journal::ouvrir(&d).unwrap();
        j.ajouter("s1", "session", json!({"m": 1}), 1).unwrap();
        j.ajouter("s1", "decision", json!({"v": "allow"}), 2).unwrap();
        j.ajouter("s2", "session", json!({}), 3).unwrap();
        // Reprise par un nouveau processus.
        let mut j2 = Journal::ouvrir(&d).unwrap();
        let e = j2.ajouter("s1", "decision", json!({"v": "deny"}), 4).unwrap();
        assert_eq!(e.seq, 3);
        let r = j2.verifier_tout().unwrap();
        assert_eq!(r.iter().map(|(_, n)| *n).sum::<u64>(), 4);
    }

    #[test]
    fn alteration_detectee() {
        let d = dossier("alt");
        let mut j = Journal::ouvrir(&d).unwrap();
        j.ajouter("s", "decision", json!({"verdict": "deny"}), 1).unwrap();
        j.ajouter("s", "decision", json!({"verdict": "deny"}), 2).unwrap();
        let f = j.chemin("s");
        let texte = std::fs::read_to_string(&f).unwrap().replacen("deny", "allow", 1);
        std::fs::write(&f, texte).unwrap();
        assert!(matches!(verifier(&f), Err(ErreurJournal::Rompue { ligne: 1, .. })));
    }

    #[test]
    fn suppression_d_une_entree_detectee() {
        let d = dossier("suppr");
        let mut j = Journal::ouvrir(&d).unwrap();
        for t in 1..=3 {
            j.ajouter("s", "decision", json!({"t": t}), t).unwrap();
        }
        let f = j.chemin("s");
        let lignes: Vec<String> = std::fs::read_to_string(&f).unwrap().lines().map(String::from).collect();
        std::fs::write(&f, format!("{}\n{}\n", lignes[0], lignes[2])).unwrap();
        assert!(verifier(&f).is_err());
    }

    #[test]
    fn nom_de_fichier_sans_traversee() {
        let n = nom_fichier("../../etc/passwd");
        assert!(!n.contains('/') && !n.contains(".."));
    }
}
