//! **Mandat** signé (EF-A1, EF-A2) : intention, périmètre et politique dans un même
//! artefact. Les fichiers de règles Cedar sont liés au mandat par leur empreinte
//! SHA-256, elle-même couverte par la signature ed25519.
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErreurMandat {
    #[error("lecture de {0} : {1}")]
    Lecture(PathBuf, std::io::Error),
    #[error("mandat illisible : {0}")]
    Format(#[from] serde_yaml::Error),
    #[error("mandat non signé")]
    NonSigne,
    #[error("signature invalide")]
    SignatureInvalide,
    #[error("clé invalide : {0}")]
    Cle(String),
    #[error("empreinte du fichier de règles {0} différente de celle signée")]
    EmpreinteRegles(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Perimetre {
    /// Racine absolue du dépôt où l'agent travaille.
    pub racine: String,
    /// Domaines réseau autorisés (correspondance exacte ou sous-domaine).
    #[serde(default)]
    pub domaines_autorises: Vec<String>,
    /// Branches git sur lesquelles aucun push n'est permis.
    #[serde(default)]
    pub branches_protegees: Vec<String>,
    /// Canal modèle : domaines du fournisseur du modèle de l'agent (ex. `api.anthropic.com`),
    /// que l'agent confiné joint par la passerelle sans passer par la politique. Absent du
    /// texte signé quand la liste est vide : les mandats antérieurs restent valides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domaines_modele: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FichiersPolitique {
    /// Règles `permit` / `forbid` (chemin relatif au fichier du mandat).
    pub regles: String,
    /// Règles dont la correspondance impose une revue humaine.
    pub revue: String,
    #[serde(default)]
    pub regles_sha256: String,
    #[serde(default)]
    pub revue_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mandat {
    pub id: String,
    pub version: u32,
    /// Profil de domaine (`code` pour le MVP).
    pub profil: String,
    pub agent: String,
    /// Intention en langage naturel, fournie aux futurs moniteurs (EF-A2).
    pub intention: String,
    pub perimetre: Perimetre,
    pub politique: FichiersPolitique,
    /// Bornes cumulées par session (EF-A6) ; absentes : valeurs par défaut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bornes: Option<crate::bornes::Bornes>,
    /// Signature ed25519 (hex) du mandat sans ce champ (ancien format, un seul signataire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Signatures nominatives des membres de gouvernance (quatre yeux, EF-S2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<crate::gouvernance::SignatureNommee>,
}

/// Mandat vérifié, avec le texte des règles chargé.
#[derive(Debug, Clone)]
pub struct MandatCharge {
    pub mandat: Mandat,
    pub regles: String,
    pub revue: String,
    /// Empreinte du mandat signé (inscrite en tête de chaque session, EF-G3).
    pub empreinte: String,
}

fn sha256_hex(octets: &[u8]) -> String {
    hex::encode(Sha256::digest(octets))
}

fn lire(chemin: &Path) -> Result<String, ErreurMandat> {
    std::fs::read_to_string(chemin).map_err(|e| ErreurMandat::Lecture(chemin.to_path_buf(), e))
}

impl Mandat {
    /// Octets couverts par la signature : le mandat sans signature, en JSON.
    pub fn octets_signes(&self) -> Vec<u8> {
        let mut m = self.clone();
        m.signature = None;
        m.signatures.clear();
        serde_json::to_vec(&m).expect("sérialisation d'un mandat")
    }

    /// Calcule les empreintes des règles puis signe le mandat.
    pub fn signer(&mut self, dossier: &Path, cle: &SigningKey) -> Result<(), ErreurMandat> {
        self.politique.regles_sha256 =
            sha256_hex(lire(&dossier.join(&self.politique.regles))?.as_bytes());
        self.politique.revue_sha256 =
            sha256_hex(lire(&dossier.join(&self.politique.revue))?.as_bytes());
        self.signature = None;
        let sig = cle.sign(&self.octets_signes());
        self.signature = Some(hex::encode(sig.to_bytes()));
        Ok(())
    }

    /// Vérifie la signature avec la clé publique de confiance (jamais une clé fournie
    /// par le mandat lui-même).
    pub fn verifier(&self, cle: &VerifyingKey) -> Result<(), ErreurMandat> {
        let hex_sig = self.signature.as_ref().ok_or(ErreurMandat::NonSigne)?;
        let octets = hex::decode(hex_sig).map_err(|_| ErreurMandat::SignatureInvalide)?;
        let tab: [u8; 64] = octets.try_into().map_err(|_| ErreurMandat::SignatureInvalide)?;
        cle.verify(&self.octets_signes(), &Signature::from_bytes(&tab))
            .map_err(|_| ErreurMandat::SignatureInvalide)
    }
}

/// Charge un mandat, vérifie sa signature et l'empreinte de ses règles. Refus sinon.
pub fn charger(chemin: &Path, cle: &VerifyingKey) -> Result<MandatCharge, ErreurMandat> {
    let texte = lire(chemin)?;
    let mandat: Mandat = serde_yaml::from_str(&texte)?;
    mandat.verifier(cle)?;
    let dossier = chemin.parent().unwrap_or(Path::new("."));
    let chemin_regles = dossier.join(&mandat.politique.regles);
    let chemin_revue = dossier.join(&mandat.politique.revue);
    let regles = lire(&chemin_regles)?;
    let revue = lire(&chemin_revue)?;
    if sha256_hex(regles.as_bytes()) != mandat.politique.regles_sha256 {
        return Err(ErreurMandat::EmpreinteRegles(chemin_regles));
    }
    if sha256_hex(revue.as_bytes()) != mandat.politique.revue_sha256 {
        return Err(ErreurMandat::EmpreinteRegles(chemin_revue));
    }
    let empreinte = sha256_hex(&mandat.octets_signes());
    Ok(MandatCharge { mandat, regles, revue, empreinte })
}

/// Charge un mandat cosigné : au moins `seuil` membres distincts de la gouvernance ont
/// signé ce contenu exact (EF-S2), et les règles correspondent aux empreintes signées.
pub fn charger_cosigne(
    chemin: &Path,
    confiance: &crate::gouvernance::Confiance,
) -> Result<(MandatCharge, Vec<String>), String> {
    let texte = lire(chemin).map_err(|e| e.to_string())?;
    let mandat: Mandat = serde_yaml::from_str(&texte).map_err(|e| e.to_string())?;
    let signataires = confiance.verifier(&mandat.octets_signes(), &mandat.signatures)?;
    let dossier = chemin.parent().unwrap_or(Path::new("."));
    let regles = lire(&dossier.join(&mandat.politique.regles)).map_err(|e| e.to_string())?;
    let revue = lire(&dossier.join(&mandat.politique.revue)).map_err(|e| e.to_string())?;
    if sha256_hex(regles.as_bytes()) != mandat.politique.regles_sha256
        || sha256_hex(revue.as_bytes()) != mandat.politique.revue_sha256
    {
        return Err("les règles Cedar ont changé depuis la signature : faire recosigner le mandat".into());
    }
    let empreinte = sha256_hex(&mandat.octets_signes());
    Ok((MandatCharge { mandat, regles, revue, empreinte }, signataires))
}

/// Met à jour les empreintes des règles ; vrai si elles ont changé (les signatures déjà
/// posées portent alors sur un autre contenu et sont retirées).
pub fn actualiser_empreintes(mandat: &mut Mandat, dossier: &Path) -> Result<bool, String> {
    let r = sha256_hex(lire(&dossier.join(&mandat.politique.regles)).map_err(|e| e.to_string())?.as_bytes());
    let v = sha256_hex(lire(&dossier.join(&mandat.politique.revue)).map_err(|e| e.to_string())?.as_bytes());
    let change = r != mandat.politique.regles_sha256 || v != mandat.politique.revue_sha256;
    mandat.politique.regles_sha256 = r;
    mandat.politique.revue_sha256 = v;
    if change {
        mandat.signatures.clear();
    }
    Ok(change)
}

/// Clé publique depuis sa forme hexadécimale.
pub fn cle_publique(hex_cle: &str) -> Result<VerifyingKey, ErreurMandat> {
    let octets = hex::decode(hex_cle.trim()).map_err(|e| ErreurMandat::Cle(e.to_string()))?;
    let tab: [u8; 32] = octets.try_into().map_err(|_| ErreurMandat::Cle("32 octets attendus".into()))?;
    VerifyingKey::from_bytes(&tab).map_err(|e| ErreurMandat::Cle(e.to_string()))
}

/// Clé privée depuis sa forme hexadécimale.
pub fn cle_privee(hex_cle: &str) -> Result<SigningKey, ErreurMandat> {
    let octets = hex::decode(hex_cle.trim()).map_err(|e| ErreurMandat::Cle(e.to_string()))?;
    let tab: [u8; 32] = octets.try_into().map_err(|_| ErreurMandat::Cle("32 octets attendus".into()))?;
    Ok(SigningKey::from_bytes(&tab))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier_test(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aplomb-mandat-{nom}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("regles.cedar"), "permit(principal, action, resource);").unwrap();
        std::fs::write(d.join("revue.cedar"), "").unwrap();
        d
    }

    fn mandat() -> Mandat {
        Mandat {
            id: "m1".into(),
            version: 1,
            profil: "code".into(),
            agent: "claude-code".into(),
            intention: "tester".into(),
            perimetre: Perimetre {
                racine: "/tmp/depot".into(),
                domaines_autorises: vec![],
                branches_protegees: vec!["main".into()],
                domaines_modele: vec![],
            },
            politique: FichiersPolitique {
                regles: "regles.cedar".into(),
                revue: "revue.cedar".into(),
                regles_sha256: String::new(),
                revue_sha256: String::new(),
            },
            bornes: None,
            signature: None,
            signatures: Vec::new(),
        }
    }

    fn ecrire_signe(d: &Path, cle: &SigningKey) -> PathBuf {
        let mut m = mandat();
        m.signer(d, cle).unwrap();
        let chemin = d.join("mandat.yaml");
        std::fs::write(&chemin, serde_yaml::to_string(&m).unwrap()).unwrap();
        chemin
    }

    #[test]
    fn mandat_signe_accepte() {
        let d = dossier_test("ok");
        let cle = SigningKey::from_bytes(&[7; 32]);
        let chemin = ecrire_signe(&d, &cle);
        assert!(charger(&chemin, &cle.verifying_key()).is_ok());
    }

    #[test]
    fn mauvaise_cle_refusee() {
        let d = dossier_test("cle");
        let chemin = ecrire_signe(&d, &SigningKey::from_bytes(&[7; 32]));
        let autre = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert!(matches!(charger(&chemin, &autre), Err(ErreurMandat::SignatureInvalide)));
    }

    #[test]
    fn mandat_altere_refuse() {
        let d = dossier_test("altere");
        let cle = SigningKey::from_bytes(&[7; 32]);
        let chemin = ecrire_signe(&d, &cle);
        let texte = std::fs::read_to_string(&chemin).unwrap().replace("/tmp/depot", "/");
        std::fs::write(&chemin, texte).unwrap();
        assert!(matches!(charger(&chemin, &cle.verifying_key()), Err(ErreurMandat::SignatureInvalide)));
    }

    #[test]
    fn regles_alterees_refusees() {
        let d = dossier_test("regles");
        let cle = SigningKey::from_bytes(&[7; 32]);
        let chemin = ecrire_signe(&d, &cle);
        std::fs::write(d.join("revue.cedar"), "permit(principal, action, resource);").unwrap();
        assert!(matches!(charger(&chemin, &cle.verifying_key()), Err(ErreurMandat::EmpreinteRegles(_))));
    }

    #[test]
    fn mandat_non_signe_refuse() {
        let d = dossier_test("nonsigne");
        let chemin = d.join("mandat.yaml");
        std::fs::write(&chemin, serde_yaml::to_string(&mandat()).unwrap()).unwrap();
        let cle = SigningKey::from_bytes(&[7; 32]).verifying_key();
        assert!(matches!(charger(&chemin, &cle), Err(ErreurMandat::NonSigne)));
    }
}
