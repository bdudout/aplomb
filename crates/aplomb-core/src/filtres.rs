//! **Filtres de contenu** (étape « filtrage », EF-D1, EF-M1) : des packs de détection
//! déclarés au mandat, qui relèvent un palier quand une action contient une donnée qu'on
//! ne veut pas voir sortir. Ils ne décident jamais seuls d'autoriser.
//!
//! ```yaml
//! moniteurs:
//!   filtres:
//!   - pack: bancaire                 # intégré : IBAN (clé vérifiée), cartes (Luhn)
//!   - pack: identifiant_national     # intégré : numéros de sécurité sociale (NIR)
//!   - pack: sante                    # intégré : vocabulaire médical
//!   - pack: coordonnees              # intégré : courriels, téléphones
//!   - fichier: ../filtres/maison.yaml   # déclaratif ; empreinte posée par la cosignature
//! ```
//!
//! Un pack en fichier :
//!
//! ```yaml
//! nom: contrats
//! motifs:
//! - {nom: numéro de contrat, motif: 'CT-\d{8}'}
//! sortant: critique   # trouvé dans une action qui sort de la machine (défaut : critique, gel)
//! local: suspect      # trouvé ailleurs (défaut : conforme, sans effet)
//! ```
//!
//! Les avis nomment ce qui a été trouvé, jamais la valeur (EF-P1).
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::decision::{Avis, Niveau};

/// Packs intégrés : nom, description.
pub const PACKS: &[(&str, &str)] = &[
    ("bancaire", "IBAN (clé vérifiée) et numéros de carte (Luhn)"),
    ("identifiant_national", "numéros de sécurité sociale (NIR)"),
    ("sante", "vocabulaire médical (diagnostic, ordonnance, arrêt de travail…)"),
    ("coordonnees", "adresses de courriel et numéros de téléphone"),
];

/// Un filtre déclaré au mandat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Filtre {
    Pack {
        pack: String,
        #[serde(default = "critique", skip_serializing_if = "est_critique")]
        sortant: Niveau,
        #[serde(default = "conforme", skip_serializing_if = "est_conforme")]
        local: Niveau,
    },
    Fichier {
        fichier: String,
        /// Empreinte du fichier, posée par la cosignature (EF-M3).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        sha256: String,
    },
}

fn critique() -> Niveau {
    Niveau::Critique
}
fn conforme() -> Niveau {
    Niveau::Conforme
}
fn est_critique(n: &Niveau) -> bool {
    *n == Niveau::Critique
}
fn est_conforme(n: &Niveau) -> bool {
    *n == Niveau::Conforme
}

/// Contenu d'un pack en fichier.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackFichier {
    pub nom: String,
    pub motifs: Vec<MotifFichier>,
    #[serde(default = "critique")]
    pub sortant: Niveau,
    #[serde(default = "conforme")]
    pub local: Niveau,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MotifFichier {
    pub nom: String,
    pub motif: String,
}

/// Détecteur d'un pack.
#[derive(Debug, Clone)]
enum Detecteur {
    /// Pack intégré : catégorie du détecteur de données sensibles.
    Integre(&'static str),
    Motifs(Vec<(String, Regex)>),
    Coordonnees,
}

/// Pack prêt à l'emploi.
#[derive(Debug, Clone)]
pub struct PackCompile {
    pub nom: String,
    detecteur: Detecteur,
    pub sortant: Niveau,
    pub local: Niveau,
}

fn coordonnees(texte: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static COURRIEL: OnceLock<Regex> = OnceLock::new();
    static TEL: OnceLock<Regex> = OnceLock::new();
    let c = COURRIEL.get_or_init(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").expect("motif courriel"));
    let t = TEL.get_or_init(|| Regex::new(r"(?:\+33[ .]?|\b0)[1-9](?:[ .-]?\d{2}){4}\b").expect("motif téléphone"));
    let mut v = Vec::new();
    if c.is_match(texte) {
        v.push("adresse de courriel".to_string());
    }
    if t.is_match(texte) {
        v.push("numéro de téléphone".to_string());
    }
    v
}

impl PackCompile {
    /// Ce que le pack trouve dans le texte (noms des motifs, sans les valeurs).
    pub fn trouver(&self, texte: &str) -> Vec<String> {
        match &self.detecteur {
            Detecteur::Integre(cat) => {
                let (cats, _) = crate::profils::metier::donnees_sensibles(texte);
                if cats.contains(cat) {
                    vec![(*cat).replace('_', " ")]
                } else {
                    Vec::new()
                }
            }
            Detecteur::Coordonnees => coordonnees(texte),
            Detecteur::Motifs(m) => m.iter().filter(|(_, r)| r.is_match(texte)).map(|(n, _)| n.clone()).collect(),
        }
    }

    /// Avis du pack sur une action, `sortante` selon les signaux du profil.
    pub fn avis(&self, texte: &str, sortante: bool) -> Option<Avis> {
        let niveau = if sortante { self.sortant } else { self.local };
        if niveau == Niveau::Conforme {
            return None;
        }
        let trouve = self.trouver(texte);
        if trouve.is_empty() {
            return None;
        }
        let ou = if sortante { "dans une action qui sort de la machine" } else { "dans une action locale" };
        Some(Avis { moniteur: format!("filtre:{}", self.nom), niveau, score: 1.0, motif: format!("{} {ou}", trouve.join(", ")) })
    }
}

/// Compile un pack intégré.
pub fn pack_integre(nom: &str, sortant: Niveau, local: Niveau) -> Result<PackCompile, String> {
    let detecteur = match nom {
        "bancaire" => Detecteur::Integre("bancaire"),
        "identifiant_national" => Detecteur::Integre("identifiant_national"),
        "sante" => Detecteur::Integre("sante"),
        "coordonnees" => Detecteur::Coordonnees,
        autre => {
            let noms: Vec<&str> = PACKS.iter().map(|(n, _)| *n).collect();
            return Err(format!("moniteurs.filtres : pack « {autre} » inconnu (packs : {}, ou « fichier: » pour le vôtre)", noms.join(", ")));
        }
    };
    Ok(PackCompile { nom: nom.to_string(), detecteur, sortant, local })
}

/// Compile un pack en fichier (texte YAML). Le message dit quoi corriger.
pub fn pack_fichier(texte: &str, ou: &str) -> Result<PackCompile, String> {
    let p: PackFichier = serde_yaml::from_str(texte).map_err(|e| format!("filtre {ou} : {e}"))?;
    if p.motifs.is_empty() {
        return Err(format!("filtre {ou} : aucun motif"));
    }
    let mut motifs = Vec::new();
    for m in &p.motifs {
        let r = regex::RegexBuilder::new(&m.motif).size_limit(1 << 20).build().map_err(|e| format!("filtre {ou}, motif « {} » : {e}", m.nom))?;
        motifs.push((m.nom.clone(), r));
    }
    Ok(PackCompile { nom: p.nom, detecteur: Detecteur::Motifs(motifs), sortant: p.sortant, local: p.local })
}

/// Empreinte d'un fichier de filtre.
pub fn empreinte(octets: &[u8]) -> String {
    crate::preuves::sha256_hex(octets)
}

/// Charge les filtres déclarés. `dossier` : celui du mandat (les fichiers y sont relatifs).
/// `exiger_empreinte` : en service, un fichier non lié au mandat par la cosignature, ou
/// modifié depuis, est refusé (EF-M3).
pub fn charger(filtres: &[Filtre], dossier: Option<&Path>, exiger_empreinte: bool) -> Result<Vec<PackCompile>, String> {
    let mut packs = Vec::new();
    for f in filtres {
        match f {
            Filtre::Pack { pack, sortant, local } => packs.push(pack_integre(pack, *sortant, *local)?),
            Filtre::Fichier { fichier, sha256 } => {
                let Some(d) = dossier else { return Err(format!("filtre {fichier} : dossier du mandat inconnu")) };
                let chemin = d.join(fichier);
                let octets = std::fs::read(&chemin).map_err(|e| format!("filtre {} : {e}", chemin.display()))?;
                let e = empreinte(&octets);
                if sha256.is_empty() && exiger_empreinte {
                    return Err(format!("filtre {fichier} non lié au mandat : faire cosigner le mandat (aplomb cosigner)"));
                }
                if !sha256.is_empty() && &e != sha256 {
                    return Err(format!("filtre {} modifié depuis la cosignature : faire recosigner le mandat", chemin.display()));
                }
                packs.push(pack_fichier(&String::from_utf8_lossy(&octets), fichier)?);
            }
        }
    }
    Ok(packs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IBAN: &str = "FR76 3000 6000 0112 3456 7890 189";

    #[test]
    fn packs_integres() {
        let b = pack_integre("bancaire", Niveau::Critique, Niveau::Conforme).unwrap();
        assert_eq!(b.avis(&format!("virement vers {IBAN}"), true).unwrap().niveau, Niveau::Critique);
        assert!(b.avis(&format!("virement vers {IBAN}"), false).is_none(), "local : sans effet par défaut");
        assert!(!b.avis(&format!("vers {IBAN}"), true).unwrap().motif.contains("3000"), "jamais la valeur");
        let c = pack_integre("coordonnees", Niveau::Suspect, Niveau::Conforme).unwrap();
        assert_eq!(c.trouver("écrire à paul@exemple.fr ou au 06 12 34 56 78"), vec!["adresse de courriel", "numéro de téléphone"]);
        assert!(pack_integre("inconnu", Niveau::Critique, Niveau::Conforme).unwrap_err().contains("bancaire"));
    }

    #[test]
    fn pack_en_fichier() {
        let p = pack_fichier("nom: contrats\nmotifs:\n- {nom: numéro de contrat, motif: 'CT-\\d{8}'}\nlocal: suspect\n", "t").unwrap();
        assert_eq!(p.avis("dossier CT-12345678", false).unwrap().niveau, Niveau::Suspect);
        assert_eq!(p.avis("dossier CT-12345678", true).unwrap().moniteur, "filtre:contrats");
        assert!(p.avis("rien", true).is_none());
        assert!(pack_fichier("nom: x\nmotifs: []\n", "t").unwrap_err().contains("aucun motif"));
        assert!(pack_fichier("nom: x\nmotifs: [{nom: a, motif: '('}]\n", "t").is_err());
        assert!(pack_fichier("nom: x\nmotif: []\n", "t").is_err(), "champ inconnu refusé");
    }

    #[test]
    fn declaration() {
        let f: Vec<Filtre> = serde_yaml::from_str("[{pack: bancaire}, {pack: sante, local: suspect}, {fichier: f.yaml}]").unwrap();
        assert!(matches!(&f[0], Filtre::Pack { sortant: Niveau::Critique, local: Niveau::Conforme, .. }));
        assert!(matches!(&f[1], Filtre::Pack { local: Niveau::Suspect, .. }));
        assert!(matches!(&f[2], Filtre::Fichier { .. }));
        assert_eq!(serde_yaml::to_string(&f[0]).unwrap().trim(), "pack: bancaire");
        assert!(charger(&f[2..], None, false).is_err());
    }
}
