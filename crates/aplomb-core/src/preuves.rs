//! **Dossier de preuves** (J6) : correspondance avec les référentiels et preuves AI Act par
//! système d'IA (un mandat).
//!
//! - [`familles`] : correspondance indicative des familles d'exigences d'Aplomb avec l'AI Act,
//!   le NIST AI RMF, l'ISO/IEC 42001, l'OWASP (LLM 2025, Agentic 2026), l'ANSSI et le CRA
//!   (expression de besoin, §13).
//! - [`articles`] : pour chaque article de l'AI Act utile à un système à haut risque, ce
//!   qu'Aplomb apporte, son statut **constaté** sur l'instance (couvert, partiel, hors
//!   périmètre) et les pièces du dossier qui le montrent. Le statut découle de [`Constats`]
//!   mesurés, jamais d'une déclaration.
//! - [`Manifeste`] : liste des pièces avec leur empreinte SHA-256, signée par l'instance. Un
//!   auditeur vérifie le dossier sans Aplomb en service et sans aucune clé secrète.
//!
//! Correspondances indicatives : à vérifier article par article avant usage réglementaire.
//! Aplomb fournit des mesures techniques et leurs preuves ; la conformité d'un système reste
//! celle de son fournisseur et de son déployeur (gestion des risques, qualité, procédures).
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version du format de dossier.
pub const FORMAT: u32 = 1;
/// Nom du manifeste dans le dossier.
pub const MANIFESTE: &str = "manifeste.json";
/// Durée minimale de conservation des journaux (AI Act, art. 19 et 26, § 6) : six mois.
pub const CONSERVATION_MIN_JOURS: u64 = 183;

pub const AVERTISSEMENT: &str = "Correspondances indicatives, à vérifier article par article avant usage réglementaire. \
Aplomb fournit des mesures techniques et leurs preuves ; la conformité du système reste celle de son fournisseur et de son déployeur.";

// ---------------------------------------------------------------------------------------
// Correspondance des familles d'exigences
// ---------------------------------------------------------------------------------------

/// Une famille d'exigences d'Aplomb et ses correspondances (une case vide : sans objet).
#[derive(Debug, Clone, Serialize)]
pub struct Famille {
    pub familles: &'static str,
    pub objet: &'static str,
    pub ai_act: &'static str,
    pub nist_ai_rmf: &'static str,
    pub iso_42001: &'static str,
    pub owasp_llm_2025: &'static str,
    pub owasp_agentic_2026: &'static str,
    pub anssi: &'static str,
    pub cra: &'static str,
}

/// Table de l'expression de besoin, §13.
pub fn familles() -> Vec<Famille> {
    let f = |familles, objet, ai_act, nist_ai_rmf, iso_42001, owasp_llm_2025, owasp_agentic_2026, anssi, cra| Famille {
        familles,
        objet,
        ai_act,
        nist_ai_rmf,
        iso_42001,
        owasp_llm_2025,
        owasp_agentic_2026,
        anssi,
        cra,
    };
    vec![
        f("EF-A, EF-B, EF-K", "Mandat, autorisation par action, algèbre de décision", "Supervision humaine, gestion des risques",
          "Govern, Manage", "Contrôles opérationnels", "LLM06 Excessive Agency", "Usage des outils, identité", "Autorisation, moindre privilège", ""),
        f("EF-C", "Confinement et sens des flux", "Robustesse, cybersécurité", "Manage", "", "", "Exécution de code", "Sandboxing (Zero Trust)", ""),
        f("EF-D", "Entrées non fiables, injection", "", "Measure", "", "LLM01 Prompt Injection", "Planification, mémoire", "Restrictions entrée/sortie", ""),
        f("EF-E, EF-F, EF-H", "Moniteurs, juge, évaluation continue", "Exactitude, robustesse", "Measure", "Surveillance", "",
          "Agents incontrôlés, cascades", "Monitoring", ""),
        f("EF-G", "Intégrité et provenance des modèles et extensions", "", "Map", "Fournisseurs", "LLM03 Supply Chain",
          "Chaîne d'approvisionnement", "", "SBOM, intégrité"),
        f("EF-I", "Journal probatoire", "Journalisation (art. 12)", "Govern", "Traçabilité", "", "", "Journalisation", "Journalisation de sécurité"),
        f("EF-J", "Humain dans la boucle", "Supervision humaine (art. 14)", "Govern", "", "", "Confiance humain-agent",
          "Pas d'autonomie totale sur décisions critiques", ""),
        f("EF-S", "Sécurité du superviseur", "Cybersécurité (art. 15)", "Manage", "Contrôles de sécurité", "", "Identité, privilèges",
          "Authentification, cloisonnement", "Annexe I partie I (sécurité dès la conception, configuration sûre par défaut)"),
        f("EF-P", "Vie privée", "Gouvernance des données", "Govern", "Impact sur les personnes", "LLM02 Sensitive Information Disclosure", "",
          "Protection des données", "Minimisation des données (Annexe I)"),
        f("EF-L", "Conformité du produit", "Annexe III, art. 12, 14, 26", "Govern", "Exigences légales", "", "", "", "Art. 14, Annexes I, III, VII"),
    ]
}

// ---------------------------------------------------------------------------------------
// Articles de l'AI Act, statut constaté
// ---------------------------------------------------------------------------------------

/// Ce qui a été mesuré sur l'instance au moment de l'export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Constats {
    /// Mandat cosigné : signataires distincts, seuil de la confiance.
    pub signataires_mandat: Vec<String>,
    pub seuil: usize,
    /// Comptes d'administration cosignés, et rôles présents.
    pub comptes_cosignes: bool,
    pub approbateurs: usize,
    pub operateurs: usize,
    /// Banc rouge/bleu rejoué (sans juge) : sûreté et utilité, ou absent si pas de jeu.
    pub evaluation: Option<(f64, f64)>,
    /// Une référence de non-régression existe (rapport de la cosignature précédente).
    pub reference_non_regression: bool,
    pub juge: bool,
    /// Protocole AI control du mandat (surveillance, report, reechantillonnage).
    pub protocole: String,
    /// Journal : sessions intactes, rompues ; scellés signés et chaînés ; ancre vérifiée.
    pub sessions_intactes: u64,
    pub sessions_rompues: u64,
    pub scelles: u64,
    pub scelles_valides: bool,
    pub ancre_verifiee: bool,
    /// Plus ancienne et plus récente entrée du journal (ms), pour la conservation.
    pub premiere_entree: Option<u64>,
    pub derniere_entree: Option<u64>,
    /// Indicateurs de la période : décisions, revues humaines, gels.
    pub decisions: u64,
    pub revues: u64,
    pub gels: u64,
    /// Modes de branchement vus (« hook-claude-code/1 »…).
    pub branchements: Vec<String>,
}

impl Constats {
    fn journal_probant(&self) -> bool {
        self.sessions_rompues == 0 && self.sessions_intactes > 0 && self.scelles > 0 && self.scelles_valides
    }

    fn jours_conserves(&self) -> u64 {
        match (self.premiere_entree, self.derniere_entree) {
            (Some(a), Some(b)) if b > a => (b - a) / 86_400_000,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Statut {
    /// Les mesures techniques d'Aplomb répondent à l'article, constat à l'appui.
    Couvert,
    /// Aplomb y contribue ; le reste relève de l'organisation, ou le constat est incomplet.
    Partiel,
    /// Hors du champ d'un superviseur (données d'entraînement, système qualité…).
    HorsPerimetre,
}

/// Un article et ce que le dossier en montre.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Article {
    pub article: String,
    pub objet: String,
    pub statut: Statut,
    /// Ce qu'Aplomb apporte, et ce qui a été constaté sur l'instance.
    pub apport: String,
    pub constat: String,
    /// Ce qui reste à l'organisation.
    pub reste: String,
    /// Pièces du dossier qui le montrent.
    pub pieces: Vec<String>,
    pub exigences: String,
}

fn pct(x: f64) -> String {
    format!("{:.0} %", x * 100.0)
}

/// Statut article par article, déduit des constats.
pub fn articles(c: &Constats) -> Vec<Article> {
    let a = |article: &str, objet: &str, statut, apport: &str, constat: String, reste: &str, pieces: &[&str], exigences: &str| Article {
        article: article.into(),
        objet: objet.into(),
        statut,
        apport: apport.into(),
        constat,
        reste: reste.into(),
        pieces: pieces.iter().map(|p| p.to_string()).collect(),
        exigences: exigences.into(),
    };
    let quatre_yeux = c.signataires_mandat.len() >= c.seuil.max(2) && c.comptes_cosignes;
    let eval = match c.evaluation {
        Some((s, u)) => format!("banc rouge/bleu rejoué sans juge : sûreté {}, utilité {}", pct(s), pct(u)),
        None => "aucun jeu d'évaluation pour ce profil".into(),
    };
    let journal = format!(
        "{} session(s) intacte(s), {} rompue(s) ; {} scellé(s){} ; ancre {}",
        c.sessions_intactes,
        c.sessions_rompues,
        c.scelles,
        if c.scelles > 0 && !c.scelles_valides { " INVALIDES" } else { "" },
        if c.ancre_verifiee { "vérifiée" } else { "absente ou non vérifiée" }
    );
    let jours = c.jours_conserves();
    let conservation = format!("le journal couvre {jours} jour(s) ; durée minimale : {CONSERVATION_MIN_JOURS} jours (six mois)");
    vec![
        a("Art. 9", "Système de gestion des risques",
          Statut::Partiel,
          "Les risques de l'agent sont traduits en invariants et en règles (mandat cosigné) ; chaque élargissement rejoue le banc rouge/bleu et refuse une régression de sûreté (EF-H4).",
          format!("{eval} ; référence de non-régression {}", if c.reference_non_regression { "présente" } else { "absente" }),
          "Identifier et estimer les risques du système dans son contexte, décider des risques résiduels acceptables.",
          &["mandat/", "evaluation.json"], "EF-A, EF-H1, EF-H4"),
        a("Art. 10", "Données et gouvernance des données", Statut::HorsPerimetre,
          "Sans objet pour un superviseur : il n'entraîne pas le modèle. Il minimise et chiffre ce qu'il journalise (EF-P1, EF-P2).",
          "—".into(), "Gouvernance des données d'entraînement, de validation et de test (fournisseur du modèle).", &[], "EF-P"),
        a("Art. 11, annexe IV", "Documentation technique", Statut::Partiel,
          "Le dossier décrit les mesures de contrôle humain, la surveillance et la journalisation en place, avec leurs preuves.",
          "dossier généré ; toutes ses pièces sont dans le manifeste signé".into(),
          "Documentation complète du système (finalité, conception, données, performances), tenue à jour par le fournisseur.",
          &["LISEZMOI.md", "correspondance.json", MANIFESTE], "EF-L"),
        a("Art. 12", "Enregistrement (journalisation automatique)",
          if c.journal_probant() { Statut::Couvert } else { Statut::Partiel },
          "Chaque action de l'agent est journalisée avant d'être autorisée : chaîne de hachage par session, scellés de Merkle signés, ancrage hors de la machine (EF-I1, EF-I2) ; mandat et mode de branchement en tête de session (EF-G3).",
          journal.clone(),
          if c.ancre_verifiee { "Conserver l'ancre hors de la machine." } else { "Ancrer le journal hors de la machine (aplomb ancrer)." },
          &["journal.json"], "EF-I, EF-G3"),
        a("Art. 13", "Transparence et informations aux déployeurs", Statut::Partiel,
          "L'intention et le périmètre de l'agent sont déclarés dans le mandat ; les limites des mesures sont documentées.",
          "intention du mandat jointe".into(), "Notice d'utilisation du système (fournisseur).", &["mandat/"], "EF-A2"),
        a("Art. 14", "Contrôle humain",
          if quatre_yeux && c.approbateurs + c.operateurs > 0 { Statut::Couvert } else { Statut::Partiel },
          "Paliers par action (auto, revue humaine, refus), file de revue avec expiration = refus, arrêt immédiat (gel) et dégel à quatre yeux ; un moniteur ne peut que durcir une décision (EF-J, EF-K1).",
          format!(
            "mandat cosigné par {} (seuil {}) ; comptes {} ; {} opérateur(s), {} approbateur(s) ; sur la période : {} revue(s) humaine(s), {} gel(s)",
            if c.signataires_mandat.is_empty() { "personne".into() } else { c.signataires_mandat.join(" et ") },
            c.seuil,
            if c.comptes_cosignes { "cosignés" } else { "NON cosignés" },
            c.operateurs, c.approbateurs, c.revues, c.gels
          ),
          "Confier le contrôle à des personnes compétentes, formées et dotées de l'autorité nécessaire.",
          &["mandat/", "gouvernance/confiance.yaml", "gouvernance/comptes.json", "indicateurs.json"], "EF-J, EF-K, EF-S2"),
        a("Art. 15", "Exactitude, robustesse et cybersécurité",
          if c.evaluation.is_some_and(|(s, _)| s >= 0.8) { Statut::Couvert } else { Statut::Partiel },
          "Confinement et passerelles (réseau, modèle, MCP), résistance à l'injection (provenance), réponses signées, superviseur dans un autre domaine de confiance ; robustesse mesurée par le banc rouge/bleu.",
          format!("{eval} ; juge {} ; protocole {} ; branchements {}", if c.juge { "déclaré" } else { "absent" }, c.protocole,
                  if c.branchements.is_empty() { "aucun vu".into() } else { c.branchements.join(", ") }),
          "Niveau d'exactitude déclaré du système lui-même ; tests de robustesse du modèle.",
          &["evaluation.json", "mandat/", "indicateurs.json"], "EF-C, EF-D, EF-E, EF-H, EF-S"),
        a("Art. 17", "Système de gestion de la qualité", Statut::HorsPerimetre,
          "Sans objet : relève de l'organisation du fournisseur. Les cosignatures et la non-régression peuvent y être citées.",
          "—".into(), "Politique, procédures et responsabilités qualité.", &[], "EF-L"),
        a("Art. 19, art. 26 § 6", "Conservation des journaux (six mois au moins)",
          if jours >= CONSERVATION_MIN_JOURS && c.journal_probant() { Statut::Couvert } else { Statut::Partiel },
          "Journal conservé et vérifiable ; une purge garde les scellés, l'effacement d'une session détruit sa clé sans rompre la chaîne (EF-I5, EF-P2).",
          conservation,
          "Fixer la durée de conservation (six mois au moins, davantage si le droit applicable l'exige) et la tenir.",
          &["journal.json"], "EF-I5, EF-P2, EF-P4"),
        a("Art. 26", "Obligations des déployeurs (contrôle humain, surveillance du fonctionnement)",
          Statut::Partiel,
          "Comptes nominatifs à rôles, indicateurs de fonctionnement agrégés et signés, gel immédiat en cas de risque.",
          format!("{} décision(s) sur la période ; {} compte(s) opérateur ou approbateur", c.decisions, c.operateurs + c.approbateurs),
          "Utiliser le système selon sa notice, informer le fournisseur et suspendre en cas de risque, informer les personnes concernées.",
          &["indicateurs.json", "gouvernance/comptes.json"], "EF-J, EF-P3"),
        a("Art. 72", "Surveillance après commercialisation", Statut::Partiel,
          "Indicateurs agrégés, signés par chaque instance et fédérables, sans rien de nominatif (EF-P3, EF-P6).",
          format!("indicateurs signés joints ({} décision(s))", c.decisions),
          "Plan de surveillance après commercialisation du fournisseur ; collecte auprès des déployeurs.",
          &["indicateurs.json"], "EF-P6, J6"),
        a("Art. 73", "Signalement des incidents graves", Statut::HorsPerimetre,
          "Les gels, refus et écarts de contrôle croisé sont des signaux à instruire ; le journal en garde la preuve.",
          format!("{} gel(s) sur la période", c.gels), "Procédure de qualification et de signalement aux autorités.", &["indicateurs.json", "journal.json"], "EF-J4"),
    ]
}

// ---------------------------------------------------------------------------------------
// Manifeste signé
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Piece {
    pub fichier: String,
    pub sha256: String,
    pub octets: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifeste {
    pub format: u32,
    pub systeme: String,
    pub version_mandat: u32,
    pub empreinte_mandat: String,
    pub instance: String,
    /// Horodatage de l'export (ms).
    pub genere: u64,
    pub aplomb: String,
    pub pieces: Vec<Piece>,
    pub cle_publique: String,
    #[serde(default)]
    pub signature: String,
}

impl Manifeste {
    fn octets_signes(&self) -> Vec<u8> {
        let mut m = self.clone();
        m.signature.clear();
        serde_json::to_vec(&m).expect("sérialisation JSON")
    }

    pub fn signer(&mut self, cle: &SigningKey) {
        self.cle_publique = hex::encode(cle.verifying_key().to_bytes());
        self.signature = hex::encode(cle.sign(&self.octets_signes()).to_bytes());
    }
}

pub fn sha256_hex(octets: &[u8]) -> String {
    hex::encode(Sha256::digest(octets))
}

/// Pièces d'un dossier : tous ses fichiers sauf le manifeste, triés.
pub fn inventorier(dossier: &Path) -> Result<Vec<Piece>, String> {
    fn parcourir(racine: &Path, d: &Path, res: &mut Vec<Piece>) -> Result<(), String> {
        for e in std::fs::read_dir(d).map_err(|e| format!("{} : {e}", d.display()))? {
            let p = e.map_err(|e| e.to_string())?.path();
            if p.is_dir() {
                parcourir(racine, &p, res)?;
                continue;
            }
            let rel = p.strip_prefix(racine).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
            if rel == MANIFESTE {
                continue;
            }
            let o = std::fs::read(&p).map_err(|e| format!("{} : {e}", p.display()))?;
            res.push(Piece { fichier: rel, sha256: sha256_hex(&o), octets: o.len() as u64 });
        }
        Ok(())
    }
    let mut res = Vec::new();
    parcourir(dossier, dossier, &mut res)?;
    res.sort_by(|a, b| a.fichier.cmp(&b.fichier));
    Ok(res)
}

/// Résultat de la vérification d'un dossier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub pieces: usize,
    pub cle_publique: String,
}

/// Vérifie un dossier : signature du manifeste (par sa clé, ou par `cle_attendue` si donnée),
/// puis chaque pièce (présente, inchangée) et aucune pièce en trop.
pub fn verifier(dossier: &Path, cle_attendue: Option<&str>) -> Result<Verification, String> {
    let texte = std::fs::read_to_string(dossier.join(MANIFESTE)).map_err(|e| format!("{MANIFESTE} : {e}"))?;
    let m: Manifeste = serde_json::from_str(&texte).map_err(|e| format!("{MANIFESTE} illisible : {e}"))?;
    if let Some(c) = cle_attendue {
        if c.trim() != m.cle_publique.trim() {
            return Err("manifeste signé par une autre clé que celle de l'instance attendue".into());
        }
    }
    let cle = crate::mandat::cle_publique(&m.cle_publique).map_err(|e| e.to_string())?;
    let sig = hex::decode(m.signature.trim()).map_err(|_| "signature illisible".to_string())?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| "signature de longueur invalide".to_string())?;
    cle.verify(&m.octets_signes(), &Signature::from_bytes(&sig)).map_err(|_| "signature du manifeste invalide".to_string())?;
    let presentes = inventorier(dossier)?;
    for p in &m.pieces {
        match presentes.iter().find(|x| x.fichier == p.fichier) {
            None => return Err(format!("pièce manquante : {}", p.fichier)),
            Some(x) if x.sha256 != p.sha256 => return Err(format!("pièce modifiée : {}", p.fichier)),
            _ => {}
        }
    }
    if let Some(x) = presentes.iter().find(|x| !m.pieces.iter().any(|p| p.fichier == x.fichier)) {
        return Err(format!("pièce ajoutée hors du manifeste : {}", x.fichier));
    }
    Ok(Verification { pieces: m.pieces.len(), cle_publique: m.cle_publique })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constats() -> Constats {
        Constats {
            signataires_mandat: vec!["alice".into(), "bob".into()],
            seuil: 2,
            comptes_cosignes: true,
            approbateurs: 1,
            operateurs: 1,
            evaluation: Some((0.9, 1.0)),
            sessions_intactes: 3,
            scelles: 2,
            scelles_valides: true,
            ancre_verifiee: true,
            premiere_entree: Some(0),
            derniere_entree: Some(200 * 86_400_000),
            decisions: 10,
            ..Default::default()
        }
    }

    fn statut(c: &Constats, art: &str) -> Statut {
        articles(c).into_iter().find(|a| a.article == art).unwrap().statut
    }

    #[test]
    fn statuts_constates() {
        let mut c = constats();
        assert_eq!(statut(&c, "Art. 12"), Statut::Couvert);
        assert_eq!(statut(&c, "Art. 14"), Statut::Couvert);
        assert_eq!(statut(&c, "Art. 15"), Statut::Couvert);
        assert_eq!(statut(&c, "Art. 19, art. 26 § 6"), Statut::Couvert);
        assert_eq!(statut(&c, "Art. 10"), Statut::HorsPerimetre);
        // Un journal rompu, une gouvernance à un seul signataire, une sûreté faible : partiel.
        c.sessions_rompues = 1;
        c.signataires_mandat.pop();
        c.evaluation = Some((0.5, 1.0));
        c.derniere_entree = Some(30 * 86_400_000);
        for art in ["Art. 12", "Art. 14", "Art. 15", "Art. 19, art. 26 § 6"] {
            assert_eq!(statut(&c, art), Statut::Partiel, "{art}");
        }
    }

    #[test]
    fn manifeste_signe_et_verifie() {
        let d = std::env::temp_dir().join(format!("aplomb-preuves-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("mandat")).unwrap();
        std::fs::write(d.join("mandat/m.yaml"), "id: m").unwrap();
        std::fs::write(d.join("journal.json"), "{}").unwrap();
        let cle = SigningKey::from_bytes(&[7; 32]);
        let mut m = Manifeste {
            format: FORMAT,
            systeme: "m".into(),
            version_mandat: 1,
            empreinte_mandat: "e".into(),
            instance: "i".into(),
            genere: 1,
            aplomb: "0.1.0".into(),
            pieces: inventorier(&d).unwrap(),
            cle_publique: String::new(),
            signature: String::new(),
        };
        m.signer(&cle);
        std::fs::write(d.join(MANIFESTE), serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(verifier(&d, None).unwrap().pieces, 2);
        assert!(verifier(&d, Some(&hex::encode([1u8; 32]))).unwrap_err().contains("autre clé"));
        std::fs::write(d.join("journal.json"), "{\"falsifie\": 1}").unwrap();
        assert!(verifier(&d, None).unwrap_err().contains("modifiée : journal.json"));
        std::fs::write(d.join("journal.json"), "{}").unwrap();
        std::fs::write(d.join("ajout.txt"), "x").unwrap();
        assert!(verifier(&d, None).unwrap_err().contains("ajoutée"));
        std::fs::remove_file(d.join("ajout.txt")).unwrap();
        std::fs::remove_file(d.join("mandat/m.yaml")).unwrap();
        assert!(verifier(&d, None).unwrap_err().contains("manquante"));
    }
}
