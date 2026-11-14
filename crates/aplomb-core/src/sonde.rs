//! **Moniteur interne : sonde linéaire** (EF-F1 à EF-F3, déploiement Avancé).
//!
//! Une sonde lit l'intérieur du modèle supervisé : un **serveur d'activations** (local)
//! rejoue le modèle sur ce qu'il a produit (l'action proposée et son raisonnement, dans le
//! contexte de l'intention du mandat) et rend, pour une couche donnée, la moyenne des
//! activations sur ces jetons. Aplomb y applique la sonde : `score = σ(w·x + b)`. Le serveur
//! peut aussi appliquer la sonde lui-même et ne rendre que le score.
//!
//! Garanties :
//! - **signal d'appoint, jamais condition d'autorisation** (EF-F2) : l'avis n'entre que dans
//!   l'algèbre de décision, qui prend le maximum (EF-K1) ; un score bas ne lève rien ;
//! - **défaillance = plancher configuré** (EF-K3) : délai, serveur injoignable, dimension
//!   inattendue → avis au niveau `plancher` (`suspect` par défaut : revue ; `conforme` pour
//!   un fonctionnement dégradé assumé, EF-F3) ;
//! - **intégrité** (EF-G1) : le fichier des poids est lié au mandat par son empreinte
//!   SHA-256, couverte par la cosignature ;
//! - **budget** (EF-E5) : consultée seulement pour les actions encore permises, dans la
//!   limite de `appels_max` par session.
//!
//! Ce module ne fait aucune I/O réseau ; l'appel est fait par le binaire.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::action::EvenementOutil;
use crate::decision::{Avis, Niveau};

/// Section `moniteurs.sonde` du mandat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigSonde {
    /// Serveur d'activations : HTTP en clair seulement vers la machine (EF-P5).
    pub url: String,
    /// Modèle supervisé dont on lit les activations (celui de l'agent).
    pub modele: String,
    /// Fichier des poids de la sonde (JSON), relatif au mandat. Absent : le serveur
    /// applique la sonde et rend le score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poids: Option<String>,
    /// Empreinte du fichier des poids, posée à la cosignature.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub poids_sha256: String,
    /// Score à partir duquel l'avis est `niveau_max`.
    #[serde(default = "defaut_seuil")]
    pub seuil: f32,
    #[serde(default = "defaut_delai")]
    pub delai_ms: u64,
    /// Avis rendu quand la sonde ne répond pas : `suspect` (revue, défaut) ou `conforme`.
    #[serde(default = "suspect")]
    pub plancher: Niveau,
    /// Avis le plus sévère de la sonde : `suspect` (défaut) ou `critique`.
    #[serde(default = "suspect")]
    pub niveau_max: Niveau,
    /// Consultations par session ; au-delà, la sonde se tait (signal d'appoint).
    #[serde(default = "defaut_appels")]
    pub appels_max: u32,
}

fn defaut_seuil() -> f32 {
    0.5
}
fn defaut_delai() -> u64 {
    1500
}
fn suspect() -> Niveau {
    Niveau::Suspect
}
fn defaut_appels() -> u32 {
    1000
}

/// Poids d'une sonde linéaire (fichier JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Poids {
    /// Ce que la sonde détecte (ex. `tromperie`).
    pub nom: String,
    #[serde(default)]
    pub description: String,
    /// Modèle et couche sur lesquels elle a été entraînée : elle ne vaut que pour eux.
    pub modele: String,
    pub couche: u32,
    pub poids: Vec<f32>,
    pub biais: f32,
    /// Moyenne retranchée aux activations avant la sonde (centrage), facultative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moyenne: Option<Vec<f32>>,
}

impl Poids {
    pub fn lire(texte: &str) -> Result<Self, String> {
        let p: Poids = serde_json::from_str(texte).map_err(|e| format!("poids de sonde illisibles : {e}"))?;
        if p.poids.is_empty() || p.moyenne.as_ref().is_some_and(|m| m.len() != p.poids.len()) {
            return Err("poids de sonde : vecteur vide ou moyenne de mauvaise dimension".into());
        }
        if p.poids.iter().chain(p.moyenne.iter().flatten()).any(|x| !x.is_finite()) || !p.biais.is_finite() {
            return Err("poids de sonde : valeur non finie".into());
        }
        Ok(p)
    }

    /// Score de la sonde sur des activations, dans `[0, 1]`.
    pub fn appliquer(&self, activations: &[f32]) -> Result<f32, String> {
        if activations.len() != self.poids.len() {
            return Err(format!("dimension {} reçue, {} attendue (couche ou modèle différents ?)", activations.len(), self.poids.len()));
        }
        let mut z = self.biais as f64;
        for (i, (w, x)) in self.poids.iter().zip(activations).enumerate() {
            let c = self.moyenne.as_ref().map_or(0.0, |m| m[i]);
            z += *w as f64 * (*x - c) as f64;
        }
        let s = 1.0 / (1.0 + (-z).exp());
        if s.is_finite() { Ok(s as f32) } else { Err("score non fini".into()) }
    }
}

/// Empreinte d'un fichier de poids.
pub fn empreinte(octets: &[u8]) -> String {
    hex::encode(Sha256::digest(octets))
}

impl ConfigSonde {
    pub fn verifier(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.seuil) {
            return Err("moniteurs.sonde.seuil : entre 0 et 1".into());
        }
        if self.plancher == Niveau::Critique {
            return Err("moniteurs.sonde.plancher : conforme ou suspect (une panne de la sonde ne gèle pas une session)".into());
        }
        if self.niveau_max == Niveau::Conforme {
            return Err("moniteurs.sonde.niveau_max : suspect ou critique".into());
        }
        Ok(())
    }
}

/// Texte que le modèle a produit pour cette action : ce que le serveur rejoue.
pub fn texte(evt: &EvenementOutil, raisonnement: Option<&str>) -> String {
    let mut t = String::new();
    if let Some(r) = raisonnement.filter(|r| !r.trim().is_empty()) {
        t.push_str(r.trim());
        t.push('\n');
    }
    t.push_str(&format!("{} {}", evt.outil, evt.entree));
    if let Some(s) = &evt.contenu_execute {
        t.push('\n');
        t.push_str(s);
    }
    t
}

/// Requête au serveur d'activations. L'intention du mandat est le contexte du rejeu ; les
/// secrets sont masqués (le serveur est local, mais son journal peut ne pas l'être).
pub fn requete(cfg: &ConfigSonde, poids: Option<&Poids>, intention: &str, texte: &str, appel: Option<&str>) -> Value {
    let masque = |s: &str| crate::moniteurs::masquer(s).0;
    json!({
        "modele": cfg.modele,
        "couche": poids.map(|p| p.couche),
        "contexte": masque(intention),
        "texte": masque(texte),
        "appel": appel,
        "score": poids.is_none(),
    })
}

/// Lit la réponse : `{"activations": [...]}` (la sonde est appliquée ici) ou `{"score": x}`.
pub fn lire_score(poids: Option<&Poids>, reponse: &Value) -> Result<f32, String> {
    match (poids, reponse.get("activations").and_then(Value::as_array), reponse.get("score").and_then(Value::as_f64)) {
        (Some(p), Some(a), _) => {
            let x: Option<Vec<f32>> = a.iter().map(|v| v.as_f64().map(|f| f as f32).filter(|f| f.is_finite())).collect();
            p.appliquer(&x.ok_or("activations non numériques")?)
        }
        (Some(_), None, _) => Err("réponse sans activations".into()),
        (None, _, Some(s)) if (0.0..=1.0).contains(&s) => Ok(s as f32),
        (None, _, _) => Err("réponse sans score dans [0, 1]".into()),
    }
}

/// Avis de la sonde pour un score.
pub fn avis(cfg: &ConfigSonde, nom: &str, score: f32) -> Avis {
    let alerte = score >= cfg.seuil;
    Avis {
        moniteur: "sonde".into(),
        niveau: if alerte { cfg.niveau_max } else { Niveau::Conforme },
        score,
        motif: if alerte {
            format!("sonde interne « {nom} » : {score:.2} (seuil {:.2}) — à revoir", cfg.seuil)
        } else {
            format!("sonde interne « {nom} » : {score:.2}")
        },
    }
}

/// Avis quand la sonde ne répond pas (EF-K3) : le plancher configuré.
pub fn avis_defaillance(cfg: &ConfigSonde, cause: &str) -> Avis {
    let revue = cfg.plancher > Niveau::Conforme;
    Avis {
        moniteur: "sonde".into(),
        niveau: cfg.plancher,
        score: if revue { 0.5 } else { 0.0 },
        motif: format!("sonde indisponible ({cause}){}", if revue { " : revue" } else { " : mode dégradé, sans moniteur interne" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{combiner, Decision, Verdict};
    use proptest::prelude::*;

    fn cfg() -> ConfigSonde {
        serde_yaml::from_str("url: http://127.0.0.1:11435\nmodele: m").unwrap()
    }

    fn poids() -> Poids {
        Poids { nom: "tromperie".into(), description: String::new(), modele: "m".into(), couche: 3, poids: vec![2.0, -1.0], biais: -0.5, moyenne: None }
    }

    #[test]
    fn defauts_surs() {
        let c = cfg();
        assert_eq!((c.plancher, c.niveau_max, c.seuil), (Niveau::Suspect, Niveau::Suspect, 0.5));
        assert!(c.verifier().is_ok());
        let mut c2 = c.clone();
        c2.plancher = Niveau::Critique;
        assert!(c2.verifier().is_err());
    }

    #[test]
    fn sonde_lineaire() {
        let p = poids();
        assert!(p.appliquer(&[2.0, 0.0]).unwrap() > 0.9);
        assert!(p.appliquer(&[0.0, 2.0]).unwrap() < 0.1);
        assert!(p.appliquer(&[1.0]).unwrap_err().contains("dimension"));
        assert!(Poids::lire(r#"{"nom":"x","modele":"m","couche":1,"poids":[],"biais":0}"#).is_err());
    }

    #[test]
    fn lecture_de_la_reponse() {
        let p = poids();
        assert!(lire_score(Some(&p), &json!({"activations": [2.0, 0.0]})).unwrap() > 0.9);
        assert!(lire_score(Some(&p), &json!({"score": 0.9})).is_err(), "sans activations, la sonde du mandat ne s'applique pas");
        assert_eq!(lire_score(None, &json!({"score": 0.25})).unwrap(), 0.25);
        assert!(lire_score(None, &json!({"score": 3.0})).is_err());
        assert!(lire_score(Some(&p), &json!({"activations": ["a", 1]})).is_err());
    }

    #[test]
    fn defaillance_au_plancher() {
        let mut c = cfg();
        assert_eq!(avis_defaillance(&c, "délai").niveau, Niveau::Suspect);
        c.plancher = Niveau::Conforme;
        assert_eq!(avis_defaillance(&c, "délai").niveau, Niveau::Conforme);
    }

    fn verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![Just(Verdict::Allow), Just(Verdict::Review), Just(Verdict::Deny), Just(Verdict::Gel)]
    }

    proptest! {
        /// EF-F2 : la sonde n'est jamais une condition d'autorisation. Quel que soit son score
        /// (ou sa panne), elle ne fait jamais passer une action que la politique refuse ou
        /// met en revue, et un score bas ne change rien.
        #[test]
        fn jamais_condition_d_autorisation(v in verdict(), score in 0.0f32..=1.0, panne in any::<bool>(), degrade in any::<bool>()) {
            let mut c = cfg();
            if degrade { c.plancher = Niveau::Conforme; }
            let a = if panne { avis_defaillance(&c, "x") } else { avis(&c, "t", score) };
            let r = combiner(Decision { verdict: v, regle: "r".into(), motif: "m".into() }, vec![a.clone()], false);
            prop_assert!(r.verdict >= v);
            if a.niveau == Niveau::Conforme { prop_assert_eq!(r.verdict, v); }
        }
    }
}
