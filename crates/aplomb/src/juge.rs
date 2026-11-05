//! **Juge** (EF-E1, EF-E5) : interroge le modèle juge déclaré au mandat. La cascade, la
//! saisine et la lecture de l'avis sont dans `aplomb_core::moniteurs` ; ici, seulement
//! l'appel réseau, borné par le délai du mandat.
use std::time::{Duration, Instant};

use aplomb_core::decision::Avis;
use aplomb_core::moniteurs::{chemin, lire_avis, requete, ApiJuge, ConfigJuge};

/// Délai maximal du juge : le hook attend la décision 8 s.
const DELAI_MAX_MS: u64 = 6000;

pub struct Juge {
    pub cfg: ConfigJuge,
    /// Hôte validé (`https://…`, ou `http://` vers la machine seulement).
    amont: String,
    /// Jeton du modèle confié à Aplomb, pour l'API Messages.
    jeton: Option<String>,
    client: reqwest::Client,
}

impl Juge {
    pub fn nouveau(cfg: ConfigJuge, jeton: Option<String>) -> Result<Self, String> {
        let amont = aplomb_core::modele::amont(&cfg.url).map_err(|e| format!("moniteurs.juge.url : {e}"))?;
        if cfg.delai_ms > DELAI_MAX_MS {
            return Err(format!("moniteurs.juge.delai_ms : {DELAI_MAX_MS} au plus (le hook attend 8 s le superviseur)"));
        }
        if cfg.api == ApiJuge::Anthropic && jeton.is_none() {
            return Err("juge sur l'API Messages sans jeton : lancer aplomb modele jeton".into());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.delai_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { cfg, amont, jeton, client })
    }

    pub fn description(&self) -> String {
        format!("{} ({:?}, {})", self.cfg.modele, self.cfg.api, self.amont).to_lowercase()
    }

    /// Consulte le juge ; rend son avis et la latence, ou la cause de l'échec.
    pub async fn consulter(&self, consigne: &str, message: &str) -> (Result<Avis, String>, u64) {
        let debut = Instant::now();
        let mut r = self
            .client
            .post(format!("{}{}", self.amont, chemin(self.cfg.api)))
            .header("content-type", "application/json")
            .body(requete(self.cfg.api, &self.cfg.modele, consigne, message).to_string());
        if let (ApiJuge::Anthropic, Some(jeton)) = (self.cfg.api, &self.jeton) {
            for (n, v) in aplomb_core::modele::entetes_amont(&[("anthropic-version".into(), "2023-06-01".into())], jeton) {
                r = r.header(n, v);
            }
        }
        let issue = async {
            let reponse = r.send().await.map_err(|e| if e.is_timeout() { "délai dépassé".to_string() } else { "injoignable".to_string() })?;
            if !reponse.status().is_success() {
                return Err(format!("statut {}", reponse.status().as_u16()));
            }
            let octets = reponse.bytes().await.map_err(|_| "réponse interrompue".to_string())?;
            let v: serde_json::Value = serde_json::from_slice(&octets).map_err(|_| "réponse illisible".to_string())?;
            lire_avis(&self.cfg, &v)
        }
        .await;
        (issue, debut.elapsed().as_millis() as u64)
    }
}
