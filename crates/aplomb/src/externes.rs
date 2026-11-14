//! **Moniteurs externes** (EF-M1) : appel des services déclarés au mandat
//! (`moniteurs.externes`), selon le contrat v1 de `aplomb_core::modules`. Chaque appel est
//! borné par le délai du moniteur ; une panne vaut son plancher.
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use aplomb_core::decision::Avis;
use aplomb_core::modules::{self, ConfigMoniteurExterne};
use serde_json::Value;

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client HTTP"))
}

/// Consulte un moniteur externe : son avis (le plancher en cas d'échec), la latence, et
/// vrai s'il a échoué.
pub async fn consulter(cfg: &ConfigMoniteurExterne, requete: &Value) -> (Avis, u64, bool) {
    let debut = Instant::now();
    let issue = async {
        let r = client()
            .post(&cfg.url)
            .timeout(Duration::from_millis(cfg.delai_ms))
            .header("content-type", "application/json")
            .body(requete.to_string())
            .send()
            .await
            .map_err(|e| if e.is_timeout() { "délai dépassé".to_string() } else { "service injoignable".to_string() })?;
        if !r.status().is_success() {
            return Err(format!("réponse {}", r.status().as_u16()));
        }
        let octets = r.bytes().await.map_err(|_| "réponse illisible".to_string())?;
        let v: Value = serde_json::from_slice(&octets).map_err(|_| "réponse illisible".to_string())?;
        modules::lire_avis(cfg, &v)
    }
    .await;
    let latence = debut.elapsed().as_millis() as u64;
    match issue {
        Ok(a) => (a, latence, false),
        Err(e) => (modules::avis_panne(cfg, &e), latence, true),
    }
}
