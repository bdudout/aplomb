//! **Sonde** (moniteur interne, EF-F) : interroge le serveur d'activations déclaré au mandat.
//! Les poids, la lecture du score et l'avis sont dans `aplomb_core::sonde` ; ici, le
//! chargement des poids (vérifiés par leur empreinte) et l'appel réseau, borné par le délai.
use std::path::Path;
use std::time::{Duration, Instant};

use aplomb_core::decision::Avis;
use aplomb_core::sonde::{self, ConfigSonde, Poids};

/// Délai maximal : le hook attend la décision 8 s, le juge peut en prendre 6.
const DELAI_MAX_MS: u64 = 2000;

pub struct Sonde {
    pub cfg: ConfigSonde,
    pub poids: Option<Poids>,
    amont: String,
    client: reqwest::Client,
}

impl Sonde {
    /// `dossier` : celui du mandat (les poids y sont relatifs). `exiger_empreinte` : en
    /// service, des poids non liés au mandat par la cosignature sont refusés.
    pub fn nouvelle(cfg: ConfigSonde, dossier: &Path, exiger_empreinte: bool) -> Result<Self, String> {
        cfg.verifier()?;
        let amont = aplomb_core::modele::amont(&cfg.url).map_err(|e| format!("moniteurs.sonde.url : {}", e.replace("domaines_modele", "url")))?;
        if !amont.starts_with("http://") {
            // Les activations rejouent le contenu des actions : elles ne quittent pas la machine (EF-P5).
            return Err("moniteurs.sonde.url : serveur d'activations local attendu (http://127.0.0.1:<port>)".into());
        }
        if cfg.delai_ms > DELAI_MAX_MS {
            return Err(format!("moniteurs.sonde.delai_ms : {DELAI_MAX_MS} au plus"));
        }
        let poids = match &cfg.poids {
            None => None,
            Some(f) => {
                let chemin = dossier.join(f);
                let octets = std::fs::read(&chemin).map_err(|e| format!("poids de la sonde {} : {e}", chemin.display()))?;
                let e = sonde::empreinte(&octets);
                if cfg.poids_sha256.is_empty() && exiger_empreinte {
                    return Err("poids de la sonde non liés au mandat : faire cosigner le mandat (aplomb cosigner)".into());
                }
                if !cfg.poids_sha256.is_empty() && e != cfg.poids_sha256 {
                    return Err(format!("poids de la sonde {} modifiés depuis la cosignature : faire recosigner le mandat", chemin.display()));
                }
                let p = Poids::lire(&String::from_utf8_lossy(&octets))?;
                if p.modele != cfg.modele {
                    eprintln!("  attention : sonde entraînée sur « {} », mandat pour « {} » — elle ne vaut que pour son modèle", p.modele, cfg.modele);
                }
                Some(p)
            }
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.delai_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { cfg, poids, amont, client })
    }

    pub fn nom(&self) -> String {
        self.poids.as_ref().map_or_else(|| "score du serveur".into(), |p| p.nom.clone())
    }

    pub fn description(&self) -> String {
        format!("{} sur {} ({}, seuil {:.2}, panne : {:?})", self.nom(), self.cfg.modele, self.amont, self.cfg.seuil, self.cfg.plancher).to_lowercase()
    }

    /// Consulte la sonde ; rend son avis (le plancher en cas d'échec), la latence, et vrai si
    /// elle a échoué.
    pub async fn consulter(&self, intention: &str, texte: &str, appel: Option<&str>) -> (Avis, u64, bool) {
        let debut = Instant::now();
        let corps = sonde::requete(&self.cfg, self.poids.as_ref(), intention, texte, appel);
        let issue = async {
            let r = self
                .client
                .post(format!("{}/v1/activations", self.amont))
                .header("content-type", "application/json")
                .body(corps.to_string())
                .send()
                .await
                .map_err(|e| if e.is_timeout() { "délai dépassé".to_string() } else { "injoignable".to_string() })?;
            if !r.status().is_success() {
                return Err(format!("statut {}", r.status().as_u16()));
            }
            let octets = r.bytes().await.map_err(|_| "réponse interrompue".to_string())?;
            let v: serde_json::Value = serde_json::from_slice(&octets).map_err(|_| "réponse illisible".to_string())?;
            sonde::lire_score(self.poids.as_ref(), &v)
        }
        .await;
        let latence = debut.elapsed().as_millis() as u64;
        match issue {
            Ok(s) => (sonde::avis(&self.cfg, &self.nom(), s), latence, false),
            Err(e) => (sonde::avis_defaillance(&self.cfg, &e), latence, true),
        }
    }
}
