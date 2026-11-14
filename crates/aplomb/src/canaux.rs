//! **Canaux d'approbation** (étape 6, option désactivée sans `approbation.yaml`) : préviennent
//! les réviseurs qu'une action attend leur décision (Slack, Teams, ticket ITSM, courriel,
//! webhook signé). On décide toujours dans Aplomb Watch.
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use aplomb_core::approbation::{self, Canal, ConfigCanaux, Priorite, TypeCanal};
use serde_json::{json, Value};

/// Lecture seule de la configuration (aplomb modules), sans exiger les secrets.
pub fn charger_sans_secrets(chemin: &Path) -> Result<Option<ConfigCanaux>, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => ConfigCanaux::depuis_yaml(&t).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} : {e}", chemin.display())),
    }
}

pub fn charger(chemin: &Path) -> Result<Option<ConfigCanaux>, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => {
            let c = ConfigCanaux::depuis_yaml(&t)?;
            for k in &c.canaux {
                for v in [&k.url_env, &k.jeton_env]
                    .into_iter()
                    .filter(|v| !v.is_empty())
                {
                    if std::env::var(v).map(|s| s.is_empty()).unwrap_or(true) {
                        return Err(format!(
                            "approbation.yaml, canal « {} » : variable {v} absente",
                            k.id
                        ));
                    }
                }
            }
            Ok(Some(c))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} : {e}", chemin.display())),
    }
}

pub fn annonce(c: Option<&ConfigCanaux>) -> String {
    match c {
        Some(c) if !c.canaux.is_empty() => {
            let v: Vec<String> = c
                .canaux
                .iter()
                .map(|k| {
                    format!(
                        "{} ({:?}{})",
                        k.id,
                        k.type_,
                        if k.priorite_min > Priorite::Normale {
                            format!(", dès {:?}", k.priorite_min).to_lowercase()
                        } else {
                            String::new()
                        }
                    )
                    .to_lowercase()
                })
                .collect();
            v.join(", ")
        }
        _ => "Aplomb Watch seulement (option : approbation.yaml, voir docs/APPROBATION.md)".into(),
    }
}

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("client HTTP")
    })
}

fn env(v: &str) -> Option<String> {
    (!v.is_empty()).then(|| std::env::var(v).ok()).flatten()
}

async fn envoyer(k: &Canal, demande: &Value, lien: &str, instance: &str) -> Result<(), String> {
    if k.type_ == TypeCanal::Courriel {
        let de = if k.de.is_empty() {
            "aplomb@localhost".to_string()
        } else {
            k.de.clone()
        };
        let message = approbation::courriel(&de, &k.a, demande, lien, k.details);
        let sendmail = if k.sendmail.is_empty() {
            "/usr/sbin/sendmail".to_string()
        } else {
            k.sendmail.clone()
        };
        let mut p = tokio::process::Command::new(&sendmail)
            .arg("-t")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("{sendmail} : {e}"))?;
        use tokio::io::AsyncWriteExt;
        p.stdin
            .take()
            .ok_or("sendmail sans entrée")?
            .write_all(message.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let s = tokio::time::timeout(Duration::from_secs(20), p.wait())
            .await
            .map_err(|_| "sendmail : délai dépassé".to_string())?
            .map_err(|e| e.to_string())?;
        return if s.success() {
            Ok(())
        } else {
            Err(format!("sendmail : code {}", s.code().unwrap_or(-1)))
        };
    }
    let url = env(&k.url_env).unwrap_or_else(|| k.url.clone());
    let corps = approbation::charge(k.type_, demande, lien, k.details, instance);
    let octets = serde_json::to_vec(&corps).expect("JSON");
    let mut r = client()
        .post(&url)
        .header("content-type", "application/json");
    match k.type_ {
        TypeCanal::Itsm => {
            if let Some(j) = env(&k.jeton_env) {
                r = r.header("authorization", format!("Bearer {j}"));
            }
        }
        TypeCanal::Webhook => {
            let t = crate::identite::maintenant() / 1000;
            let secret = env(&k.jeton_env).ok_or("secret absent")?;
            r = r
                .header("x-aplomb-schema", "aplomb.revue/1")
                .header("x-aplomb-horodatage", t.to_string())
                .header(
                    "x-aplomb-signature",
                    aplomb_core::diffusion::signer_webhook(secret.as_bytes(), t, &octets),
                );
        }
        _ => {}
    }
    let rep = r.body(octets).send().await.map_err(|e| {
        if e.is_timeout() {
            "délai dépassé".into()
        } else {
            "injoignable".to_string()
        }
    })?;
    if rep.status().is_success() {
        Ok(())
    } else {
        Err(format!("réponse {}", rep.status().as_u16()))
    }
}

/// Prévient les canaux concernés par la priorité de la demande ; l'issue de chaque envoi
/// est rendue à `journaliser`.
pub fn prevenir(
    cfg: Arc<ConfigCanaux>,
    demande: Value,
    instance: String,
    journaliser: Arc<dyn Fn(Value) + Send + Sync>,
) {
    let prio: Priorite =
        serde_json::from_value(demande["priorite"].clone()).unwrap_or(Priorite::Normale);
    for k in cfg
        .canaux
        .iter()
        .filter(|k| prio >= k.priorite_min)
        .cloned()
    {
        let (cfg, demande, instance, journaliser) = (
            cfg.clone(),
            demande.clone(),
            instance.clone(),
            journaliser.clone(),
        );
        tokio::spawn(async move {
            let issue = envoyer(&k, &demande, &cfg.lien, &instance).await;
            journaliser(
                json!({"action": "notification-revue", "canal": k.id, "revue": demande["id"],
                               "issue": match &issue { Ok(()) => "envoyée".to_string(), Err(e) => format!("échec : {e}") }}),
            );
        });
    }
}
