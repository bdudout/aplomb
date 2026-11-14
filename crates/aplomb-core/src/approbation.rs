//! **Approbation** (étape 6, EF-M1, J2/J3 de l'audit) : délai de revue fixé au mandat,
//! priorité des demandes, demande enrichie pour l'humain, et canaux qui le préviennent
//! (Slack, Teams, ITSM, courriel, webhook signé).
//!
//! Les canaux ne font que **prévenir** : on approuve dans Aplomb Watch, authentifié (et
//! avec second facteur si la MFA est exigée). Ils ne reçoivent que le strict nécessaire
//! (outil, verbe, priorité, moniteurs, lien), jamais la ressource ni les paramètres, sauf
//! si le canal le déclare (`details: true`).
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::decision::{Avis, Niveau};
use crate::profils::Signaux;

/// Délai de revue par défaut, en secondes.
pub const DELAI_DEFAUT_S: u64 = 120;

/// Réglages d'approbation du mandat (couverts par la signature).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigApprobation {
    /// Temps laissé à l'humain ; ensuite, refus (15 s à 1 h).
    #[serde(default = "delai")]
    pub delai_s: u64,
}

fn delai() -> u64 {
    DELAI_DEFAUT_S
}

impl ConfigApprobation {
    pub fn verifier(&self) -> Result<(), String> {
        if !(15..=3600).contains(&self.delai_s) {
            return Err("approbation.delai_s : entre 15 et 3600 secondes".into());
        }
        Ok(())
    }
}

/// Délai de revue d'un mandat.
pub fn delai_s(c: Option<&ConfigApprobation>) -> u64 {
    c.map(|c| c.delai_s).unwrap_or(DELAI_DEFAUT_S)
}

/// Priorité d'une demande de revue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priorite {
    Normale,
    Haute,
    Critique,
}

/// Verbes dont l'effet ne se défait pas.
pub const IRREVERSIBLES: &[&str] = &[
    "payer",
    "supprimer",
    "exporter",
    "envoyer",
    "exploiter",
    "deleguer",
];

/// Priorité et raisons, lisibles par l'humain (J2).
pub fn priorite(verbe: &str, avis: &[Avis], s: &Signaux) -> (Priorite, Vec<String>) {
    let mut raisons = Vec::new();
    let critiques: Vec<&str> = avis
        .iter()
        .filter(|a| a.niveau == Niveau::Critique)
        .map(|a| a.moniteur.as_str())
        .collect();
    let suspects: Vec<&str> = avis
        .iter()
        .filter(|a| a.niveau == Niveau::Suspect)
        .map(|a| a.moniteur.as_str())
        .collect();
    let irreversible = IRREVERSIBLES.contains(&verbe) || s.envoi;
    if !critiques.is_empty() {
        raisons.push(format!("moniteur critique : {}", critiques.join(", ")));
    }
    if !suspects.is_empty() {
        raisons.push(format!("moniteur suspect : {}", suspects.join(", ")));
    }
    if irreversible {
        raisons.push("effet irréversible (envoi, paiement, suppression, export…)".into());
    }
    if s.sortante {
        raisons.push("sort de la machine".into());
    }
    if s.lit_sensible {
        raisons.push("touche une donnée sensible".into());
    }
    let p = if !critiques.is_empty() || (irreversible && (s.lit_sensible || !suspects.is_empty())) {
        Priorite::Critique
    } else if !suspects.is_empty() || irreversible || s.sortante {
        Priorite::Haute
    } else {
        Priorite::Normale
    };
    if raisons.is_empty() {
        raisons.push("règle de revue du mandat".into());
    }
    (p, raisons)
}

/// Ce que l'humain doit savoir pour décider (J3).
pub fn consequences(delai_s: u64) -> Value {
    json!({
        "approuver": "l'action s'exécute une fois ; l'approbation et le compte sont journalisés",
        "refuser": "l'agent reçoit un refus et peut proposer autre chose ; la session continue",
        "sans_reponse": format!("refus après {delai_s} s"),
        "geler": "en cas de doute : bouton Geler, la session s'arrête aussitôt (dégel à quatre yeux)",
    })
}

// ------------------------------------------------------------------ canaux

/// Fichier `approbation.yaml` de l'instance (option, désactivée sans lui).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigCanaux {
    /// Adresse d'Aplomb Watch telle que les réviseurs la joignent (lien des messages).
    #[serde(default)]
    pub lien: String,
    #[serde(default)]
    pub canaux: Vec<Canal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeCanal {
    Slack,
    Teams,
    /// Ticket ITSM (champs compatibles ServiceNow : short_description, urgency…).
    Itsm,
    /// Courriel par `sendmail -t`.
    Courriel,
    /// JSON signé HMAC-SHA256 (comme la diffusion).
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Canal {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: TypeCanal,
    /// URL (ITSM, webhook).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// Variable qui porte l'URL quand elle est un secret (Slack, Teams).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url_env: String,
    /// Variable qui porte le jeton (ITSM) ou le secret (webhook).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jeton_env: String,
    /// Destinataires (courriel).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub de: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sendmail: String,
    /// Priorité minimale des demandes envoyées sur ce canal.
    #[serde(default = "normale")]
    pub priorite_min: Priorite,
    /// Joindre le motif détaillé (peut nommer la ressource visée). Défaut : non.
    #[serde(default)]
    pub details: bool,
}

fn normale() -> Priorite {
    Priorite::Normale
}

impl ConfigCanaux {
    pub fn depuis_yaml(t: &str) -> Result<Self, String> {
        let c: ConfigCanaux =
            serde_yaml::from_str(t).map_err(|e| format!("approbation.yaml : {e}"))?;
        let mut ids = std::collections::BTreeSet::new();
        for k in &c.canaux {
            let ou = format!("approbation.yaml, canal « {} »", k.id);
            if !ids.insert(&k.id) {
                return Err(format!("{ou} : déclaré deux fois"));
            }
            match k.type_ {
                TypeCanal::Slack | TypeCanal::Teams if k.url_env.is_empty() => {
                    return Err(format!(
                        "{ou} : url_env (variable qui porte l'adresse du webhook, un secret)"
                    ))
                }
                TypeCanal::Itsm | TypeCanal::Webhook
                    if k.url.is_empty() && k.url_env.is_empty() =>
                {
                    return Err(format!("{ou} : url requise"))
                }
                TypeCanal::Webhook if k.jeton_env.is_empty() => {
                    return Err(format!("{ou} : jeton_env (secret de signature)"))
                }
                TypeCanal::Courriel if k.a.is_empty() => {
                    return Err(format!("{ou} : a: [destinataires]"))
                }
                _ => {}
            }
            if !k.url.is_empty()
                && !(k.url.starts_with("https://")
                    || crate::diffusion::hote_url(&k.url).is_some_and(|(s, h)| {
                        s == "http" && (h == "127.0.0.1" || h == "localhost")
                    }))
            {
                return Err(format!(
                    "{ou} : https:// exigé (http seulement vers la machine elle-même)"
                ));
            }
            if k.a
                .iter()
                .chain(std::iter::once(&k.de))
                .any(|x| x.contains(['\r', '\n']))
            {
                return Err(format!("{ou} : adresse de courriel invalide"));
            }
        }
        if !c.canaux.is_empty() && c.lien.is_empty() {
            return Err(
                "approbation.yaml : lien (adresse d'Aplomb Watch pour les réviseurs) requis".into(),
            );
        }
        Ok(c)
    }
}

/// Résumé d'une demande pour les canaux : rien de la ressource, sauf `details`.
pub fn message(demande: &Value, lien: &str, details: bool) -> (String, String) {
    let s = |k: &str| {
        demande
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let prio = s("priorite");
    let titre = format!(
        "[Aplomb] Revue demandée ({prio}) : {} — système {}",
        s("outil"),
        s("systeme")
    );
    let raisons: Vec<String> = demande["raisons"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_str().map(String::from))
        .collect();
    let mut corps = format!(
        "Une action de l'agent attend une décision humaine.\n\nSystème : {}\nOutil : {} ({})\nPriorité : {prio}\nPourquoi : {}\nSans réponse : refus dans {} s.\n",
        s("systeme"),
        s("outil"),
        s("verbe"),
        raisons.join(" ; "),
        demande["delai"].as_u64().unwrap_or(DELAI_DEFAUT_S)
    );
    if details {
        corps.push_str(&format!("Motif : {}\n", s("motif")));
    }
    corps.push_str(&format!(
        "\nDécider dans Aplomb Watch (revue n° {}) : {lien}\n",
        demande["id"]
    ));
    (titre, corps)
}

/// Corps HTTP d'une notification selon le canal.
pub fn charge(
    type_: TypeCanal,
    demande: &Value,
    lien: &str,
    details: bool,
    instance: &str,
) -> Value {
    let (titre, corps) = message(demande, lien, details);
    match type_ {
        TypeCanal::Slack => json!({"text": format!("*{titre}*\n{corps}")}),
        TypeCanal::Teams => json!({
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                "body": [{"type": "TextBlock", "text": titre, "weight": "Bolder", "wrap": true}, {"type": "TextBlock", "text": corps, "wrap": true}],
                "actions": [{"type": "Action.OpenUrl", "title": "Ouvrir Aplomb Watch", "url": lien}],
            }}],
        }),
        TypeCanal::Itsm => {
            let urgence = match demande["priorite"].as_str() {
                Some("critique") => 1,
                Some("haute") => 2,
                _ => 3,
            };
            json!({"short_description": titre, "description": corps, "urgency": urgence, "impact": urgence,
                   "category": "security", "correlation_id": format!("aplomb-{instance}-revue-{}", demande["id"])})
        }
        TypeCanal::Webhook | TypeCanal::Courriel => {
            let mut d = json!({"schema": "aplomb.revue/1", "id": demande["id"], "systeme": demande["systeme"], "outil": demande["outil"],
                "verbe": demande["verbe"], "priorite": demande["priorite"], "raisons": demande["raisons"], "delai": demande["delai"], "lien": lien});
            if details {
                d["motif"] = demande["motif"].clone();
            }
            d
        }
    }
}

/// Courriel RFC 5322 pour `sendmail -t`.
pub fn courriel(de: &str, a: &[String], demande: &Value, lien: &str, details: bool) -> String {
    let (titre, corps) = message(demande, lien, details);
    let sujet: String = titre.chars().filter(|c| !c.is_control()).collect();
    format!(
        "From: {de}\r\nTo: {}\r\nSubject: =?UTF-8?B?{}?=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n{}",
        a.join(", "),
        base64_std(sujet.as_bytes()),
        corps.replace('\n', "\r\n")
    )
}

fn base64_std(o: &[u8]) -> String {
    crate::identite::base64url(o)
        .replace('-', "+")
        .replace('_', "/")
        + ["", "==", "="][o.len() % 3]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avis(n: Niveau) -> Avis {
        Avis {
            moniteur: "juge".into(),
            niveau: n,
            score: 0.8,
            motif: "m".into(),
        }
    }

    #[test]
    fn priorites() {
        let rien = Signaux::default();
        assert_eq!(priorite("lire", &[], &rien).0, Priorite::Normale);
        assert_eq!(
            priorite("lire", &[avis(Niveau::Suspect)], &rien).0,
            Priorite::Haute
        );
        assert_eq!(priorite("payer", &[], &rien).0, Priorite::Haute);
        let sensible = Signaux {
            lit_sensible: true,
            ..Default::default()
        };
        let (p, r) = priorite("exporter", &[], &sensible);
        assert_eq!(p, Priorite::Critique);
        assert!(r.iter().any(|x| x.contains("irréversible")));
        assert_eq!(
            priorite("lire", &[avis(Niveau::Critique)], &rien).0,
            Priorite::Critique
        );
        let envoi = Signaux {
            envoi: true,
            sortante: true,
            ..Default::default()
        };
        assert_eq!(priorite("reseau", &[], &envoi).0, Priorite::Haute);
    }

    #[test]
    fn canaux_et_messages() {
        let ok = "lien: https://aplomb.ex\ncanaux:\n- {id: s, type: slack, url_env: S}\n- {id: m, type: courriel, a: [secops@ex.fr], priorite_min: haute}\n- {id: i, type: itsm, url: 'https://itsm/api', jeton_env: J}\n";
        let c = ConfigCanaux::depuis_yaml(ok).unwrap();
        assert_eq!(c.canaux[1].priorite_min, Priorite::Haute);
        for (y, e) in [
            (
                "lien: x\ncanaux: [{id: s, type: slack, url: 'https://hooks.slack.com/x'}]",
                "url_env",
            ),
            ("canaux: [{id: s, type: slack, url_env: S}]", "lien"),
            (
                "lien: x\ncanaux: [{id: w, type: webhook, url: 'http://ex.fr/h', jeton_env: J}]",
                "https",
            ),
            (
                "lien: x\ncanaux: [{id: m, type: courriel, a: [\"a@b\\r\\nBcc: x\"]}]",
                "invalide",
            ),
            (
                "lien: x\ncanaux: [{id: m, type: courriel}]",
                "destinataires",
            ),
        ] {
            assert!(ConfigCanaux::depuis_yaml(y).unwrap_err().contains(e), "{y}");
        }
        let d = json!({"id": 7, "systeme": "code", "outil": "Bash", "verbe": "reseau", "priorite": "haute",
                       "raisons": ["sort de la machine"], "delai": 300, "motif": "domaine secret.exemple.org"});
        let (titre, corps) = message(&d, "https://aplomb.ex", false);
        assert!(
            titre.contains("(haute)")
                && corps.contains("refus dans 300 s")
                && corps.contains("n° 7")
        );
        assert!(
            !corps.contains("secret.exemple.org"),
            "pas de ressource sans details"
        );
        assert!(message(&d, "l", true).1.contains("secret.exemple.org"));
        assert!(charge(TypeCanal::Teams, &d, "l", false, "i")
            .to_string()
            .contains("AdaptiveCard"));
        assert_eq!(charge(TypeCanal::Itsm, &d, "l", false, "i")["urgency"], 2);
        assert!(charge(TypeCanal::Webhook, &d, "l", false, "i")
            .get("motif")
            .is_none());
        let m = courriel("aplomb@ex.fr", &["a@ex.fr".into()], &d, "l", false);
        assert!(m.starts_with("From: aplomb@ex.fr\r\nTo: a@ex.fr\r\nSubject: =?UTF-8?B?"));
        assert_eq!(base64_std(b"foob"), "Zm9vYg==");
    }
}
