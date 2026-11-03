//! **Proxy LLM** (Aplomb Gate, niveau d'assurance 2) : règles pures, sans I/O.
//!
//! L'agent ne parle plus à son modèle directement : il passe par Aplomb, qui
//! - ne laisse passer que les appels de conversation (`POST /v1/messages`, et son comptage
//!   de jetons) : ni fichiers, ni lots, ni administration du compte ;
//! - retire toute clé fournie par l'agent et injecte la sienne : une clé apportée par un
//!   script de l'agent ne sert à rien, ce qui ferme l'exfiltration par le canal modèle ;
//! - relève dans la réponse les outils que le modèle demande, pour le journal.

/// Chemins permis (la requête peut porter une chaîne de requête, ex. `?beta=true`).
const CHEMINS: &[&str] = &["/v1/messages", "/v1/messages/count_tokens"];

/// En-têtes jamais transmis à l'amont : authentification de l'agent, saut à saut, et
/// compression (Aplomb lit la réponse pour le journal).
const RETIRES: &[&str] = &[
    "authorization", "x-api-key", "cookie", "host", "content-length", "connection", "keep-alive",
    "transfer-encoding", "te", "upgrade", "accept-encoding", "proxy-authorization", "proxy-connection",
];

/// Indicateur de bêta exigé par l'API pour un jeton OAuth (`claude setup-token`).
const BETA_OAUTH: &str = "oauth-2025-04-20";

pub fn chemin_permis(methode: &str, chemin: &str) -> bool {
    methode.eq_ignore_ascii_case("POST") && CHEMINS.contains(&chemin)
}

/// En-têtes à envoyer à l'amont : ceux de l'agent, moins les retirés, plus le jeton d'Aplomb.
pub fn entetes_amont(entrants: &[(String, String)], jeton: &str) -> Vec<(String, String)> {
    let mut sortie: Vec<(String, String)> = entrants
        .iter()
        .filter(|(n, _)| {
            let n = n.to_ascii_lowercase();
            !RETIRES.contains(&n.as_str()) && !n.starts_with("proxy-")
        })
        .cloned()
        .collect();
    // Clé d'API (`sk-ant-api…`) en x-api-key ; tout autre jeton est un jeton de compte
    // Claude (OAuth, `claude setup-token`), dont le format peut évoluer.
    if !jeton.starts_with("sk-ant-api") {
        sortie.push(("authorization".into(), format!("Bearer {jeton}")));
        match sortie.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case("anthropic-beta")) {
            Some((_, v)) if v.split(',').any(|b| b.trim() == BETA_OAUTH) => {}
            Some((_, v)) => *v = format!("{v},{BETA_OAUTH}"),
            None => sortie.push(("anthropic-beta".into(), BETA_OAUTH.into())),
        }
    } else {
        sortie.push(("x-api-key".into(), jeton.into()));
    }
    sortie
}

/// Ce que le journal retient d'un échange avec le modèle.
#[derive(Debug, Default, PartialEq)]
pub struct Bilan {
    /// Outils demandés par le modèle, dans l'ordre.
    pub outils: Vec<String>,
    pub jetons_entree: Option<u64>,
    pub jetons_sortie: Option<u64>,
}

/// Lit une réponse de l'API Messages, en JSON ou en flux d'événements (SSE).
pub fn analyser_reponse(corps: &[u8]) -> Bilan {
    use serde_json::Value;
    let texte = String::from_utf8_lossy(corps);
    let mut b = Bilan::default();
    let mut lire = |v: &Value| {
        let u = |v: &Value, k: &str| v.get("usage").and_then(|u| u.get(k)).and_then(Value::as_u64);
        match v.get("type").and_then(Value::as_str) {
            // Réponse complète.
            Some("message") => {
                for c in v.get("content").and_then(Value::as_array).into_iter().flatten() {
                    if c.get("type").and_then(Value::as_str) == Some("tool_use") {
                        b.outils.extend(c.get("name").and_then(Value::as_str).map(String::from));
                    }
                }
                b.jetons_entree = u(v, "input_tokens").or(b.jetons_entree);
                b.jetons_sortie = u(v, "output_tokens").or(b.jetons_sortie);
            }
            // Flux.
            Some("message_start") => {
                if let Some(m) = v.get("message") {
                    b.jetons_entree = u(m, "input_tokens").or(b.jetons_entree);
                }
            }
            Some("content_block_start") => {
                let c = v.get("content_block");
                if c.and_then(|c| c.get("type")).and_then(Value::as_str) == Some("tool_use") {
                    b.outils.extend(c.and_then(|c| c.get("name")).and_then(Value::as_str).map(String::from));
                }
            }
            Some("message_delta") => b.jetons_sortie = u(v, "output_tokens").or(b.jetons_sortie),
            _ => {}
        }
    };
    if let Ok(v) = serde_json::from_str::<Value>(&texte) {
        lire(&v);
    } else {
        for ligne in texte.lines() {
            if let Some(Ok(v)) = ligne.strip_prefix("data:").map(|d| serde_json::from_str::<Value>(d.trim())) {
                lire(&v);
            }
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(n: &str, v: &str) -> (String, String) {
        (n.into(), v.into())
    }

    #[test]
    fn seuls_les_appels_de_conversation_passent() {
        assert!(chemin_permis("POST", "/v1/messages"));
        assert!(chemin_permis("post", "/v1/messages/count_tokens"));
        assert!(!chemin_permis("GET", "/v1/messages"));
        assert!(!chemin_permis("POST", "/v1/files"));
        assert!(!chemin_permis("POST", "/v1/messages/batches"));
        assert!(!chemin_permis("POST", "/v1/messages/../files"));
    }

    #[test]
    fn la_cle_de_l_agent_est_remplacee() {
        let entrants = [
            e("X-Api-Key", "sk-ant-api03-cle-de-l-agent"),
            e("Authorization", "Bearer autre"),
            e("anthropic-version", "2023-06-01"),
            e("Accept-Encoding", "gzip"),
            e("Proxy-Authorization", "x"),
        ];
        let s = entetes_amont(&entrants, "sk-ant-api03-cle-aplomb");
        assert!(!s.iter().any(|(_, v)| v.contains("cle-de-l-agent") || v == "Bearer autre"));
        assert!(s.contains(&e("x-api-key", "sk-ant-api03-cle-aplomb")));
        assert!(s.contains(&e("anthropic-version", "2023-06-01")));
        assert!(!s.iter().any(|(n, _)| n.eq_ignore_ascii_case("accept-encoding") || n.starts_with("Proxy")));
    }

    #[test]
    fn jeton_oauth_en_bearer_avec_sa_beta() {
        let s = entetes_amont(&[e("anthropic-beta", "outils-2025")], "sk-ant-oat01-abc");
        assert!(s.contains(&e("authorization", "Bearer sk-ant-oat01-abc")));
        assert!(s.contains(&e("anthropic-beta", "outils-2025,oauth-2025-04-20")));
        assert!(!s.iter().any(|(n, _)| n == "x-api-key"));
        let s = entetes_amont(&[], "sk-ant-oat01-abc");
        assert!(s.contains(&e("anthropic-beta", "oauth-2025-04-20")));
        // Jeton de compte d'un autre format : toujours en Bearer.
        let s = entetes_amont(&[], "cai-0123456789abcdef");
        assert!(s.contains(&e("authorization", "Bearer cai-0123456789abcdef")));
    }

    #[test]
    fn outils_et_jetons_releves() {
        let json = br#"{"type":"message","content":[{"type":"text","text":"x"},{"type":"tool_use","name":"Bash","input":{}}],"usage":{"input_tokens":12,"output_tokens":7}}"#;
        assert_eq!(
            analyser_reponse(json),
            Bilan { outils: vec!["Bash".into()], jetons_entree: Some(12), jetons_sortie: Some(7) }
        );
        let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":30}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"Read\"}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"Edit\"}}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":44}}\n\n";
        assert_eq!(
            analyser_reponse(sse),
            Bilan { outils: vec!["Read".into(), "Edit".into()], jetons_entree: Some(30), jetons_sortie: Some(44) }
        );
        assert_eq!(analyser_reponse(b"pas du json"), Bilan::default());
    }
}
