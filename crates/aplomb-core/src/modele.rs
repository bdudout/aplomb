//! **Proxy LLM** (Aplomb Gate, niveau d'assurance 2) : règles pures, sans I/O.
//!
//! L'agent ne parle plus à son modèle directement : il passe par Aplomb, qui
//! - ne laisse passer que les appels de conversation (`POST /v1/messages`, et son comptage
//!   de jetons) : ni fichiers, ni lots, ni administration du compte ;
//! - retire toute clé fournie par l'agent et injecte la sienne : une clé apportée par un
//!   script de l'agent ne sert à rien, ce qui ferme l'exfiltration par le canal modèle ;
//! - relève dans la réponse les outils que le modèle demande, pour le journal.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

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

/// Amont du proxy depuis une entrée de `domaines_modele` : un domaine (`api.anthropic.com`,
/// joint en HTTPS) ou une URL. HTTP en clair n'est permis que vers la machine elle-même
/// (modèle local servi par Ollama, vLLM, llama.cpp ; banc d'essai).
pub fn amont(entree: &str) -> Result<String, String> {
    let e = entree.trim().trim_end_matches('/');
    let Some(reste) = e.strip_prefix("http://") else {
        let hote = e.strip_prefix("https://").unwrap_or(e);
        if hote.is_empty() || hote.contains('/') || hote.contains(char::is_whitespace) {
            return Err(format!("domaines_modele : « {entree} » n'est ni un domaine ni une URL d'hôte"));
        }
        return Ok(format!("https://{hote}"));
    };
    let hote = reste.rsplit_once(':').map_or(reste, |(h, port)| if port.chars().all(|c| c.is_ascii_digit()) { h } else { reste });
    if reste.contains('/') || !matches!(hote, "127.0.0.1" | "localhost" | "[::1]") {
        return Err(format!("domaines_modele : « {entree} » : HTTP en clair seulement vers 127.0.0.1, localhost ou [::1]"));
    }
    Ok(e.to_string())
}

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

/// Outil demandé par le modèle, avec l'identifiant d'appel qu'il lui donne (`toolu_…`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutilDemande {
    pub nom: String,
    pub id: String,
}

/// Ce que le journal retient d'un échange avec le modèle.
#[derive(Debug, Default, PartialEq)]
pub struct Bilan {
    /// Outils demandés par le modèle, dans l'ordre.
    pub outils: Vec<OutilDemande>,
    /// Jetons d'entrée, cache compris (lus et écrits).
    pub jetons_entree: Option<u64>,
    pub jetons_sortie: Option<u64>,
}

/// Jetons d'entrée d'un bloc `usage` : directs, plus ceux lus ou écrits dans le cache.
fn entree_totale(usage: &serde_json::Value) -> Option<u64> {
    let champs = ["input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"];
    let valeurs: Vec<u64> = champs.iter().filter_map(|k| usage.get(*k).and_then(serde_json::Value::as_u64)).collect();
    (!valeurs.is_empty()).then(|| valeurs.iter().sum())
}

fn outil_demande(c: &serde_json::Value) -> Option<OutilDemande> {
    use serde_json::Value;
    (c.get("type").and_then(Value::as_str) == Some("tool_use")).then_some(())?;
    Some(OutilDemande {
        nom: c.get("name").and_then(Value::as_str)?.to_string(),
        id: c.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
    })
}

/// Lit une réponse de l'API Messages, en JSON ou en flux d'événements (SSE).
pub fn analyser_reponse(corps: &[u8]) -> Bilan {
    use serde_json::Value;
    let texte = String::from_utf8_lossy(corps);
    let mut b = Bilan::default();
    let mut lire = |v: &Value| {
        let sortie = |v: &Value| v.get("usage").and_then(|u| u.get("output_tokens")).and_then(Value::as_u64);
        let entree = |v: &Value| v.get("usage").and_then(entree_totale);
        match v.get("type").and_then(Value::as_str) {
            // Réponse complète.
            Some("message") => {
                b.outils.extend(v.get("content").and_then(Value::as_array).into_iter().flatten().filter_map(outil_demande));
                b.jetons_entree = entree(v).or(b.jetons_entree);
                b.jetons_sortie = sortie(v).or(b.jetons_sortie);
            }
            // Flux.
            Some("message_start") => {
                if let Some(m) = v.get("message") {
                    b.jetons_entree = entree(m).or(b.jetons_entree);
                }
            }
            Some("content_block_start") => b.outils.extend(v.get("content_block").and_then(outil_demande)),
            Some("message_delta") => b.jetons_sortie = sortie(v).or(b.jetons_sortie),
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

/// Appel d'outil annoncé par le modèle : dans quel échange, et pour quelle session d'agent
/// si l'agent l'a dite au proxy.
#[derive(Debug, Clone, PartialEq)]
pub struct Annonce {
    pub echange: u64,
    pub session_agent: Option<String>,
}

/// Registre borné des appels d'outils annoncés par le modèle (contrôle croisé : une action
/// présentée au superviseur doit avoir été demandée par le modèle).
#[derive(Debug, Default)]
pub struct Annonces {
    ids: HashMap<String, Annonce>,
    ordre: VecDeque<String>,
}

impl Annonces {
    const MAX: usize = 10_000;

    pub fn annoncer(&mut self, id: &str, annonce: Annonce) {
        if id.is_empty() || self.ids.insert(id.to_string(), annonce).is_some() {
            return;
        }
        self.ordre.push_back(id.to_string());
        if self.ordre.len() > Self::MAX {
            if let Some(ancien) = self.ordre.pop_front() {
                self.ids.remove(&ancien);
            }
        }
    }

    pub fn trouver(&self, id: &str) -> Option<&Annonce> {
        self.ids.get(id)
    }
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
    fn amont_en_https_sauf_modele_local() {
        assert_eq!(amont("api.anthropic.com").unwrap(), "https://api.anthropic.com");
        assert_eq!(amont("https://api.example.com/").unwrap(), "https://api.example.com");
        assert_eq!(amont("http://127.0.0.1:11434").unwrap(), "http://127.0.0.1:11434");
        assert_eq!(amont("http://localhost:8000").unwrap(), "http://localhost:8000");
        assert!(amont("http://api.anthropic.com").is_err());
        assert!(amont("http://127.0.0.1.evil.com").is_err());
        assert!(amont("http://127.0.0.1:80/chemin").is_err());
        assert!(amont("https://h/chemin").is_err());
        assert!(amont("").is_err());
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
        let json = br#"{"type":"message","content":[{"type":"text","text":"x"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}],"usage":{"input_tokens":12,"output_tokens":7}}"#;
        let o = |nom: &str, id: &str| OutilDemande { nom: nom.into(), id: id.into() };
        assert_eq!(
            analyser_reponse(json),
            Bilan { outils: vec![o("Bash", "toolu_1")], jetons_entree: Some(12), jetons_sortie: Some(7) }
        );
        let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2,\"cache_read_input_tokens\":20,\"cache_creation_input_tokens\":8}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"Read\"}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_3\",\"name\":\"Edit\"}}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":44}}\n\n";
        assert_eq!(
            analyser_reponse(sse),
            Bilan { outils: vec![o("Read", "toolu_2"), o("Edit", "toolu_3")], jetons_entree: Some(30), jetons_sortie: Some(44) }
        );
        assert_eq!(analyser_reponse(b"pas du json"), Bilan::default());
    }

    #[test]
    fn registre_borne_des_annonces() {
        let mut a = Annonces::default();
        a.annoncer("toolu_a", Annonce { echange: 1, session_agent: None });
        a.annoncer("", Annonce { echange: 1, session_agent: None });
        assert_eq!(a.trouver("toolu_a").map(|x| x.echange), Some(1));
        assert!(a.trouver("").is_none());
        for i in 0..Annonces::MAX {
            a.annoncer(&format!("x{i}"), Annonce { echange: 2, session_agent: None });
        }
        assert!(a.trouver("toolu_a").is_none(), "le plus ancien sort du registre");
        assert!(a.trouver("x0").is_some());
    }
}
