//! **Aplomb Gate, proxy LLM** (niveau d'assurance 2) : l'agent parle à son modèle par
//! Aplomb (`ANTHROPIC_BASE_URL`), jamais directement.
//!
//! 1. Seuls les appels de conversation passent (`aplomb_core::modele::chemin_permis`).
//! 2. Gel : plus rien ne part vers le modèle.
//! 3. Journal avant envoi (fail-closed), puis bilan à la fin de la réponse : modèle,
//!    volumes, jetons, outils demandés par le modèle.
//! 4. La clé de l'agent est retirée, celle d'Aplomb injectée : le canal modèle ne peut pas
//!    servir à exfiltrer vers un autre compte.
//!
//! La réponse est relayée au fil de l'eau (flux SSE compris) et lue au passage.
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use aplomb_core::action::{EvenementOutil, Phase};
use aplomb_core::modele::{analyser_reponse, chemin_permis, entetes_amont, Annonce};
use futures_util::StreamExt;
use serde_json::{json, Value};

use crate::serveur::{constater, Etat};

/// Session du journal pour les échanges avec le modèle.
const SESSION: &str = "modele";
const OUTIL: &str = "Modele";
/// Taille maximale d'une requête (contexte long, images).
const REQUETE_MAX: usize = 64 * 1024 * 1024;
/// Part de la réponse conservée pour le bilan.
const REPONSE_LUE_MAX: usize = 16 * 1024 * 1024;
/// Numéro d'échange : relie l'envoi au bilan dans le journal.
static ECHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub struct Reglages {
    pub agent: String,
    /// Amont, ex. `https://api.anthropic.com` ; `None` si le mandat ne déclare aucun modèle.
    pub amont: Option<String>,
    pub jeton: Option<String>,
}

type Partage = (Etat, Arc<Reglages>);

pub fn routeur(etat: Etat, reglages: Reglages) -> Router {
    Router::new()
        .fallback(relayer)
        .layer(DefaultBodyLimit::max(REQUETE_MAX))
        .with_state((etat, Arc::new(reglages)))
}

fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client HTTP")
    })
}

/// Erreur au format de l'API Messages, pour que l'agent l'affiche telle quelle.
fn refus(statut: StatusCode, motif: &str) -> Response {
    let corps = json!({"type": "error", "error": {"type": "permission_error", "message": format!("Aplomb : {motif}")}});
    (statut, axum::Json(corps)).into_response()
}

fn evenement(agent: &str, ressource: &str, methode: &str) -> EvenementOutil {
    EvenementOutil {
        session: SESSION.into(),
        agent: agent.into(),
        mode: "proxy-llm".into(),
        cwd: String::new(),
        outil: OUTIL.into(),
        entree: json!({"url": ressource, "methode": methode}),
        phase: Phase::Avant,
        chemin_reel: None,
        contenu_execute: None,
        nonce: None,
        appel: None,
    }
}

async fn relayer(State((etat, r)): State<Partage>, methode: Method, uri: Uri, entetes: HeaderMap, corps: Bytes) -> Response {
    let chemin = uri.path();
    let evt = evenement(&r.agent, chemin, methode.as_str());
    let echange = ECHANGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    // Session de l'agent, s'il la donne (Claude Code : en-tête x-claude-code-session-id).
    let session_agent = entetes
        .iter()
        .find(|(n, _)| n.as_str().contains("session-id"))
        .and_then(|(_, v)| v.to_str().ok())
        .map(String::from);
    let base = json!({"outil": OUTIL, "verbe": "modele", "ressource": chemin, "methode": methode.as_str(),
        "echange": echange, "session_agent": session_agent});
    let journaliser = |mut detail: Value, extra: Value| {
        if let (Some(d), Some(e)) = (detail.as_object_mut(), extra.as_object()) {
            d.extend(e.clone());
        }
        constater(&etat, &evt, detail)
    };

    if !chemin_permis(methode.as_str(), chemin) {
        let _ = journaliser(base, json!({"refus": "chemin non permis"}));
        return refus(StatusCode::FORBIDDEN, &format!("{methode} {chemin} non permis : seuls les appels de conversation passent"));
    }
    if etat.gele(SESSION) {
        return refus(StatusCode::FORBIDDEN, "superviseur gelé : plus aucun appel au modèle");
    }
    let (Some(amont), Some(jeton)) = (&r.amont, &r.jeton) else {
        let motif = if r.amont.is_none() {
            "aucun modèle dans le mandat (perimetre.domaines_modele)"
        } else {
            "aucun jeton du modèle : lancer aplomb modele jeton, puis redémarrer aplomb serve"
        };
        return refus(StatusCode::SERVICE_UNAVAILABLE, motif);
    };
    let modele = serde_json::from_slice::<Value>(&corps)
        .ok()
        .and_then(|v| v.get("model").and_then(Value::as_str).map(String::from))
        .unwrap_or_default();
    // Journalisé avant tout envoi : sans journal, rien ne part.
    if let Err(e) = journaliser(base.clone(), json!({"modele": modele, "envoye": corps.len()})) {
        return refus(StatusCode::SERVICE_UNAVAILABLE, &format!("{e} — fail-closed"));
    }

    let entrants: Vec<(String, String)> = entetes
        .iter()
        .filter_map(|(n, v)| v.to_str().ok().map(|v| (n.as_str().to_string(), v.to_string())))
        .collect();
    let mut requete = client().request(methode.clone(), format!("{amont}{}", uri.path_and_query().map_or(chemin, |p| p.as_str())));
    for (n, v) in entetes_amont(&entrants, jeton) {
        requete = requete.header(n, v);
    }
    let reponse = match requete.body(corps).send().await {
        Ok(r) => r,
        Err(e) => {
            let _ = journaliser(base, json!({"erreur": "amont injoignable"}));
            return refus(StatusCode::BAD_GATEWAY, &format!("modèle injoignable : {e}"));
        }
    };

    let statut = reponse.status();
    let mut sortie = Response::builder().status(statut.as_u16());
    for (n, v) in reponse.headers() {
        if !matches!(n.as_str(), "connection" | "keep-alive" | "transfer-encoding" | "content-length") {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_str().as_bytes()), HeaderValue::from_bytes(v.as_bytes())) {
                sortie = sortie.header(n, v);
            }
        }
    }
    // Bilan journalisé quand le flux se termine (ou que l'agent coupe).
    let bilan = Arc::new(Mutex::new(Bilan { etat: etat.clone(), evt: evt.clone(), base, statut: statut.as_u16(), lu: Vec::new(), recu: 0 }));
    let annonce = Annonce { echange, session_agent };
    let flux = reponse.bytes_stream().map(move |morceau| {
        if let Ok(m) = &morceau {
            let mut b = bilan.lock().expect("verrou");
            b.recu += m.len() as u64;
            if b.lu.len() + m.len() <= REPONSE_LUE_MAX {
                b.lu.extend_from_slice(m);
            }
            // Annonce au fil de l'eau : l'agent peut exécuter l'outil dès la fin du flux,
            // avant même que le bilan soit écrit.
            if m.windows(8).any(|f| f == b"tool_use") {
                for o in analyser_reponse(&b.lu).outils {
                    b.etat.annoncer(&o.id, annonce.clone());
                }
            }
        }
        morceau
    });
    sortie.body(Body::from_stream(flux)).unwrap_or_else(|_| refus(StatusCode::BAD_GATEWAY, "réponse du modèle illisible"))
}

struct Bilan {
    etat: Etat,
    evt: EvenementOutil,
    base: Value,
    statut: u16,
    lu: Vec<u8>,
    recu: u64,
}

impl Drop for Bilan {
    fn drop(&mut self) {
        let a = analyser_reponse(&self.lu);
        let mut detail = self.base.clone();
        if let Some(d) = detail.as_object_mut() {
            d.insert("statut".into(), json!(self.statut));
            d.insert("recu".into(), json!(self.recu));
            for o in &a.outils {
                self.etat.annoncer(&o.id, Annonce { echange: d["echange"].as_u64().unwrap_or(0), session_agent: d["session_agent"].as_str().map(String::from) });
            }
            d.insert("outils".into(), json!(a.outils));
            d.insert("jetons_entree".into(), json!(a.jetons_entree));
            d.insert("jetons_sortie".into(), json!(a.jetons_sortie));
        }
        let _ = constater(&self.etat, &self.evt, detail);
    }
}
