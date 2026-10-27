//! **Service réseau** : deux API sur deux ports (ADR 0001, EF-S1).
//!
//! - **Décision** (`--ecoute-decision`, joignable par l'agent) :
//!   `POST /v1/decide`, `POST /v1/observe`, `GET /v1/health`.
//! - **Administration** (`--ecoute-admin`, jamais exposée à l'agent) :
//!   `GET /` (vue technique), `GET /admin/etat`, `GET /admin/historique`,
//!   `GET /admin/events` (SSE), `GET /admin/verify`,
//!   `POST /admin/gel`, `POST /admin/degel` (jeton requis).
//!
//! Limites J1 : pas de mTLS ni de comptes ; le jeton d'administration protège seulement
//! les actions de gel/dégel (J2).
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use sal_core::action::{EvenementOutil, Phase};
use sal_core::journal::Journal;
use sal_core::superviseur::Superviseur;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

const HISTORIQUE: usize = 500;
/// Taille maximale d'un événement (EF-S7) : un `Write` peut porter un fichier entier.
const TAILLE_MAX: usize = 4 * 1024 * 1024;

#[derive(clap::Args)]
pub struct Options {
    /// Mandat signé (YAML).
    #[arg(long)]
    mandat: PathBuf,
    /// Fichier contenant la clé publique de confiance (hex).
    #[arg(long)]
    cle_publique: PathBuf,
    /// Dossier du journal.
    #[arg(long, default_value = "journal")]
    journal: PathBuf,
    #[arg(long, default_value = "127.0.0.1:7700")]
    ecoute_decision: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:7701")]
    ecoute_admin: SocketAddr,
}

struct Interne {
    superviseur: Superviseur,
    journal: Journal,
    historique: VecDeque<Value>,
    compteurs: [u64; 4],
}

#[derive(Clone)]
struct Etat {
    interne: Arc<Mutex<Interne>>,
    diffusion: broadcast::Sender<String>,
    jeton_admin: Arc<String>,
}

fn maintenant() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Niveau d'assurance déclaré par mode de branchement (§11).
fn niveau_assurance(mode: &str) -> u8 {
    match mode {
        "hook-claude-code" => 1,
        "proxy-llm" | "passerelle-mcp" => 2,
        "conteneur-isole" => 3,
        _ => 1,
    }
}

fn erreur(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (code, Json(json!({"verdict": "deny", "motif": msg.into()})))
}

impl Etat {
    fn publier(&self, interne: &mut Interne, evt: Value) {
        interne.historique.push_back(evt.clone());
        if interne.historique.len() > HISTORIQUE {
            interne.historique.pop_front();
        }
        let _ = self.diffusion.send(evt.to_string());
    }

    /// Première entrée d'une session : mandat, mode et niveau d'assurance (EF-G3).
    fn ouvrir_session(&self, interne: &mut Interne, evt: &EvenementOutil, t: u64) -> Result<(), String> {
        if interne.journal.connait(&evt.session).map_err(|e| e.to_string())? {
            return Ok(());
        }
        let m = &interne.superviseur.mandat;
        let contenu = json!({
            "mandat": m.mandat.id, "version": m.mandat.version, "empreinte_mandat": m.empreinte,
            "profil": m.mandat.profil, "agent": evt.agent, "mode": evt.mode,
            "niveau_assurance": niveau_assurance(&evt.mode),
        });
        interne.journal.ajouter(&evt.session, "session", contenu, t).map_err(|e| e.to_string())?;
        Ok(())
    }
}

async fn decider(State(etat): State<Etat>, Json(evt): Json<EvenementOutil>) -> impl IntoResponse {
    if evt.phase != Phase::Avant {
        return erreur(StatusCode::BAD_REQUEST, "phase « avant » attendue");
    }
    let t = maintenant();
    let mut interne = etat.interne.lock().expect("verrou");
    if let Err(e) = etat.ouvrir_session(&mut interne, &evt, t) {
        return erreur(StatusCode::INTERNAL_SERVER_ERROR, format!("journal indisponible : {e}"));
    }
    let (action, d) = interne.superviseur.decider(&evt);
    let contenu = json!({
        "outil": evt.outil, "verbe": action.verbe, "ressource": action.ressource,
        "contexte": action.contexte, "verdict": d.verdict, "regle": d.politique.regle,
        "motif": d.motif, "durci": d.durci,
    });
    // Journal d'abord : une décision non journalisée n'est pas rendue (fail-closed).
    let entree = match interne.journal.ajouter(&evt.session, "decision", contenu.clone(), t) {
        Ok(e) => e,
        Err(e) => return erreur(StatusCode::INTERNAL_SERVER_ERROR, format!("journal indisponible : {e}")),
    };
    interne.compteurs[d.verdict as usize] += 1;
    let evenement = json!({"type": "decision", "horodatage": t, "session": evt.session, "seq": entree.seq, "detail": contenu});
    etat.publier(&mut interne, evenement);
    (StatusCode::OK, Json(json!({"verdict": d.verdict, "regle": d.politique.regle, "motif": d.motif, "seq": entree.seq})))
}

async fn observer(State(etat): State<Etat>, Json(evt): Json<EvenementOutil>) -> impl IntoResponse {
    let t = maintenant();
    let mut interne = etat.interne.lock().expect("verrou");
    if etat.ouvrir_session(&mut interne, &evt, t).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let action = interne.superviseur.normaliser(&evt);
    // Minimisation : ni le contenu écrit ni la sortie de l'outil ne sont journalisés.
    let contenu = json!({"outil": evt.outil, "verbe": action.verbe, "ressource": action.ressource});
    match interne.journal.ajouter(&evt.session, "observation", contenu.clone(), t) {
        Ok(e) => {
            let evenement = json!({"type": "observation", "horodatage": t, "session": evt.session, "seq": e.seq, "detail": contenu});
            etat.publier(&mut interne, evenement);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn sante() -> &'static str {
    "ok"
}

async fn page() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

async fn etat_admin(State(etat): State<Etat>) -> Json<Value> {
    let interne = etat.interne.lock().expect("verrou");
    let m = &interne.superviseur.mandat;
    let (gel_global, sessions_gelees) = interne.superviseur.etat_gel();
    let c = interne.compteurs;
    Json(json!({
        "mandat": {"id": m.mandat.id, "version": m.mandat.version, "profil": m.mandat.profil,
                   "intention": m.mandat.intention, "racine": m.mandat.perimetre.racine, "empreinte": m.empreinte},
        "gel_global": gel_global, "sessions_gelees": sessions_gelees,
        "compteurs": {"allow": c[0], "review": c[1], "deny": c[2], "gel": c[3]},
    }))
}

async fn historique(State(etat): State<Etat>) -> Json<Value> {
    let interne = etat.interne.lock().expect("verrou");
    Json(Value::Array(interne.historique.iter().cloned().collect()))
}

async fn flux(State(etat): State<Etat>) -> Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let flux = BroadcastStream::new(etat.diffusion.subscribe())
        .filter_map(|m| async move { m.ok().map(|s| Ok(Event::default().data(s))) });
    Sse::new(flux).keep_alive(KeepAlive::default())
}

async fn verifier_journal(State(etat): State<Etat>) -> impl IntoResponse {
    let interne = etat.interne.lock().expect("verrou");
    match interne.journal.verifier_tout() {
        Ok(s) => (StatusCode::OK, Json(json!({"intact": true, "sessions": s.len(),
            "entrees": s.iter().map(|(_, n)| n).sum::<u64>()}))),
        Err((f, e)) => (StatusCode::OK, Json(json!({"intact": false, "fichier": f, "erreur": e.to_string()}))),
    }
}

#[derive(Deserialize, Default)]
struct DemandeGel {
    session: Option<String>,
}

fn jeton_valide(etat: &Etat, entetes: &HeaderMap) -> bool {
    entetes
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|j| j == etat.jeton_admin.as_str())
}

async fn changer_gel(etat: Etat, entetes: HeaderMap, demande: DemandeGel, geler: bool) -> impl IntoResponse {
    if !jeton_valide(&etat, &entetes) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"erreur": "jeton d'administration requis"})));
    }
    let t = maintenant();
    let mut interne = etat.interne.lock().expect("verrou");
    let session = demande.session.as_deref();
    if geler {
        interne.superviseur.geler(session);
    } else {
        interne.superviseur.degeler(session);
    }
    let detail = json!({"action": if geler { "gel" } else { "degel" }, "session": session});
    if let Some(s) = session {
        let _ = interne.journal.ajouter(s, "administration", detail.clone(), t);
    }
    etat.publier(&mut interne, json!({"type": "administration", "horodatage": t, "detail": detail}));
    (StatusCode::OK, Json(json!({"ok": true})))
}

async fn gel(State(etat): State<Etat>, entetes: HeaderMap, corps: Option<Json<DemandeGel>>) -> impl IntoResponse {
    changer_gel(etat, entetes, corps.map(|j| j.0).unwrap_or_default(), true).await
}

async fn degel(State(etat): State<Etat>, entetes: HeaderMap, corps: Option<Json<DemandeGel>>) -> impl IntoResponse {
    changer_gel(etat, entetes, corps.map(|j| j.0).unwrap_or_default(), false).await
}

fn jeton_aleatoire() -> String {
    let mut o = [0u8; 24];
    getrandom::getrandom(&mut o).expect("source d'aléa");
    hex::encode(o)
}

pub fn lancer(opts: Options) -> Result<(), String> {
    let cle_hex = std::fs::read_to_string(&opts.cle_publique).map_err(|e| format!("clé publique : {e}"))?;
    let cle = sal_core::mandat::cle_publique(&cle_hex).map_err(|e| e.to_string())?;
    let mandat = sal_core::mandat::charger(&opts.mandat, &cle).map_err(|e| format!("mandat refusé : {e}"))?;
    if mandat.mandat.profil != "code" {
        return Err(format!("profil « {} » non pris en charge (MVP : code)", mandat.mandat.profil));
    }
    let id = format!("{} v{}", mandat.mandat.id, mandat.mandat.version);
    let superviseur = Superviseur::nouveau(mandat).map_err(|e| e.to_string())?;
    let journal = Journal::ouvrir(&opts.journal).map_err(|e| e.to_string())?;
    let jeton = std::env::var("SAL_JETON_ADMIN").unwrap_or_else(|_| jeton_aleatoire());
    let (diffusion, _) = broadcast::channel(1024);
    let etat = Etat {
        interne: Arc::new(Mutex::new(Interne { superviseur, journal, historique: VecDeque::new(), compteurs: [0; 4] })),
        diffusion,
        jeton_admin: Arc::new(jeton.clone()),
    };

    let api_decision = Router::new()
        .route("/v1/decide", post(decider))
        .route("/v1/observe", post(observer))
        .route("/v1/health", get(sante))
        .layer(DefaultBodyLimit::max(TAILLE_MAX))
        .with_state(etat.clone());
    let api_admin = Router::new()
        .route("/", get(page))
        .route("/admin/etat", get(etat_admin))
        .route("/admin/historique", get(historique))
        .route("/admin/events", get(flux))
        .route("/admin/verify", get(verifier_journal))
        .route("/admin/gel", post(gel))
        .route("/admin/degel", post(degel))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(etat);

    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let l_decision = tokio::net::TcpListener::bind(opts.ecoute_decision).await.map_err(|e| e.to_string())?;
        let l_admin = tokio::net::TcpListener::bind(opts.ecoute_admin).await.map_err(|e| e.to_string())?;
        eprintln!("SAL — mandat {id}");
        eprintln!("  API décision       : http://{}", opts.ecoute_decision);
        eprintln!("  API administration : http://{}  (vue technique)", opts.ecoute_admin);
        if std::env::var("SAL_JETON_ADMIN").is_err() {
            eprintln!("  jeton d'administration (session) : {jeton}");
        }
        let arret = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        tokio::select! {
            r = axum::serve(l_decision, api_decision) => r.map_err(|e| e.to_string()),
            r = axum::serve(l_admin, api_admin) => r.map_err(|e| e.to_string()),
            _ = arret => Ok(()),
        }
    })
}
