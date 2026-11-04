//! **Service réseau** : deux API sur deux ports (ADR 0001, EF-S1).
//!
//! - **Décision** (`--ecoute-decision`, joignable par l'agent) :
//!   `POST /v1/decide`, `POST /v1/observe`, `GET /v1/health`.
//! - **Administration** (`--ecoute-admin`, jamais exposée à l'agent), réservée aux
//!   comptes déclarés dans `--comptes` (EF-S2, module `aplomb_core::autorite`) :
//!   - `POST /admin/requete` : requête signée par la clé d'un compte (`aplomb admin`) ;
//!   - `GET /connexion?ticket=…` : ouvre une session de navigateur (cookie) ;
//!   - `GET /admin/etat`, `/admin/historique`, `/admin/events` (SSE), `/admin/verify`,
//!     `POST /admin/gel`, `/admin/degel`, `/admin/deconnexion` : session requise ;
//!   - `GET /admin/revues`, `POST /admin/revue` : file de revue des passerelles (une action
//!     en revue attend qu'un opérateur ou un approbateur l'approuve ou la refuse) ;
//!   - `GET /` : la page de la vue technique (sans données).
//!
//! Geler se fait seul ; dégeler exige deux comptes distincts (quatre yeux).
//!
//! **Minimisation** (EF-P1, EF-P2) : le journal sur disque ne garde en clair que des
//! métadonnées ; les contenus venant de l'agent sont chiffrés par une clé de session
//! tenue dans un coffre distinct (`--coffre`). La vue technique, en mémoire, montre les
//! actions en clair à l'opérateur pendant la session.
//!
//! Limites : pas de mTLS (reporté au niveau 3, J3) ; HTTP en clair sur la boucle
//! locale ; le fichier de comptes n'est pas encore signé.
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use aplomb_core::action::{EvenementOutil, Phase};
use aplomb_core::autorite::{Autorite, Issue, Operation, RequeteSignee};
use aplomb_core::confidentiel::{minimiser, Coffre};
use aplomb_core::journal::Journal;
use aplomb_core::superviseur::Superviseur;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

const HISTORIQUE: usize = 500;
/// Taille maximale d'un événement (EF-S7) : un `Write` peut porter un fichier entier.
const TAILLE_MAX: usize = 4 * 1024 * 1024;

#[derive(clap::Args)]
pub struct Options {
    /// Mandat cosigné (YAML).
    #[arg(long)]
    mandat: PathBuf,
    /// Mandat d'un type de sous-agent (répétable), cosigné et inclus dans le mandat (EF-B6).
    #[arg(long = "mandat-enfant")]
    mandats_enfants: Vec<PathBuf>,
    /// Fichier de confiance : membres de la gouvernance et seuil (au moins 2).
    #[arg(long, default_value = crate::gouverner::CONFIANCE)]
    confiance: PathBuf,
    /// Passerelle réseau sortante (proxy HTTP pour `HTTPS_PROXY`), sur la boucle locale.
    #[arg(long, default_value = "127.0.0.1:7702")]
    ecoute_passerelle: SocketAddr,
    /// Proxy LLM (`ANTHROPIC_BASE_URL` de l'agent), sur la boucle locale.
    #[arg(long, default_value = "127.0.0.1:7703")]
    ecoute_llm: SocketAddr,
    /// Passerelle MCP (serveurs MCP du mandat, en HTTP), sur la boucle locale.
    #[arg(long, default_value = "127.0.0.1:7704")]
    ecoute_mcp: SocketAddr,
    /// Plafond d'envoi par connexion de la passerelle, en octets (sens des flux, EF-C4).
    #[arg(long, default_value_t = 1024 * 1024)]
    plafond_envoi: u64,
    /// Intervalle de scellement du journal, en secondes (EF-I1).
    #[arg(long, default_value_t = 60)]
    scellement: u64,
    /// Dossier du journal.
    #[arg(long, default_value = "journal")]
    journal: PathBuf,
    /// Dossier des clés de session (distinct du journal ; effacer une clé efface les
    /// contenus de la session).
    #[arg(long, default_value = "journal-cles")]
    coffre: PathBuf,
    /// Clé de signature des réponses (enveloppée), créée au premier démarrage ; sa clé
    /// publique (`.pub` à côté) est donnée au hook par `--cle-serveur` (EF-S3).
    #[arg(long, default_value = "cles/reponses.cle")]
    cle_reponses: PathBuf,
    /// Comptes d'administration (YAML) : identifiants, rôles, clés publiques.
    #[arg(long, default_value = "comptes.yaml")]
    comptes: PathBuf,
    #[arg(long, default_value = "127.0.0.1:7700")]
    ecoute_decision: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:7701")]
    ecoute_admin: SocketAddr,
}

struct Interne {
    superviseur: Superviseur,
    journal: Journal,
    coffre: Coffre,
    historique: VecDeque<Value>,
    compteurs: [u64; 4],
    autorite: Autorite,
    /// Appels d'outils annoncés par le modèle (proxy LLM), pour le contrôle croisé.
    annonces: aplomb_core::modele::Annonces,
    /// Actions des passerelles en attente d'une réponse humaine, par numéro.
    revues: HashMap<u64, Revue>,
    revue_suivante: u64,
}

/// Action en revue : ce que voit l'humain, et la passerelle qui attend sa réponse.
struct Revue {
    publique: Value,
    reponse: tokio::sync::oneshot::Sender<(bool, String)>,
}

/// Temps laissé à l'humain pour répondre ; ensuite, refus.
const DELAI_REVUE: std::time::Duration = std::time::Duration::from_secs(120);

#[derive(Clone)]
pub(crate) struct Etat {
    interne: Arc<Mutex<Interne>>,
    diffusion: broadcast::Sender<String>,
    signataire: Arc<ed25519_dalek::SigningKey>,
}

/// Session globale du journal pour les actions d'administration sans session visée.
const SESSION_ADMIN: &str = "_administration";
const COOKIE: &str = "aplomb_session";

/// Compte de la session de navigateur, depuis le cookie.
fn compte_web(interne: &mut Interne, entetes: &HeaderMap) -> Option<String> {
    let cookies = entetes.get("cookie")?.to_str().ok()?;
    let jeton = cookies.split(';').find_map(|c| c.trim().strip_prefix(&format!("{COOKIE}=")))?;
    interne.autorite.session_web(jeton, maintenant()).ok()
}

fn non_connecte() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"erreur": "non connecté : aplomb admin connexion --compte <id>"}))).into_response()
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
    /// Le proxy LLM a vu le modèle demander cet appel d'outil.
    pub(crate) fn annoncer(&self, id: &str, annonce: aplomb_core::modele::Annonce) {
        self.interne.lock().expect("verrou").annonces.annoncer(id, annonce);
    }

    /// Gel global, ou gel de cette session.
    pub(crate) fn gele(&self, session: &str) -> bool {
        let (global, sessions) = self.interne.lock().expect("verrou").superviseur.etat_gel();
        global || sessions.iter().any(|s| s == session)
    }

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

/// Juge un événement et journalise la décision (journal d'abord : une décision non
/// journalisée n'est jamais rendue). Chemin unique du hook et de la passerelle.
pub(crate) fn juger(etat: &Etat, evt: &EvenementOutil) -> Result<(aplomb_core::decision::DecisionFinale, u64), String> {
    let t = maintenant();
    let mut interne = etat.interne.lock().expect("verrou");
    etat.ouvrir_session(&mut interne, evt, t).map_err(|e| format!("journal indisponible : {e}"))?;
    let (action, d) = interne.superviseur.decider(evt);
    let mut contenu = json!({
        "outil": evt.outil, "verbe": action.verbe, "ressource": action.ressource,
        "contexte": action.contexte, "verdict": d.verdict, "regle": d.politique.regle,
        "motif": d.motif, "durci": d.durci, "avis": d.avis, "appel": evt.appel,
    });
    // Provenance (EF-B5) : contenus non fiables reçus par la session avant cette action.
    let sources = interne.superviseur.influences(&evt.session);
    if !sources.is_empty() {
        contenu["provenance"] = json!(sources);
    }
    // Chaîne de délégation (EF-B6) : sous-agent, et mandat enfant appliqué.
    if let Some(dl) = &evt.delegation {
        let enfant = interne.superviseur.mandat_enfant(evt).map(|m| format!("{} v{}", m.mandat.id, m.mandat.version));
        contenu["delegation"] = json!({"type_agent": dl.type_agent, "id": dl.id, "mandat_enfant": enfant});
    }
    // Contrôle croisé (niveaux 2 et 3) : dans le conteneur, le modèle ne passe que par le
    // proxy LLM, donc toute action doit avoir été demandée par lui. Un écart est signalé au
    // journal et dans la vue ; il ne change pas (encore) la décision.
    if evt.mode == "conteneur-isole" {
        contenu["controle_croise"] = json!(match evt.appel.as_deref().map(|a| interne.annonces.trouver(a)) {
            Some(Some(a)) => format!("demandée par le modèle (échange {})", a.echange),
            Some(None) => "ÉCART : action sans demande du modèle".to_string(),
            None => "ÉCART : action sans identifiant d'appel".to_string(),
        });
    }
    let cle = interne.coffre.cle_ou_creer(&evt.session).map_err(|e| format!("coffre indisponible : {e}"))?;
    let minimise = minimiser(&cle, &evt.session, &contenu);
    let entree = interne
        .journal
        .ajouter(&evt.session, "decision", minimise, t)
        .map_err(|e| format!("journal indisponible : {e}"))?;
    interne.compteurs[d.verdict as usize] += 1;
    let evenement = json!({"type": "decision", "horodatage": t, "session": evt.session, "seq": entree.seq, "detail": contenu});
    etat.publier(&mut interne, evenement);
    Ok((d, entree.seq))
}

/// Journalise ce qui s'est passé après une action (minimisé comme les décisions).
pub(crate) fn constater(etat: &Etat, evt: &EvenementOutil, contenu: Value) -> Result<(), String> {
    let t = maintenant();
    let mut interne = etat.interne.lock().expect("verrou");
    etat.ouvrir_session(&mut interne, evt, t).map_err(|e| e.to_string())?;
    let cle = interne.coffre.cle_ou_creer(&evt.session).map_err(|e| e.to_string())?;
    let e = interne
        .journal
        .ajouter(&evt.session, "observation", minimiser(&cle, &evt.session, &contenu), t)
        .map_err(|e| e.to_string())?;
    let evenement = json!({"type": "observation", "horodatage": t, "session": evt.session, "seq": e.seq, "detail": contenu});
    etat.publier(&mut interne, evenement);
    Ok(())
}

/// Soumet une action des passerelles à un humain (Aplomb Watch) et attend sa réponse :
/// le compte qui approuve, ou le motif du refus. Sans réponse dans le délai : refus. L'issue
/// est journalisée dans la session de l'action.
pub(crate) async fn demander_revue(etat: &Etat, evt: &EvenementOutil, resume: &str, motif: &str) -> Result<String, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let id = {
        let mut interne = etat.interne.lock().expect("verrou");
        interne.revue_suivante += 1;
        let id = interne.revue_suivante;
        let publique = json!({"id": id, "session": evt.session, "mode": evt.mode, "outil": evt.outil, "resume": resume,
            "motif": motif, "horodatage": maintenant(), "appel": evt.appel, "delai": DELAI_REVUE.as_secs()});
        interne.revues.insert(id, Revue { publique: publique.clone(), reponse: tx });
        etat.publier(&mut interne, json!({"type": "revue", "horodatage": maintenant(), "session": evt.session, "detail": publique}));
        id
    };
    let (approuvee, par) = match tokio::time::timeout(DELAI_REVUE, rx).await {
        Ok(Ok(r)) => r,
        _ => {
            let mut interne = etat.interne.lock().expect("verrou");
            interne.revues.remove(&id);
            let fin = json!({"id": id, "issue": "expirée"});
            etat.publier(&mut interne, json!({"type": "revue-close", "horodatage": maintenant(), "session": evt.session, "detail": fin}));
            (false, String::new())
        }
    };
    let issue = match (approuvee, par.is_empty()) {
        (true, _) => "approuvée",
        (false, true) => "expirée",
        (false, false) => "refusée",
    };
    let _ = constater(etat, evt, json!({"outil": evt.outil, "verbe": "revue", "ressource": resume, "appel": evt.appel,
        "revue": issue, "par": par}));
    match issue {
        "approuvée" => Ok(par),
        "expirée" => Err(format!("revue sans réponse en {} s : refus", DELAI_REVUE.as_secs())),
        _ => Err(format!("revue refusée par {par}")),
    }
}

async fn decider(State(etat): State<Etat>, Json(evt): Json<EvenementOutil>) -> impl IntoResponse {
    if evt.phase != Phase::Avant {
        return erreur(StatusCode::BAD_REQUEST, "phase « avant » attendue");
    }
    let (d, seq) = match juger(&etat, &evt) {
        Ok(r) => r,
        Err(e) => return erreur(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let mut reponse = json!({"verdict": d.verdict, "regle": d.politique.regle, "motif": d.motif, "seq": seq});
    if let Some(nonce) = &evt.nonce {
        let verdict = serde_json::to_value(d.verdict).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        reponse["signature"] = json!(aplomb_core::reponse::signer(&etat.signataire, nonce, &evt.session, &verdict, &d.politique.regle));
    }
    (StatusCode::OK, Json(reponse))
}

async fn observer(State(etat): State<Etat>, Json(evt): Json<EvenementOutil>) -> impl IntoResponse {
    let t = maintenant();
    let mut interne = etat.interne.lock().expect("verrou");
    if etat.ouvrir_session(&mut interne, &evt, t).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let action = interne.superviseur.normaliser(&evt);
    let source = interne.superviseur.observer(&evt);
    // Minimisation : ni le contenu écrit ni la sortie de l'outil ne sont journalisés.
    let mut contenu = json!({"outil": evt.outil, "verbe": action.verbe, "ressource": action.ressource, "appel": evt.appel});
    if source.is_some() {
        contenu["contenu_non_fiable"] = json!(true);
    }
    if let Some(dl) = &evt.delegation {
        contenu["delegation"] = json!({"type_agent": dl.type_agent, "id": dl.id});
    }
    let Ok(cle) = interne.coffre.cle_ou_creer(&evt.session) else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    match interne.journal.ajouter(&evt.session, "observation", minimiser(&cle, &evt.session, &contenu), t) {
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

async fn etat_admin(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    let Some(compte) = compte_web(&mut interne, &entetes) else { return non_connecte() };
    let roles = interne.autorite.roles(&compte);
    let demandes: Vec<Value> = interne
        .autorite
        .demandes_en_attente()
        .into_iter()
        .map(|(s, c)| json!({"session": s, "demandeur": c}))
        .collect();
    let m = &interne.superviseur.mandat;
    let (gel_global, sessions_gelees) = interne.superviseur.etat_gel();
    let c = interne.compteurs;
    Json(json!({
        "mandat": {"id": m.mandat.id, "version": m.mandat.version, "profil": m.mandat.profil,
                   "intention": m.mandat.intention, "racine": m.mandat.perimetre.racine, "empreinte": m.empreinte},
        "gel_global": gel_global, "sessions_gelees": sessions_gelees,
        "compteurs": {"allow": c[0], "review": c[1], "deny": c[2], "gel": c[3]},
        "compte": compte, "roles": roles, "degels_en_attente": demandes,
    }))
    .into_response()
}

async fn historique(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    if compte_web(&mut interne, &entetes).is_none() {
        return non_connecte();
    }
    Json(Value::Array(interne.historique.iter().cloned().collect())).into_response()
}

async fn flux(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    if compte_web(&mut etat.interne.lock().expect("verrou"), &entetes).is_none() {
        return non_connecte();
    }
    let flux = BroadcastStream::new(etat.diffusion.subscribe())
        .filter_map(|m| async move { m.ok().map(|s| Ok::<_, std::convert::Infallible>(Event::default().data(s))) });
    Sse::new(flux).keep_alive(KeepAlive::default()).into_response()
}

async fn verifier_journal(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    if compte_web(&mut interne, &entetes).is_none() {
        return non_connecte();
    }
    match interne.journal.verifier_tout() {
        Ok(s) => Json(json!({"intact": true, "sessions": s.len(),
            "entrees": s.iter().map(|(_, n)| n).sum::<u64>()})).into_response(),
        Err((f, e)) => Json(json!({"intact": false, "fichier": f, "erreur": e.to_string()})).into_response(),
    }
}

/// Sessions techniques, rattachées aux sessions d'agents dans la vue chaînée.
const SESSIONS_TECHNIQUES: &[&str] = &["modele", "passerelle", SESSION_ADMIN];

/// Sessions d'agents du journal, les plus récentes d'abord (métadonnées seulement).
async fn sessions(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    let dossier = {
        let mut interne = etat.interne.lock().expect("verrou");
        if compte_web(&mut interne, &entetes).is_none() {
            return non_connecte();
        }
        interne.journal.dossier().to_path_buf()
    };
    let mut liste = Vec::new();
    for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
        let Ok(texte) = std::fs::read_to_string(f.path()) else { continue };
        let lignes: Vec<Value> = texte.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
        let (Some(premiere), Some(derniere)) = (lignes.first(), lignes.last()) else { continue };
        let session = premiere["session"].as_str().unwrap_or_default();
        if SESSIONS_TECHNIQUES.contains(&session) {
            continue;
        }
        let tete = lignes.iter().find(|l| l["type"] == "session").map(|l| l["contenu"].clone()).unwrap_or_default();
        liste.push(json!({"session": session, "mode": tete["mode"], "niveau": tete["niveau_assurance"],
            "debut": premiere["horodatage"], "fin": derniere["horodatage"],
            "decisions": lignes.iter().filter(|l| l["type"] == "decision").count()}));
    }
    liste.sort_by_key(|s| std::cmp::Reverse(s["fin"].as_u64().unwrap_or(0)));
    liste.truncate(200);
    Json(Value::Array(liste)).into_response()
}

#[derive(Deserialize)]
struct DemandeChaine {
    session: String,
}

/// Vue chaînée d'une session : appels au modèle, outils demandés, actions, réseau.
async fn chaine(State(etat): State<Etat>, entetes: HeaderMap, Query(q): Query<DemandeChaine>) -> Response {
    let chemins = {
        let mut interne = etat.interne.lock().expect("verrou");
        if compte_web(&mut interne, &entetes).is_none() {
            return non_connecte();
        }
        let j = &interne.journal;
        [j.chemin(&q.session), j.chemin("modele"), j.chemin("passerelle")]
    };
    // Seules des chaînes vérifiées sont montrées ; une session technique absente est vide.
    let mut lues = Vec::new();
    for (i, c) in chemins.iter().enumerate() {
        match aplomb_core::mermaid::lire_session(c) {
            Ok(e) => lues.push(e),
            Err(_) if i > 0 && !c.exists() => lues.push(Vec::new()),
            Err(e) => {
                return (StatusCode::CONFLICT, Json(json!({"erreur": format!("{} : {e}", c.display())}))).into_response()
            }
        }
    }
    if lues[0].is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({"erreur": "session inconnue"}))).into_response();
    }
    Json(aplomb_core::chaine::chainer(&lues[0], &lues[1], &lues[2])).into_response()
}

#[derive(Deserialize, Default)]
struct DemandeGel {
    session: Option<String>,
}

/// Applique l'issue d'une opération autorisée et la journalise avec le ou les comptes.
fn appliquer(etat: &Etat, interne: &mut Interne, issue: &Issue, compte: &str, session: Option<&str>) -> Value {
    let t = maintenant();
    let detail = match issue {
        Issue::Ticket(_) => return json!({"issue": "ticket"}),
        Issue::Gel => {
            interne.superviseur.geler(session);
            json!({"action": "gel", "session": session, "compte": compte})
        }
        Issue::DegelEnAttente => {
            json!({"action": "demande-degel", "session": session, "compte": compte})
        }
        Issue::Degel { demandeur, approbateur } => {
            interne.superviseur.degeler(session);
            json!({"action": "degel", "session": session, "demandeur": demandeur, "approbateur": approbateur})
        }
    };
    let _ = interne.journal.ajouter(session.unwrap_or(SESSION_ADMIN), "administration", detail.clone(), t);
    etat.publier(interne, json!({"type": "administration", "horodatage": t, "session": session, "detail": detail}));
    let issue = match issue {
        Issue::Gel => "gel",
        Issue::DegelEnAttente => "degel-en-attente",
        Issue::Degel { .. } => "degel",
        Issue::Ticket(_) => "ticket",
    };
    json!({"issue": issue, "detail": detail})
}

/// Requête signée par la clé d'un compte (`aplomb admin`).
async fn requete_signee(State(etat): State<Etat>, Json(r): Json<RequeteSignee>) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    match interne.autorite.traiter(&r, maintenant()) {
        Ok(Issue::Ticket(ticket)) => Json(json!({"issue": "ticket", "ticket": ticket})).into_response(),
        Ok(issue) => {
            let s = r.corps.session.clone();
            Json(appliquer(&etat, &mut interne, &issue, &r.corps.compte, s.as_deref())).into_response()
        }
        Err(e) => (StatusCode::FORBIDDEN, Json(json!({"erreur": e.to_string()}))).into_response(),
    }
}

/// Action depuis la vue technique : session de navigateur et en-tête anti-CSRF exigés.
async fn action_web(etat: Etat, entetes: HeaderMap, demande: DemandeGel, operation: Operation) -> Response {
    if entetes.get("x-aplomb").and_then(|v| v.to_str().ok()) != Some("1") {
        return (StatusCode::FORBIDDEN, Json(json!({"erreur": "en-tête X-Aplomb manquant"}))).into_response();
    }
    let mut interne = etat.interne.lock().expect("verrou");
    let Some(compte) = compte_web(&mut interne, &entetes) else { return non_connecte() };
    let session = demande.session;
    match interne.autorite.agir(&compte, operation, session.clone(), maintenant()) {
        Ok(issue) => Json(appliquer(&etat, &mut interne, &issue, &compte, session.as_deref())).into_response(),
        Err(e) => (StatusCode::FORBIDDEN, Json(json!({"erreur": e.to_string()}))).into_response(),
    }
}

async fn gel(State(etat): State<Etat>, entetes: HeaderMap, corps: Option<Json<DemandeGel>>) -> Response {
    action_web(etat, entetes, corps.map(|j| j.0).unwrap_or_default(), Operation::Gel).await
}

async fn degel(State(etat): State<Etat>, entetes: HeaderMap, corps: Option<Json<DemandeGel>>) -> Response {
    action_web(etat, entetes, corps.map(|j| j.0).unwrap_or_default(), Operation::Degel).await
}

/// File de revue des passerelles.
async fn revues(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    if compte_web(&mut interne, &entetes).is_none() {
        return non_connecte();
    }
    let mut liste: Vec<Value> = interne.revues.values().map(|r| r.publique.clone()).collect();
    liste.sort_by_key(|r| r["id"].as_u64());
    Json(Value::Array(liste)).into_response()
}

#[derive(Deserialize)]
struct Reponse {
    id: u64,
    approuver: bool,
}

/// Réponse d'un opérateur ou d'un approbateur à une revue (session de navigateur, anti-CSRF).
async fn repondre_revue(State(etat): State<Etat>, entetes: HeaderMap, Json(r): Json<Reponse>) -> Response {
    if entetes.get("x-aplomb").and_then(|v| v.to_str().ok()) != Some("1") {
        return (StatusCode::FORBIDDEN, Json(json!({"erreur": "en-tête X-Aplomb manquant"}))).into_response();
    }
    let mut interne = etat.interne.lock().expect("verrou");
    let Some(compte) = compte_web(&mut interne, &entetes) else { return non_connecte() };
    use aplomb_core::autorite::Role;
    if !interne.autorite.roles(&compte).iter().any(|x| matches!(x, Role::Operateur | Role::Approbateur)) {
        return (StatusCode::FORBIDDEN, Json(json!({"erreur": "rôle opérateur ou approbateur requis"}))).into_response();
    }
    let Some(revue) = interne.revues.remove(&r.id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"erreur": "revue inconnue ou déjà close"}))).into_response();
    };
    let issue = if r.approuver { "approuvée" } else { "refusée" };
    let session = revue.publique["session"].as_str().unwrap_or_default().to_string();
    let detail = json!({"action": "revue", "id": r.id, "issue": issue, "compte": compte, "outil": revue.publique["outil"]});
    let t = maintenant();
    let _ = interne.journal.ajouter(SESSION_ADMIN, "administration", detail.clone(), t);
    etat.publier(&mut interne, json!({"type": "revue-close", "horodatage": t, "session": session, "detail": detail}));
    let _ = revue.reponse.send((r.approuver, compte));
    Json(json!({"issue": issue})).into_response()
}

#[derive(Deserialize)]
struct Ticket {
    ticket: String,
}

/// Échange un ticket de connexion contre un cookie de session, puis renvoie vers la vue.
async fn connexion(State(etat): State<Etat>, Query(q): Query<Ticket>) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    match interne.autorite.ouvrir_session_web(&q.ticket, maintenant()) {
        Ok((jeton, _)) => {
            let cookie = format!(
                "{COOKIE}={jeton}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                aplomb_core::autorite::SESSION_WEB_MS / 1000
            );
            ([("set-cookie", cookie)], Redirect::to("/")).into_response()
        }
        Err(e) => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    }
}

async fn deconnexion(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    let cookies = entetes.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(j) = cookies.split(';').find_map(|c| c.trim().strip_prefix(&format!("{COOKIE}="))) {
        etat.interne.lock().expect("verrou").autorite.fermer_session_web(j);
    }
    ([("set-cookie", format!("{COOKIE}=; Path=/; Max-Age=0"))], StatusCode::NO_CONTENT).into_response()
}

/// Clé de signature des réponses : lue, ou créée (enveloppée) avec sa clé publique.
fn cle_reponses(chemin: &std::path::Path) -> Result<ed25519_dalek::SigningKey, String> {
    if chemin.exists() {
        return crate::cle_maitresse::lire_cle_privee(chemin, "reponses");
    }
    let mut graine = [0u8; 32];
    getrandom::getrandom(&mut graine).map_err(|e| e.to_string())?;
    let cle = ed25519_dalek::SigningKey::from_bytes(&graine);
    if let Some(d) = chemin.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    crate::cle_maitresse::ecrire_cle_privee(chemin, "reponses", &cle)?;
    let publique = chemin.with_extension("pub");
    std::fs::write(&publique, hex::encode(cle.verifying_key().to_bytes())).map_err(|e| e.to_string())?;
    eprintln!("  clé de signature des réponses créée ; clé publique pour le hook : {}", publique.display());
    Ok(cle)
}

pub fn lancer(opts: Options) -> Result<(), String> {
    let confiance = aplomb_core::gouvernance::Confiance::depuis_yaml(&std::fs::read_to_string(&opts.confiance).map_err(
        |e| format!("{} : {e} — première installation : aplomb init --membre <id> --membre <id>", opts.confiance.display()),
    )?)?;
    let (mandat, signataires_mandat) = aplomb_core::mandat::charger_cosigne(&opts.mandat, &confiance).map_err(|e| {
        format!("mandat refusé : {e} — faire cosigner : aplomb cosigner {} --compte <id>", opts.mandat.display())
    })?;
    if mandat.mandat.profil != "code" {
        return Err(format!("profil « {} » non pris en charge (MVP : code)", mandat.mandat.profil));
    }
    let id = format!("{} v{}", mandat.mandat.id, mandat.mandat.version);
    let mut superviseur = Superviseur::nouveau(mandat).map_err(|e| e.to_string())?;
    let mut enfants = Vec::new();
    for chemin in &opts.mandats_enfants {
        let (enfant, _) = aplomb_core::mandat::charger_cosigne(chemin, &confiance)
            .map_err(|e| format!("mandat enfant {} refusé : {e}", chemin.display()))?;
        let nom = format!("{} v{}", enfant.mandat.id, enfant.mandat.version);
        let type_agent = superviseur
            .ajouter_enfant(enfant)
            .map_err(|e| format!("mandat enfant {} non inclus dans le mandat : {e}", chemin.display()))?;
        enfants.push(format!("{nom} (sous-agent {type_agent})"));
    }
    let journal = Journal::ouvrir(&opts.journal).map_err(|e| e.to_string())?;
    let maitre = crate::cle_maitresse::cle_maitresse()?;
    let coffre = Coffre::ouvrir(&opts.coffre).map_err(|e| format!("coffre : {e}"))?.avec_maitre(maitre);
    let signataire = cle_reponses(&opts.cle_reponses)?;
    let jeton = crate::cle_maitresse::jeton_modele()?;
    let texte_comptes = std::fs::read_to_string(&opts.comptes)
        .map_err(|e| format!("comptes {} : {e} (créer un compte : aplomb compte nouveau)", opts.comptes.display()))?;
    let (autorite, signataires_comptes) = Autorite::depuis_yaml_cosigne(&texte_comptes, &confiance).map_err(|e| {
        format!("comptes refusés : {e} — faire cosigner : aplomb cosigner {} --compte <id>", opts.comptes.display())
    })?;
    let dossier_journal = opts.journal.clone();
    let cle_scelles = signataire.clone();
    let (diffusion, _) = broadcast::channel(1024);
    let etat = Etat {
        interne: Arc::new(Mutex::new(Interne {
            superviseur,
            journal,
            coffre,
            historique: VecDeque::new(),
            compteurs: [0; 4],
            autorite,
            annonces: Default::default(),
            revues: HashMap::new(),
            revue_suivante: 0,
        })),
        diffusion,
        signataire: Arc::new(signataire),
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
        .route("/admin/sessions", get(sessions))
        .route("/admin/chaine", get(chaine))
        .route("/connexion", get(connexion))
        .route("/admin/requete", post(requete_signee))
        .route("/admin/deconnexion", post(deconnexion))
        .route("/admin/gel", post(gel))
        .route("/admin/degel", post(degel))
        .route("/admin/revues", get(revues))
        .route("/admin/revue", post(repondre_revue))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(etat.clone());
    let etat_scellement = etat;

    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let l_decision = tokio::net::TcpListener::bind(opts.ecoute_decision).await.map_err(|e| e.to_string())?;
        let l_admin = tokio::net::TcpListener::bind(opts.ecoute_admin).await.map_err(|e| e.to_string())?;
        let l_passerelle = tokio::net::TcpListener::bind(opts.ecoute_passerelle).await.map_err(|e| e.to_string())?;
        let l_llm = tokio::net::TcpListener::bind(opts.ecoute_llm).await.map_err(|e| e.to_string())?;
        let l_mcp = tokio::net::TcpListener::bind(opts.ecoute_mcp).await.map_err(|e| e.to_string())?;
        let (agent, amont, racine, serveurs_mcp) = {
            let m = &etat_scellement.interne.lock().expect("verrou").superviseur.mandat.mandat;
            (
                m.agent.clone(),
                m.perimetre.domaines_modele.first().map(|d| aplomb_core::modele::amont(d)).transpose()?,
                m.perimetre.racine.clone(),
                m.perimetre.serveurs_mcp.clone(),
            )
        };
        let lances: Vec<String> = serveurs_mcp.iter().filter(|s| !s.commande.is_empty()).map(|s| s.nom.clone()).collect();
        let mcp = crate::mcp::routeur(etat_scellement.clone(), crate::mcp::Reglages { agent: agent.clone(), racine, serveurs: serveurs_mcp });
        tokio::spawn(async move { axum::serve(l_mcp, mcp).await });
        let reglages = crate::passerelle::Reglages { agent: agent.clone(), plafond: opts.plafond_envoi };
        tokio::spawn(crate::passerelle::servir(l_passerelle, etat_scellement.clone(), reglages));
        let canal = match (&amont, &jeton) {
            (None, _) => "aucun modèle dans le mandat".to_string(),
            (Some(a), None) => format!("{a} — aucun jeton : aplomb modele jeton"),
            (Some(a), Some(_)) => format!("{a}, jeton injecté par Aplomb"),
        };
        let proxy = crate::modele::routeur(etat_scellement.clone(), crate::modele::Reglages { agent, amont, jeton });
        tokio::spawn(async move { axum::serve(l_llm, proxy).await });
        eprintln!("Aplomb — mandat {id}, cosigné par {}", signataires_mandat.join(" et "));
        eprintln!("  API décision       : http://{}", opts.ecoute_decision);
        eprintln!("  API administration : http://{}  (Aplomb Watch, vue technique)", opts.ecoute_admin);
        eprintln!("  Aplomb Gate        : http://{}  (passerelle sortante, HTTPS_PROXY de l'agent ; envoi plafonné à {} Kio par connexion)", opts.ecoute_passerelle, opts.plafond_envoi / 1024);
        eprintln!("  proxy LLM          : http://{}  (ANTHROPIC_BASE_URL de l'agent ; {canal})", opts.ecoute_llm);
        eprintln!(
            "  passerelle MCP     : http://{}/mcp/<nom>  ({})",
            opts.ecoute_mcp,
            if lances.is_empty() { "aucun serveur MCP au mandat".to_string() } else { lances.join(", ") }
        );
        if !enfants.is_empty() {
            eprintln!("  mandats enfants    : {}", enfants.join(", "));
        }
        eprintln!("  comptes            : {} (cosignés par {})", opts.comptes.display(), signataires_comptes.join(" et "));
        eprintln!("  scellement         : toutes les {} s, et à l'arrêt", opts.scellement);
        eprintln!("  réponses signées   : clé publique {}", opts.cle_reponses.with_extension("pub").display());
        eprintln!("  connexion à la vue : aplomb admin connexion --compte <id>");
        let arret = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        // Scellement périodique (EF-I1) ; le verrou garantit qu'aucune écriture n'est en cours.
        let (etat_scelle, dossier_scelle, cle_periodique) = (etat_scellement.clone(), dossier_journal.clone(), cle_scelles.clone());
        let periode = std::time::Duration::from_secs(opts.scellement.max(5));
        tokio::spawn(async move {
            let mut tic = tokio::time::interval(periode);
            loop {
                tic.tick().await;
                let _verrou = etat_scelle.interne.lock().expect("verrou");
                if let Err(e) = aplomb_core::scellement::sceller(&dossier_scelle, &cle_periodique, maintenant()) {
                    eprintln!("  SCELLEMENT EN ÉCHEC : {e}");
                }
            }
        });
        let r = tokio::select! {
            r = axum::serve(l_decision, api_decision) => r.map_err(|e| e.to_string()),
            r = axum::serve(l_admin, api_admin) => r.map_err(|e| e.to_string()),
            _ = arret => Ok(()),
        };
        // Scellé final : l'état à l'arrêt est figé et signé.
        let _verrou = etat_scellement.interne.lock().expect("verrou");
        match aplomb_core::scellement::sceller(&dossier_journal, &cle_scelles, maintenant()) {
            Ok(Some(s)) => eprintln!("  scellé final n° {}", s.seq),
            Ok(None) => {}
            Err(e) => eprintln!("  SCELLEMENT FINAL EN ÉCHEC : {e}"),
        }
        r
    })
}
