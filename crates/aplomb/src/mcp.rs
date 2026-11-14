//! **Aplomb Gate, passerelle MCP** (niveau d'assurance 2) : l'agent joint ses serveurs MCP
//! par Aplomb (`http://127.0.0.1:7704/mcp/<nom>`, transport HTTP « streamable »), jamais
//! directement.
//!
//! 1. Seuls les serveurs du mandat signé existent ; Aplomb les lance lui-même (stdio), un
//!    processus par session MCP, avec un environnement minimal.
//! 2. Chaque `tools/call` est jugé avant d'être transmis (journal d'abord, fail-closed) ;
//!    un refus revient à l'agent comme un résultat d'outil en erreur. Une revue attend la
//!    réponse d'un humain dans Aplomb Watch (2 min, puis refus).
//! 3. Les définitions d'outils sont épinglées à leur première présentation ; un outil dont
//!    la définition change ensuite est refusé (`aplomb_core::mcp::Epingles`).
//! 4. Gel : plus aucun appel ne passe.
//!
//! **Deux générations du protocole.** Jusqu'à 2025-11-25 : `initialize`, puis une session
//! (`Mcp-Session-Id`) et un processus par session. Version 2026-07-28, sans état : chaque
//! requête porte sa version (`_meta` et en-tête `MCP-Protocol-Version`) ; la passerelle
//! répond à `server/discover`, refuse un en-tête `Mcp-Method` ou `Mcp-Name` qui ne
//! correspond pas au corps, et sert ces requêtes par un processus partagé par serveur,
//! qu'elle initialise elle-même dans l'ancienne version (les serveurs stdio d'aujourd'hui).
//!
//! Les requêtes envoyées par le serveur au client (échantillonnage, élicitation) ne sont
//! pas relayées : la passerelle y répond par une erreur.
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aplomb_core::action::{EvenementOutil, Phase};
use aplomb_core::decision::Verdict;
use aplomb_core::mandat::ServeurMcp;
use aplomb_core::mcp::{erreur, lire_appel, refus, Epingles};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::oneshot;

use crate::serveur::{constater, demander_revue, juger, Etat};

/// Session du journal pour la passerelle MCP.
const SESSION: &str = "mcp";
const ENTETE_SESSION: &str = "mcp-session-id";
/// Sessions MCP ouvertes en même temps, tous serveurs confondus.
const SESSIONS_MAX: usize = 32;
const DELAI_REPONSE: Duration = Duration::from_secs(120);
const REQUETE_MAX: usize = 8 * 1024 * 1024;

pub struct Reglages {
    pub agent: String,
    /// Répertoire de travail des serveurs (racine du mandat).
    pub racine: String,
    pub serveurs: Vec<ServeurMcp>,
}

/// Serveur MCP lancé par Aplomb pour une session.
struct Processus {
    entree: tokio::sync::Mutex<ChildStdin>,
    en_attente: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    _enfant: Child,
}

struct Partage {
    etat: Etat,
    reglages: Reglages,
    sessions: Mutex<HashMap<String, (String, Arc<Processus>)>>,
    /// Version sans état : un processus par serveur, et ses capacités.
    sans_etat: Mutex<HashMap<String, (Arc<Processus>, Value)>>,
    epingles: Mutex<Epingles>,
}

pub fn routeur(etat: Etat, reglages: Reglages) -> Router {
    let partage = Arc::new(Partage {
        etat,
        reglages,
        sessions: Mutex::new(HashMap::new()),
        sans_etat: Mutex::new(HashMap::new()),
        epingles: Mutex::new(Epingles::default()),
    });
    Router::new()
        .route("/mcp/{nom}", post(recevoir).get(sans_flux).delete(fermer))
        .layer(DefaultBodyLimit::max(REQUETE_MAX))
        .with_state(partage)
}

/// Pas de flux ouvert par le serveur (notifications spontanées) : le client s'en passe.
async fn sans_flux() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

async fn fermer(State(p): State<Arc<Partage>>, entetes: HeaderMap) -> StatusCode {
    match session_de(&entetes).and_then(|s| p.sessions.lock().expect("verrou").remove(&s)) {
        Some(_) => StatusCode::NO_CONTENT,
        None => StatusCode::NOT_FOUND,
    }
}

fn session_de(entetes: &HeaderMap) -> Option<String> {
    entetes.get(ENTETE_SESSION).and_then(|v| v.to_str().ok()).map(String::from)
}

fn cle_id(id: &Value) -> String {
    id.to_string()
}

fn evenement(r: &Reglages, outil: String, entree: Value, appel: Option<String>, phase: Phase) -> EvenementOutil {
    EvenementOutil {
        session: SESSION.into(),
        agent: r.agent.clone(),
        mode: "passerelle-mcp".into(),
        cwd: r.racine.clone(),
        outil,
        entree,
        phase,
        chemin_reel: None,
        contenu_execute: None,
        nonce: None,
        appel,
        delegation: None,
    }
}

/// Lance le serveur déclaré au mandat, et lit ses réponses en tâche de fond.
fn lancer(serveur: &ServeurMcp, racine: &str) -> Result<Arc<Processus>, String> {
    let (programme, args) = serveur.commande.split_first().ok_or("serveur sans commande au mandat")?;
    let mut c = Command::new(programme);
    c.args(args).current_dir(racine).env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    for k in ["PATH", "HOME", "LANG", "TMPDIR"] {
        if let Some(v) = std::env::var_os(k) {
            c.env(k, v);
        }
    }
    let mut enfant = c.spawn().map_err(|e| format!("lancement de {programme} : {e}"))?;
    let entree = enfant.stdin.take().ok_or("stdin du serveur")?;
    let sortie = enfant.stdout.take().ok_or("stdout du serveur")?;
    let p = Arc::new(Processus { entree: tokio::sync::Mutex::new(entree), en_attente: Mutex::new(HashMap::new()), _enfant: enfant });
    let faible = Arc::downgrade(&p);
    tokio::spawn(async move {
        let mut lignes = BufReader::new(sortie).lines();
        while let Ok(Some(ligne)) = lignes.next_line().await {
            let Some(p) = faible.upgrade() else { break };
            let Ok(m) = serde_json::from_str::<Value>(&ligne) else { continue };
            let est_reponse = m.get("result").is_some() || m.get("error").is_some();
            match (m.get("id"), est_reponse) {
                (Some(id), true) => {
                    if let Some(tx) = p.en_attente.lock().expect("verrou").remove(&cle_id(id)) {
                        let _ = tx.send(m);
                    }
                }
                // Requête du serveur vers le client : non relayée.
                (Some(id), false) => {
                    let r = erreur(id, -32601, "requête du serveur non relayée par la passerelle");
                    let _ = ecrire(&p, &r).await;
                }
                _ => {}
            }
        }
    });
    Ok(p)
}

async fn ecrire(p: &Processus, m: &Value) -> Result<(), String> {
    let mut ligne = serde_json::to_vec(m).map_err(|e| e.to_string())?;
    ligne.push(b'\n');
    let mut e = p.entree.lock().await;
    e.write_all(&ligne).await.map_err(|e| e.to_string())?;
    e.flush().await.map_err(|e| e.to_string())
}

/// Transmet une requête et attend sa réponse. L'identifiant est renuméroté par la
/// passerelle : des clients différents qui partagent un processus (version sans état) ne
/// peuvent pas se répondre l'un à l'autre.
async fn transmettre(p: &Processus, m: &Value, id: &Value) -> Value {
    static SUIVANT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let interne = json!(format!("aplomb-{}", SUIVANT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut envoi = m.clone();
    envoi["id"] = interne.clone();
    let (tx, rx) = oneshot::channel();
    p.en_attente.lock().expect("verrou").insert(cle_id(&interne), tx);
    if let Err(e) = ecrire(p, &envoi).await {
        p.en_attente.lock().expect("verrou").remove(&cle_id(&interne));
        return erreur(id, -32603, &format!("serveur MCP injoignable : {e}"));
    }
    match tokio::time::timeout(DELAI_REPONSE, rx).await {
        Ok(Ok(mut r)) => {
            r["id"] = id.clone();
            r
        }
        _ => {
            p.en_attente.lock().expect("verrou").remove(&cle_id(&interne));
            erreur(id, -32603, "pas de réponse du serveur MCP")
        }
    }
}

/// Processus partagé d'un serveur pour la version sans état, initialisé par la passerelle.
async fn processus_partage(p: &Partage, serveur: &ServeurMcp) -> Result<(Arc<Processus>, Value), String> {
    if let Some(x) = p.sans_etat.lock().expect("verrou").get(&serveur.nom) {
        return Ok(x.clone());
    }
    let proc_ = lancer(serveur, &p.reglages.racine)?;
    let init = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "aplomb-passerelle", "version": env!("CARGO_PKG_VERSION")}}});
    let r = transmettre(&proc_, &init, &json!(0)).await;
    let capacites = r.pointer("/result/capabilities").cloned().ok_or_else(|| format!("serveur MCP « {} » : initialisation refusée", serveur.nom))?;
    ecrire(&proc_, &json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await?;
    let mut s = p.sans_etat.lock().expect("verrou");
    Ok(s.entry(serveur.nom.clone()).or_insert((proc_, capacites)).clone())
}

fn entete(e: &HeaderMap, nom: &str) -> Option<String> {
    e.get(nom).and_then(|v| v.to_str().ok()).map(String::from)
}

async fn recevoir(State(p): State<Arc<Partage>>, Path(nom): Path<String>, entetes: HeaderMap, Json(corps): Json<Value>) -> Response {
    let Some(serveur) = p.reglages.serveurs.iter().find(|s| s.nom == nom && !s.commande.is_empty()) else {
        return (StatusCode::NOT_FOUND, format!("Aplomb : serveur MCP « {nom} » absent du mandat")).into_response();
    };
    if !aplomb_core::mcp::origine_admise(entete(&entetes, "origin").as_deref()) {
        return (StatusCode::FORBIDDEN, "Aplomb : origine refusée (seules les pages de cette machine)").into_response();
    }
    let lot = corps.is_array();
    let messages = match corps {
        Value::Array(v) => v,
        m => vec![m],
    };
    // Génération du protocole et cohérence des en-têtes.
    let ent = aplomb_core::mcp::Entetes {
        version: entete(&entetes, "mcp-protocol-version"),
        methode: entete(&entetes, "mcp-method"),
        nom: entete(&entetes, "mcp-name"),
    };
    let mut sans_etat = false;
    for m in &messages {
        match aplomb_core::mcp::ere(&ent, m) {
            Ok(aplomb_core::mcp::Ere::SansEtat) => sans_etat = true,
            Ok(_) => {}
            Err(e) => return (StatusCode::BAD_REQUEST, Json(e)).into_response(),
        }
    }
    if sans_etat {
        let (processus, capacites) = match processus_partage(&p, serveur).await {
            Ok(x) => x,
            Err(e) => return (StatusCode::BAD_GATEWAY, format!("Aplomb : {e}")).into_response(),
        };
        let mut reponses = Vec::new();
        for m in messages {
            let Some(id) = m.get("id").cloned().filter(|_| m.get("method").is_some()) else {
                let _ = ecrire(&processus, &m).await;
                continue;
            };
            let r = match m.get("method").and_then(Value::as_str) {
                Some("server/discover") => aplomb_core::mcp::decouverte(&id, &nom, &capacites),
                Some("subscriptions/listen") => erreur(&id, -32601, "abonnements non relayés par la passerelle"),
                _ => aplomb_core::mcp::completer_sans_etat(traiter(&p, serveur, &processus, m, id).await, &nom),
            };
            reponses.push(r);
        }
        return if reponses.is_empty() {
            StatusCode::ACCEPTED.into_response()
        } else if lot {
            Json(Value::Array(reponses)).into_response()
        } else {
            Json(reponses.remove(0)).into_response()
        };
    }
    // Session MCP : ouverte par `initialize`, un processus par session.
    let mut nouvelle = None;
    let processus = match session_de(&entetes) {
        Some(sid) => match p.sessions.lock().expect("verrou").get(&sid) {
            Some((n, proc_)) if *n == nom => proc_.clone(),
            _ => return (StatusCode::NOT_FOUND, "Aplomb : session MCP inconnue").into_response(),
        },
        None if messages.iter().any(|m| m.get("method").and_then(Value::as_str) == Some("initialize")) => {
            if p.sessions.lock().expect("verrou").len() >= SESSIONS_MAX {
                return (StatusCode::SERVICE_UNAVAILABLE, "Aplomb : trop de sessions MCP").into_response();
            }
            let proc_ = match lancer(serveur, &p.reglages.racine) {
                Ok(x) => x,
                Err(e) => return (StatusCode::BAD_GATEWAY, format!("Aplomb : {e}")).into_response(),
            };
            let mut octets = [0u8; 16];
            let _ = getrandom::getrandom(&mut octets);
            let sid = hex::encode(octets);
            p.sessions.lock().expect("verrou").insert(sid.clone(), (nom.clone(), proc_.clone()));
            nouvelle = Some(sid);
            proc_
        }
        None => return (StatusCode::BAD_REQUEST, "Aplomb : session MCP absente (initialize d'abord)").into_response(),
    };

    let mut reponses = Vec::new();
    for m in messages {
        let Some(id) = m.get("id").cloned().filter(|_| m.get("method").is_some()) else {
            // Notification ou réponse du client : transmise sans attente.
            let _ = ecrire(&processus, &m).await;
            continue;
        };
        reponses.push(traiter(&p, serveur, &processus, m, id).await);
    }

    let mut sortie = if reponses.is_empty() {
        StatusCode::ACCEPTED.into_response()
    } else if lot {
        Json(Value::Array(reponses)).into_response()
    } else {
        Json(reponses.remove(0)).into_response()
    };
    if let Some(sid) = nouvelle {
        if let Ok(v) = sid.parse() {
            sortie.headers_mut().insert(ENTETE_SESSION, v);
        }
    }
    sortie
}

async fn traiter(p: &Partage, serveur: &ServeurMcp, processus: &Processus, m: Value, id: Value) -> Value {
    let methode = m.get("method").and_then(Value::as_str).unwrap_or_default().to_string();
    let Some(appel) = lire_appel(&m) else {
        let r = transmettre(processus, &m, &id).await;
        if methode == "tools/list" {
            let changes = p.epingles.lock().expect("verrou").retenir(&serveur.nom, &r);
            if !changes.is_empty() {
                let evt = evenement(&p.reglages, format!("mcp__{}", serveur.nom), json!({}), None, Phase::Apres);
                let _ = constater(&p.etat, &evt, json!({"outil": evt.outil, "verbe": "outil_mcp", "ressource": serveur.nom,
                    "ecart": format!("définition modifiée depuis sa première présentation : {}", changes.join(", "))}));
            }
        }
        return r;
    };
    let outil = format!("mcp__{}__{}", serveur.nom, appel.outil);
    if p.etat.gele(SESSION) {
        return refus(&id, "superviseur gelé : plus aucun appel d'outil MCP");
    }
    if p.epingles.lock().expect("verrou").modifie(&serveur.nom, &appel.outil) {
        let evt = evenement(&p.reglages, outil.clone(), json!({}), appel.appel.clone(), Phase::Apres);
        let _ = constater(&p.etat, &evt, json!({"outil": outil, "verbe": "outil_mcp", "ressource": serveur.nom, "refus": "définition modifiée"}));
        return refus(&id, &format!("{outil} refusé : sa définition a changé depuis sa première présentation"));
    }
    let evt = evenement(&p.reglages, outil.clone(), appel.arguments.clone(), appel.appel.clone(), Phase::Avant);
    let d = match juger(&p.etat, &evt).await {
        Ok((d, _)) => d,
        Err(e) => return refus(&id, &format!("{e} — fail-closed")),
    };
    match d.verdict {
        Verdict::Allow => {}
        Verdict::Review => {
            let resume = format!("{outil} {}", appel.arguments);
            if let Err(e) = demander_revue(&p.etat, &evt, &resume, &d).await {
                return refus(&id, &format!("{outil} : {e} — {}", d.motif));
            }
        }
        _ => {
            let palier = serde_json::to_value(d.verdict).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
            return refus(&id, &format!("{outil} {palier} — {}", d.motif));
        }
    }
    let r = transmettre(processus, &m, &id).await;
    let mut apres = evt.clone();
    apres.phase = Phase::Apres;
    let en_erreur = r.get("error").is_some() || r.pointer("/result/isError") == Some(&json!(true));
    let _ = constater(&p.etat, &apres, json!({"outil": outil, "verbe": "outil_mcp", "ressource": serveur.nom,
        "appel": appel.appel, "statut": if en_erreur { "erreur" } else { "ok" }}));
    r
}
