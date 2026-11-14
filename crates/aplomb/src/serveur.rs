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
//!   - `GET /admin/consommation?heures=24` : jetons et contexte par utilisateur, compte
//!     technique, prompt et session d'agent (module `aplomb_core::consommation`) ;
//!   - `GET /admin/gouvernance?heures=24&systeme=…&signer=1` : indicateurs agrégés, sans
//!     rien de nominatif (J6, EF-P3) ; signés par la clé de l'instance pour la fédération ;
//!   - `GET /` : la page de la vue technique (sans données).
//! - **Reporting** (`--ecoute-reporting`, module `crate::reporting`) : `POST /mcp`, serveur
//!   MCP en lecture seule pour les outils de gouvernance, sur jeton de client.
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
use aplomb_core::consommation::{ComptesAgents, Consommation, Releve};
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
    /// Comptes techniques des agents (`aplomb agent nouveau`) ; absent : consommation
    /// imputée à « anonyme », pour l'utilisateur qui lance le service.
    #[arg(long, default_value = crate::agents::FICHIER)]
    agents: PathBuf,
    /// Reporting MCP en lecture seule (outils de gouvernance : ACRA, GRC…). Pour un outil
    /// sur une autre machine, écouter sur son interface derrière un relais TLS.
    #[arg(long, default_value = crate::reporting::ECOUTE_DEFAUT)]
    ecoute_reporting: SocketAddr,
    /// Clients du reporting (`aplomb reporting nouveau`), relus à chaque requête.
    #[arg(long, default_value = crate::reporting::FICHIER)]
    reporting: PathBuf,
    /// Activité des comptes (revue des comptes inactifs, EF-N5).
    #[arg(long, default_value = "activite-comptes.json")]
    activite: PathBuf,
    /// Diffusion du journal vers le SIEM (option) : absent, rien ne sort
    /// (`aplomb diffusion exemple > diffusion.yaml`).
    #[arg(long, default_value = "diffusion.yaml")]
    diffusion: PathBuf,
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
    /// Mesure du juge (EF-E5) : consultations, échecs, latence cumulée.
    stats_juge: StatsJuge,
    /// Sonde : consultations, pannes, alertes (avis au-dessus du seuil).
    stats_sonde: (u64, u64, u64),
    /// Consommation du modèle, relevée par le proxy LLM.
    consommation: Consommation,
    agents: ComptesAgents,
    /// Protocole appliqué aux réponses du modèle (EF-E2).
    stats_protocole: StatsProtocole,
    /// Utilisateur à qui imputer les appels quand aucun compte technique n'est déclaré.
    utilisateur_local: String,
    /// Seconds facteurs des comptes (si la MFA est exigée).
    mfa: crate::identite::Mfa,
    /// Activité des comptes et suspensions.
    activite: crate::identite::Activite,
    /// Connexions SSO en cours.
    sso_attente: crate::identite::AttentesSso,
}

/// Compte auquel imputer un appel au modèle.
pub(crate) struct Imputation {
    pub compte: String,
    pub utilisateur: String,
}

#[derive(Default)]
struct StatsJuge {
    consultations: u64,
    indisponible: u64,
    durcies: u64,
    latence_ms: u64,
}

/// Mesure du protocole (EF-E2) : réponses du modèle examinées, suspectes, et leur sort.
#[derive(Default, serde::Serialize)]
pub(crate) struct StatsProtocole {
    pub examinees: u64,
    pub suspectes: u64,
    pub remplacees: u64,
    pub reechantillonnages: u64,
    pub incriminations: u64,
    pub fiable_indisponible: u64,
    pub latence_ms: u64,
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
    /// Juge déclaré au mandat, consulté hors verrou.
    juge: Option<Arc<crate::juge::Juge>>,
    /// Sonde (moniteur interne) déclarée au mandat, consultée hors verrou.
    sonde: Option<Arc<crate::sonde::Sonde>>,
    /// Clients de reporting (relus pour l'onglet Modules).
    reporting: Arc<std::path::PathBuf>,
    /// Diffusion vers le SIEM : état des destinations, si l'option est active.
    siem: Arc<std::sync::OnceLock<crate::diffusion::Etats>>,
    /// Fichier de diffusion (pour l'onglet Modules).
    fichier_diffusion: Arc<PathBuf>,
    /// Fournisseur d'identité (SSO), si déclaré dans comptes.yaml.
    sso: Option<Arc<aplomb_core::identite::ConfigSso>>,
}

impl Etat {
    /// Clé publique de l'instance (réponses, scellés, agrégats).
    pub(crate) fn cle_publique(&self) -> ed25519_dalek::VerifyingKey {
        self.signataire.verifying_key()
    }

    pub(crate) fn mandat(&self) -> aplomb_core::mandat::MandatCharge {
        self.interne.lock().expect("verrou").superviseur.mandat.clone()
    }

    pub(crate) fn signer_agregat(&self, a: aplomb_core::indicateurs::Agregat) -> aplomb_core::indicateurs::AgregatSigne {
        aplomb_core::indicateurs::signer(a, &self.signataire)
    }

    /// Journalise une alerte de la diffusion (dérive d'horloge, destination en échec).
    pub(crate) fn journaliser_alerte(&self, detail: Value) {
        let mut interne = self.interne.lock().expect("verrou");
        let t = maintenant();
        if interne.journal.ajouter(SESSION_ADMIN, "administration", detail.clone(), t).is_ok() {
            self.publier(&mut interne, json!({"type": "administration", "horodatage": t, "session": SESSION_ADMIN, "detail": detail}));
        }
    }

    /// Journalise un appel de reporting (client technique, outil, issue).
    pub(crate) fn journaliser_reporting(&self, client: &str, outil: &str, reussi: bool) {
        let mut interne = self.interne.lock().expect("verrou");
        let detail = json!({"action": "reporting", "client": client, "outil": outil, "issue": if reussi { "ok" } else { "erreur" }});
        let _ = interne.journal.ajouter(SESSION_REPORTING, "administration", detail, maintenant());
    }

    /// État courant de la supervision, sans rien de nominatif (reporting).
    pub(crate) fn etat_supervision(&self) -> Value {
        let interne = self.interne.lock().expect("verrou");
        let (gel_global, sessions_gelees) = interne.superviseur.etat_gel();
        let c = interne.compteurs;
        let s = &interne.stats_juge;
        let m = &interne.superviseur.mandat;
        json!({
            "systeme": m.mandat.id, "version_mandat": m.mandat.version,
            "gel_global": gel_global, "sessions_gelees": sessions_gelees.len(),
            "revues_en_attente": interne.revues.len(), "degels_en_attente": interne.autorite.demandes_en_attente().len(),
            "decisions_depuis_demarrage": {"allow": c[0], "review": c[1], "deny": c[2], "gel": c[3]},
            "juge": self.juge.as_ref().map(|_| json!({"consultations": s.consultations, "indisponibles": s.indisponible,
                "durcies": s.durcies, "latence_moyenne_ms": if s.consultations > 0 { s.latence_ms / s.consultations } else { 0 }})),
            "deploiement": aplomb_core::moniteurs::profil_deploiement(m.mandat.moniteurs.as_ref()),
            "sonde": self.sonde.as_ref().map(|_| json!({"consultations": interne.stats_sonde.0, "indisponibles": interne.stats_sonde.1,
                "alertes": interne.stats_sonde.2})),
            "protocole": m.mandat.moniteurs.as_ref().and_then(|x| x.protocole.as_ref()).map(|p| {
                let mut v = json!(interne.stats_protocole);
                v["mode"] = json!(p.mode);
                v
            }),
        })
    }
}

/// Session du journal où s'inscrivent les appels de reporting.
const SESSION_REPORTING: &str = "_reporting";

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

    /// Compte technique de la clé présentée au proxy LLM, et quota du jour. Sans compte
    /// déclaré, tout est imputé à « anonyme ». Rend le motif du refus sinon : clé inconnue
    /// (401), quota atteint (429).
    pub(crate) fn imputer(&self, cle: Option<&str>) -> Result<Imputation, (StatusCode, String)> {
        let interne = self.interne.lock().expect("verrou");
        if interne.agents.agents.is_empty() {
            return Ok(Imputation { compte: "anonyme".into(), utilisateur: interne.utilisateur_local.clone() });
        }
        let Some(a) = cle.and_then(|c| interne.agents.identifier(c)) else {
            return Err((StatusCode::UNAUTHORIZED, "clé d'agent inconnue : créer un compte technique (aplomb agent nouveau)".into()));
        };
        if let Some(q) = a.jetons_par_jour {
            let jour = interne.consommation.jetons_du_jour(&a.id, maintenant());
            if jour >= q {
                return Err((StatusCode::TOO_MANY_REQUESTS, format!("quota du compte {} atteint : {jour} jetons aujourd'hui pour {q} (UTC)", a.id)));
            }
        }
        Ok(Imputation { compte: a.id.clone(), utilisateur: a.utilisateur.clone() })
    }

    /// Verdict des moniteurs déterministes pour une action proposée par le modèle, sans
    /// effet sur l'état (protocole du proxy LLM).
    pub(crate) fn examiner(&self, evt: &EvenementOutil) -> aplomb_core::decision::Verdict {
        self.interne.lock().expect("verrou").superviseur.examiner(evt).1
    }

    pub(crate) fn ecarter(&self, evt: &EvenementOutil) -> bool {
        self.interne.lock().expect("verrou").superviseur.ecarter(evt)
    }

    pub(crate) fn noter_protocole(&self, f: impl FnOnce(&mut StatsProtocole)) {
        f(&mut self.interne.lock().expect("verrou").stats_protocole);
    }

    pub(crate) fn relever(&self, r: Releve) {
        self.interne.lock().expect("verrou").consommation.ajouter(r);
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
        let mut contenu = json!({
            "mandat": m.mandat.id, "version": m.mandat.version, "empreinte_mandat": m.empreinte,
            "profil": m.mandat.profil, "agent": evt.agent, "mode": evt.mode,
            "niveau_assurance": niveau_assurance(&evt.mode),
            "deploiement": aplomb_core::moniteurs::profil_deploiement(m.mandat.moniteurs.as_ref()),
        });
        // Modules actifs du chemin de décision et leur empreinte (EF-M3, EF-G3).
        contenu["modules"] = json!(aplomb_core::modules::modules_du_mandat(&m.mandat)
            .into_iter()
            .filter(|x| x.actif && x.etape.decision())
            .map(|x| json!({"id": x.id, "etape": x.etape, "facon": x.facon, "version": x.version, "empreinte": x.empreinte}))
            .collect::<Vec<_>>());
        // Empreinte des poids du moniteur interne (EF-G3) : un rejeu sait quelle sonde a jugé.
        if let Some(s) = m.mandat.moniteurs.as_ref().and_then(|x| x.sonde.as_ref()) {
            contenu["sonde"] = json!({"modele": s.modele, "poids_sha256": s.poids_sha256, "seuil": s.seuil});
        }
        interne.journal.ajouter(&evt.session, "session", contenu, t).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Tirage uniforme dans `[0, 1)` et nonce, pour la cascade et l'enveloppe du juge.
fn alea() -> (f64, String) {
    let mut o = [0u8; 16];
    let _ = getrandom::getrandom(&mut o);
    let tirage = u64::from_le_bytes(o[..8].try_into().expect("8 octets")) as f64 / (u64::MAX as f64 + 1.0);
    (tirage, hex::encode(&o[8..]))
}

/// Consulte le juge si la cascade le demande (EF-E5), hors verrou : rend son avis et ce
/// qui en sera journalisé. `raisonnement` : celui du modèle qui a demandé l'action, si le
/// proxy LLM l'a vu (EF-E3).
pub(crate) async fn consulter_juge(etat: &Etat, evt: &EvenementOutil, raisonnement: Option<&str>) -> (Vec<aplomb_core::decision::Avis>, Option<Value>) {
    use aplomb_core::superviseur::Consultation;
    let Some(juge) = &etat.juge else { return (Vec::new(), None) };
    let (tirage, nonce) = alea();
    let consultation = etat.interne.lock().expect("verrou").superviseur.preparer_avec(evt, tirage, &nonce, raisonnement);
    match consultation {
        None => (Vec::new(), None),
        Some(Consultation::BudgetEpuise(a)) => (vec![a], Some(json!({"issue": "budget épuisé"}))),
        Some(Consultation::Sonde { .. } | Consultation::Externe { .. }) => (Vec::new(), None),
        Some(Consultation::Juge { raison, consigne, message }) => {
            let (issue, latence) = juge.consulter(&consigne, &message).await;
            let mut interne = etat.interne.lock().expect("verrou");
            let appels = interne.superviseur.noter_appel_juge(&evt.session);
            interne.stats_juge.consultations += 1;
            interne.stats_juge.latence_ms += latence;
            let (avis, trace) = match issue {
                Ok(a) => {
                    if a.niveau > aplomb_core::decision::Niveau::Conforme {
                        interne.stats_juge.durcies += 1;
                    }
                    let t = json!({"raison": raison, "latence_ms": latence, "appels": appels, "niveau": a.niveau});
                    (a, t)
                }
                Err(e) => {
                    interne.stats_juge.indisponible += 1;
                    let t = json!({"raison": raison, "latence_ms": latence, "appels": appels, "issue": "indisponible", "cause": e});
                    (aplomb_core::moniteurs::avis_indisponible(&juge.cfg, &e), t)
                }
            };
            (vec![avis], Some(trace))
        }
    }
}

/// Consulte la sonde (moniteur interne, EF-F) si l'action est encore permise, hors verrou.
/// Signal d'appoint : son avis ne fait que durcir ; sa panne vaut son plancher (EF-K3).
pub(crate) async fn consulter_sonde(etat: &Etat, evt: &EvenementOutil, raisonnement: Option<&str>) -> (Vec<aplomb_core::decision::Avis>, Option<Value>) {
    use aplomb_core::superviseur::Consultation;
    let Some(sonde) = &etat.sonde else { return (Vec::new(), None) };
    let consultation = etat.interne.lock().expect("verrou").superviseur.preparer_sonde(evt, raisonnement);
    let Some(Consultation::Sonde { intention, texte }) = consultation else { return (Vec::new(), None) };
    let (avis, latence, panne) = sonde.consulter(&intention, &texte, evt.appel.as_deref()).await;
    let mut interne = etat.interne.lock().expect("verrou");
    interne.superviseur.noter_appel_sonde(&evt.session);
    interne.stats_sonde.0 += 1;
    if panne {
        interne.stats_sonde.1 += 1;
    } else if avis.niveau > aplomb_core::decision::Niveau::Conforme {
        interne.stats_sonde.2 += 1;
    }
    let trace = json!({"score": aplomb_core::decision::arrondi_score(avis.score), "niveau": avis.niveau, "latence_ms": latence, "panne": panne});
    (vec![avis], Some(trace))
}

/// Consulte les moniteurs externes du mandat (EF-M1), en parallèle et hors verrou. Leurs
/// avis ne font que durcir ; une panne vaut le plancher déclaré du moniteur.
pub(crate) async fn consulter_externes(etat: &Etat, evt: &EvenementOutil) -> (Vec<aplomb_core::decision::Avis>, Option<Value>) {
    use aplomb_core::superviseur::Consultation;
    let a_consulter: Vec<(aplomb_core::modules::ConfigMoniteurExterne, Value)> = {
        let interne = etat.interne.lock().expect("verrou");
        let mut tirage = || alea().0;
        interne
            .superviseur
            .preparer_externes(evt, &mut tirage)
            .into_iter()
            .filter_map(|c| match c {
                Consultation::Externe { id, requete } => interne.superviseur.moniteur_externe(&id).cloned().map(|cfg| (cfg, requete)),
                _ => None,
            })
            .collect()
    };
    if a_consulter.is_empty() {
        return (Vec::new(), None);
    }
    let issues = futures_util::future::join_all(a_consulter.iter().map(|(cfg, r)| crate::externes::consulter(cfg, r))).await;
    let mut interne = etat.interne.lock().expect("verrou");
    let mut traces = Vec::new();
    let mut avis = Vec::new();
    for ((cfg, _), (a, latence, panne)) in a_consulter.iter().zip(issues) {
        interne.superviseur.noter_appel_externe(&cfg.id, &evt.session);
        traces.push(json!({"id": cfg.id, "niveau": a.niveau, "latence_ms": latence, "panne": panne}));
        avis.push(a);
    }
    (avis, Some(json!(traces)))
}

/// Juge un événement et journalise la décision (journal d'abord : une décision non
/// journalisée n'est jamais rendue). Chemin unique du hook et des passerelles.
pub(crate) async fn juger(etat: &Etat, evt: &EvenementOutil) -> Result<(aplomb_core::decision::DecisionFinale, u64), String> {
    // Ce que le proxy LLM a vu de la réponse qui a demandé cette action : raisonnement, avis
    // déjà rendus (EF-E2, EF-E3). Un script exécuté n'était pas connu du proxy : le juge
    // le voit alors ici.
    let annonce = evt.appel.as_deref().and_then(|a| etat.interne.lock().expect("verrou").annonces.trouver(a).cloned());
    let (mut externes, trace_juge) = match &annonce {
        Some(a) if a.juge && evt.contenu_execute.is_none() => (Vec::new(), Some(json!({"issue": "jugée au proxy LLM, avant l'agent"}))),
        a => consulter_juge(etat, evt, a.as_ref().and_then(|a| a.raisonnement.as_deref())).await,
    };
    let (avis_sonde, trace_sonde) = consulter_sonde(etat, evt, annonce.as_ref().and_then(|a| a.raisonnement.as_deref())).await;
    externes.extend(avis_sonde);
    let (avis_externes, trace_externes) = consulter_externes(etat, evt).await;
    externes.extend(avis_externes);
    externes.extend(annonce.map(|a| a.avis).unwrap_or_default());
    let t = maintenant();
    let mut interne = etat.interne.lock().expect("verrou");
    etat.ouvrir_session(&mut interne, evt, t).map_err(|e| format!("journal indisponible : {e}"))?;
    let (action, d) = interne.superviseur.decider_avec(evt, externes);
    let mut contenu = json!({
        "outil": evt.outil, "verbe": action.verbe, "ressource": action.ressource,
        "contexte": action.contexte, "verdict": d.verdict, "regle": d.politique.regle,
        "motif": d.motif, "durci": d.durci, "avis": d.avis, "appel": evt.appel,
    });
    if let Some(j) = trace_juge {
        contenu["juge"] = j;
    }
    if let Some(s) = trace_sonde {
        contenu["sonde"] = s;
    }
    if let Some(x) = trace_externes {
        contenu["externes"] = x;
    }
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
    let (d, seq) = match juger(&etat, &evt).await {
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
    let s = &interne.stats_juge;
    let juge = etat.juge.as_ref().map(|j| json!({"modele": j.description(), "consultations": s.consultations,
        "indisponible": s.indisponible, "durcies": s.durcies,
        "latence_moyenne_ms": if s.consultations > 0 { s.latence_ms / s.consultations } else { 0 }}));
    let protocole = m.mandat.moniteurs.as_ref().and_then(|x| x.protocole.as_ref()).map(|p| {
        let mut v = json!(interne.stats_protocole);
        v["mode"] = json!(p.mode);
        v
    });
    Json(json!({
        "juge": juge,
        "protocole": protocole,
        "mandat": {"id": m.mandat.id, "version": m.mandat.version, "profil": m.mandat.profil,
                   "intention": m.mandat.intention, "racine": m.mandat.perimetre.racine, "empreinte": m.empreinte},
        "gel_global": gel_global, "sessions_gelees": sessions_gelees,
        "compteurs": {"allow": c[0], "review": c[1], "deny": c[2], "gel": c[3]},
        "compte": compte, "roles": roles, "degels_en_attente": demandes,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct Periode {
    heures: Option<u64>,
}

async fn consommation_admin(State(etat): State<Etat>, entetes: HeaderMap, Query(p): Query<Periode>) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    if compte_web(&mut interne, &entetes).is_none() {
        return non_connecte();
    }
    let t = maintenant();
    let depuis = t.saturating_sub(p.heures.unwrap_or(24).saturating_mul(3_600_000));
    Json(interne.consommation.synthese(depuis, t, &interne.agents)).into_response()
}

#[derive(Deserialize)]
struct ParamGouvernance {
    heures: Option<u64>,
    systeme: Option<String>,
    seuil_k: Option<u64>,
    signer: Option<u8>,
}

/// Vue gouvernance (J6) : indicateurs agrégés du journal, avec leurs taux ; avec `signer=1`,
/// l'agrégat signé par l'instance, prêt à fédérer.
/// Onglet « Modules » : ce qui est actif à chaque étape et comment ajouter le reste.
async fn modules_admin(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    let (mandat, identite) = {
        let mut interne = etat.interne.lock().expect("verrou");
        if compte_web(&mut interne, &entetes).is_none() {
            return non_connecte();
        }
        (interne.superviseur.mandat.mandat.clone(), interne.autorite.identite().clone())
    };
    let clients = crate::reporting::charger(&etat.reporting).map(|c| c.clients.len()).unwrap_or(0);
    let diffusion = crate::diffusion::charger(&etat.fichier_diffusion).ok().flatten();
    let etapes: Vec<Value> = aplomb_core::modules::Etape::TOUTES.iter().map(|e| json!({"etape": e, "libelle": e.libelle(), "decision": e.decision()})).collect();
    Json(json!({
        "mandat": {"id": mandat.id, "version": mandat.version, "profil": mandat.profil},
        "deploiement": aplomb_core::moniteurs::profil_deploiement(mandat.moniteurs.as_ref()),
        "etapes": etapes,
        "modules": crate::modules::tous(&mandat, clients, diffusion.as_ref(), &identite),
    }))
    .into_response()
}

async fn diffusion_admin(State(etat): State<Etat>, entetes: HeaderMap) -> Response {
    if compte_web(&mut etat.interne.lock().expect("verrou"), &entetes).is_none() {
        return non_connecte();
    }
    Json(crate::diffusion::etat_json(etat.siem.get())).into_response()
}

async fn gouvernance(State(etat): State<Etat>, entetes: HeaderMap, Query(p): Query<ParamGouvernance>) -> Response {
    use aplomb_core::indicateurs;
    let dossier = {
        let mut interne = etat.interne.lock().expect("verrou");
        if compte_web(&mut interne, &entetes).is_none() {
            return non_connecte();
        }
        interne.journal.dossier().to_path_buf()
    };
    let instance = indicateurs::identifiant_instance(&etat.signataire.verifying_key());
    let calcul = indicateurs::Calcul {
        instance: &instance,
        systeme: p.systeme.as_deref(),
        periode: crate::vue_gouvernance::periode(p.heures),
        seuil_k: p.seuil_k.unwrap_or(indicateurs::SEUIL_K_DEFAUT).max(1),
    };
    let a = match indicateurs::calculer(&dossier, &calcul) {
        Ok(a) => a,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"erreur": e}))).into_response(),
    };
    if p.signer == Some(1) {
        return Json(indicateurs::signer(a, &etat.signataire)).into_response();
    }
    let taux = indicateurs::taux(&a);
    Json(json!({"agregat": a, "taux": taux})).into_response()
}

/// Relevés de consommation des sessions précédentes, relus dans le journal du proxy LLM
/// (prompts déchiffrés par le coffre ; clé effacée : jetons sans prompt).
fn relire_consommation(journal: &Journal, coffre: &Coffre) -> Consommation {
    let mut c = Consommation::default();
    let chemin = journal.chemin(crate::modele::SESSION);
    let Ok(entrees) = aplomb_core::mermaid::lire_session(&chemin) else { return c };
    for e in aplomb_core::mermaid::ouvrir_contenus(entrees, Some(coffre)) {
        if let Some(r) = crate::modele::releve_du_journal(e.horodatage, &e.contenu) {
            c.ajouter(r);
        }
    }
    c
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
const SESSIONS_TECHNIQUES: &[&str] = &["modele", "passerelle", SESSION_ADMIN, SESSION_REPORTING];

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
        Issue::ReactivationEnAttente => json!({"action": "demande-reactivation", "compte": compte}),
        Issue::Reactivation { cible, demandeur, approbateur } => {
            interne.activite.reactiver(cible, t);
            json!({"action": "reactivation", "cible": cible, "demandeur": demandeur, "approbateur": approbateur})
        }
    };
    let _ = interne.journal.ajouter(session.unwrap_or(SESSION_ADMIN), "administration", detail.clone(), t);
    etat.publier(interne, json!({"type": "administration", "horodatage": t, "session": session, "detail": detail}));
    let issue = match issue {
        Issue::Gel => "gel",
        Issue::DegelEnAttente => "degel-en-attente",
        Issue::Degel { .. } => "degel",
        Issue::Ticket(_) => "ticket",
        Issue::ReactivationEnAttente => "reactivation-en-attente",
        Issue::Reactivation { .. } => "reactivation",
    };
    json!({"issue": issue, "detail": detail})
}

/// Requête signée par la clé d'un compte (`aplomb admin`).
async fn requete_signee(State(etat): State<Etat>, Json(r): Json<RequeteSignee>) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    let t = maintenant();
    let issue = {
        let Interne { autorite, mfa, .. } = &mut *interne;
        autorite.traiter_avec(&r, t, &mut |c, code| mfa.verifier(c, code))
    };
    if issue.is_ok() {
        interne.activite.noter(&r.corps.compte, t);
    }
    match issue {
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
    interne.activite.noter(&compte, maintenant());
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
    interne.activite.noter(&compte, maintenant());
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
    // Avec la MFA, le ticket n'est échangé qu'avec le code (formulaire).
    if interne.autorite.mfa_a_la_connexion() {
        return Html(crate::identite::page_code(&q.ticket, None)).into_response();
    }
    match interne.autorite.ouvrir_session_web(&q.ticket, maintenant()) {
        Ok((jeton, compte)) => {
            interne.activite.noter(&compte, maintenant());
            avec_cookie(&jeton)
        }
        Err(e) => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    }
}

fn avec_cookie(jeton: &str) -> Response {
    let cookie = format!("{COOKIE}={jeton}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", aplomb_core::autorite::SESSION_WEB_MS / 1000);
    ([("set-cookie", cookie)], Redirect::to("/")).into_response()
}

#[derive(Deserialize)]
struct TicketCode {
    ticket: String,
    code: String,
}

/// Ticket et code du second facteur (formulaire de connexion avec la MFA).
async fn connexion_code(State(etat): State<Etat>, axum::Form(f): axum::Form<TicketCode>) -> Response {
    let mut interne = etat.interne.lock().expect("verrou");
    let t = maintenant();
    let r = {
        let Interne { autorite, mfa, .. } = &mut *interne;
        autorite.ouvrir_session_web_avec(&f.ticket, Some(&f.code), t, &mut |c, code| mfa.verifier(c, code))
    };
    match r {
        Ok((jeton, compte)) => {
            interne.activite.noter(&compte, t);
            avec_cookie(&jeton)
        }
        Err(e) => {
            let detail = json!({"action": "connexion-refusee", "cause": e.to_string()});
            let _ = interne.journal.ajouter(SESSION_ADMIN, "administration", detail, t);
            (StatusCode::FORBIDDEN, Html(format!("<p>{e}. Demander un nouveau lien : aplomb admin --compte &lt;id&gt; connexion</p>"))).into_response()
        }
    }
}

/// SSO : renvoie vers le fournisseur d'identité.
async fn sso_debut(State(etat): State<Etat>) -> Response {
    let Some(cfg) = etat.sso.clone() else {
        return (StatusCode::NOT_FOUND, "SSO non configuré (identite.sso dans comptes.yaml)").into_response();
    };
    let url = etat.interne.lock().expect("verrou").sso_attente.debut(&cfg, maintenant());
    Redirect::to(&url).into_response()
}

#[derive(Deserialize)]
struct RetourSso {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// SSO : retour du fournisseur ; le code est échangé contre le jeton d'identité.
async fn sso_retour(State(etat): State<Etat>, Query(q): Query<RetourSso>) -> Response {
    let Some(cfg) = etat.sso.clone() else { return StatusCode::NOT_FOUND.into_response() };
    let refus = |e: String| {
        etat.journaliser_alerte(json!({"action": "connexion-sso-refusee", "cause": e}));
        (StatusCode::FORBIDDEN, Html(format!("<p>Connexion refusée : {e}</p><p><a href=\"/sso/debut\">Réessayer</a></p>"))).into_response()
    };
    if let Some(e) = q.error {
        return refus(format!("le fournisseur d'identité répond {e}"));
    }
    let (Some(code), Some(etat_sso)) = (q.code, q.state) else { return refus("réponse incomplète".into()) };
    let Some((nonce, verif)) = etat.interne.lock().expect("verrou").sso_attente.prendre(&etat_sso, maintenant()) else {
        return refus("connexion inconnue ou expirée".into());
    };
    let id = match crate::identite::retour(&cfg, &code, &nonce, &verif).await {
        Ok(id) => id,
        Err(e) => return refus(e),
    };
    let mut interne = etat.interne.lock().expect("verrou");
    if interne.autorite.identite().mfa_exigee() && !id.mfa {
        drop(interne);
        return refus(format!("{} : le fournisseur d'identité n'atteste pas de second facteur (amr), exigé par Aplomb", id.compte));
    }
    let t = maintenant();
    let roles: Vec<String> = id.roles.iter().map(|r| format!("{r:?}").to_lowercase()).collect();
    let jeton = interne.autorite.ouvrir_session_sso(&id.compte, id.roles.clone(), t);
    let detail = json!({"action": "connexion-sso", "compte": id.compte, "roles": roles, "mfa": id.mfa});
    let _ = interne.journal.ajouter(SESSION_ADMIN, "administration", detail.clone(), t);
    etat.publier(&mut interne, json!({"type": "administration", "horodatage": t, "session": SESSION_ADMIN, "detail": detail}));
    // Retour d'un autre site : cookie Lax, sinon le navigateur ne l'enverrait pas.
    let cookie = format!("{COOKIE}={jeton}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}", aplomb_core::autorite::SESSION_WEB_MS / 1000);
    ([("set-cookie", cookie)], Redirect::to("/")).into_response()
}

fn annonce_identite(c: &aplomb_core::identite::ConfigIdentite, etat: &Etat) -> String {
    let mut v = Vec::new();
    if c.mfa_exigee() {
        let i = etat.interne.lock().expect("verrou");
        v.push(format!("MFA exigée (TOTP : {}/{} compte(s) enrôlé(s))", i.mfa.enroles(), i.autorite.comptes().len()));
    }
    if let Some(s) = &c.sso {
        v.push(format!("SSO {} (/sso/debut)", s.emetteur));
    }
    if let Some(r) = &c.revue {
        v.push(format!("comptes suspendus après {} j d'inactivité", r.inactivite_jours));
    }
    if v.is_empty() {
        "comptes à clé (options : MFA, SSO, revue des comptes, voir docs/IDENTITE.md)".into()
    } else {
        v.join(" ; ")
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
    // Profil du mandat : connu du registre, extension de schéma valide (fiche…).
    let profil = aplomb_core::profils::verifier_mandat(&mandat.mandat).map_err(|e| format!("mandat refusé : {e}"))?;
    let resume_profil: Vec<String> = std::iter::once(profil.description().to_string()).chain(profil.resume(&mandat.mandat)).collect();
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
    let maitre: aplomb_core::confidentiel::Cle = maitre;
    let signataire = cle_reponses(&opts.cle_reponses)?;
    let jeton = crate::cle_maitresse::jeton_modele()?;
    let juge = superviseur.juge().cloned().map(|cfg| crate::juge::Juge::nouveau(cfg, jeton.clone()).map(Arc::new)).transpose()?;
    let dossier_mandat = opts.mandat.parent().unwrap_or(std::path::Path::new("."));
    let sonde = superviseur.sonde().cloned().map(|cfg| crate::sonde::Sonde::nouvelle(cfg, dossier_mandat, true).map(Arc::new)).transpose()?;
    superviseur.charger_filtres(dossier_mandat, true)?;
    let texte_comptes = std::fs::read_to_string(&opts.comptes)
        .map_err(|e| format!("comptes {} : {e} (créer un compte : aplomb compte nouveau)", opts.comptes.display()))?;
    let (autorite, signataires_comptes) = Autorite::depuis_yaml_cosigne(&texte_comptes, &confiance).map_err(|e| {
        format!("comptes refusés : {e} — faire cosigner : aplomb cosigner {} --compte <id>", opts.comptes.display())
    })?;
    // Identité (options cosignées dans comptes.yaml) : seconds facteurs, activité, SSO.
    let config_identite = autorite.identite().clone();
    let mfa = if config_identite.mfa_exigee() {
        crate::identite::Mfa::charger(&maitre, &autorite.comptes())?
    } else {
        Default::default()
    };
    if let Some(s) = &config_identite.sso {
        crate::identite::verifier_sso(s)?;
    }
    let mut autorite = autorite;
    let mut activite = crate::identite::Activite::charger(&opts.activite)?;
    let suspensions = activite.appliquer(&mut autorite, maintenant());
    let agents = crate::agents::charger(&opts.agents)?;
    // Diffusion (option) : configuration et jetons vérifiés avant de démarrer.
    let config_diffusion = crate::diffusion::charger(&opts.diffusion)?;
    if let Some(c) = &config_diffusion {
        crate::diffusion::jetons_presents(c)?;
    }
    let consommation = relire_consommation(&journal, &coffre);
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
            stats_juge: StatsJuge::default(),
            stats_sonde: (0, 0, 0),
            consommation,
            agents: agents.clone(),
            utilisateur_local: std::env::var("USER").unwrap_or_else(|_| "local".into()),
            stats_protocole: StatsProtocole::default(),
            mfa,
            activite,
            sso_attente: Default::default(),
        })),
        diffusion,
        signataire: Arc::new(signataire),
        juge,
        sonde,
        reporting: Arc::new(opts.reporting.clone()),
        siem: Arc::new(std::sync::OnceLock::new()),
        fichier_diffusion: Arc::new(opts.diffusion.clone()),
        sso: config_identite.sso.clone().map(Arc::new),
    };
    for (compte, derniere) in &suspensions {
        etat.journaliser_alerte(json!({"action": "compte-suspendu", "compte": compte, "derniere_activite": derniere, "cause": "inactivité"}));
    }

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
        .route("/connexion", get(connexion).post(connexion_code))
        .route("/sso/debut", get(sso_debut))
        .route("/sso/retour", get(sso_retour))
        .route("/admin/requete", post(requete_signee))
        .route("/admin/deconnexion", post(deconnexion))
        .route("/admin/gel", post(gel))
        .route("/admin/degel", post(degel))
        .route("/admin/revues", get(revues))
        .route("/admin/revue", post(repondre_revue))
        .route("/admin/consommation", get(consommation_admin))
        .route("/admin/gouvernance", get(gouvernance))
        .route("/admin/modules", get(modules_admin))
        .route("/admin/diffusion", get(diffusion_admin))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(etat.clone());
    let reglages_reporting = crate::reporting::Reglages {
        clients: opts.reporting.clone(),
        mandat: opts.mandat.clone(),
        journal: opts.journal.clone(),
        confiance: opts.confiance.clone(),
        comptes: opts.comptes.clone(),
        cosignataires: signataires_mandat.len(),
    };
    let api_reporting = crate::reporting::routeur(etat.clone(), reglages_reporting);
    let clients_reporting = crate::reporting::charger(&opts.reporting)?.clients.len();
    let juge_affiche = etat.juge.as_ref().map(|j| j.description());
    let sonde_affichee = etat.sonde.as_ref().map(|s| s.description());
    let etat_scellement = etat;

    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let l_decision = tokio::net::TcpListener::bind(opts.ecoute_decision).await.map_err(|e| e.to_string())?;
        let l_admin = tokio::net::TcpListener::bind(opts.ecoute_admin).await.map_err(|e| e.to_string())?;
        let l_passerelle = tokio::net::TcpListener::bind(opts.ecoute_passerelle).await.map_err(|e| e.to_string())?;
        let l_llm = tokio::net::TcpListener::bind(opts.ecoute_llm).await.map_err(|e| e.to_string())?;
        let l_mcp = tokio::net::TcpListener::bind(opts.ecoute_mcp).await.map_err(|e| e.to_string())?;
        let l_reporting = tokio::net::TcpListener::bind(opts.ecoute_reporting).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move { axum::serve(l_reporting, api_reporting).await });
        let (agent, amont, racine, serveurs_mcp, moniteurs, profil) = {
            let m = &etat_scellement.interne.lock().expect("verrou").superviseur.mandat.mandat;
            (
                m.agent.clone(),
                m.perimetre.domaines_modele.first().map(|d| aplomb_core::modele::amont(d)).transpose()?,
                m.perimetre.racine.clone(),
                m.perimetre.serveurs_mcp.clone(),
                m.moniteurs.clone(),
                m.profil.clone(),
            )
        };
        let deploiement = aplomb_core::moniteurs::profil_deploiement(moniteurs.as_ref());
        let reglages_protocole = crate::protocole::Reglages::depuis(moniteurs.as_ref(), &agent, &racine)?;
        let protocole_affiche = reglages_protocole.description();
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
        let proxy = crate::modele::routeur(etat_scellement.clone(), crate::modele::Reglages { agent, amont, jeton, protocole: reglages_protocole });
        tokio::spawn(async move { axum::serve(l_llm, proxy).await });
        eprintln!("Aplomb — mandat {id}, cosigné par {}", signataires_mandat.join(" et "));
        eprintln!("  profil             : {profil} — déploiement {deploiement}");
        for ligne in &resume_profil {
            eprintln!("                       {ligne}");
        }
        eprintln!("  API décision       : http://{}", opts.ecoute_decision);
        eprintln!("  API administration : http://{}  (Aplomb Watch, vue technique)", opts.ecoute_admin);
        eprintln!("  Aplomb Gate        : http://{}  (passerelle sortante, HTTPS_PROXY de l'agent ; envoi plafonné à {} Kio par connexion)", opts.ecoute_passerelle, opts.plafond_envoi / 1024);
        eprintln!("  proxy LLM          : http://{}  (ANTHROPIC_BASE_URL de l'agent ; {canal})", opts.ecoute_llm);
        eprintln!(
            "  passerelle MCP     : http://{}/mcp/<nom>  ({})",
            opts.ecoute_mcp,
            if lances.is_empty() { "aucun serveur MCP au mandat".to_string() } else { lances.join(", ") }
        );
        eprintln!(
            "  moniteurs          : secrets{}{}",
            juge_affiche.map(|j| format!(", juge {j}")).unwrap_or_else(|| " (aucun juge au mandat)".into()),
            sonde_affichee.map(|s| format!(", sonde interne {s}")).unwrap_or_default()
        );
        eprintln!("  protocole          : {protocole_affiche}");
        if !enfants.is_empty() {
            eprintln!("  mandats enfants    : {}", enfants.join(", "));
        }
        eprintln!("  comptes            : {} (cosignés par {})", opts.comptes.display(), signataires_comptes.join(" et "));
        eprintln!(
            "  comptes techniques : {}",
            if agents.agents.is_empty() {
                format!("aucun ({} absent) : consommation imputée à « anonyme »", opts.agents.display())
            } else {
                format!("{} dans {} : clé d'agent exigée par le proxy LLM", agents.agents.len(), opts.agents.display())
            }
        );
        eprintln!(
            "  reporting MCP      : http://{}/mcp  (lecture seule ; {})",
            opts.ecoute_reporting,
            if clients_reporting == 0 { "aucun client : aplomb reporting nouveau --id acra".to_string() } else { format!("{clients_reporting} client(s)") }
        );
        eprintln!("  identité           : {}", annonce_identite(&config_identite, &etat_scellement));
        if config_identite.revue.is_some() {
            let e = etat_scellement.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    let nouvelles = {
                        let mut i = e.interne.lock().expect("verrou");
                        let Interne { autorite, activite, .. } = &mut *i;
                        activite.appliquer(autorite, maintenant())
                    };
                    for (compte, derniere) in nouvelles {
                        e.journaliser_alerte(json!({"action": "compte-suspendu", "compte": compte, "derniere_activite": derniere, "cause": "inactivité"}));
                    }
                }
            });
        }
        eprintln!("  diffusion (SIEM)   : {}", crate::diffusion::annonce(config_diffusion.as_ref()));
        if let Some(c) = config_diffusion {
            let e = etat_scellement.clone();
            let etats = crate::diffusion::lancer(c, dossier_journal.clone(), Arc::new(move |d| e.journaliser_alerte(d)));
            let _ = etat_scellement.siem.set(etats);
        }
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
