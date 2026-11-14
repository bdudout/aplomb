//! **Reporting MCP** (lecture seule) : un outil de gouvernance cyber (ACRA, un GRC, ou tout
//! client MCP piloté par un LLM) interroge Aplomb pour collecter l'état de conformité et les
//! indicateurs de l'agent supervisé. Protocole et jetons : `aplomb_core::reporting`.
//!
//! - `aplomb reporting nouveau --id acra` : crée un client et affiche son jeton une seule
//!   fois, avec la configuration à coller dans l'outil ;
//! - `aplomb reporting liste`, `aplomb reporting retirer --id acra` ;
//! - `serve` sert `POST /mcp` sur `--ecoute-reporting` (127.0.0.1:7705) ; les clients sont
//!   relus à chaque requête : en ajouter ou en retirer ne demande pas de redémarrage.
//!
//! Chaque appel d'outil est journalisé (session `_reporting` : client, outil, issue).
use std::path::{Path, PathBuf};

use aplomb_core::preuves::{articles, familles, Statut, AVERTISSEMENT};
use aplomb_core::reporting::{self, ClientsReporting};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::serveur::Etat;

pub const FICHIER: &str = "reporting.yaml";
pub const ECOUTE_DEFAUT: &str = "127.0.0.1:7705";

pub fn charger(chemin: &Path) -> Result<ClientsReporting, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => serde_yaml::from_str(&t).map_err(|e| format!("{} : {e}", chemin.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ClientsReporting::default()),
        Err(e) => Err(format!("{} : {e}", chemin.display())),
    }
}

fn enregistrer(chemin: &Path, c: &ClientsReporting) -> Result<(), String> {
    let temporaire = chemin.with_extension("yaml.tmp");
    std::fs::write(&temporaire, serde_yaml::to_string(c).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&temporaire, chemin).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------------------
// Commandes
// ---------------------------------------------------------------------------------------

pub fn nouveau(chemin: &Path, id: &str, description: &str, url: &str) -> Result<(), String> {
    let mut c = charger(chemin)?;
    let mut alea = [0u8; 24];
    getrandom::getrandom(&mut alea).map_err(|e| e.to_string())?;
    let jeton = c.creer(id, description, alea)?;
    enregistrer(chemin, &c)?;
    println!("client de reporting « {id} » ajouté à {} (lecture seule, actif tout de suite)", chemin.display());
    println!();
    println!("jeton, affiché une seule fois (Aplomb n'en garde que l'empreinte) :");
    println!("  {jeton}");
    println!();
    println!("à configurer dans l'outil de gouvernance (client MCP, transport HTTP) :");
    println!("  adresse : {url}");
    println!("  en-tête : Authorization: Bearer {jeton}");
    println!();
    println!("exemple avec Claude Code :");
    println!("  claude mcp add --transport http aplomb {url} --header \"Authorization: Bearer {jeton}\"");
    println!();
    println!("outils offerts : {}", reporting::OUTILS.join(", "));
    println!("retirer l'accès : aplomb reporting retirer --id {id}");
    Ok(())
}

pub fn liste(chemin: &Path) -> Result<(), String> {
    let c = charger(chemin)?;
    if c.clients.is_empty() {
        println!("aucun client de reporting dans {} : aplomb reporting nouveau --id acra", chemin.display());
    }
    for x in &c.clients {
        println!("{:<20} {}", x.id, if x.description.is_empty() { "—" } else { &x.description });
    }
    Ok(())
}

pub fn retirer(chemin: &Path, id: &str) -> Result<(), String> {
    let mut c = charger(chemin)?;
    c.retirer(id)?;
    enregistrer(chemin, &c)?;
    println!("client « {id} » retiré : son jeton est refusé dès maintenant");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------

/// Ce que le service de reporting doit savoir de l'instance.
#[derive(Clone)]
pub struct Reglages {
    pub clients: PathBuf,
    pub mandat: PathBuf,
    pub journal: PathBuf,
    pub confiance: PathBuf,
    pub comptes: PathBuf,
    pub cosignataires: usize,
}

#[derive(Clone)]
struct Partage {
    etat: Etat,
    r: Reglages,
}

pub fn routeur(etat: Etat, r: Reglages) -> Router {
    Router::new()
        .route("/mcp", post(recevoir).get(sans_flux).delete(sans_flux))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(Partage { etat, r })
}

/// Pas de flux serveur → client (aucune notification à pousser).
async fn sans_flux() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

fn refus(code: StatusCode, message: &str) -> Response {
    (code, [("www-authenticate", "Bearer")], Json(json!({"erreur": message}))).into_response()
}

async fn recevoir(State(p): State<Partage>, entetes: HeaderMap, corps: axum::body::Bytes) -> Response {
    let jeton = entetes.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let clients = match charger(&p.r.clients) {
        Ok(c) => c,
        Err(e) => return refus(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let Some(client) = jeton.and_then(|j| clients.identifier(j)).map(|c| c.id.clone()) else {
        let aide = if clients.clients.is_empty() { "aucun client : aplomb reporting nouveau --id <outil>" } else { "jeton de reporting inconnu ou retiré" };
        return refus(StatusCode::UNAUTHORIZED, aide);
    };
    let Ok(message) = serde_json::from_slice::<Value>(&corps) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "JSON illisible"}}))).into_response();
    };
    if message.is_array() {
        return (StatusCode::BAD_REQUEST, Json(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "lots JSON-RPC non pris en charge"}}))).into_response();
    }
    // Les outils lisent des fichiers et rejouent le banc : hors du fil asynchrone.
    let (p2, client2) = (p.clone(), client.clone());
    let reponse = tokio::task::spawn_blocking(move || {
        let mut appeler = |nom: &str, args: &Value| {
            let r = outil(&p2, nom, args);
            p2.etat.journaliser_reporting(&client2, nom, r.is_ok());
            r
        };
        reporting::traiter(&message, &mut appeler)
    })
    .await
    .unwrap_or_else(|_| Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32603, "message": "erreur interne"}})));
    match reponse {
        Some(r) => Json(r).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// Libellés neutres à la place des noms des signataires : le reporting ne nomme personne.
fn anonymiser(mut c: aplomb_core::preuves::Constats) -> aplomb_core::preuves::Constats {
    c.signataires_mandat = (1..=c.signataires_mandat.len()).map(|i| format!("membre {i}")).collect();
    c
}

fn outil(p: &Partage, nom: &str, args: &Value) -> reporting::ResultatOutil {
    let cle = p.etat.cle_publique();
    let instance = aplomb_core::indicateurs::identifiant_instance(&cle);
    match nom {
        "lister_systemes" => {
            let m = p.etat.mandat();
            let mandat = &m.mandat;
            Ok(json!({"instance": instance, "systemes": [{
                "id": mandat.id, "version": mandat.version, "profil": mandat.profil, "agent": mandat.agent,
                "intention": mandat.intention.trim(), "empreinte": &m.empreinte[..m.empreinte.len().min(16)],
                "cosignataires": p.r.cosignataires,
                "referentiels_profil": aplomb_core::profils::pour(&mandat.profil).referentiels(),
                "deploiement": aplomb_core::moniteurs::profil_deploiement(mandat.moniteurs.as_ref()),
            }]}))
        }
        "etat_conformite" => {
            let src = crate::preuves::Sources {
                mandat: &p.r.mandat,
                journal: &p.r.journal,
                heures: reporting::heures(args)?,
                confiance: &p.r.confiance,
                comptes: &p.r.comptes,
            };
            let col = crate::preuves::collecter(&src, &instance, &cle)?;
            let arts = articles(&anonymiser(col.constats));
            let compte = |s: Statut| arts.iter().filter(|a| a.statut == s).count();
            Ok(json!({
                "instance": instance, "systeme": col.m.mandat.id, "version_mandat": col.m.mandat.version,
                "periode": col.periode, "avertissement": AVERTISSEMENT,
                "synthese": {"couvert": compte(Statut::Couvert), "partiel": compte(Statut::Partiel), "hors_perimetre": compte(Statut::HorsPerimetre)},
                "articles": arts.iter().map(|a| json!({"article": a.article, "objet": a.objet, "statut": a.statut,
                    "constat": a.constat, "reste_a_l_organisation": a.reste, "exigences": a.exigences})).collect::<Vec<_>>(),
                "evaluation": col.evaluation.as_ref().map(|r| json!({"surete": r.surete, "surete_sans_humain": r.surete_sans_humain,
                    "utilite": r.utilite, "taux_revue": r.taux_revue})),
            }))
        }
        "indicateurs" => {
            let calcul = aplomb_core::indicateurs::Calcul {
                instance: &instance,
                systeme: None,
                periode: crate::vue_gouvernance::periode(reporting::heures(args)?),
                seuil_k: aplomb_core::indicateurs::SEUIL_K_DEFAUT,
            };
            let a = aplomb_core::indicateurs::calculer(&p.r.journal, &calcul)?;
            if args.get("signer").and_then(Value::as_bool) == Some(true) {
                return serde_json::to_value(p.etat.signer_agregat(a)).map_err(|e| e.to_string());
            }
            let taux = aplomb_core::indicateurs::taux(&a);
            Ok(json!({"agregat": a, "taux": taux}))
        }
        "integrite_journal" => {
            let src = crate::preuves::Sources { mandat: &p.r.mandat, journal: &p.r.journal, heures: None, confiance: &p.r.confiance, comptes: &p.r.comptes };
            Ok(crate::preuves::collecter(&src, &instance, &cle)?.journal)
        }
        "etat_supervision" => Ok(p.etat.etat_supervision()),
        "correspondance_referentiels" => {
            let profil = p.etat.mandat().mandat.profil.clone();
            Ok(json!({"avertissement": AVERTISSEMENT, "familles": familles(),
                "profil": profil, "referentiels_profil": aplomb_core::profils::pour(&profil).referentiels()}))
        }
        "rapport_reglementaire" => {
            let r = aplomb_core::rapports::Referentiel::depuis(args.get("referentiel").and_then(Value::as_str).unwrap_or(""))?;
            let src = crate::preuves::Sources { mandat: &p.r.mandat, journal: &p.r.journal, heures: reporting::heures(args)?, confiance: &p.r.confiance, comptes: &p.r.comptes };
            let col = crate::preuves::collecter(&src, &instance, &cle)?;
            let x = aplomb_core::rapports::rapport(r, &anonymiser(col.constats), &col.m.mandat.id, col.m.mandat.version, &instance, crate::identite::maintenant());
            serde_json::to_value(x).map_err(|e| e.to_string())
        }
        "modules" => Ok(p.etat.modules_json()),
        "revues_en_attente" => Ok(p.etat.revues_en_attente()),
        _ => Err(format!("outil inconnu : {nom}")),
    }
}
