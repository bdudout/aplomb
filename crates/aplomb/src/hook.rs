//! **Adaptateur hook Claude Code** (mode de branchement, niveau d'assurance 1).
//!
//! Claude Code exécute `aplomb hook` avant (`PreToolUse`) et après (`PostToolUse`) chaque
//! outil, en passant l'événement en JSON sur stdin. Traduction de la décision :
//! - `Allow` → aucune décision : la main revient aux permissions habituelles de Claude
//!   Code (Aplomb ne fait que durcir, il n'accorde rien de plus) ;
//! - `Review` → `ask` : Claude Code demande confirmation à l'utilisateur ;
//! - `Deny` / `Gel` → `deny`.
//!
//! **Fail-closed** : superviseur injoignable ou réponse invalide ⇒ `deny`.
//!
//! **Réponses signées** (EF-S3) : avec `--cle-serveur`, le hook envoie un nonce et
//! n'accepte qu'une réponse signée sur ce nonce par la clé du superviseur. Un faux
//! superviseur sur le port de décision ne peut donc rien autoriser.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{json, Value};

const URL_DEFAUT: &str = "http://127.0.0.1:7700";

/// Chemin réel (liens résolus) ; pour un fichier à créer, le parent est résolu.
fn chemin_reel(cwd: &str, chemin: &str) -> Option<String> {
    if chemin.is_empty() {
        return None;
    }
    let p = Path::new(cwd).join(chemin);
    if let Ok(c) = std::fs::canonicalize(&p) {
        return Some(c.to_string_lossy().into());
    }
    let parent = std::fs::canonicalize(p.parent()?).ok()?;
    Some(parent.join(p.file_name()?).to_string_lossy().into())
}

/// Taille maximale lue par script exécuté.
const MAX_SCRIPT: u64 = 64 * 1024;

/// Contenu des scripts locaux que la commande exécute (ressource réelle, EF-B4).
fn contenu_execute(cwd: &str, commande: &str) -> Option<String> {
    let mut contenu = String::new();
    for script in aplomb_core::profils::code::scripts_executes(commande) {
        let p = Path::new(cwd).join(&script);
        let lisible = std::fs::metadata(&p).is_ok_and(|m| m.is_file() && m.len() <= MAX_SCRIPT);
        if let Some(texte) = lisible.then(|| std::fs::read_to_string(&p).ok()).flatten() {
            contenu.push_str(&texte);
            contenu.push('\n');
        }
    }
    (!contenu.is_empty()).then_some(contenu)
}

fn sortie_pre(decision: &str, motif: &str) -> ExitCode {
    let mut sortie = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": format!("Aplomb : {motif}"),
        }
    });
    if decision == "allow" {
        sortie = json!({});
    }
    println!("{sortie}");
    ExitCode::SUCCESS
}

/// Vrai si la session doit être supervisée. Sans périmètre déclaré : toujours. Un
/// répertoire de travail introuvable est supervisé (fail-closed).
fn supervise(cwd: &str, perimetre: &[PathBuf]) -> bool {
    if perimetre.is_empty() {
        return true;
    }
    let Ok(cwd) = std::fs::canonicalize(cwd) else { return true };
    perimetre.iter().any(|p| std::fs::canonicalize(p).map_or(true, |p| cwd.starts_with(p)))
}

fn nonce() -> String {
    let mut o = [0u8; 16];
    getrandom::getrandom(&mut o).expect("source d'aléa");
    hex::encode(o)
}

pub fn executer(perimetre: &[PathBuf], cle_serveur: Option<&Path>, branchement: &str) -> ExitCode {
    let cle_serveur = match cle_serveur.map(|p| std::fs::read_to_string(p).map_err(|e| e.to_string())) {
        None => None,
        Some(Ok(t)) => match aplomb_core::mandat::cle_publique(&t) {
            Ok(c) => Some(c),
            Err(_) => return sortie_pre("deny", "clé publique du superviseur illisible (fail-closed)"),
        },
        Some(Err(_)) => return sortie_pre("deny", "clé publique du superviseur introuvable (fail-closed)"),
    };
    let mut brut = String::new();
    if std::io::stdin().read_to_string(&mut brut).is_err() {
        return sortie_pre("deny", "événement illisible (fail-closed)");
    }
    let evt: Value = match serde_json::from_str(&brut) {
        Ok(v) => v,
        Err(_) => return sortie_pre("deny", "événement JSON invalide (fail-closed)"),
    };
    let s = |k: &str| evt.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let nom_evt = s("hook_event_name");
    let phase = if nom_evt == "PostToolUse" { "apres" } else { "avant" };
    let entree = evt.get("tool_input").cloned().unwrap_or(json!({}));
    let cwd = s("cwd");
    if !supervise(&cwd, perimetre) {
        // Hors des dossiers supervisés : aucune décision, Claude Code décide seul.
        println!("{{}}");
        return ExitCode::SUCCESS;
    }
    let chemin = ["file_path", "notebook_path", "path"]
        .iter()
        .find_map(|k| entree.get(*k).and_then(Value::as_str))
        .unwrap_or("");
    let commande = entree.get("command").and_then(Value::as_str).unwrap_or("");
    let nonce = nonce();
    let session = s("session_id");
    let corps = json!({
        "session": s("session_id"),
        "agent": std::env::var("APLOMB_AGENT").unwrap_or_else(|_| "claude-code".into()),
        "mode": branchement,
        "cwd": cwd,
        "outil": s("tool_name"),
        "entree": entree,
        "phase": phase,
        "chemin_reel": chemin_reel(&cwd, chemin),
        "contenu_execute": contenu_execute(&cwd, commande),
        "nonce": nonce,
        "appel": evt.get("tool_use_id").and_then(Value::as_str),
        // Sous-agent (Claude Code : agent_type et agent_id dans un sous-agent).
        "delegation": evt.get("agent_type").and_then(Value::as_str).filter(|t| !t.is_empty())
            .map(|t| json!({"type_agent": t, "id": s("agent_id")})),
    });
    let base = std::env::var("APLOMB_URL").unwrap_or_else(|_| URL_DEFAUT.into());
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(3)).build();

    if phase == "apres" {
        // Observation : best effort, ne bloque jamais l'agent après coup.
        let _ = agent.post(&format!("{base}/v1/observe")).send_json(corps);
        return ExitCode::SUCCESS;
    }

    let reponse: Value = match agent.post(&format!("{base}/v1/decide")).send_json(corps) {
        Ok(r) => match r.into_json() {
            Ok(v) => v,
            Err(_) => return sortie_pre("deny", "réponse du superviseur invalide (fail-closed)"),
        },
        Err(e) => return sortie_pre("deny", &format!("superviseur injoignable ({e}) — fail-closed")),
    };
    let motif = reponse.get("motif").and_then(Value::as_str).unwrap_or("");
    if let Some(cle) = &cle_serveur {
        let champ = |k: &str| reponse.get(k).and_then(Value::as_str).unwrap_or("");
        if !aplomb_core::reponse::verifier(cle, champ("signature"), &nonce, &session, champ("verdict"), champ("regle")) {
            return sortie_pre("deny", "réponse non signée par le superviseur attendu (usurpation possible) — fail-closed");
        }
    }
    match reponse.get("verdict").and_then(Value::as_str) {
        Some("allow") => sortie_pre("allow", motif),
        Some("review") => sortie_pre("ask", motif),
        Some("deny") => sortie_pre("deny", motif),
        Some("gel") => sortie_pre("deny", &format!("SESSION GELÉE — {motif}")),
        _ => sortie_pre("deny", "verdict inconnu (fail-closed)"),
    }
}
