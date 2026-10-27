//! **Adaptateur hook Claude Code** (mode de branchement, niveau d'assurance 1).
//!
//! Claude Code exécute `sal hook` avant (`PreToolUse`) et après (`PostToolUse`) chaque
//! outil, en passant l'événement en JSON sur stdin. Traduction de la décision :
//! - `Allow` → aucune décision : la main revient aux permissions habituelles de Claude
//!   Code (SAL ne fait que durcir, il n'accorde rien de plus) ;
//! - `Review` → `ask` : Claude Code demande confirmation à l'utilisateur ;
//! - `Deny` / `Gel` → `deny`.
//!
//! **Fail-closed** : superviseur injoignable ou réponse invalide ⇒ `deny`.
use std::io::Read;
use std::path::Path;
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

fn sortie_pre(decision: &str, motif: &str) -> ExitCode {
    let mut sortie = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": format!("SAL : {motif}"),
        }
    });
    if decision == "allow" {
        sortie = json!({});
    }
    println!("{sortie}");
    ExitCode::SUCCESS
}

pub fn executer() -> ExitCode {
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
    let chemin = ["file_path", "notebook_path", "path"]
        .iter()
        .find_map(|k| entree.get(*k).and_then(Value::as_str))
        .unwrap_or("");
    let corps = json!({
        "session": s("session_id"),
        "agent": std::env::var("SAL_AGENT").unwrap_or_else(|_| "claude-code".into()),
        "mode": "hook-claude-code",
        "cwd": cwd,
        "outil": s("tool_name"),
        "entree": entree,
        "phase": phase,
        "chemin_reel": chemin_reel(&cwd, chemin),
    });
    let base = std::env::var("SAL_URL").unwrap_or_else(|_| URL_DEFAUT.into());
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
    match reponse.get("verdict").and_then(Value::as_str) {
        Some("allow") => sortie_pre("allow", motif),
        Some("review") => sortie_pre("ask", motif),
        Some("deny") => sortie_pre("deny", motif),
        Some("gel") => sortie_pre("deny", &format!("SESSION GELÉE — {motif}")),
        _ => sortie_pre("deny", "verdict inconnu (fail-closed)"),
    }
}
