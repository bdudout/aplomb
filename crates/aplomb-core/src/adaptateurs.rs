//! **Adaptateurs de hook** (étape 1, branchement) : d'autres agents de code que Claude Code
//! appellent `aplomb hook --agent <nom>`. Chacun a son format d'événement et de réponse ;
//! l'adaptateur le ramène à l'événement d'Aplomb (noms d'outils de Claude Code, que le
//! profil `code` sait normaliser) et traduit le verdict dans la langue de l'agent.
//!
//! | Agent | Événements | Revue (`review`) |
//! |---|---|---|
//! | Claude Code | `PreToolUse`, `PostToolUse` | `ask` : l'utilisateur confirme |
//! | Codex CLI | `PreToolUse`, `PostToolUse` | refus motivé (pas d'`ask` dans `PreToolUse`) |
//! | Cursor | `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `postToolUse`, `afterShellExecution`, `afterFileEdit` | refus motivé (`ask` n'est pas appliqué partout) |
//!
//! Règle commune : Aplomb ne fait que durcir. Quand l'agent ne sait pas demander une
//! confirmation fiable, une revue devient un refus qui dit pourquoi.
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHook {
    ClaudeCode,
    Codex,
    Cursor,
}

pub const AGENTS: &[&str] = &["claude-code", "codex", "cursor"];

impl AgentHook {
    pub fn depuis(nom: &str) -> Result<Self, String> {
        match nom {
            "claude-code" => Ok(Self::ClaudeCode),
            "codex" => Ok(Self::Codex),
            "cursor" => Ok(Self::Cursor),
            _ => Err(format!("agent « {nom} » inconnu : {}", AGENTS.join(", "))),
        }
    }

    pub fn nom(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    /// Mode de branchement déclaré au journal (niveau d'assurance 1).
    pub fn branchement(self) -> &'static str {
        match self {
            Self::ClaudeCode => "hook-claude-code",
            Self::Codex => "hook-codex",
            Self::Cursor => "hook-cursor",
        }
    }
}

/// Appel d'outil ramené au format d'Aplomb.
#[derive(Debug, Clone, PartialEq)]
pub struct Appel {
    pub session: String,
    pub cwd: String,
    /// Nom d'outil à la Claude Code (`Bash`, `Read`, `Edit`, `mcp__serveur__outil`…).
    pub outil: String,
    pub entree: Value,
    /// `avant` (décision) ou `apres` (observation).
    pub phase: &'static str,
    pub appel: Option<String>,
    pub delegation: Option<Value>,
    /// Nom de l'événement de l'agent, pour la réponse.
    pub evenement: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reponse {
    /// Aplomb n'objecte pas : l'agent applique ses propres permissions.
    Rien,
    Demander,
    Refuser,
}

fn texte(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

/// Fichiers visés par un correctif `apply_patch` de Codex (`*** Update File: …`).
pub fn fichiers_patch(patch: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for l in patch.lines() {
        for p in ["*** Update File: ", "*** Add File: ", "*** Delete File: ", "*** Move to: "] {
            if let Some(f) = l.strip_prefix(p) {
                let f = f.trim().to_string();
                if !f.is_empty() && !v.contains(&f) {
                    v.push(f);
                }
            }
        }
    }
    v
}

/// Premier texte d'une entrée (un correctif peut être une chaîne ou un champ).
fn texte_entree(e: &Value) -> String {
    match e {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.values().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

/// Événement de l'agent → appels d'Aplomb. Un correctif sur plusieurs fichiers donne un
/// appel par fichier ; le hook retient le verdict le plus dur. Rend `Ok(vec![])` pour un
/// événement à ignorer.
pub fn normaliser(agent: AgentHook, evt: &Value) -> Result<Vec<Appel>, String> {
    match agent {
        AgentHook::ClaudeCode | AgentHook::Codex => {
            let evenement = texte(evt, "hook_event_name");
            let phase = match evenement.as_str() {
                "PostToolUse" => "apres",
                "PreToolUse" | "" => "avant",
                _ => return Ok(vec![]),
            };
            let mut outil = texte(evt, "tool_name");
            let mut entree = evt.get("tool_input").cloned().unwrap_or(json!({}));
            let base = Appel {
                session: texte(evt, "session_id"),
                cwd: texte(evt, "cwd"),
                outil: String::new(),
                entree: json!({}),
                phase,
                appel: evt.get("tool_use_id").and_then(Value::as_str).map(String::from),
                delegation: evt.get("agent_type").and_then(Value::as_str).filter(|t| !t.is_empty()).map(|t| json!({"type_agent": t, "id": texte(evt, "agent_id")})),
                evenement,
            };
            if agent == AgentHook::Codex {
                match outil.as_str() {
                    "shell" | "exec_command" | "local_shell" => {
                        // Commande en tableau (["bash", "-lc", "…"]) ou en chaîne.
                        let c = match entree.get("command") {
                            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).last().unwrap_or_default().to_string(),
                            Some(Value::String(s)) => s.clone(),
                            _ => String::new(),
                        };
                        outil = "Bash".into();
                        entree = json!({"command": c});
                    }
                    "apply_patch" => {
                        let patch = texte_entree(&entree);
                        let fichiers = fichiers_patch(&patch);
                        if fichiers.is_empty() {
                            return Ok(vec![Appel { outil: "Edit".into(), entree: json!({"file_path": "", "correctif": patch}), ..base }]);
                        }
                        return Ok(fichiers.into_iter().map(|f| Appel { outil: "Edit".into(), entree: json!({"file_path": f}), ..base.clone() }).collect());
                    }
                    _ => {}
                }
            }
            Ok(vec![Appel { outil, entree, ..base }])
        }
        AgentHook::Cursor => {
            let evenement = texte(evt, "hook_event_name");
            let racine = evt.get("workspace_roots").and_then(Value::as_array).and_then(|r| r.first()).and_then(Value::as_str).unwrap_or_default();
            let cwd = Some(texte(evt, "cwd")).filter(|c| !c.is_empty()).unwrap_or_else(|| racine.to_string());
            let session = Some(texte(evt, "conversation_id")).filter(|s| !s.is_empty()).unwrap_or_else(|| texte(evt, "session_id"));
            let appel = evt.get("tool_use_id").or(evt.get("generation_id")).and_then(Value::as_str).map(String::from);
            let base = Appel { session, cwd, outil: String::new(), entree: json!({}), phase: "avant", appel, delegation: None, evenement: evenement.clone() };
            let (outil, entree, phase) = match evenement.as_str() {
                "beforeShellExecution" => ("Bash".to_string(), json!({"command": texte(evt, "command")}), "avant"),
                "afterShellExecution" => ("Bash".to_string(), json!({"command": texte(evt, "command")}), "apres"),
                "beforeReadFile" => ("Read".to_string(), json!({"file_path": texte(evt, "file_path")}), "avant"),
                "afterFileEdit" => ("Edit".to_string(), json!({"file_path": texte(evt, "file_path")}), "apres"),
                "beforeMCPExecution" | "afterMCPExecution" => {
                    let serveur = Some(texte(evt, "mcp_server_name")).filter(|s| !s.is_empty()).unwrap_or_else(|| "inconnu".into());
                    // tool_input est une chaîne JSON.
                    let entree = match evt.get("tool_input") {
                        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or_else(|_| json!({"brut": s})),
                        Some(v) => v.clone(),
                        None => json!({}),
                    };
                    let phase = if evenement.starts_with("before") { "avant" } else { "apres" };
                    (format!("mcp__{serveur}__{}", texte(evt, "tool_name")), entree, phase)
                }
                "preToolUse" | "postToolUse" => {
                    let phase = if evenement == "preToolUse" { "avant" } else { "apres" };
                    let entree = evt.get("tool_input").cloned().unwrap_or(json!({}));
                    let nom = texte(evt, "tool_name");
                    let outil = match nom.as_str() {
                        "Shell" | "Terminal" => "Bash".to_string(),
                        // Supprimer un fichier est une écriture.
                        "Delete" => "Write".to_string(),
                        n if n.starts_with("MCP:") => format!("mcp__cursor__{}", &n[4..]),
                        n => n.to_string(),
                    };
                    (outil, entree, phase)
                }
                _ => return Ok(vec![]),
            };
            Ok(vec![Appel { outil, entree, phase, ..base }])
        }
    }
}

/// Réponse à écrire sur la sortie standard, dans le format de l'agent (`None` : rien).
pub fn sortie(agent: AgentHook, evenement: &str, r: Reponse, motif: &str) -> Option<Value> {
    let motif = format!("Aplomb : {motif}");
    match agent {
        AgentHook::ClaudeCode | AgentHook::Codex => {
            let decision = match (agent, r) {
                (_, Reponse::Rien) => return Some(json!({})),
                (AgentHook::ClaudeCode, Reponse::Demander) => "ask",
                _ => "deny",
            };
            let motif = if r == Reponse::Demander && agent == AgentHook::Codex { format!("{motif} (revue humaine requise : relancer après accord)") } else { motif };
            Some(json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": motif}}))
        }
        AgentHook::Cursor => {
            if evenement.starts_with("after") || evenement == "postToolUse" {
                return None;
            }
            Some(match r {
                Reponse::Rien => json!({"permission": "allow"}),
                Reponse::Demander => json!({"permission": "deny", "user_message": format!("{motif} (revue humaine requise)"),
                                            "agent_message": format!("{motif}. Demander l'accord de l'utilisateur avant de réessayer.")}),
                Reponse::Refuser => json!({"permission": "deny", "user_message": motif, "agent_message": motif}),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_shell_et_correctif() {
        let e = json!({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/d", "tool_name": "shell", "tool_input": {"command": ["bash", "-lc", "ls -la"]}});
        let a = normaliser(AgentHook::Codex, &e).unwrap();
        assert_eq!((a[0].outil.as_str(), a[0].entree["command"].as_str()), ("Bash", Some("ls -la")));
        let p = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-x\n+y\n*** Add File: b.txt\n+z\n*** End Patch";
        let e = json!({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/d", "tool_name": "apply_patch", "tool_input": {"input": p}});
        let a = normaliser(AgentHook::Codex, &e).unwrap();
        assert_eq!(a.iter().map(|x| x.entree["file_path"].as_str().unwrap()).collect::<Vec<_>>(), ["src/a.rs", "b.txt"]);
        assert_eq!(normaliser(AgentHook::Codex, &json!({"hook_event_name": "SessionStart"})).unwrap(), vec![]);
    }

    #[test]
    fn cursor() {
        let e = json!({"hook_event_name": "beforeShellExecution", "conversation_id": "c1", "command": "rm -rf /", "workspace_roots": ["/w"]});
        let a = &normaliser(AgentHook::Cursor, &e).unwrap()[0];
        assert_eq!((a.session.as_str(), a.cwd.as_str(), a.outil.as_str()), ("c1", "/w", "Bash"));
        let e = json!({"hook_event_name": "beforeMCPExecution", "conversation_id": "c", "mcp_server_name": "notes", "tool_name": "effacer", "tool_input": "{\"q\":1}"});
        let a = &normaliser(AgentHook::Cursor, &e).unwrap()[0];
        assert_eq!((a.outil.as_str(), a.entree["q"].as_i64()), ("mcp__notes__effacer", Some(1)));
        let e = json!({"hook_event_name": "preToolUse", "conversation_id": "c", "tool_name": "Delete", "tool_input": {"file_path": "x"}});
        assert_eq!(normaliser(AgentHook::Cursor, &e).unwrap()[0].outil, "Write");
    }

    #[test]
    fn reponses() {
        assert_eq!(sortie(AgentHook::ClaudeCode, "PreToolUse", Reponse::Demander, "m").unwrap()["hookSpecificOutput"]["permissionDecision"], "ask");
        let c = sortie(AgentHook::Codex, "PreToolUse", Reponse::Demander, "m").unwrap();
        assert_eq!(c["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(c["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap().contains("revue humaine"));
        assert_eq!(sortie(AgentHook::Cursor, "beforeShellExecution", Reponse::Demander, "m").unwrap()["permission"], "deny");
        assert_eq!(sortie(AgentHook::Cursor, "preToolUse", Reponse::Rien, "").unwrap()["permission"], "allow");
        assert!(sortie(AgentHook::Cursor, "afterFileEdit", Reponse::Rien, "").is_none());
    }
}
