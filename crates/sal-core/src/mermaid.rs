//! **Export Mermaid** du journal : un diagramme de séquence par session, pour suivre
//! les requêtes d'un agent (rendu par tout outil Mermaid, dont Pele).
//!
//! Quatre participants, indépendants du domaine : l'agent, SAL, les outils (le monde)
//! et l'humain. Une décision devient une flèche de l'agent vers SAL, puis :
//! - `allow`  → SAL laisse passer vers les outils ;
//! - `review` → SAL demande à l'humain ;
//! - `deny`   → flèche barrée vers l'agent ;
//! - `gel`    → flèche barrée et note « session gelée ».
//!
//! Une observation (après exécution) est une flèche retour des outils vers l'agent.
//! On n'exporte qu'une chaîne vérifiée : un diagramme ne doit jamais montrer un journal
//! altéré comme s'il était intact.
use std::path::Path;

use serde_json::Value;

use crate::journal::{self, Entree, ErreurJournal};

/// Lit une session après vérification de sa chaîne.
pub fn lire_session(chemin: &Path) -> Result<Vec<Entree>, ErreurJournal> {
    journal::verifier(chemin)?;
    let texte = std::fs::read_to_string(chemin)?;
    texte
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| serde_json::from_str(l).map_err(|e| ErreurJournal::Format(i + 1, e.to_string())))
        .collect()
}

/// Texte sûr pour un message Mermaid : une ligne, sans séparateur ni code d'entité,
/// tronqué.
fn texte(s: &str, max: usize) -> String {
    let propre: String = s
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            ';' => ',',
            '#' => '№',
            '<' => '‹',
            '>' => '›',
            '%' => '‰',
            '{' => '(',
            '}' => ')',
            '"' | '`' => '\'',
            c => c,
        })
        .collect();
    let propre = propre.split_whitespace().collect::<Vec<_>>().join(" ");
    if propre.chars().count() > max {
        format!("{}…", propre.chars().take(max).collect::<String>())
    } else {
        propre
    }
}

/// Ressource lisible : une ligne, et l'**extrémité** gardée quand c'est long (le nom de
/// fichier compte plus que le début du chemin).
fn ressource(s: &str, max: usize) -> String {
    let t = texte(s, usize::MAX);
    let n = t.chars().count();
    if n > max {
        format!("…{}", t.chars().skip(n - max).collect::<String>())
    } else {
        t
    }
}

fn champ<'a>(v: &'a Value, cle: &str) -> &'a str {
    v.get(cle).and_then(Value::as_str).unwrap_or("")
}

/// Diagramme de séquence d'une session ; au-delà de `max` actions, les plus anciennes
/// sont résumées par une note.
pub fn sequence(entrees: &[Entree], max: usize) -> String {
    let mut l = vec!["sequenceDiagram".to_string()];
    let session = entrees.first().map(|e| e.session.as_str()).unwrap_or("");
    let ouverture = entrees.iter().find(|e| e.type_ == "session").map(|e| &e.contenu);
    let agent = ouverture.map(|c| champ(c, "agent")).filter(|a| !a.is_empty()).unwrap_or("agent");
    l.push(format!("    participant A as Agent ({})", texte(agent, 40)));
    l.push("    participant S as SAL".into());
    l.push("    participant O as Outils".into());
    l.push("    participant H as Humain".into());
    match ouverture {
        Some(c) => l.push(format!(
            "    Note over A,H: session {} · mandat {} v{} · niveau {} ({}) · empreinte {}… · chaîne vérifiée",
            texte(session, 40),
            texte(champ(c, "mandat"), 40),
            c.get("version").and_then(Value::as_u64).unwrap_or(0),
            c.get("niveau_assurance").and_then(Value::as_u64).unwrap_or(0),
            texte(champ(c, "mode"), 30),
            &champ(c, "empreinte_mandat").chars().take(12).collect::<String>(),
        )),
        None => l.push(format!("    Note over A,H: session {} · chaîne vérifiée", texte(session, 40))),
    }

    let actions: Vec<&Entree> = entrees.iter().filter(|e| e.type_ != "session").collect();
    let omises = actions.len().saturating_sub(max);
    if omises > 0 {
        l.push(format!("    Note over A,H: {omises} entrées plus anciennes omises"));
    }
    // Une fois la session gelée, la règle de chaque refus n'est plus la cause : le gel l'est.
    let mut gelee = false;
    for e in &actions[omises..] {
        let c = &e.contenu;
        let n = e.seq;
        match e.type_.as_str() {
            "decision" => {
                let outil = format!("{} {}", texte(champ(c, "outil"), 30), texte(champ(c, "verbe"), 20));
                l.push(format!("    A->>S: {n}. {outil} {}", ressource(champ(c, "ressource"), 50)));
                let regle = texte(champ(c, "regle"), 40);
                match champ(c, "verdict") {
                    "allow" => l.push("    S->>O: autorisé".into()),
                    "review" => l.push(format!("    S->>H: revue demandée ({regle})")),
                    "gel" if gelee => l.push("    S--xA: GEL (session déjà gelée)".into()),
                    "gel" => {
                        gelee = true;
                        l.push(format!("    S--xA: GEL ({regle})"));
                        l.push("    Note over A,S: session gelée".into());
                    }
                    autre => l.push(format!("    S--xA: {} ({regle})", texte(&autre.to_uppercase(), 10))),
                }
            }
            "observation" => {
                let outil = texte(champ(c, "outil"), 30);
                l.push(format!("    O-->>A: {n}. exécuté : {outil} {}", ressource(champ(c, "ressource"), 50)));
            }
            "administration" => {
                let action = champ(c, "action");
                if action == "degel" {
                    gelee = false;
                }
                l.push(format!("    H->>S: {n}. administration : {}", texte(action, 20)));
            }
            autre => l.push(format!("    Note over S: {n}. {}", texte(autre, 30))),
        }
    }
    l.push(String::new());
    l.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;
    use serde_json::json;

    fn session_type(nom: &str) -> Vec<Entree> {
        let d = std::env::temp_dir().join(format!("sal-mermaid-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut j = Journal::ouvrir(&d).unwrap();
        let s = "s1";
        j.ajouter(s, "session", json!({"mandat": "m", "version": 2, "agent": "claude-code", "mode": "hook-claude-code", "niveau_assurance": 1, "empreinte_mandat": "abcdef0123456789"}), 1).unwrap();
        let d1 = json!({"outil": "Read", "verbe": "lire", "ressource": "/depot/a.py", "verdict": "allow", "regle": "lire"});
        j.ajouter(s, "decision", d1, 2).unwrap();
        j.ajouter(s, "observation", json!({"outil": "Read", "verbe": "lire", "ressource": "/depot/a.py"}), 3).unwrap();
        let d2 = json!({"outil": "Bash", "verbe": "executer", "ressource": "pip install x; echo #1 <b>", "verdict": "review", "regle": "revue-installation-de-dependance"});
        j.ajouter(s, "decision", d2, 4).unwrap();
        let d3 = json!({"outil": "Bash", "verbe": "executer", "ressource": "evil.example", "verdict": "deny", "regle": "reseau-non-autorise"});
        j.ajouter(s, "decision", d3, 5).unwrap();
        let d4 = json!({"outil": "Bash", "verbe": "executer", "ressource": "mv .claude .old", "verdict": "gel", "regle": "point-protege"});
        j.ajouter(s, "decision", d4, 6).unwrap();
        j.ajouter(s, "decision", json!({"outil": "Read", "verbe": "lire", "ressource": "a", "verdict": "gel", "regle": "lire"}), 7).unwrap();
        j.ajouter(s, "administration", json!({"action": "degel", "session": s}), 8).unwrap();
        let long = json!({"outil": "Read", "verbe": "lire", "ressource": format!("/{}/calcul.py", "d".repeat(80)), "verdict": "allow", "regle": "lire"});
        j.ajouter(s, "decision", long, 9).unwrap();
        lire_session(&j.chemin(s)).unwrap()
    }

    #[test]
    fn une_fleche_par_decision() {
        let m = sequence(&session_type("fleches"), 200);
        assert!(m.starts_with("sequenceDiagram\n"));
        assert!(m.contains("participant A as Agent (claude-code)"));
        assert!(m.contains("mandat m v2 · niveau 1 (hook-claude-code) · empreinte abcdef012345…"));
        assert!(m.contains("A->>S: 2. Read lire /depot/a.py\n    S->>O: autorisé"));
        assert!(m.contains("O-->>A: 3. exécuté : Read /depot/a.py"));
        assert!(m.contains("S->>H: revue demandée (revue-installation-de-dependance)"));
        assert!(m.contains("S--xA: DENY (reseau-non-autorise)"));
        assert!(m.contains("S--xA: GEL (point-protege)\n    Note over A,S: session gelée"));
        assert!(m.contains("A->>S: 7. Read lire a\n    S--xA: GEL (session déjà gelée)\n    H->>S: 8"));
        assert_eq!(m.matches("session gelée").count(), 1);
        assert!(m.contains("H->>S: 8. administration : degel"));
        // Chemin long : l'extrémité (le nom de fichier) est gardée.
        assert!(m.contains("A->>S: 9. Read lire …") && m.contains("/calcul.py\n"));
    }

    #[test]
    fn texte_neutralise() {
        let m = sequence(&session_type("texte"), 200);
        // Ni `;` (séparateur), ni `#` (code d'entité), ni balises dans les messages.
        let messages: Vec<&str> = m.lines().filter(|l| l.contains(':')).map(|l| l.split_once(':').unwrap().1).collect();
        assert!(messages.iter().all(|t| !t.contains(';') && !t.contains('#') && !t.contains('<')));
        assert_eq!(texte(&"x".repeat(100), 10), format!("{}…", "x".repeat(10)));
    }

    #[test]
    fn longues_sessions_tronquees() {
        let m = sequence(&session_type("tronque"), 2);
        assert!(m.contains("6 entrées plus anciennes omises"));
        assert!(!m.contains("/depot/a.py"));
    }

    #[test]
    fn journal_altere_refuse() {
        let d = std::env::temp_dir().join(format!("sal-mermaid-alt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut j = Journal::ouvrir(&d).unwrap();
        j.ajouter("s", "decision", json!({"verdict": "deny"}), 1).unwrap();
        let f = j.chemin("s");
        std::fs::write(&f, std::fs::read_to_string(&f).unwrap().replace("deny", "allow")).unwrap();
        assert!(lire_session(&f).is_err());
    }
}
