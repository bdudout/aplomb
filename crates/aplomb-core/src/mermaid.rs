//! **Export Mermaid** du journal : un diagramme de séquence par session, pour suivre
//! les requêtes d'un agent (rendu par tout outil Mermaid, dont Pele).
//!
//! Quatre participants, indépendants du domaine : l'agent, Aplomb, les outils (le monde)
//! et l'humain. Une décision devient une flèche de l'agent vers Aplomb, puis :
//! - `allow`  → Aplomb laisse passer vers les outils ;
//! - `review` → Aplomb demande à l'humain ;
//! - `deny`   → flèche barrée vers l'agent ;
//! - `gel`    → flèche barrée et note « session gelée ».
//!
//! Une observation (après exécution) est une flèche retour des outils vers l'agent.
//! On n'exporte qu'une chaîne vérifiée : un diagramme ne doit jamais montrer un journal
//! altéré comme s'il était intact.
//!
//! Contenus scellés (EF-P1) : sans la clé de session, le diagramme montre les outils,
//! verdicts et règles, et désigne chaque ressource par sa référence (`réf 3f2a…`). Avec
//! la clé (option explicite), les ressources apparaissent en clair. Une session dont la
//! clé a été détruite est marquée « contenus effacés ».
use std::path::Path;

use serde_json::Value;

use crate::confidentiel::{restaurer, Coffre, Etat};
use crate::journal::{self, Entree, ErreurJournal};

/// Déchiffre les entrées si un coffre est fourni ; marque `efface` celles dont la clé
/// n'existe plus. Sans coffre, les entrées restent scellées.
pub fn ouvrir_contenus(entrees: Vec<Entree>, coffre: Option<&Coffre>) -> Vec<Entree> {
    let Some(coffre) = coffre else { return entrees };
    let Some(session) = entrees.first().map(|e| e.session.clone()) else { return entrees };
    let cle = coffre.cle(&session);
    entrees
        .into_iter()
        .map(|mut e| {
            let (contenu, etat) = restaurer(cle.as_ref(), &session, &e.contenu);
            e.contenu = contenu;
            if etat == Etat::Scelle && cle.is_none() {
                if let Some(o) = e.contenu.as_object_mut() {
                    o.insert("efface".into(), Value::Bool(true));
                }
            }
            e
        })
        .collect()
}

/// Ressource en clair si elle est disponible, sinon sa référence.
fn designation(c: &Value) -> String {
    match (champ(c, "ressource"), champ(c, "ref")) {
        ("", "") => String::new(),
        ("", r) => format!("réf {r}"),
        (clair, _) => ressource(clair, 50),
    }
}

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
    l.push("    participant S as Aplomb".into());
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
    let mention = if entrees.iter().any(|e| e.contenu.get("efface").is_some()) {
        Some("contenus effacés (clé de session détruite) : références seulement")
    } else if entrees.iter().any(|e| e.contenu.get("scelle").is_some()) {
        Some("contenus scellés : références seulement")
    } else {
        None
    };
    if let Some(m) = mention {
        l.push(format!("    Note over A,H: {m}"));
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
                l.push(format!("    A->>S: {n}. {outil} {}", designation(c)));
                // Un avis qui a durci la décision (borne, moniteur) en est la vraie cause.
                let durci_par = c
                    .get("avis")
                    .and_then(Value::as_array)
                    .and_then(|a| a.last())
                    .filter(|_| c.get("durci").and_then(Value::as_bool).unwrap_or(false))
                    .map(|a| champ(a, "moniteur"));
                let regle = texte(durci_par.unwrap_or(champ(c, "regle")), 40);
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
                // Bilans de la passerelle et du proxy LLM : coupure, refus, ou réponse du modèle.
                let issue = if c.get("coupe_plafond").and_then(Value::as_bool).unwrap_or(false) {
                    "COUPÉ (plafond d'envoi)".to_string()
                } else if !champ(c, "refus").is_empty() {
                    format!("REFUSÉ ({})", texte(champ(c, "refus"), 30))
                } else if let Some(s) = c.get("statut").and_then(Value::as_u64) {
                    format!("réponse {s}")
                } else if outil == "Modele" {
                    "envoyé au modèle".to_string()
                } else {
                    "exécuté".to_string()
                };
                // Outils demandés par le modèle : `outils` (nom et identifiant d'appel), ou
                // `outils_demandes` (noms seuls, journaux antérieurs).
                let outils: Vec<&str> = c
                    .get("outils")
                    .or_else(|| c.get("outils_demandes"))
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|o| o.get("nom").unwrap_or(o).as_str()).collect())
                    .unwrap_or_default();
                let demandes = if outils.is_empty() { String::new() } else { format!(" — outils demandés : {}", texte(&outils.join(", "), 60)) };
                l.push(format!("    O-->>A: {n}. {issue} : {outil} {}{demandes}", designation(c)));
            }
            "administration" => {
                let action = champ(c, "action");
                if action == "degel" {
                    gelee = false;
                }
                // Qui a agi : un compte, ou les deux comptes d'un dégel à quatre yeux.
                let qui = match (champ(c, "compte"), champ(c, "demandeur"), champ(c, "approbateur")) {
                    ("", "", _) => String::new(),
                    ("", d, a) => format!(" par {} et {}", texte(d, 30), texte(a, 30)),
                    (compte, _, _) => format!(" par {}", texte(compte, 30)),
                };
                l.push(format!("    H->>S: {n}. administration : {}{qui}", texte(action, 20)));
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
        let d = std::env::temp_dir().join(format!("aplomb-mermaid-{nom}-{}", std::process::id()));
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
    fn cause_du_durcissement_affichee() {
        let d = std::env::temp_dir().join(format!("aplomb-mermaid-durci-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut j = Journal::ouvrir(&d).unwrap();
        let c = json!({"outil": "WebFetch", "verbe": "reseau", "ressource": "x.org", "verdict": "gel",
            "regle": "reseau-non-autorise", "durci": true, "avis": [{"moniteur": "borne-refus"}]});
        j.ajouter("s", "decision", c, 1).unwrap();
        let m = sequence(&lire_session(&j.chemin("s")).unwrap(), 200);
        assert!(m.contains("S--xA: GEL (borne-refus)"), "{m}");
    }

    #[test]
    fn contenus_scelles_puis_effaces() {
        use crate::confidentiel::minimiser;
        let base = std::env::temp_dir().join(format!("aplomb-mermaid-scelle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mut j = Journal::ouvrir(base.join("journal")).unwrap();
        let coffre = Coffre::ouvrir(base.join("cles")).unwrap();
        let cle = coffre.cle_ou_creer("s").unwrap();
        let d = json!({"outil": "Read", "verbe": "lire", "ressource": "/depot/secret.py", "verdict": "allow",
            "regle": "lire", "contexte": {"chemin": "/depot/secret.py", "dans_depot": true}});
        j.ajouter("s", "decision", minimiser(&cle, "s", &d), 1).unwrap();
        let entrees = lire_session(&j.chemin("s")).unwrap();

        // Sans clé : aucune ressource en clair, une référence à la place.
        let m = sequence(&ouvrir_contenus(entrees.clone(), None), 200);
        assert!(!m.contains("secret.py") && m.contains("réf ") && m.contains("contenus scellés"), "{m}");
        // Avec la clé : en clair.
        let m = sequence(&ouvrir_contenus(entrees.clone(), Some(&coffre)), 200);
        assert!(m.contains("/depot/secret.py") && !m.contains("contenus scellés"), "{m}");
        // Clé détruite : la chaîne reste vérifiable, le contenu est perdu.
        assert!(coffre.effacer("s").unwrap());
        let entrees = lire_session(&j.chemin("s")).unwrap();
        let m = sequence(&ouvrir_contenus(entrees, Some(&coffre)), 200);
        assert!(!m.contains("secret.py") && m.contains("contenus effacés"), "{m}");
    }

    #[test]
    fn journal_altere_refuse() {
        let d = std::env::temp_dir().join(format!("aplomb-mermaid-alt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut j = Journal::ouvrir(&d).unwrap();
        j.ajouter("s", "decision", json!({"verdict": "deny"}), 1).unwrap();
        let f = j.chemin("s");
        std::fs::write(&f, std::fs::read_to_string(&f).unwrap().replace("deny", "allow")).unwrap();
        assert!(lire_session(&f).is_err());
    }
}
