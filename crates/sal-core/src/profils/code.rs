//! **Profil C — agent de code** (Claude Code).
//!
//! Traduit les outils de Claude Code en verbes du profil et calcule, pour la politique,
//! des attributs **toujours présents** :
//!
//! | Attribut | Sens |
//! |---|---|
//! | `outil`, `commande`, `chemin`, `domaine` | Données de l'action (chaînes, éventuellement vides) |
//! | `dans_depot`, `cwd_dans_depot` | Chemin et répertoire courant sous la racine du mandat |
//! | `chemin_sensible`, `commande_lit_secret` | Secrets : `.env`, clés, `.ssh`, `.aws`… |
//! | `reseau`, `domaine_autorise` | Accès réseau, et tous les domaines vus sont autorisés |
//! | `pousse_branche_protegee` | `git push` vers une branche protégée ou en force |
//! | `suppression_recursive`, `suppression_hors_depot` | `rm -r`, et cible hors du dépôt |
//! | `contourne_controles` | `--no-verify`, désactivation des hooks git |
//! | `desactive_tests` | Contenu écrit qui désactive des tests (`skip`, `#[ignore]`…) |
//! | `installe_dependance` | Installation de paquet |
//! | `touche_supervision` | Agit sur sa propre supervision (config `.claude`, API d'administration, arrêt de `sal`) |
//!
//! Heuristiques volontairement simples (MVP) : elles relèvent un palier ou refusent ;
//! elles ne servent jamais à autoriser. Le confinement réel arrive au niveau 3 (J3).
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::action::{Action, EvenementOutil};
use crate::mandat::Mandat;

/// Verbe du profil pour un outil Claude Code.
pub fn verbe(outil: &str) -> &'static str {
    match outil {
        "Bash" | "BashOutput" | "KillShell" => "executer",
        "Read" | "Glob" | "Grep" | "LS" | "NotebookRead" => "lire",
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => "ecrire",
        "WebFetch" | "WebSearch" => "reseau",
        "Task" | "Agent" => "deleguer",
        "TodoWrite" | "TodoRead" | "ExitPlanMode" | "EnterPlanMode" | "ToolSearch" | "Skill" => "interne",
        o if o.starts_with("mcp__") => "outil_mcp",
        _ => "autre",
    }
}

/// Normalisation lexicale (`.` et `..`), sans accès disque.
fn normaliser_chemin(base: &Path, chemin: &str) -> PathBuf {
    let brut = if chemin.starts_with('~') {
        PathBuf::from(chemin) // laissé tel quel : jamais sous la racine du dépôt
    } else {
        base.join(chemin)
    };
    let mut sortie = PathBuf::new();
    for c in brut.components() {
        match c {
            Component::ParentDir => {
                sortie.pop();
            }
            Component::CurDir => {}
            autre => sortie.push(autre.as_os_str()),
        }
    }
    sortie
}

fn sous(chemin: &Path, racine: &Path) -> bool {
    chemin.starts_with(racine)
}

const MOTIFS_SENSIBLES: &[&str] = &[
    ".env", "id_rsa", "id_ed25519", ".ssh/", ".aws/", ".gnupg", "credentials", ".pem", ".p12",
    ".key", ".netrc", ".npmrc", ".pypirc", "secrets",
];

fn est_sensible(texte: &str) -> bool {
    let t = texte.to_ascii_lowercase();
    MOTIFS_SENSIBLES.iter().any(|m| t.contains(m))
}

const MARQUEURS_SKIP: &[&str] = &[
    "#[ignore]", "@pytest.mark.skip", "@unittest.skip", "it.skip(", "describe.skip(", "test.skip(",
    "xit(", "xdescribe(", "t.skip(", "@disabled", "@ignore",
];

const INSTALLATIONS: &[&str] = &[
    "npm install", "npm i ", "yarn add", "pnpm add", "pip install", "pip3 install", "poetry add",
    "uv add", "uv pip install", "cargo add", "cargo install", "go get", "go install", "brew install",
    "gem install", "apt install", "apt-get install",
];

const OUTILS_RESEAU: &[&str] = &["curl ", "wget ", "nc ", "ncat ", "ssh ", "scp ", "rsync ", "ftp ", "telnet "];

/// Domaines extraits des URL `http(s)://` présentes dans un texte.
fn domaines(texte: &str) -> Vec<String> {
    let mut res = Vec::new();
    for (i, _) in texte.match_indices("://") {
        let avant = &texte[..i];
        if !(avant.ends_with("http") || avant.ends_with("https")) {
            continue;
        }
        let reste = &texte[i + 3..];
        let fin = reste
            .find(|c: char| c == '/' || c == ':' || c == '?' || c == '#' || c == '"' || c == '\'' || c.is_whitespace())
            .unwrap_or(reste.len());
        let hote = reste[..fin].rsplit('@').next().unwrap_or("").to_ascii_lowercase();
        if !hote.is_empty() {
            res.push(hote);
        }
    }
    res
}

fn domaine_autorise(domaine: &str, autorises: &[String]) -> bool {
    autorises.iter().any(|a| domaine == a || domaine.ends_with(&format!(".{a}")))
}

/// Mots de la commande (découpage grossier, suffisant pour les heuristiques).
fn mots(commande: &str) -> Vec<&str> {
    commande.split(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '|').filter(|m| !m.is_empty()).collect()
}

fn pousse_branche_protegee(commande: &str, protegees: &[String]) -> bool {
    if !commande.contains("git push") && !commande.contains("git -c") {
        return false;
    }
    let m = mots(commande);
    let force = m.iter().any(|w| *w == "--force" || *w == "-f" || w.starts_with("--force-with-lease") || w.starts_with('+'));
    let cible = m.iter().any(|w| {
        let w = w.trim_start_matches('+');
        protegees.iter().any(|b| w == b || w.ends_with(&format!(":{b}")) || w == &format!("HEAD:{b}"))
    });
    commande.contains("git push") && (force || cible)
}

/// Cibles d'un `rm -r` / `rm -rf`.
fn cibles_suppression_recursive<'a>(commande: &'a str) -> Option<Vec<&'a str>> {
    let m = mots(commande);
    let mut res = None;
    for (i, w) in m.iter().enumerate() {
        if *w != "rm" {
            continue;
        }
        let args = &m[i + 1..];
        let recursive = args.iter().take_while(|a| a.starts_with('-')).any(|a| {
            *a == "--recursive" || (a.starts_with('-') && !a.starts_with("--") && (a.contains('r') || a.contains('R')))
        });
        if recursive {
            res.get_or_insert_with(Vec::new)
                .extend(args.iter().filter(|a| !a.starts_with('-')).copied());
        }
    }
    res
}

fn touche_supervision(texte: &str) -> bool {
    let t = texte.to_ascii_lowercase();
    t.contains(".claude/settings")
        || t.contains(":7701")
        || t.contains("/admin/")
        || t.contains("pkill sal")
        || t.contains("killall sal")
        || t.contains("sal serve")
        || t.contains("disableallhooks")
}

fn texte_ecrit(entree: &Value) -> String {
    let mut s = String::new();
    for cle in ["content", "new_string", "new_source"] {
        if let Some(v) = entree.get(cle).and_then(Value::as_str) {
            s.push_str(v);
            s.push('\n');
        }
    }
    if let Some(edits) = entree.get("edits").and_then(Value::as_array) {
        for e in edits {
            if let Some(v) = e.get("new_string").and_then(Value::as_str) {
                s.push_str(v);
                s.push('\n');
            }
        }
    }
    s
}

fn chaine(entree: &Value, cles: &[&str]) -> String {
    cles.iter()
        .find_map(|c| entree.get(*c).and_then(Value::as_str))
        .unwrap_or("")
        .to_string()
}

/// Traduit un événement Claude Code en action normalisée pour le mandat donné.
pub fn normaliser(evt: &EvenementOutil, mandat: &Mandat) -> Action {
    let racine = normaliser_chemin(Path::new("/"), &mandat.perimetre.racine);
    let cwd = normaliser_chemin(Path::new("/"), &evt.cwd);
    let verbe = verbe(&evt.outil);
    let e = &evt.entree;

    let commande = chaine(e, &["command"]);
    let chemin_brut = chaine(e, &["file_path", "notebook_path", "path"]);
    let chemin = match (&evt.chemin_reel, chemin_brut.is_empty()) {
        (Some(reel), _) => normaliser_chemin(&cwd, reel),
        (None, false) => normaliser_chemin(&cwd, &chemin_brut),
        // Glob/Grep sans chemin : le répertoire courant.
        (None, true) if verbe == "lire" => cwd.clone(),
        _ => PathBuf::new(),
    };
    let chemin_txt = chemin.to_string_lossy().to_string();
    let dans_depot = !chemin_txt.is_empty() && sous(&chemin, &racine);

    let url = chaine(e, &["url"]);
    let mut doms = domaines(&commande);
    doms.extend(domaines(&url));
    let recherche_web = evt.outil == "WebSearch";
    let reseau = verbe == "reseau"
        || !doms.is_empty()
        || OUTILS_RESEAU.iter().any(|o| commande.contains(o) || commande.starts_with(o.trim_end()));
    let autorise = if recherche_web {
        false
    } else {
        !doms.is_empty() && doms.iter().all(|d| domaine_autorise(d, &mandat.perimetre.domaines_autorises))
    };
    let domaine = doms.first().cloned().unwrap_or_default();

    let cibles_rm = cibles_suppression_recursive(&commande);
    let suppression_hors_depot = cibles_rm.as_ref().is_some_and(|cibles| {
        cibles.is_empty()
            || cibles.iter().any(|c| {
                c.starts_with('~') || c.starts_with('$') || !sous(&normaliser_chemin(&cwd, c), &racine)
            })
    });

    let ecrit = texte_ecrit(e);
    let desactive_tests = MARQUEURS_SKIP.iter().any(|m| ecrit.contains(m));
    let contourne_controles = commande.contains("--no-verify")
        || commande.contains("core.hooksPath")
        || commande.contains("HUSKY=0")
        || commande.contains("SKIP=")
        || mots(&commande).windows(2).any(|w| w[0] == "commit" && w[1] == "-n");

    let mut contexte = Map::new();
    let mut mettre = |k: &str, v: Value| {
        contexte.insert(k.to_string(), v);
    };
    mettre("outil", json!(evt.outil));
    mettre("commande", json!(commande));
    mettre("chemin", json!(chemin_txt));
    mettre("domaine", json!(domaine));
    mettre("dans_depot", json!(dans_depot));
    mettre("cwd_dans_depot", json!(sous(&cwd, &racine)));
    mettre("chemin_sensible", json!(est_sensible(&chemin_txt)));
    mettre("commande_lit_secret", json!(est_sensible(&commande)));
    mettre("reseau", json!(reseau));
    mettre("domaine_autorise", json!(autorise));
    mettre("pousse_branche_protegee", json!(pousse_branche_protegee(&commande, &mandat.perimetre.branches_protegees)));
    mettre("suppression_recursive", json!(cibles_rm.is_some()));
    mettre("suppression_hors_depot", json!(suppression_hors_depot));
    mettre("contourne_controles", json!(contourne_controles));
    mettre("desactive_tests", json!(desactive_tests));
    mettre("installe_dependance", json!(INSTALLATIONS.iter().any(|i| commande.contains(i))));
    mettre("touche_supervision", json!(touche_supervision(&commande) || touche_supervision(&chemin_txt)));

    let ressource = if !chemin_txt.is_empty() && verbe != "executer" {
        chemin_txt
    } else if !domaine.is_empty() {
        domaine
    } else if !commande.is_empty() {
        commande.chars().take(200).collect()
    } else {
        evt.outil.clone()
    };

    Action {
        session: evt.session.clone(),
        agent: evt.agent.clone(),
        verbe: verbe.to_string(),
        ressource,
        contexte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Phase;
    use crate::mandat::{FichiersPolitique, Perimetre};

    fn mandat() -> Mandat {
        Mandat {
            id: "m".into(),
            version: 1,
            profil: "code".into(),
            agent: "claude-code".into(),
            intention: "i".into(),
            perimetre: Perimetre {
                racine: "/depot".into(),
                domaines_autorises: vec!["crates.io".into(), "pypi.org".into()],
                branches_protegees: vec!["main".into(), "master".into()],
            },
            politique: FichiersPolitique {
                regles: String::new(),
                revue: String::new(),
                regles_sha256: String::new(),
                revue_sha256: String::new(),
            },
            signature: None,
        }
    }

    fn evt(outil: &str, entree: Value) -> EvenementOutil {
        EvenementOutil {
            session: "s".into(),
            agent: "claude-code".into(),
            mode: "test".into(),
            cwd: "/depot".into(),
            outil: outil.into(),
            entree,
            phase: Phase::Avant,
            chemin_reel: None,
        }
    }

    fn ctx(outil: &str, entree: Value) -> Map<String, Value> {
        normaliser(&evt(outil, entree), &mandat()).contexte
    }

    fn b(c: &Map<String, Value>, k: &str) -> bool {
        c[k].as_bool().unwrap()
    }

    #[test]
    fn chemin_relatif_et_remontee() {
        assert!(b(&ctx("Read", json!({"file_path": "src/a.rs"})), "dans_depot"));
        assert!(!b(&ctx("Read", json!({"file_path": "../etc/passwd"})), "dans_depot"));
        assert!(!b(&ctx("Write", json!({"file_path": "/depot/../x"})), "dans_depot"));
    }

    #[test]
    fn secrets() {
        assert!(b(&ctx("Read", json!({"file_path": ".env"})), "chemin_sensible"));
        assert!(b(&ctx("Bash", json!({"command": "cat ~/.ssh/id_rsa"})), "commande_lit_secret"));
    }

    #[test]
    fn reseau_et_domaines() {
        let c = ctx("Bash", json!({"command": "curl https://evil.example.com/x"}));
        assert!(b(&c, "reseau"));
        assert!(!b(&c, "domaine_autorise"));
        let c = ctx("WebFetch", json!({"url": "https://index.crates.io/config.json"}));
        assert!(b(&c, "domaine_autorise"));
        let c = ctx("Bash", json!({"command": "nc 10.0.0.1 4444"}));
        assert!(b(&c, "reseau") && !b(&c, "domaine_autorise"));
    }

    #[test]
    fn push_protege() {
        assert!(b(&ctx("Bash", json!({"command": "git push origin main"})), "pousse_branche_protegee"));
        assert!(b(&ctx("Bash", json!({"command": "git push -f origin feature"})), "pousse_branche_protegee"));
        assert!(!b(&ctx("Bash", json!({"command": "git push origin feature"})), "pousse_branche_protegee"));
    }

    #[test]
    fn suppression() {
        let c = ctx("Bash", json!({"command": "rm -rf target"}));
        assert!(b(&c, "suppression_recursive") && !b(&c, "suppression_hors_depot"));
        assert!(b(&ctx("Bash", json!({"command": "rm -rf ~/Documents"})), "suppression_hors_depot"));
        assert!(b(&ctx("Bash", json!({"command": "rm -r ../autre"})), "suppression_hors_depot"));
        assert!(!b(&ctx("Bash", json!({"command": "rm fichier.txt"})), "suppression_recursive"));
    }

    #[test]
    fn controles_et_tests() {
        assert!(b(&ctx("Bash", json!({"command": "git commit -n -m x"})), "contourne_controles"));
        assert!(b(&ctx("Bash", json!({"command": "git commit --no-verify -m x"})), "contourne_controles"));
        assert!(b(&ctx("Edit", json!({"file_path": "t.py", "new_string": "@pytest.mark.skip\ndef test_a(): pass"})), "desactive_tests"));
        assert!(b(&ctx("Bash", json!({"command": "pip install requests"})), "installe_dependance"));
    }

    #[test]
    fn supervision() {
        assert!(b(&ctx("Edit", json!({"file_path": ".claude/settings.json", "new_string": "{}"})), "touche_supervision"));
        assert!(b(&ctx("Bash", json!({"command": "curl -X POST http://127.0.0.1:7701/admin/degel"})), "touche_supervision"));
        assert!(!b(&ctx("Read", json!({"file_path": "src/a.rs"})), "touche_supervision"));
    }

    #[test]
    fn attributs_toujours_presents() {
        let attendus = [
            "outil", "commande", "chemin", "domaine", "dans_depot", "cwd_dans_depot", "chemin_sensible",
            "commande_lit_secret", "reseau", "domaine_autorise", "pousse_branche_protegee",
            "suppression_recursive", "suppression_hors_depot", "contourne_controles", "desactive_tests",
            "installe_dependance", "touche_supervision",
        ];
        for outil in ["Bash", "Read", "Edit", "WebFetch", "Task", "mcp__x__y", "Inconnu"] {
            let c = ctx(outil, json!({}));
            for a in attendus {
                assert!(c.contains_key(a), "{outil} : attribut {a} manquant");
            }
        }
    }
}
