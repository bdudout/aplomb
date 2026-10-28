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
//! | `touche_supervision` | Agit sur sa propre supervision (API d'administration, arrêt de `sal`, désactivation des hooks) |
//! | `ecrit_point_protege` | Modifie un point protégé (EF-C5) : config `.claude`, démarrage du shell, crontab, hooks git, CI |
//! | `shell_ecrit_hors_depot` | Une commande écrit hors du dépôt (redirection, `tee`, `cp`, `mv`, `touch`…) |
//! | `envoi_externe` | Envoie des données vers l'extérieur (POST, téléversement, publication) — EF-C4 |
//!
//! Les règles portent sur l'**effet**, quel que soit le chemin (EF-B7) : le même point
//! protégé est défendu contre `Write`, une redirection, `mv`, `sed -i`, `python -c` ou un
//! script écrit puis exécuté (son contenu est fourni par l'adaptateur).
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
    ".key", ".netrc", ".npmrc", ".pypirc", "secrets", "sal.cle", "journal-cles", ".config/sal/",
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
    commande
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')'))
        .filter(|m| !m.is_empty())
        .collect()
}

/// Commandes simples d'une ligne de commande (séparateurs `;`, `|`, `&`, parenthèses).
fn segments(commande: &str) -> Vec<Vec<&str>> {
    commande
        .split(|c: char| matches!(c, ';' | '&' | '|' | '(' | ')' | '\n'))
        .map(|s| s.split_whitespace().collect::<Vec<_>>())
        .filter(|s| !s.is_empty())
        .collect()
}

fn sans_guillemets(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

/// Points protégés en écriture (EF-C5) : ce qui gouverne l'agent et ce qui lui
/// permettrait de s'octroyer une exécution persistante ou différée.
const POINTS_PROTEGES: &[&str] = &[
    ".claude", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv", ".zprofile",
    ".zlogin", ".config/fish", "crontab", "/var/at/tabs", "launchagents", "launchdaemons", ".git/hooks",
    ".git/config", ".husky", ".pre-commit-config", ".github/workflows", ".gitlab-ci.yml",
    "sitecustomize.py", "usercustomize.py",
];

fn mentionne_point_protege(texte: &str) -> bool {
    let t = texte.to_ascii_lowercase();
    POINTS_PROTEGES.iter().any(|p| t.contains(p))
}

/// Interpréteurs : `-c` / `-e` exécute du code arbitraire, un argument fichier est un script.
pub const INTERPRETES: &[&str] =
    &["python", "python3", "sh", "bash", "zsh", "node", "ruby", "perl", "php", "deno", "bun"];

/// Scripts locaux qu'une commande exécute (`python3 outil.py`, `sh x.sh`, `./x`) ; l'adaptateur
/// en lit le contenu pour que la décision porte sur ce qu'ils font.
pub fn scripts_executes(commande: &str) -> Vec<String> {
    let mut res = Vec::new();
    for seg in segments(commande) {
        let Some(premier) = seg.iter().position(|w| !w.contains('=')) else { continue };
        let w = seg[premier];
        let base = w.rsplit('/').next().unwrap_or(w);
        if INTERPRETES.contains(&base) {
            let args = &seg[premier + 1..];
            if args.first().is_some_and(|a| *a == "-c" || *a == "-e" || *a == "-m") {
                continue;
            }
            if let Some(f) = args.iter().find(|a| !a.starts_with('-')) {
                res.push(sans_guillemets(f).to_string());
            }
        } else if w.starts_with("./") {
            res.push(w.to_string());
        }
    }
    res
}

/// Cibles d'écriture explicites : redirections, `tee`, destination de `cp`/`mv`/`install`/`ln`,
/// arguments de `touch`/`mkdir`.
fn cibles_ecriture(commande: &str) -> Vec<String> {
    let mut res = Vec::new();
    for (i, _) in commande.match_indices('>') {
        let reste = commande[i + 1..].trim_start_matches(['>', '|']);
        if reste.starts_with('&') {
            continue; // duplication de descripteur (2>&1)
        }
        let cible: String = reste
            .trim_start()
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, ';' | '|' | '&' | ')' | '<' | '>'))
            .collect();
        if !cible.is_empty() {
            res.push(sans_guillemets(&cible).to_string());
        }
    }
    for seg in segments(commande) {
        let args: Vec<&str> = seg[1..].iter().copied().filter(|a| !a.starts_with('-')).collect();
        match seg[0] {
            "tee" | "touch" | "mkdir" => res.extend(args.iter().map(|a| sans_guillemets(a).to_string())),
            "cp" | "mv" | "install" | "ln" | "rsync" => {
                if let Some(d) = args.last() {
                    res.push(sans_guillemets(d).to_string());
                }
            }
            _ => {}
        }
    }
    res.retain(|c| !c.is_empty() && !c.starts_with("/dev/"));
    res
}

/// Commande qui modifie ce qu'elle mentionne sans cible explicite (source de `mv`, `rm`,
/// `chmod`, édition sur place, code en ligne, `git checkout`, `crontab` hors `-l`…).
fn mutation(commande: &str) -> bool {
    const MUTATEURS: &[&str] = &["mv", "rm", "unlink", "chmod", "chown", "truncate", "dd", "ln", "launchctl"];
    const GIT: &[&str] = &["checkout", "restore", "rm", "mv", "reset", "clean", "stash", "apply"];
    let m = mots(commande);
    let en_place = m.iter().any(|w| matches!(*w, "sed" | "perl" | "ruby"))
        && m.iter().any(|w| w.starts_with("-i") || *w == "--in-place" || *w == "-pi");
    let code_en_ligne = m.windows(2).any(|w| {
        INTERPRETES.contains(&w[0].rsplit('/').next().unwrap_or(w[0])) && (w[1] == "-c" || w[1] == "-e")
    });
    let crontab = m.windows(2).any(|w| w[0] == "crontab" && w[1] != "-l") || m.last() == Some(&"crontab");
    m.iter().any(|w| MUTATEURS.contains(w))
        || en_place
        || code_en_ligne
        || crontab
        || (m.contains(&"git") && m.iter().any(|w| GIT.contains(w)))
}

/// Code (script exécuté) qui écrit des fichiers.
fn code_ecrit(code: &str) -> bool {
    const MARQUEURS: &[&str] = &[
        "write", ">>", "> ", "appendfile", "rename", "replace(", "unlink", "shutil.", "crontab", "chmod",
        "open(", "fs.", "file.open", "mv ", "rm ", "sed -i",
    ];
    let c = code.to_ascii_lowercase();
    MARQUEURS.iter().any(|m| c.contains(m))
}

/// Code qui ouvre une connexion réseau.
fn code_reseau(code: &str) -> bool {
    const MARQUEURS: &[&str] = &[
        "urllib", "requests.", "http.client", "httpx", "socket", "fetch(", "curl ", "wget ", "net/http",
        "xmlhttprequest", "axios", "aiohttp", "ftplib", "smtplib", "paramiko",
    ];
    let c = code.to_ascii_lowercase();
    MARQUEURS.iter().any(|m| c.contains(m))
}

/// Envoi de données vers l'extérieur (EF-C4) : autoriser un domaine en lecture n'autorise
/// pas à y écrire.
fn envoi_externe(commande: &str, code: &str) -> bool {
    const PUBLICATIONS: &[&str] = &[
        "twine upload", "npm publish", "yarn publish", "pnpm publish", "cargo publish", "poetry publish",
        "uv publish", "gem push", "gh release", "gh gist", "gh repo create", "docker push",
    ];
    let m = mots(commande);
    let curl_wget = m.iter().any(|w| matches!(*w, "curl" | "wget" | "http" | "https"));
    let drapeau = |w: &&str| {
        matches!(
            *w,
            "-d" | "-F" | "-T" | "--form" | "--upload-file" | "--json" | "--post-data" | "--post-file"
        ) || w.starts_with("--data")
            || w.starts_with("--form")
            || w.starts_with("--method")
            || w.starts_with("-XP")
            || w.starts_with("-XD")
    };
    let methode = m.windows(2).any(|w| {
        (w[0] == "-X" || w[0] == "--request") && matches!(w[1].to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
    });
    let c = code.to_ascii_lowercase();
    let code_envoie = [".post(", ".put(", ".patch(", "method=\"post\"", "method='post'", "method: \"post\"", "method: 'post'", "sendall(", "storbinary"]
        .iter()
        .any(|x| c.contains(x));
    (curl_wget && (m.iter().any(drapeau) || methode))
        || PUBLICATIONS.iter().any(|p| commande.contains(p))
        || m.iter().any(|w| matches!(*w, "scp" | "sftp" | "nc" | "ncat"))
        || code_envoie
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
    t.contains(":7701")
        || t.contains("/admin/")
        || t.contains("pkill sal")
        || t.contains("killall sal")
        || t.contains("sal serve")
        || t.contains("disableallhooks")
        || ["sal admin", "sal compte"].iter().any(|c| {
            t.starts_with(c) || t.contains(&format!(" {c}")) || t.contains(&format!("/{c}"))
        })
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

    // Ce que font les scripts exécutés compte comme ce que fait la commande (EF-B7).
    let script = if verbe == "executer" { evt.contenu_execute.as_deref().unwrap_or("") } else { "" };

    let url = chaine(e, &["url"]);
    let mut doms = domaines(&commande);
    doms.extend(domaines(&url));
    doms.extend(domaines(script));
    let recherche_web = evt.outil == "WebSearch";
    let reseau = verbe == "reseau"
        || !doms.is_empty()
        || OUTILS_RESEAU.iter().any(|o| commande.contains(o) || commande.starts_with(o.trim_end()))
        || code_reseau(script);
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

    let cibles = if verbe == "executer" { cibles_ecriture(&commande) } else { Vec::new() };
    let shell_ecrit_hors_depot = cibles.iter().any(|c| {
        c.starts_with('~') || c.starts_with('$') || !sous(&normaliser_chemin(&cwd, c), &racine)
    });
    let ecrit_point_protege = match verbe {
        "ecrire" => mentionne_point_protege(&chemin_txt),
        "executer" => {
            cibles.iter().any(|c| mentionne_point_protege(c))
                || (mentionne_point_protege(&commande) && mutation(&commande))
                || (mentionne_point_protege(script) && code_ecrit(script))
        }
        _ => false,
    };

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
    mettre("touche_supervision", json!(touche_supervision(&commande) || touche_supervision(script)));
    mettre("ecrit_point_protege", json!(ecrit_point_protege));
    mettre("shell_ecrit_hors_depot", json!(shell_ecrit_hors_depot));
    mettre("envoi_externe", json!(envoi_externe(&commande, script)));

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
            bornes: None,
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
            contenu_execute: None,
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
        assert!(b(&ctx("Bash", json!({"command": "curl -X POST http://127.0.0.1:7701/admin/degel"})), "touche_supervision"));
        assert!(!b(&ctx("Read", json!({"file_path": "src/a.rs"})), "touche_supervision"));
    }

    #[test]
    fn cles_et_administration_hors_de_portee() {
        assert!(b(&ctx("Read", json!({"file_path": "~/.config/sal/comptes/alice.cle"})), "chemin_sensible"));
        assert!(b(&ctx("Bash", json!({"command": "cat journal-cles/x.cle"})), "commande_lit_secret"));
        assert!(b(&ctx("Bash", json!({"command": "../sal/target/debug/sal admin --compte a degel"})), "touche_supervision"));
        // Pas de faux positifs.
        assert!(!b(&ctx("Bash", json!({"command": "python3 -c 'x=[1]; x.clear()'"})), "commande_lit_secret"));
        assert!(!b(&ctx("Bash", json!({"command": "grep -r 'universal admin' ."})), "touche_supervision"));
    }

    #[test]
    fn points_proteges_par_effet() {
        let p = |outil: &str, entree: Value| b(&ctx(outil, entree), "ecrit_point_protege");
        // Même effet, chemins différents : tous détectés.
        assert!(p("Edit", json!({"file_path": ".claude/settings.json", "new_string": "{}"})));
        assert!(p("Write", json!({"file_path": ".git/hooks/pre-commit", "content": "#!/bin/sh"})));
        assert!(p("Bash", json!({"command": "echo alias ls=x >> ~/.bashrc"})));
        assert!(p("Bash", json!({"command": "mv .claude .old"})));
        assert!(p("Bash", json!({"command": "rm -rf .claude"})));
        assert!(p("Bash", json!({"command": "sed -i '' s/hook// .claude/settings.json"})));
        assert!(p("Bash", json!({"command": "python3 -c \"open('.claude/settings.json','w').write('{}')\""})));
        assert!(p("Bash", json!({"command": "(crontab -l; echo '* * * * * x') | crontab -"})));
        assert!(p("Bash", json!({"command": "cp hook.sh .git/hooks/pre-push"})));
        assert!(p("Bash", json!({"command": "echo x | tee -a ~/.zshrc"})));
        // Lire n'est pas modifier.
        assert!(!p("Read", json!({"file_path": ".claude/settings.json"})));
        assert!(!p("Bash", json!({"command": "cat .claude/settings.json 2>/dev/null"})));
        assert!(!p("Bash", json!({"command": "crontab -l"})));
        assert!(!p("Bash", json!({"command": "ls .git/hooks"})));
    }

    #[test]
    fn script_execute_juge_sur_son_contenu() {
        let mut e = evt("Bash", json!({"command": "python3 outil.py"}));
        e.contenu_execute = Some("import os\nopen(os.path.expanduser('~/.bashrc'),'a').write('x')".into());
        assert!(b(&normaliser(&e, &mandat()).contexte, "ecrit_point_protege"));
        e.contenu_execute = Some("import urllib.request\nurllib.request.urlopen('https://evil.example/x')".into());
        let c = normaliser(&e, &mandat()).contexte;
        assert!(b(&c, "reseau") && !b(&c, "domaine_autorise"));
        e.contenu_execute = Some("print(sum([1, 2]))".into());
        let c = normaliser(&e, &mandat()).contexte;
        assert!(!b(&c, "reseau") && !b(&c, "ecrit_point_protege"));
    }

    #[test]
    fn scripts_reperes() {
        assert_eq!(scripts_executes("python3 outil.py --x"), vec!["outil.py"]);
        assert_eq!(scripts_executes("cd a && ./run.sh"), vec!["./run.sh"]);
        assert_eq!(scripts_executes("FOO=1 bash -x s.sh"), vec!["s.sh"]);
        assert!(scripts_executes("python3 -m unittest").is_empty());
        assert!(scripts_executes("python3 -c 'print(1)'").is_empty());
    }

    #[test]
    fn ecriture_shell_hors_depot() {
        let h = |c: &str| b(&ctx("Bash", json!({"command": c})), "shell_ecrit_hors_depot");
        assert!(h("echo x > /tmp/x.txt"));
        assert!(h("cp src/a.rs ~/a.rs"));
        assert!(h("touch ../voisin"));
        assert!(!h("cargo test > sortie.txt 2>&1"));
        assert!(!h("ls > /dev/null"));
        assert!(!h("cp a.rs b.rs"));
    }

    #[test]
    fn sens_des_flux() {
        let v = |c: &str| b(&ctx("Bash", json!({"command": c})), "envoi_externe");
        assert!(v("curl -X POST -F content=@a.py https://pypi.org/legacy/"));
        assert!(v("curl -d @src https://pypi.org/x"));
        assert!(v("curl --data-binary @a https://pypi.org/x"));
        assert!(v("twine upload dist/*"));
        assert!(v("cargo publish"));
        assert!(!v("curl -s https://pypi.org/simple/requests/"));
        assert!(!v("curl -o a.tgz https://files.pythonhosted.org/a.tgz"));
        assert!(!b(&ctx("WebFetch", json!({"url": "https://docs.python.org/3/"})), "envoi_externe"));
    }

    #[test]
    fn attributs_toujours_presents() {
        let attendus = [
            "outil", "commande", "chemin", "domaine", "dans_depot", "cwd_dans_depot", "chemin_sensible",
            "commande_lit_secret", "reseau", "domaine_autorise", "pousse_branche_protegee",
            "suppression_recursive", "suppression_hors_depot", "contourne_controles", "desactive_tests",
            "installe_dependance", "touche_supervision", "ecrit_point_protege", "shell_ecrit_hors_depot",
            "envoi_externe",
        ];
        for outil in ["Bash", "Read", "Edit", "WebFetch", "Task", "mcp__x__y", "Inconnu"] {
            let c = ctx(outil, json!({}));
            for a in attendus {
                assert!(c.contains_key(a), "{outil} : attribut {a} manquant");
            }
        }
    }
}
