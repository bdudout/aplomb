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

fn lire_borne(p: &Path) -> Option<String> {
    let lisible = std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() <= MAX_SCRIPT);
    lisible.then(|| std::fs::read_to_string(p).ok()).flatten()
}

/// Recettes d'une cible de Makefile, et de ses prérequis (première cible si aucune).
fn recettes_make(makefile: &str, cibles: &[String]) -> String {
    let regles: Vec<(String, Vec<String>, Vec<String>)> = {
        let mut v: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
        for ligne in makefile.lines() {
            if let Some(r) = ligne.strip_prefix('\t') {
                if let Some(d) = v.last_mut() {
                    d.2.push(r.to_string());
                }
            } else if let Some((tete, prerequis)) = ligne.split_once(':').filter(|(t, _)| !t.trim().is_empty() && !t.contains('=') && !ligne.contains(":=")) {
                for nom in tete.split_whitespace() {
                    v.push((nom.to_string(), prerequis.split_whitespace().map(String::from).collect(), Vec::new()));
                }
            }
        }
        v
    };
    let mut a_voir: Vec<String> = if cibles.is_empty() {
        regles.iter().find(|r| !r.0.starts_with('.')).map(|r| vec![r.0.clone()]).unwrap_or_default()
    } else {
        cibles.to_vec()
    };
    let (mut vues, mut sortie) = (Vec::new(), String::new());
    while let Some(c) = a_voir.pop() {
        if vues.contains(&c) || vues.len() > 50 {
            continue;
        }
        vues.push(c.clone());
        for (_, prerequis, recette) in regles.iter().filter(|r| r.0 == c) {
            a_voir.extend(prerequis.iter().cloned());
            for l in recette {
                sortie.push_str(l.trim_start_matches(['@', '-', '+']));
                sortie.push('\n');
            }
        }
    }
    sortie
}

/// Script `package.json` lancé par `npm run x`, `npm test`, `yarn x`, `pnpm x`, `bun run x`
/// (avec ses `pre` et `post`).
fn script_paquet(cwd: &str, programme: &str, args: &[String]) -> Option<String> {
    if !matches!(programme, "npm" | "yarn" | "pnpm" | "bun") {
        return None;
    }
    let mots: Vec<&str> = args.iter().map(String::as_str).filter(|a| !a.starts_with('-')).collect();
    let nom = match mots.as_slice() {
        ["run" | "run-script", nom, ..] => *nom,
        ["test" | "start" | "stop" | "restart", ..] => mots[0],
        [nom, ..] if programme != "npm" && !matches!(*nom, "add" | "install" | "remove" | "exec" | "dlx" | "x") => *nom,
        _ => return None,
    };
    let paquet: Value = serde_json::from_str(&lire_borne(&Path::new(cwd).join("package.json"))?).ok()?;
    let scripts = paquet.get("scripts")?;
    let texte: Vec<&str> = [format!("pre{nom}"), nom.to_string(), format!("post{nom}")]
        .iter()
        .filter_map(|n| scripts.get(n).and_then(Value::as_str))
        .collect();
    (!texte.is_empty()).then(|| texte.join("\n"))
}

/// Ce que la commande exécute réellement (ressource réelle, EF-B4), pour que la décision
/// porte sur l'effet et pas sur le nom :
/// - les scripts locaux lancés (`python3 x.py`, `sh x.sh`, `./x`, `source x`, `. x`) ;
/// - la cible d'un lien symbolique lancé (`./efface` → `rm`), avec ses arguments ;
/// - la recette d'une cible `make` et le script `npm run` / `yarn` / `pnpm`.
fn contenu_execute(cwd: &str, commande: &str) -> Option<String> {
    use aplomb_core::profils::code;
    let mut contenu = String::new();
    let mut ajouter = |t: &str| {
        contenu.push_str(t);
        contenu.push('\n');
    };
    for script in code::scripts_executes(commande) {
        if let Some(texte) = lire_borne(&Path::new(cwd).join(&script)) {
            ajouter(&texte);
        }
    }
    for (programme, args) in code::commandes_lancees(commande) {
        if programme.contains('/') {
            let p = Path::new(cwd).join(&programme);
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
                if let Ok(cible) = std::fs::canonicalize(&p) {
                    let nom = cible.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    ajouter(&format!("{nom} {}", args.join(" ")));
                }
            }
        }
        if programme == "make" || programme == "gmake" {
            let mut fichier = None;
            let mut cibles = Vec::new();
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "-f" | "--file" | "-C" => {
                        if args[i].as_str() != "-C" {
                            fichier = args.get(i + 1).cloned();
                        }
                        i += 2;
                        continue;
                    }
                    a if a.starts_with('-') || a.contains('=') => {}
                    a => cibles.push(a.to_string()),
                }
                i += 1;
            }
            let noms = fichier.map(|f| vec![f]).unwrap_or_else(|| vec!["GNUmakefile".into(), "makefile".into(), "Makefile".into()]);
            if let Some(texte) = noms.iter().find_map(|n| lire_borne(&Path::new(cwd).join(n))) {
                ajouter(&recettes_make(&texte, &cibles));
            }
        }
        if let Some(texte) = script_paquet(cwd, &programme, &args) {
            ajouter(&texte);
        }
    }
    (!contenu.is_empty()).then_some(contenu)
}

use aplomb_core::adaptateurs::{self, AgentHook, Reponse};

fn sortie_pre(agent: AgentHook, evenement: &str, r: Reponse, motif: &str) -> ExitCode {
    if let Some(s) = adaptateurs::sortie(agent, evenement, r, motif) {
        println!("{s}");
    }
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

/// Verdict le plus dur de plusieurs (correctif sur plusieurs fichiers).
fn rang(v: &str) -> u8 {
    match v {
        "allow" => 0,
        "review" => 1,
        "deny" => 2,
        _ => 3,
    }
}

pub fn executer(perimetre: &[PathBuf], cle_serveur: Option<&Path>, branchement: Option<&str>, agent: &str) -> ExitCode {
    let agent = match AgentHook::depuis(agent) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("aplomb hook : {e}");
            return ExitCode::from(2);
        }
    };
    let branchement = branchement.unwrap_or(agent.branchement()).to_string();
    let refuser = |motif: &str| sortie_pre(agent, "", Reponse::Refuser, motif);
    let cle_serveur = match cle_serveur.map(|p| std::fs::read_to_string(p).map_err(|e| e.to_string())) {
        None => None,
        Some(Ok(t)) => match aplomb_core::mandat::cle_publique(&t) {
            Ok(c) => Some(c),
            Err(_) => return refuser("clé publique du superviseur illisible (fail-closed)"),
        },
        Some(Err(_)) => return refuser("clé publique du superviseur introuvable (fail-closed)"),
    };
    let mut brut = String::new();
    if std::io::stdin().read_to_string(&mut brut).is_err() {
        return refuser("événement illisible (fail-closed)");
    }
    let evt: Value = match serde_json::from_str(&brut) {
        Ok(v) => v,
        Err(_) => return refuser("événement JSON invalide (fail-closed)"),
    };
    let appels = match adaptateurs::normaliser(agent, &evt) {
        Ok(a) => a,
        Err(e) => return refuser(&format!("{e} (fail-closed)")),
    };
    let Some(premier) = appels.first() else {
        // Événement sans action à décider (début de session…).
        return ExitCode::SUCCESS;
    };
    let evenement = premier.evenement.clone();
    let refuser = |motif: &str| sortie_pre(agent, &evenement, Reponse::Refuser, motif);
    if !supervise(&premier.cwd, perimetre) {
        // Hors des dossiers supervisés : aucune décision, l'agent décide seul.
        return sortie_pre(agent, &evenement, Reponse::Rien, "");
    }
    let base = std::env::var("APLOMB_URL").unwrap_or_else(|_| URL_DEFAUT.into());
    // Juge compris (6 s au plus) ; sous les 10 s que Claude Code laisse au hook.
    let http = ureq::AgentBuilder::new().timeout(Duration::from_secs(8)).build();
    let nom_agent = std::env::var("APLOMB_AGENT").unwrap_or_else(|_| agent.nom().into());
    let mut pire: Option<(String, String)> = None;
    for a in &appels {
        let chemin = ["file_path", "notebook_path", "path"].iter().find_map(|k| a.entree.get(*k).and_then(Value::as_str)).unwrap_or("");
        let commande = a.entree.get("command").and_then(Value::as_str).unwrap_or("");
        let nonce = nonce();
        let corps = json!({
            "session": a.session,
            "agent": nom_agent,
            "mode": branchement,
            "cwd": a.cwd,
            "outil": a.outil,
            "entree": a.entree,
            "phase": a.phase,
            "chemin_reel": chemin_reel(&a.cwd, chemin),
            "contenu_execute": contenu_execute(&a.cwd, commande),
            "nonce": nonce,
            "appel": a.appel,
            "delegation": a.delegation,
        });
        if a.phase == "apres" {
            // Observation : best effort, ne bloque jamais l'agent après coup.
            let _ = http.post(&format!("{base}/v1/observe")).send_json(corps);
            continue;
        }
        let reponse: Value = match http.post(&format!("{base}/v1/decide")).send_json(corps) {
            Ok(r) => match r.into_json() {
                Ok(v) => v,
                Err(_) => return refuser("réponse du superviseur invalide (fail-closed)"),
            },
            Err(e) => return refuser(&format!("superviseur injoignable ({e}) — fail-closed")),
        };
        let champ = |k: &str| reponse.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        if let Some(cle) = &cle_serveur {
            if !aplomb_core::reponse::verifier(cle, &champ("signature"), &nonce, &a.session, &champ("verdict"), &champ("regle")) {
                return refuser("réponse non signée par le superviseur attendu (usurpation possible) — fail-closed");
            }
        }
        let verdict = champ("verdict");
        if !matches!(verdict.as_str(), "allow" | "review" | "deny" | "gel") {
            return refuser("verdict inconnu (fail-closed)");
        }
        if pire.as_ref().is_none_or(|(v, _)| rang(&verdict) > rang(v)) {
            pire = Some((verdict, champ("motif")));
        }
    }
    match pire {
        None => ExitCode::SUCCESS,
        Some((v, motif)) => match v.as_str() {
            "allow" => sortie_pre(agent, &evenement, Reponse::Rien, &motif),
            "review" => sortie_pre(agent, &evenement, Reponse::Demander, &motif),
            "deny" => sortie_pre(agent, &evenement, Reponse::Refuser, &motif),
            _ => sortie_pre(agent, &evenement, Reponse::Refuser, &format!("SESSION GELÉE — {motif}")),
        },
    }
}
