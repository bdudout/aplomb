//! `aplomb agent` — comptes techniques des agents (`agents.yaml`) : la clé qu'un agent
//! présente au proxy LLM dit pour quel compte, et quel utilisateur, il consomme ; un quota
//! de jetons par jour peut s'y attacher. Le fichier ne garde que l'empreinte des clés.
use std::path::Path;

use aplomb_core::consommation::ComptesAgents;

pub const FICHIER: &str = "agents.yaml";

/// Comptes techniques ; fichier absent : aucun compte (le proxy compte alors en « anonyme »).
pub fn charger(chemin: &Path) -> Result<ComptesAgents, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => serde_yaml::from_str(&t).map_err(|e| format!("{} : {e}", chemin.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ComptesAgents::default()),
        Err(e) => Err(format!("{} : {e}", chemin.display())),
    }
}

pub fn nouveau(chemin: &Path, id: &str, utilisateur: &str, jetons_par_jour: Option<u64>) -> Result<(), String> {
    let mut comptes = charger(chemin)?;
    let mut alea = [0u8; 16];
    getrandom::getrandom(&mut alea).map_err(|e| e.to_string())?;
    let cle = comptes.creer(id, utilisateur, jetons_par_jour, alea)?;
    let temporaire = chemin.with_extension("yaml.tmp");
    std::fs::write(&temporaire, serde_yaml::to_string(&comptes).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&temporaire, chemin).map_err(|e| e.to_string())?;
    println!("compte technique {id} (utilisateur {utilisateur}) ajouté à {}", chemin.display());
    if let Some(q) = jetons_par_jour {
        println!("quota : {q} jetons par jour (UTC)");
    }
    println!();
    println!("clé de l'agent, affichée une seule fois (Aplomb n'en garde que l'empreinte) :");
    println!("  {cle}");
    println!();
    println!("à donner à l'agent comme ANTHROPIC_AUTH_TOKEN (conteneur : APLOMB_CLE_AGENT dans conteneur/.env),");
    println!("puis redémarrer aplomb serve");
    Ok(())
}

pub fn liste(chemin: &Path) -> Result<(), String> {
    let comptes = charger(chemin)?;
    if comptes.agents.is_empty() {
        println!("aucun compte technique dans {} : le proxy LLM compte tout en « anonyme »", chemin.display());
    }
    for a in &comptes.agents {
        let quota = a.jetons_par_jour.map(|q| format!("{q} jetons/jour")).unwrap_or_else(|| "sans quota".into());
        println!("{:<20} utilisateur {:<16} {quota}", a.id, a.utilisateur);
    }
    Ok(())
}
