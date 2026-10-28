//! Binaire **sal** : un seul exécutable pour le service et ses outils.
//!
//! - `sal serve`  — API de décision et API d'administration, sur deux ports distincts ;
//! - `sal hook`   — adaptateur hook Claude Code (niveau d'assurance 1), fail-closed ;
//! - `sal keygen` — paire de clés ed25519 pour signer les mandats ;
//! - `sal sign`   — calcule les empreintes des règles et signe un mandat ;
//! - `sal verify` — vérifie les chaînes du journal ;
//! - `sal mermaid` — exporte les sessions en diagrammes de séquence Mermaid ;
//! - `sal effacer` — efface les contenus d'une session en détruisant sa clé (EF-P2).
#![forbid(unsafe_code)]

mod hook;
mod serveur;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sal", version, about = "Superviseur d'Alignement Local")]
struct Cli {
    #[command(subcommand)]
    commande: Commande,
}

#[derive(Subcommand)]
enum Commande {
    /// Lance le service (API décision + API administration).
    Serve(serveur::Options),
    /// Hook Claude Code : lit l'événement sur stdin, répond sur stdout.
    Hook {
        /// Dossiers supervisés (répétable). Sans cette option, tout est supervisé. Utile
        /// quand le hook est installé en paramètres gérés, qui s'appliquent à toute la
        /// machine : hors de ces dossiers, le hook laisse décider Claude Code.
        #[arg(long)]
        perimetre: Vec<PathBuf>,
    },
    /// Génère une paire de clés (sal.cle privée, sal.pub publique).
    Keygen {
        #[arg(long, default_value = ".")]
        dossier: PathBuf,
    },
    /// Signe un mandat (et lie l'empreinte de ses règles Cedar).
    Sign {
        mandat: PathBuf,
        #[arg(long)]
        cle: PathBuf,
    },
    /// Vérifie toutes les chaînes du journal.
    Verify {
        #[arg(long, default_value = "journal")]
        journal: PathBuf,
    },
    /// Exporte des sessions vérifiées en diagrammes de séquence Mermaid (.mmd).
    Mermaid {
        #[arg(long, default_value = "journal")]
        journal: PathBuf,
        /// Une seule session, écrite sur la sortie standard.
        #[arg(long)]
        session: Option<String>,
        /// Sans --session : dossier où écrire un fichier .mmd par session.
        #[arg(long, default_value = "diagrammes")]
        sortie: PathBuf,
        /// Nombre maximal d'entrées par diagramme (les plus récentes sont gardées).
        #[arg(long, default_value_t = 200)]
        max: usize,
        /// Montre les ressources en clair à l'aide des clés de session (sinon : références).
        #[arg(long)]
        dechiffrer: bool,
        #[arg(long, default_value = "journal-cles")]
        coffre: PathBuf,
    },
    /// Efface les contenus d'une session : sa clé est détruite, la chaîne reste vérifiable.
    Effacer {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = "journal-cles")]
        coffre: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.commande {
        Commande::Serve(opts) => serveur::lancer(opts),
        Commande::Hook { perimetre } => return hook::executer(&perimetre),
        Commande::Keygen { dossier } => keygen(&dossier),
        Commande::Sign { mandat, cle } => signer(&mandat, &cle),
        Commande::Verify { journal } => verifier(&journal),
        Commande::Mermaid { journal, session, sortie, max, dechiffrer, coffre } => {
            let coffre = if dechiffrer { Some(coffre) } else { None };
            mermaid(&journal, session.as_deref(), &sortie, max, coffre.as_deref())
        }
        Commande::Effacer { session, coffre } => effacer(&session, &coffre),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sal : {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(dossier: &std::path::Path) -> Result<(), String> {
    let mut graine = [0u8; 32];
    getrandom::getrandom(&mut graine).map_err(|e| e.to_string())?;
    let cle = ed25519_dalek::SigningKey::from_bytes(&graine);
    std::fs::create_dir_all(dossier).map_err(|e| e.to_string())?;
    let privee = dossier.join("sal.cle");
    if privee.exists() {
        return Err(format!("{} existe déjà, refus de l'écraser", privee.display()));
    }
    std::fs::write(&privee, hex::encode(cle.to_bytes())).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&privee, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    std::fs::write(dossier.join("sal.pub"), hex::encode(cle.verifying_key().to_bytes())).map_err(|e| e.to_string())?;
    println!("clés écrites : {} (privée, 0600) et sal.pub", privee.display());
    Ok(())
}

fn signer(chemin: &std::path::Path, cle: &std::path::Path) -> Result<(), String> {
    let texte = std::fs::read_to_string(chemin).map_err(|e| e.to_string())?;
    let mut mandat: sal_core::mandat::Mandat = serde_yaml::from_str(&texte).map_err(|e| e.to_string())?;
    let privee = sal_core::mandat::cle_privee(&std::fs::read_to_string(cle).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let dossier = chemin.parent().unwrap_or(std::path::Path::new("."));
    mandat.signer(dossier, &privee).map_err(|e| e.to_string())?;
    std::fs::write(chemin, serde_yaml::to_string(&mandat).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    println!("mandat {} v{} signé", mandat.id, mandat.version);
    Ok(())
}

fn verifier(journal: &std::path::Path) -> Result<(), String> {
    let j = sal_core::journal::Journal::ouvrir(journal).map_err(|e| e.to_string())?;
    match j.verifier_tout() {
        Ok(sessions) => {
            for (f, n) in &sessions {
                println!("OK  {f}  ({n} entrées)");
            }
            println!("{} session(s), chaînes intactes", sessions.len());
            Ok(())
        }
        Err((f, e)) => Err(format!("ÉCHEC {f} : {e}")),
    }
}

fn effacer(session: &str, coffre: &std::path::Path) -> Result<(), String> {
    let c = sal_core::confidentiel::Coffre::ouvrir(coffre).map_err(|e| e.to_string())?;
    if c.effacer(session).map_err(|e| e.to_string())? {
        println!("session {session} : clé détruite, contenus effacés (la chaîne reste vérifiable)");
        Ok(())
    } else {
        Err(format!("aucune clé pour la session {session} (déjà effacée, ou journal en clair)"))
    }
}

fn mermaid(
    journal: &std::path::Path,
    session: Option<&str>,
    sortie: &std::path::Path,
    max: usize,
    coffre: Option<&std::path::Path>,
) -> Result<(), String> {
    use sal_core::mermaid::{lire_session, ouvrir_contenus, sequence};
    let coffre = match coffre {
        Some(d) => Some(sal_core::confidentiel::Coffre::ouvrir(d).map_err(|e| e.to_string())?),
        None => None,
    };
    let lire = |chemin: &std::path::Path| {
        lire_session(chemin)
            .map(|e| ouvrir_contenus(e, coffre.as_ref()))
            .map_err(|e| format!("ÉCHEC {} : {e}", chemin.display()))
    };
    if let Some(s) = session {
        let j = sal_core::journal::Journal::ouvrir(journal).map_err(|e| e.to_string())?;
        let chemin = j.chemin(s);
        if !chemin.exists() {
            return Err(format!("session {s} absente du journal"));
        }
        let entrees = lire(&chemin)?;
        print!("{}", sequence(&entrees, max));
        return Ok(());
    }
    std::fs::create_dir_all(sortie).map_err(|e| e.to_string())?;
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(journal)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    fichiers.sort();
    for f in &fichiers {
        // Une chaîne altérée arrête l'export : aucun diagramme d'un journal douteux.
        let entrees = lire(f)?;
        let cible = sortie.join(f.with_extension("mmd").file_name().unwrap_or_default());
        std::fs::write(&cible, sequence(&entrees, max)).map_err(|e| e.to_string())?;
    }
    println!("{} diagramme(s) écrits dans {}", fichiers.len(), sortie.display());
    Ok(())
}
