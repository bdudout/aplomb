//! Binaire **sal** : un seul exécutable pour le service et ses outils.
//!
//! - `sal serve`  — API de décision et API d'administration, sur deux ports distincts ;
//! - `sal hook`   — adaptateur hook Claude Code (niveau d'assurance 1), fail-closed ;
//! - `sal keygen` — paire de clés ed25519 pour signer les mandats ;
//! - `sal sign`   — calcule les empreintes des règles et signe un mandat ;
//! - `sal verify` — vérifie les chaînes du journal.
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
    Hook,
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.commande {
        Commande::Serve(opts) => serveur::lancer(opts),
        Commande::Hook => return hook::executer(),
        Commande::Keygen { dossier } => keygen(&dossier),
        Commande::Sign { mandat, cle } => signer(&mandat, &cle),
        Commande::Verify { journal } => verifier(&journal),
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
