//! Gouvernance en deux commandes, pour rester simple :
//! - `sal init` — parcours guidé : comptes, fichier de confiance, cosignature des comptes
//!   et des mandats, en une fois ;
//! - `sal cosigner <fichier>` — ajoute sa signature à un mandat ou au fichier de comptes,
//!   et dit qui doit encore signer.
use std::path::{Path, PathBuf};

use sal_core::autorite::{FichierComptes, Role};
use sal_core::gouvernance::{signer, Confiance, FichierConfiance, Membre, SignatureNommee};
use sal_core::mandat::{actualiser_empreintes, Mandat};

use crate::admin;

/// Fichier de confiance par défaut.
pub const CONFIANCE: &str = "cles/confiance.yaml";

fn lire(chemin: &Path) -> Result<String, String> {
    std::fs::read_to_string(chemin).map_err(|e| format!("{} : {e}", chemin.display()))
}

fn ecrire_yaml<T: serde::Serialize>(chemin: &Path, valeur: &T) -> Result<(), String> {
    std::fs::write(chemin, serde_yaml::to_string(valeur).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Ajoute ou remplace la signature d'un membre.
fn poser(signatures: &mut Vec<SignatureNommee>, s: SignatureNommee) {
    signatures.retain(|x| x.id != s.id);
    signatures.push(s);
}

/// Dit où en est un artefact : qui a signé, combien il en manque, et qui peut encore signer.
fn etat(confiance: Option<&Confiance>, membres: &[String], octets: &[u8], signatures: &[SignatureNommee]) -> String {
    let Some(c) = confiance else { return format!("{} signature(s)", signatures.len()) };
    let valides = c.signataires_valides(octets, signatures);
    if valides.len() >= c.seuil() {
        return format!("prêt : {} ({}/{})", valides.join(", "), valides.len(), c.seuil());
    }
    let restants: Vec<&String> = membres.iter().filter(|m| !valides.contains(m)).collect();
    format!(
        "{}/{} : encore {} signature(s), parmi : {}",
        valides.len(),
        c.seuil(),
        c.seuil() - valides.len(),
        restants.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
    )
}

fn charger_confiance(chemin: &Path) -> Result<Option<(Confiance, Vec<String>)>, String> {
    if !chemin.exists() {
        return Ok(None);
    }
    let texte = lire(chemin)?;
    let f: FichierConfiance = serde_yaml::from_str(&texte).map_err(|e| e.to_string())?;
    let membres = f.membres.iter().map(|m| m.id.clone()).collect();
    Ok(Some((Confiance::nouvelle(f)?, membres)))
}

/// Ajoute la signature du compte à un mandat ou au fichier de comptes.
pub fn cosigner(fichier: &Path, compte: &str, cle: Option<&Path>, confiance: &Path) -> Result<(), String> {
    let chemin_cle = cle.map(Path::to_path_buf).unwrap_or_else(|| admin::dossier_cles().join(format!("{compte}.cle")));
    let privee = crate::trousseau::lire_cle_privee(&chemin_cle, &format!("compte:{compte}"))?;
    let conf = charger_confiance(confiance)?;
    let (c, membres) = match &conf {
        Some((c, m)) => (Some(c), m.clone()),
        None => (None, Vec::new()),
    };
    if !membres.is_empty() && !membres.iter().any(|m| m == compte) {
        return Err(format!("{compte} n'est pas membre de la gouvernance ({})", membres.join(", ")));
    }
    let texte = lire(fichier)?;
    let valeur: serde_yaml::Value = serde_yaml::from_str(&texte).map_err(|e| e.to_string())?;
    let statut = if valeur.get("comptes").is_some() {
        let mut f: FichierComptes = serde_yaml::from_value(valeur).map_err(|e| e.to_string())?;
        let o = f.octets_signes();
        poser(&mut f.signatures, signer(compte, &privee, &o));
        ecrire_yaml(fichier, &f)?;
        format!("comptes cosignés par {compte} — {}", etat(c, &membres, &o, &f.signatures))
    } else {
        let mut m: Mandat = serde_yaml::from_value(valeur).map_err(|e| e.to_string())?;
        let dossier = fichier.parent().unwrap_or(Path::new("."));
        if actualiser_empreintes(&mut m, dossier)? {
            println!("règles modifiées depuis la dernière signature : les signatures précédentes sont retirées");
        }
        m.signature = None;
        let o = m.octets_signes();
        poser(&mut m.signatures, signer(compte, &privee, &o));
        ecrire_yaml(fichier, &m)?;
        format!("mandat {} v{} cosigné par {compte} — {}", m.id, m.version, etat(c, &membres, &o, &m.signatures))
    };
    println!("{statut}");
    Ok(())
}

/// Parcours guidé : tout ce qu'il faut pour un premier `sal serve`, en une commande.
pub fn init(membres: &[String], comptes: &Path, mandats: &[PathBuf], confiance: &Path) -> Result<(), String> {
    if membres.len() < 2 {
        return Err("indiquer deux personnes : sal init --membre <id> --membre <id> (quatre yeux)".into());
    }
    if membres[0] == membres[1] {
        return Err("les deux membres doivent être distincts".into());
    }
    // 1. Comptes : créés s'ils n'existent pas (le premier opère, le second approuve).
    let existants: FichierComptes = match std::fs::read_to_string(comptes) {
        Ok(t) => serde_yaml::from_str(&t).map_err(|e| e.to_string())?,
        Err(_) => FichierComptes { comptes: Vec::new(), signatures: Vec::new() },
    };
    for (i, id) in membres.iter().enumerate() {
        if !existants.comptes.iter().any(|c| &c.id == id) {
            let role = if i == 0 { Role::Operateur } else { Role::Approbateur };
            admin::nouveau_compte(id, &[role], &admin::dossier_cles(), comptes)?;
        }
    }
    // 2. Fichier de confiance : les membres, seuil 2.
    let f: FichierComptes = serde_yaml::from_str(&lire(comptes)?).map_err(|e| e.to_string())?;
    if confiance.exists() {
        println!("{} existe déjà : conservé", confiance.display());
    } else {
        let membres_conf = membres
            .iter()
            .map(|id| {
                let c = f.comptes.iter().find(|c| &c.id == id).ok_or(format!("compte {id} introuvable"))?;
                Ok(Membre { id: id.clone(), cle_publique: c.cle_publique.clone() })
            })
            .collect::<Result<Vec<_>, String>>()?;
        if let Some(d) = confiance.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        ecrire_yaml(confiance, &FichierConfiance { seuil: 2, membres: membres_conf })?;
        println!("fichier de confiance créé : {} (seuil 2)", confiance.display());
    }
    // 3. Cosignatures : comptes et mandats, par les deux membres.
    for id in membres.iter().take(2) {
        cosigner(comptes, id, None, confiance)?;
        for m in mandats {
            cosigner(m, id, None, confiance)?;
        }
    }
    println!();
    println!("Prêt. Lancer : ./target/debug/sal serve --mandat {}", mandats.first().map(|p| p.display().to_string()).unwrap_or_default());
    println!(
        "Les clés de {} et {} sont sur ce poste. Pour de vrais quatre yeux, chacun garde la sienne sur son propre poste.",
        membres[0], membres[1]
    );
    Ok(())
}
