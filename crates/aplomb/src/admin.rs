//! Outils d'administration en ligne de commande :
//! - `aplomb compte nouveau` — crée un compte (clé ed25519) et l'ajoute au fichier de comptes ;
//! - `aplomb admin <operation>` — envoie une requête signée par la clé du compte.
//!
//! Les clés privées des comptes vivent par défaut dans `~/.config/aplomb/comptes/`, hors de
//! tout dépôt, **enveloppées** par la clé maîtresse (phrase de passe) : les lire ne donne que
//! du chiffré (le profil C refuse en outre à l'agent de les lire).
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aplomb_core::autorite::{requete, Compte, FichierComptes, Operation, Role};
use serde_json::Value;

/// Dossier par défaut des clés privées des comptes.
pub fn dossier_cles() -> PathBuf {
    crate::cle_maitresse::dossier_config().join("comptes")
}

pub fn nouveau_compte(id: &str, roles: &[Role], dossier: &Path, fichier: &Path) -> Result<(), String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("identifiant : lettres, chiffres, - et _ seulement".into());
    }
    if roles.is_empty() {
        return Err("au moins un --role (lecteur, operateur, approbateur)".into());
    }
    let mut comptes = match std::fs::read_to_string(fichier) {
        Ok(t) => serde_yaml::from_str::<FichierComptes>(&t).map_err(|e| e.to_string())?,
        Err(_) => FichierComptes { comptes: Vec::new(), signatures: Vec::new() },
    };
    if comptes.comptes.iter().any(|c| c.id == id) {
        return Err(format!("le compte {id} existe déjà"));
    }
    std::fs::create_dir_all(dossier).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dossier, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let mut graine = [0u8; 32];
    getrandom::getrandom(&mut graine).map_err(|e| e.to_string())?;
    let cle = ed25519_dalek::SigningKey::from_bytes(&graine);
    let chemin = dossier.join(format!("{id}.cle"));
    crate::cle_maitresse::ecrire_cle_privee(&chemin, &format!("compte:{id}"), &cle)?;
    // La liste change : les signatures de la gouvernance ne la couvrent plus.
    let etaient_signes = !comptes.signatures.is_empty();
    comptes.signatures.clear();
    comptes.comptes.push(Compte {
        id: id.into(),
        roles: roles.to_vec(),
        cle_publique: hex::encode(cle.verifying_key().to_bytes()),
    });
    std::fs::write(fichier, serde_yaml::to_string(&comptes).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    println!("compte {id} ajouté à {} ; clé privée : {} (enveloppée, 0600)", fichier.display(), chemin.display());
    if etaient_signes {
        println!("la liste des comptes a changé : la faire recosigner par deux membres (aplomb cosigner {})", fichier.display());
    }
    println!("redémarrer `aplomb serve` pour le prendre en compte");
    Ok(())
}

pub fn envoyer(compte: &str, cle: Option<&Path>, url: &str, operation: Operation, session: Option<String>) -> Result<(), String> {
    let chemin = cle.map(Path::to_path_buf).unwrap_or_else(|| dossier_cles().join(format!("{compte}.cle")));
    let privee = crate::cle_maitresse::lire_cle_privee(&chemin, &format!("compte:{compte}"))?;
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let r = requete(compte, &privee, operation, session, t);
    let reponse: Value = match ureq::post(&format!("{url}/admin/requete")).send_json(&r) {
        Ok(rep) => rep.into_json().map_err(|e| e.to_string())?,
        Err(ureq::Error::Status(_, rep)) => {
            let v: Value = rep.into_json().unwrap_or_default();
            return Err(format!("refusé : {}", v.get("erreur").and_then(Value::as_str).unwrap_or("?")));
        }
        Err(e) => return Err(format!("superviseur injoignable : {e}")),
    };
    match reponse.get("issue").and_then(Value::as_str) {
        Some("ticket") => {
            let ticket = reponse.get("ticket").and_then(Value::as_str).unwrap_or("");
            println!("ouvrir dans les 2 minutes (lien à usage unique) :\n{url}/connexion?ticket={ticket}");
        }
        Some("gel") => println!("gel appliqué"),
        Some("degel-en-attente") => println!("dégel demandé : un second compte doit l'approuver (10 minutes)"),
        Some("degel") => println!("dégel appliqué (quatre yeux)"),
        _ => println!("{reponse}"),
    }
    Ok(())
}
