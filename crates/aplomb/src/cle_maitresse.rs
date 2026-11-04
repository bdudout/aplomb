//! **Clé maîtresse** d'Aplomb (EF-S4), protégée par une **phrase de passe**.
//!
//! La clé maîtresse enveloppe tous les fichiers de clés (sessions, comptes, signature des
//! réponses). Elle vit dans `~/.config/aplomb/cle-maitresse.yaml`, elle-même chiffrée par une
//! clé dérivée de la phrase de passe (Argon2id). La phrase se tape sans affichage, une
//! fois par commande ; l'agent ne la connaît pas.
//!
//! Pas de trousseau macOS : son contrôle d'accès dépend de l'empreinte exacte du binaire
//! et redemandait le mot de passe à chaque recompilation. Le trousseau n'est plus lu qu'une
//! fois, par `aplomb phrase initialiser`, pour récupérer une ancienne clé.
//!
//! Variables réservées aux tests : `APLOMB_PHRASE` (phrase sans saisie), `APLOMB_CLE_MAITRESSE`
//! (clé en hex, sans fichier), `APLOMB_FICHIER_MAITRE` (autre emplacement du fichier).
//! Une variable d'environnement est lisible par les autres processus de l'utilisateur :
//! jamais en usage réel.
use std::path::{Path, PathBuf};

use aplomb_core::confidentiel::{ouvrir_maitre, proteger_maitre, Cle, FichierMaitre};

/// Longueur minimale de la phrase de passe.
const LONGUEUR_MIN: usize = 12;

/// Dossier de configuration (`~/.config/aplomb`). L'ancien dossier `~/.config/sal`, du
/// temps où le projet s'appelait SAL, est renommé à la première utilisation.
pub fn dossier_config() -> PathBuf {
    let maison = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let dossier = maison.join(".config/aplomb");
    let ancien = maison.join(".config/sal");
    if !dossier.exists() && ancien.is_dir() && std::fs::rename(&ancien, &dossier).is_ok() {
        eprintln!("configuration déplacée : {} → {}", ancien.display(), dossier.display());
    }
    dossier
}

pub fn chemin() -> PathBuf {
    if let Some(p) = std::env::var_os("APLOMB_FICHIER_MAITRE") {
        return PathBuf::from(p);
    }
    dossier_config().join("cle-maitresse.yaml")
}

/// Clé maîtresse ouverte une seule fois par commande.
static EN_MEMOIRE: std::sync::OnceLock<Cle> = std::sync::OnceLock::new();

fn depuis_env() -> Option<Result<Cle, String>> {
    let v = std::env::var("APLOMB_CLE_MAITRESSE").ok()?;
    Some(
        hex::decode(v.trim())
            .ok()
            .and_then(|o| o.try_into().ok())
            .ok_or_else(|| "APLOMB_CLE_MAITRESSE : 64 caractères hexadécimaux attendus".to_string()),
    )
}

fn demander(invite: &str) -> Result<String, String> {
    if let Ok(p) = std::env::var("APLOMB_PHRASE") {
        return Ok(p);
    }
    rpassword::prompt_password(invite)
        .map_err(|_| "phrase de passe requise : lancer la commande dans un terminal".to_string())
}

fn lire_fichier(chemin: &Path) -> Result<FichierMaitre, String> {
    let texte = std::fs::read_to_string(chemin).map_err(|_| {
        format!("aucune clé maîtresse ({}) : première installation, lancer aplomb phrase initialiser", chemin.display())
    })?;
    serde_yaml::from_str(&texte).map_err(|e| format!("{} : {e}", chemin.display()))
}

/// Clé maîtresse au premier besoin de la commande : par le service de déverrouillage s'il
/// tourne (`aplomb deverrouiller`), sinon par la phrase de passe.
pub fn cle_maitresse() -> Result<Cle, String> {
    if let Some(c) = EN_MEMOIRE.get() {
        return Ok(*c);
    }
    let cle = match depuis_env() {
        Some(r) => r?,
        None => match crate::deverrouillage::demander_cle() {
            Some(r) => r?,
            None => cle_maitresse_par_phrase()?,
        },
    };
    Ok(*EN_MEMOIRE.get_or_init(|| cle))
}

/// Clé maîtresse ouverte par la phrase de passe, sans passer par le service.
pub fn cle_maitresse_par_phrase() -> Result<Cle, String> {
    if let Some(r) = depuis_env() {
        return r;
    }
    let f = lire_fichier(&chemin())?;
    ouvrir_maitre(&f, &demander("Phrase de passe Aplomb : ")?)
}

/// Écrit le fichier de clé maîtresse (dossier 0700, fichier 0600, écriture atomique).
fn ecrire_fichier(chemin: &Path, f: &FichierMaitre) -> Result<(), String> {
    ecrire_atomique(chemin, &serde_yaml::to_string(f).map_err(|e| e.to_string())?)
}

/// Écriture d'un fichier secret : dossier 0700, fichier 0600, remplacement atomique.
fn ecrire_atomique(chemin: &Path, contenu: &str) -> Result<(), String> {
    use std::io::Write;
    let dossier = chemin.parent().ok_or("chemin invalide")?;
    std::fs::create_dir_all(dossier).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dossier, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let temporaire = chemin.with_extension("tmp");
    let _ = std::fs::remove_file(&temporaire);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut fichier = options.open(&temporaire).map_err(|e| e.to_string())?;
    fichier.write_all(contenu.as_bytes()).map_err(|e| e.to_string())?;
    fichier.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&temporaire, chemin).map_err(|e| e.to_string())
}

/// Demande une nouvelle phrase, deux fois, avec une longueur minimale.
fn nouvelle_phrase() -> Result<String, String> {
    let p = demander(&format!("Nouvelle phrase de passe Aplomb (au moins {LONGUEUR_MIN} caractères) : "))?;
    if p.chars().count() < LONGUEUR_MIN {
        return Err(format!("phrase trop courte : au moins {LONGUEUR_MIN} caractères"));
    }
    if std::env::var("APLOMB_PHRASE").is_err() && demander("La retaper : ")? != p {
        return Err("les deux saisies diffèrent".into());
    }
    Ok(p)
}

/// Première installation, ou passage du trousseau à la phrase de passe : la clé maîtresse
/// existante est reprise telle quelle, aucun fichier de clé n'est à refaire.
pub fn initialiser() -> Result<(), String> {
    let chemin = chemin();
    if chemin.exists() {
        return Err(format!("{} existe déjà : pour changer de phrase, aplomb phrase changer", chemin.display()));
    }
    let (cle, origine) = match depuis_env() {
        Some(r) => (r?, "variable APLOMB_CLE_MAITRESSE"),
        None => match ancienne_cle_du_trousseau()? {
            Some(c) => (c, "trousseau (dernier accès : aplomb ne le lira plus)"),
            None => {
                let mut c = [0u8; 32];
                getrandom::getrandom(&mut c).map_err(|e| e.to_string())?;
                (c, "nouvelle clé")
            }
        },
    };
    let phrase = nouvelle_phrase()?;
    ecrire_fichier(&chemin, &proteger_maitre(&cle, &phrase)?)?;
    let _ = EN_MEMOIRE.set(cle);
    println!("clé maîtresse ({origine}) protégée par ta phrase de passe : {}", chemin.display());
    if origine.starts_with("trousseau") {
        println!("l'ancienne entrée « sal » du trousseau est conservée ; tu peux la supprimer dans Trousseaux d'accès");
    }
    println!("sans la phrase, les clés sont perdues : la noter en lieu sûr");
    Ok(())
}

/// Change la phrase de passe (la clé maîtresse, elle, ne change pas).
pub fn changer() -> Result<(), String> {
    let chemin = chemin();
    let f = lire_fichier(&chemin)?;
    let cle = ouvrir_maitre(&f, &demander("Phrase de passe actuelle : ")?)?;
    let phrase = nouvelle_phrase()?;
    ecrire_fichier(&chemin, &proteger_maitre(&cle, &phrase)?)?;
    println!("phrase de passe changée");
    Ok(())
}

/// Ancienne clé maîtresse du trousseau macOS (versions antérieures), si elle existe.
#[cfg(target_os = "macos")]
fn ancienne_cle_du_trousseau() -> Result<Option<Cle>, String> {
    use security_framework::passwords::get_generic_password;
    const INTROUVABLE: i32 = -25300;
    eprintln!("recherche d'une ancienne clé dans le trousseau : macOS peut demander l'accès une dernière fois");
    match get_generic_password("sal", "cle-maitresse") {
        Ok(o) => Ok(hex::decode(&o).ok().and_then(|o| o.try_into().ok())),
        Err(e) if e.code() == INTROUVABLE => Ok(None),
        Err(e) => Err(format!("trousseau : accès refusé ({e}) ; sans l'ancienne clé, les fichiers existants restent illisibles")),
    }
}

#[cfg(not(target_os = "macos"))]
fn ancienne_cle_du_trousseau() -> Result<Option<Cle>, String> {
    Ok(None)
}

/// Lit un fichier de clé privée ed25519, enveloppé ou (format antérieur) en clair. La
/// phrase de passe n'est demandée que si le fichier est enveloppé.
pub fn lire_cle_privee(chemin: &Path, etiquette: &str) -> Result<ed25519_dalek::SigningKey, String> {
    use aplomb_core::confidentiel::{est_enveloppe, lire_secret};
    let texte = std::fs::read_to_string(chemin).map_err(|e| format!("clé {} : {e}", chemin.display()))?;
    let maitre = if est_enveloppe(&texte) { Some(cle_maitresse()?) } else { None };
    let octets = lire_secret(&texte, maitre.as_ref(), etiquette)?;
    let tab: [u8; 32] = octets.try_into().map_err(|_| "clé privée : 32 octets attendus".to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&tab))
}

/// Écrit une clé privée enveloppée, en 0600, sans écraser un fichier existant.
pub fn ecrire_cle_privee(chemin: &Path, etiquette: &str, cle: &ed25519_dalek::SigningKey) -> Result<(), String> {
    use std::io::Write;
    let maitre = cle_maitresse()?;
    let texte = aplomb_core::confidentiel::envelopper(&maitre, etiquette, &cle.to_bytes());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(chemin).map_err(|e| format!("{} : {e}", chemin.display()))?;
    f.write_all(texte.as_bytes()).map_err(|e| e.to_string())
}

/// Jeton du fournisseur du modèle (clé d'API, ou jeton de `claude setup-token`), enveloppé
/// par la clé maîtresse. Le proxy LLM l'injecte : l'agent ne le voit jamais.
const ETIQUETTE_JETON: &str = "modele:jeton";

fn chemin_jeton() -> PathBuf {
    dossier_config().join("modele-jeton")
}

/// Enregistre (ou remplace) le jeton du modèle, saisi sans affichage.
pub fn enregistrer_jeton_modele() -> Result<(), String> {
    let saisi = match std::env::var("APLOMB_JETON_MODELE") {
        Ok(j) => j,
        Err(_) => rpassword::prompt_password("Jeton du modèle (rien ne s'affiche) : ")
            .map_err(|_| "jeton requis : lancer la commande dans un terminal".to_string())?,
    };
    let jeton = saisi.trim();
    if jeton.len() < 20 || jeton.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("jeton inattendu : trop court, ou contient des espaces (recopier le jeton seul)".into());
    }
    let maitre = cle_maitresse()?;
    let chemin = chemin_jeton();
    ecrire_atomique(&chemin, &aplomb_core::confidentiel::envelopper(&maitre, ETIQUETTE_JETON, jeton.as_bytes()))?;
    println!("jeton du modèle enregistré, enveloppé : {}", chemin.display());
    println!("redémarrer `aplomb serve` pour que le proxy LLM l'utilise");
    Ok(())
}

/// Jeton du modèle, s'il a été enregistré.
pub fn jeton_modele() -> Result<Option<String>, String> {
    let Ok(texte) = std::fs::read_to_string(chemin_jeton()) else { return Ok(None) };
    let octets = aplomb_core::confidentiel::lire_secret(&texte, Some(&cle_maitresse()?), ETIQUETTE_JETON)?;
    String::from_utf8(octets).map(Some).map_err(|_| "jeton du modèle illisible".to_string())
}
