//! **Clé maîtresse** de SAL (EF-S4) : une entrée du trousseau macOS (service `sal`,
//! compte `cle-maitresse`), créée au premier usage. Elle enveloppe tous les fichiers de
//! clés (sessions, comptes, signature du mandat, signature des réponses).
//!
//! Le trousseau n'autorise sans question que le binaire qui a créé l'entrée : tout autre
//! programme (l'agent qui lancerait `security find-generic-password`, par exemple)
//! déclenche une demande d'autorisation visible par l'utilisateur. Après chaque
//! recompilation de `sal`, macOS redemande une fois (« Toujours autoriser »).
//!
//! Repli explicite, moins sûr : la variable `SAL_CLE_MAITRESSE` (64 caractères hex),
//! pour les tests et les systèmes sans trousseau.
use sal_core::confidentiel::Cle;

const SERVICE: &str = "sal";
const COMPTE: &str = "cle-maitresse";

fn depuis_env() -> Option<Result<Cle, String>> {
    let v = std::env::var("SAL_CLE_MAITRESSE").ok()?;
    Some(
        hex::decode(v.trim())
            .ok()
            .and_then(|o| o.try_into().ok())
            .ok_or_else(|| "SAL_CLE_MAITRESSE : 64 caractères hexadécimaux attendus".to_string()),
    )
}

/// Clé maîtresse lue une seule fois par commande : une seule demande au trousseau, même
/// quand la commande ouvre plusieurs clés (`sal init` en ouvre quatre).
static EN_MEMOIRE: std::sync::OnceLock<Cle> = std::sync::OnceLock::new();

/// Clé maîtresse ; `creer` l'engendre si elle n'existe pas encore.
pub fn cle_maitresse(creer: bool) -> Result<Cle, String> {
    if let Some(c) = EN_MEMOIRE.get() {
        return Ok(*c);
    }
    let cle = match depuis_env() {
        Some(r) => r?,
        None => lire_ou_creer(creer)?,
    };
    Ok(*EN_MEMOIRE.get_or_init(|| cle))
}

#[cfg(target_os = "macos")]
fn lire_ou_creer(creer: bool) -> Result<Cle, String> {
    use security_framework::passwords::{get_generic_password, set_generic_password};
    const INTROUVABLE: i32 = -25300; // errSecItemNotFound
    const ANNULE: i32 = -128; // errSecUserCanceled
    match get_generic_password(SERVICE, COMPTE) {
        Ok(o) => hex::decode(&o).ok().and_then(|o| o.try_into().ok()).ok_or("entrée du trousseau illisible".into()),
        Err(e) if e.code() == INTROUVABLE && creer => {
            let mut cle = [0u8; 32];
            getrandom::getrandom(&mut cle).map_err(|e| e.to_string())?;
            set_generic_password(SERVICE, COMPTE, hex::encode(cle).as_bytes())
                .map_err(|e| format!("trousseau : écriture refusée ({e})"))?;
            eprintln!("  clé maîtresse créée dans le trousseau (service « {SERVICE} »)");
            Ok(cle)
        }
        Err(e) if e.code() == INTROUVABLE => Err("aucune clé maîtresse dans le trousseau".into()),
        Err(e) if e.code() == ANNULE => Err(
            "accès au trousseau refusé : relancer la commande et cliquer « Toujours autoriser » \
             dans la fenêtre de macOS (elle revient après chaque recompilation de sal)"
                .into(),
        ),
        Err(e) => Err(format!("trousseau : accès refusé ({e})")),
    }
}

#[cfg(not(target_os = "macos"))]
fn lire_ou_creer(_creer: bool) -> Result<Cle, String> {
    Err("pas de trousseau sur ce système : définir SAL_CLE_MAITRESSE".into())
}

/// Lit un fichier de clé privée ed25519, enveloppé ou (format antérieur) en clair. La
/// clé maîtresse n'est demandée au trousseau que si le fichier est enveloppé.
pub fn lire_cle_privee(chemin: &std::path::Path, etiquette: &str) -> Result<ed25519_dalek::SigningKey, String> {
    use sal_core::confidentiel::{est_enveloppe, lire_secret};
    let texte = std::fs::read_to_string(chemin).map_err(|e| format!("clé {} : {e}", chemin.display()))?;
    let maitre = if est_enveloppe(&texte) { Some(cle_maitresse(false)?) } else { None };
    let octets = lire_secret(&texte, maitre.as_ref(), etiquette)?;
    let tab: [u8; 32] = octets.try_into().map_err(|_| "clé privée : 32 octets attendus".to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&tab))
}

/// Écrit une clé privée enveloppée, en 0600, sans écraser un fichier existant.
pub fn ecrire_cle_privee(chemin: &std::path::Path, etiquette: &str, cle: &ed25519_dalek::SigningKey) -> Result<(), String> {
    use std::io::Write;
    let maitre = cle_maitresse(true)?;
    let texte = sal_core::confidentiel::envelopper(&maitre, etiquette, &cle.to_bytes());
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
