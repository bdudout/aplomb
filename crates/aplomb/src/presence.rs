//! **Preuve de présence** : la personne devant le poste confirme une opération sensible,
//! d'un geste que l'agent ne peut pas faire à sa place, même sous le même utilisateur.
//!
//! - macOS : Touch ID (ou le mot de passe de session, dans la fenêtre du système) ;
//! - autres systèmes : pas encore (Windows Hello est prévu) ; l'appelant retombe sur la
//!   phrase de passe.

/// Issue d'une demande de présence.
#[derive(Debug, PartialEq)]
pub enum Presence {
    Confirmee,
    Refusee(String),
    /// Aucun moyen sur ce poste : l'appelant demande la phrase de passe.
    Indisponible,
}

#[cfg(target_os = "macos")]
pub fn confirmer(raison: &str) -> Presence {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    let politique = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY : appels documentés de LocalAuthentication ; le bloc ne capture qu'un canal.
    unsafe {
        let contexte = LAContext::new();
        if contexte.canEvaluatePolicy_error(politique).is_err() {
            return Presence::Indisponible;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let reponse = RcBlock::new(move |ok: Bool, erreur: *mut NSError| {
            let motif = if erreur.is_null() { String::new() } else { (*erreur).localizedDescription().to_string() };
            let _ = tx.send((ok.as_bool(), motif));
        });
        contexte.evaluatePolicy_localizedReason_reply(politique, &NSString::from_str(raison), &reponse);
        match rx.recv_timeout(std::time::Duration::from_secs(120)) {
            Ok((true, _)) => Presence::Confirmee,
            Ok((false, motif)) => Presence::Refusee(motif),
            Err(_) => Presence::Refusee("délai dépassé".into()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn confirmer(_raison: &str) -> Presence {
    Presence::Indisponible
}
