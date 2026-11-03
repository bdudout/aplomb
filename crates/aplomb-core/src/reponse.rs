//! **Réponses signées** du superviseur (EF-S3 au niveau 1).
//!
//! Le hook joint à chaque demande un nonce aléatoire. Le superviseur signe sa décision
//! avec ce nonce par sa clé ed25519 ; le hook vérifie la signature avec la clé publique
//! qu'on lui a fixée. Un faux superviseur qui écouterait sur le port de décision (par
//! exemple démarré par l'agent pendant une panne d'Aplomb) ne peut pas produire une
//! réponse valide, et une ancienne réponse « allow » ne peut pas être rejouée.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;

#[derive(Serialize)]
struct Signe<'a> {
    nonce: &'a str,
    session: &'a str,
    verdict: &'a str,
    regle: &'a str,
}

fn octets(nonce: &str, session: &str, verdict: &str, regle: &str) -> Vec<u8> {
    serde_json::to_vec(&Signe { nonce, session, verdict, regle }).expect("sérialisation JSON")
}

pub fn signer(cle: &SigningKey, nonce: &str, session: &str, verdict: &str, regle: &str) -> String {
    hex::encode(cle.sign(&octets(nonce, session, verdict, regle)).to_bytes())
}

pub fn verifier(cle: &VerifyingKey, signature: &str, nonce: &str, session: &str, verdict: &str, regle: &str) -> bool {
    let Ok(o) = hex::decode(signature) else { return false };
    let Ok(tab) = <[u8; 64]>::try_from(o) else { return false };
    cle.verify(&octets(nonce, session, verdict, regle), &Signature::from_bytes(&tab)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reponse_liee_au_nonce_et_au_verdict() {
        let k = SigningKey::from_bytes(&[3u8; 32]);
        let p = k.verifying_key();
        let s = signer(&k, "n1", "s", "deny", "secrets");
        assert!(verifier(&p, &s, "n1", "s", "deny", "secrets"));
        // Verdict changé en route, autre nonce (rejeu), autre session, autre clé.
        assert!(!verifier(&p, &s, "n1", "s", "allow", "secrets"));
        assert!(!verifier(&p, &s, "n2", "s", "deny", "secrets"));
        assert!(!verifier(&p, &s, "n1", "t", "deny", "secrets"));
        assert!(!verifier(&SigningKey::from_bytes(&[4u8; 32]).verifying_key(), &s, "n1", "s", "deny", "secrets"));
        assert!(!verifier(&p, "zz", "n1", "s", "deny", "secrets"));
    }
}
