//! **Passerelle réseau sortante** (EF-C1, EF-C4, EF-B4) : la partie pure.
//!
//! L'agent passe par un proxy HTTP (`HTTPS_PROXY`). Chaque connexion devient une action
//! `reseau` jugée par la même politique que les outils de l'agent : domaines du mandat,
//! bornes, gel. Le proxy vérifie ensuite la **ressource réelle** : l'adresse IP à
//! laquelle le nom se résout. Une adresse interne (boucle locale, réseau privé,
//! métadonnées de cloud…) est refusée, ce qui empêche notamment de joindre l'API
//! d'administration de SAL par la passerelle.
use std::net::IpAddr;

use serde_json::json;

use crate::action::{EvenementOutil, Phase};

/// Nom d'outil des événements produits par la passerelle.
pub const OUTIL: &str = "Passerelle";

/// Destination demandée au proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cible {
    /// `CONNECT` (tunnel chiffré) ou méthode HTTP en clair (`GET`, `POST`…).
    pub methode: String,
    pub hote: String,
    pub port: u16,
}

impl Cible {
    pub fn url(&self) -> String {
        let schema = if self.methode == "CONNECT" || self.port == 443 { "https" } else { "http" };
        format!("{schema}://{}:{}/", self.hote, self.port)
    }

    /// Vrai si la requête, visible en clair, envoie des données (sens des flux, EF-C4).
    /// Un tunnel `CONNECT` est chiffré : son volume montant est plafonné à la place.
    pub fn envoie(&self) -> bool {
        matches!(self.methode.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
    }
}

/// Analyse la ligne de requête d'un proxy HTTP : `CONNECT hote:port HTTP/1.1` ou
/// `METHODE http://hote[:port]/chemin HTTP/1.1`.
pub fn analyser(ligne: &str) -> Option<Cible> {
    let mut morceaux = ligne.split_whitespace();
    let methode = morceaux.next()?.to_ascii_uppercase();
    let cible = morceaux.next()?;
    if !morceaux.next()?.starts_with("HTTP/") {
        return None;
    }
    let (autorite, defaut) = if methode == "CONNECT" {
        (cible, 443)
    } else {
        let reste = cible.strip_prefix("http://")?;
        (reste.split('/').next()?, 80)
    };
    if autorite.contains('@') {
        return None; // identifiants dans l'URL : refusés plutôt qu'interprétés
    }
    let (hote, port) = match autorite.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h, p.parse().ok()?),
        _ => (autorite, defaut),
    };
    let hote = hote.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if hote.is_empty() {
        return None;
    }
    Some(Cible { methode, hote, port })
}

/// Adresse qu'un agent ne doit jamais joindre par la passerelle.
pub fn adresse_interne(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || v.is_private()
                || v.is_link_local() // dont 169.254.169.254, métadonnées de cloud
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // 100.64.0.0/10
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7, adresses uniques locales
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10, lien local
                || v.to_ipv4_mapped().is_some_and(|v4| adresse_interne(IpAddr::V4(v4)))
        }
    }
}

/// Événement à juger pour une connexion de la passerelle.
pub fn evenement(cible: &Cible, session: &str, agent: &str, cwd: &str) -> EvenementOutil {
    EvenementOutil {
        session: session.into(),
        agent: agent.into(),
        mode: "passerelle".into(),
        cwd: cwd.into(),
        outil: OUTIL.into(),
        entree: json!({"url": cible.url(), "methode": cible.methode}),
        phase: Phase::Avant,
        chemin_reel: None,
        contenu_execute: None,
        nonce: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyse_des_requetes() {
        let c = analyser("CONNECT pypi.org:443 HTTP/1.1").unwrap();
        assert_eq!((c.methode.as_str(), c.hote.as_str(), c.port), ("CONNECT", "pypi.org", 443));
        assert!(!c.envoie());
        let c = analyser("POST http://Exemple.org:8080/x?y HTTP/1.1").unwrap();
        assert_eq!((c.hote.as_str(), c.port), ("exemple.org", 8080));
        assert!(c.envoie());
        assert_eq!(analyser("GET http://exemple.org/ HTTP/1.1").unwrap().port, 80);
        assert_eq!(analyser("CONNECT [::1]:443 HTTP/1.1").unwrap().hote, "::1");
        // Formes refusées : origine sans hôte, identifiants dans l'URL, ligne incomplète.
        assert!(analyser("GET /chemin HTTP/1.1").is_none());
        assert!(analyser("GET http://moi:secret@exemple.org/ HTTP/1.1").is_none());
        assert!(analyser("CONNECT pypi.org:443").is_none());
    }

    #[test]
    fn adresses_internes() {
        for a in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(adresse_interne(a.parse().unwrap()), "{a}");
        }
        for a in ["151.101.0.223", "8.8.8.8", "2a04:4e42::223"] {
            assert!(!adresse_interne(a.parse().unwrap()), "{a}");
        }
    }
}
