//! **Identité** (étape 11, EF-N3 à EF-N5), options désactivées par défaut :
//!
//! - **MFA** : second facteur TOTP (RFC 6238) pour ouvrir une session de la vue et pour les
//!   actions qui assouplissent (dégel, réactivation d'un compte) ;
//! - **SSO** : connexion par OpenID Connect (code d'autorisation avec PKCE), groupes de
//!   l'annuaire associés aux rôles. Le SSO authentifie ; il ne remplace ni les
//!   cosignatures (mandats, comptes) ni les quatre yeux ;
//! - **revue des comptes** : un compte inactif au-delà de N jours est suspendu, et sa
//!   réactivation demande deux autres comptes.
//!
//! Ces réglages vivent dans `comptes.yaml`, sous `identite:` : ils sont cosignés avec la
//! liste des comptes, si bien que personne ne peut retirer seul le second facteur.
//!
//! Module pur : l'horloge et l'aléa sont passés par l'appelant.
use std::collections::{BTreeMap, HashMap};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::autorite::Role;

/// Réglages d'identité de l'instance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigIdentite {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<ConfigMfa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso: Option<ConfigSso>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revue: Option<ConfigRevue>,
}

impl ConfigIdentite {
    pub fn est_vide(&self) -> bool {
        *self == ConfigIdentite::default()
    }

    pub fn mfa_exigee(&self) -> bool {
        self.mfa.as_ref().is_some_and(|m| m.exiger)
    }

    pub fn verifier(&self) -> Result<(), String> {
        if let Some(s) = &self.sso {
            s.verifier()?;
        }
        if let Some(r) = &self.revue {
            if r.inactivite_jours == 0 {
                return Err("identite.revue : inactivite_jours au moins 1".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigMfa {
    /// Second facteur obligatoire (ouverture de la vue, dégel, réactivation).
    #[serde(default = "vrai")]
    pub exiger: bool,
}

fn vrai() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigRevue {
    /// Au-delà de ce nombre de jours sans activité, le compte est suspendu.
    pub inactivite_jours: u64,
}

/// Fournisseur d'identité OpenID Connect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSso {
    /// Émetteur (`iss`), par exemple `https://login.microsoftonline.com/<tenant>/v2.0`.
    pub emetteur: String,
    pub client_id: String,
    /// Variable d'environnement qui porte le secret du client (jamais le secret ici).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_env: String,
    /// Point d'autorisation (`authorization_endpoint`).
    pub autorisation: String,
    /// Point de jeton (`token_endpoint`). Le jeton d'identité est reçu directement de ce
    /// point, sur TLS : c'est ce lien qui l'authentifie (OIDC Core, § 3.1.3.7).
    pub jeton: String,
    /// Adresse de retour déclarée chez le fournisseur : `https://<vue>/sso/retour`.
    pub redirection: String,
    /// Revendication qui nomme la personne (défaut : email).
    #[serde(default = "email")]
    pub champ_identite: String,
    /// Revendication qui porte les groupes (défaut : groups).
    #[serde(default = "groupes")]
    pub champ_groupes: String,
    /// Groupe de l'annuaire → rôles dans Aplomb. Sans groupe associé, pas d'accès.
    pub roles: BTreeMap<String, Vec<Role>>,
}

fn email() -> String {
    "email".into()
}
fn groupes() -> String {
    "groups".into()
}

fn local(url: &str) -> bool {
    let hote = url.split("://").nth(1).unwrap_or("").split(['/', ':']).next().unwrap_or("");
    matches!(hote, "localhost" | "127.0.0.1" | "[")
}

impl ConfigSso {
    pub fn verifier(&self) -> Result<(), String> {
        for (nom, url) in [("autorisation", &self.autorisation), ("jeton", &self.jeton), ("redirection", &self.redirection)] {
            if !(url.starts_with("https://") || (url.starts_with("http://") && local(url))) {
                return Err(format!("identite.sso.{nom} : https:// exigé (http seulement vers la machine elle-même)"));
            }
        }
        if self.client_id.is_empty() || self.emetteur.is_empty() {
            return Err("identite.sso : emetteur et client_id requis".into());
        }
        if self.roles.is_empty() || self.roles.values().any(Vec::is_empty) {
            return Err("identite.sso.roles : associer au moins un groupe à des rôles (lecteur, operateur, approbateur)".into());
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ encodages

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 (RFC 4648) sans remplissage, comme l'attendent les applications TOTP.
pub fn base32(octets: &[u8]) -> String {
    let mut s = String::new();
    let (mut tampon, mut bits) = (0u32, 0);
    for &o in octets {
        tampon = (tampon << 8) | o as u32;
        bits += 8;
        while bits >= 5 {
            s.push(B32[((tampon >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        s.push(B32[((tampon << (5 - bits)) & 31) as usize] as char);
    }
    s
}

pub fn depuis_base32(s: &str) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    let (mut tampon, mut bits) = (0u32, 0);
    for c in s.chars().filter(|c| *c != '=' && !c.is_whitespace()) {
        let i = B32.iter().position(|b| *b as char == c.to_ascii_uppercase())? as u32;
        tampon = (tampon << 5) | i;
        bits += 5;
        if bits >= 8 {
            v.push((tampon >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(v)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 URL sans remplissage (JWT, PKCE).
pub fn base64url(octets: &[u8]) -> String {
    let mut s = String::new();
    for bloc in octets.chunks(3) {
        let n = bloc.iter().enumerate().fold(0u32, |n, (i, o)| n | (*o as u32) << (16 - 8 * i));
        for i in 0..=bloc.len() {
            s.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    s
}

pub fn depuis_base64url(s: &str) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    let (mut tampon, mut bits) = (0u32, 0);
    for c in s.trim_end_matches('=').chars() {
        let c = match c {
            '+' => '-',
            '/' => '_',
            c => c,
        };
        let i = B64.iter().position(|b| *b as char == c)? as u32;
        tampon = (tampon << 6) | i;
        bits += 6;
        if bits >= 8 {
            v.push((tampon >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(v)
}

// ------------------------------------------------------------------ TOTP

/// SHA-1 (FIPS 180-4), seulement pour HMAC-SHA1 du TOTP, que toutes les applications
/// d'authentification connaissent.
fn sha1(message: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut m = message.to_vec();
    let longueur = (message.len() as u64).wrapping_mul(8);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&longueur.to_be_bytes());
    for bloc in m.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(bloc[4 * i..4 * i + 4].try_into().expect("4 octets"));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut r = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        r[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    r
}

fn hmac_sha1(cle: &[u8], message: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if cle.len() > 64 {
        k[..20].copy_from_slice(&sha1(cle));
    } else {
        k[..cle.len()].copy_from_slice(cle);
    }
    let interne: Vec<u8> = k.iter().map(|b| b ^ 0x36).chain(message.iter().copied()).collect();
    let externe: Vec<u8> = k.iter().map(|b| b ^ 0x5c).chain(sha1(&interne)).collect();
    sha1(&externe)
}

/// Pas de temps TOTP (30 s).
pub const PAS_S: u64 = 30;

/// Code TOTP à 6 chiffres pour un pas donné.
pub fn code_totp(secret: &[u8], pas: u64) -> String {
    let h = hmac_sha1(secret, &pas.to_be_bytes());
    let o = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]) % 1_000_000;
    format!("{n:06}")
}

/// Vérifie un code (pas courant ± 1, pour l'écart d'horloge du téléphone). Un code déjà
/// utilisé ne repasse pas : rend le pas accepté, à retenir comme `dernier`.
pub fn verifier_totp(secret: &[u8], code: &str, maintenant_ms: u64, dernier: Option<u64>) -> Option<u64> {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let pas = maintenant_ms / 1000 / PAS_S;
    [pas.saturating_sub(1), pas, pas + 1]
        .into_iter()
        .filter(|p| dernier.is_none_or(|d| *p > d))
        .find(|p| {
            let attendu = code_totp(secret, *p);
            // Comparaison à temps constant.
            attendu.bytes().zip(code.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        })
}

/// Adresse `otpauth://` à donner à l'application d'authentification.
pub fn uri_totp(emetteur: &str, compte: &str, secret: &[u8]) -> String {
    let enc = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c.to_string() } else { format!("%{:02X}", c as u32) }).collect::<String>();
    format!("otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30", enc(emetteur), enc(compte), base32(secret), enc(emetteur))
}

// ------------------------------------------------------------------ OpenID Connect

/// Défi PKCE (S256) d'un vérificateur.
pub fn defi_pkce(verificateur: &str) -> String {
    base64url(&Sha256::digest(verificateur.as_bytes()))
}

fn encoder_url(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Adresse vers laquelle renvoyer le navigateur pour se connecter.
pub fn url_autorisation(cfg: &ConfigSso, etat: &str, nonce: &str, verificateur: &str) -> String {
    let sep = if cfg.autorisation.contains('?') { '&' } else { '?' };
    format!(
        "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        cfg.autorisation,
        encoder_url(&cfg.client_id),
        encoder_url(&cfg.redirection),
        encoder_url("openid email profile"),
        encoder_url(etat),
        encoder_url(nonce),
        defi_pkce(verificateur)
    )
}

/// Personne authentifiée par le fournisseur d'identité.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentiteSso {
    /// Identifiant dans Aplomb : `sso:<identité>`.
    pub compte: String,
    pub roles: Vec<Role>,
    /// Vrai si le fournisseur atteste un second facteur (`amr`).
    pub mfa: bool,
}

/// Valide le jeton d'identité reçu du point de jeton : émetteur, audience, dates, nonce,
/// puis rôles par les groupes.
pub fn valider_id_token(cfg: &ConfigSso, jwt: &str, nonce: &str, maintenant_ms: u64) -> Result<IdentiteSso, String> {
    let parties: Vec<&str> = jwt.split('.').collect();
    if parties.len() != 3 {
        return Err("jeton d'identité illisible".into());
    }
    let charge = depuis_base64url(parties[1]).ok_or("jeton d'identité illisible")?;
    let c: Value = serde_json::from_slice(&charge).map_err(|_| "jeton d'identité illisible")?;
    if c.get("iss").and_then(Value::as_str) != Some(cfg.emetteur.as_str()) {
        return Err("jeton d'un autre émetteur".into());
    }
    let aud_ok = match c.get("aud") {
        Some(Value::String(a)) => a == &cfg.client_id,
        Some(Value::Array(v)) => v.iter().any(|a| a.as_str() == Some(cfg.client_id.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err("jeton destiné à un autre client".into());
    }
    let s = maintenant_ms / 1000;
    if c.get("exp").and_then(Value::as_u64).is_none_or(|e| e + 60 < s) {
        return Err("jeton d'identité expiré".into());
    }
    if c.get("iat").and_then(Value::as_u64).is_some_and(|i| i > s + 300) {
        return Err("jeton d'identité daté dans le futur".into());
    }
    if c.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err("nonce du jeton incorrect (rejeu ?)".into());
    }
    let qui = c
        .get(&cfg.champ_identite)
        .and_then(Value::as_str)
        .or_else(|| c.get("sub").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .ok_or("jeton sans identité")?;
    let groupes: Vec<String> = match c.get(&cfg.champ_groupes) {
        Some(Value::Array(v)) => v.iter().filter_map(|g| g.as_str().map(String::from)).collect(),
        Some(Value::String(g)) => vec![g.clone()],
        _ => Vec::new(),
    };
    let mut roles: Vec<Role> = groupes.iter().filter_map(|g| cfg.roles.get(g)).flatten().copied().collect();
    roles.sort_by_key(|r| *r as u8);
    roles.dedup();
    if roles.is_empty() {
        return Err(format!("{qui} : aucun de ses groupes n'a de rôle dans Aplomb (identite.sso.roles)"));
    }
    let mfa = c
        .get("amr")
        .and_then(Value::as_array)
        .is_some_and(|v| v.iter().filter_map(Value::as_str).any(|m| ["mfa", "otp", "hwk", "swk", "fpt", "face", "sc"].contains(&m)));
    Ok(IdentiteSso { compte: format!("sso:{qui}"), roles, mfa })
}

// ------------------------------------------------------------------ revue des comptes

/// Comptes inactifs depuis plus de `jours` : (compte, dernière activité).
pub fn inactifs<'a>(comptes: impl Iterator<Item = &'a str>, activite: &HashMap<String, u64>, maintenant_ms: u64, jours: u64) -> Vec<(String, u64)> {
    let seuil = maintenant_ms.saturating_sub(jours * 86_400_000);
    comptes
        .filter_map(|c| activite.get(c).filter(|t| **t < seuil).map(|t| (c.to_string(), *t)))
        .collect()
}

/// Empreinte courte d'un secret TOTP, pour le journal (jamais le secret).
pub fn empreinte_secret(secret: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(b"aplomb-totp").expect("clé HMAC");
    m.update(secret);
    hex::encode(&m.finalize().into_bytes()[..6])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_et_totp_rfc6238() {
        assert_eq!(hex::encode(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        // RFC 6238, annexe B (SHA-1, 8 chiffres) : on garde les 6 derniers.
        let s = b"12345678901234567890";
        for (t, attendu) in [(59u64, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (20000000000, "65353130")] {
            assert_eq!(code_totp(s, t / 30), attendu[2..], "t = {t}");
        }
        let maintenant = 1_234_567_890_000;
        let p = verifier_totp(s, "005924", maintenant, None).unwrap();
        assert_eq!(verifier_totp(s, "005924", maintenant, Some(p)), None, "pas de rejeu");
        assert!(verifier_totp(s, &code_totp(s, 1234567890 / 30 - 1), maintenant, None).is_some(), "écart d'un pas toléré");
        assert!(verifier_totp(s, &code_totp(s, 1234567890 / 30 - 3), maintenant, None).is_none());
        assert!(verifier_totp(s, "12345", maintenant, None).is_none());
    }

    #[test]
    fn encodages() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(depuis_base32("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(depuis_base64url("Zm9vYg").unwrap(), b"foob");
        // RFC 7636, annexe B.
        assert_eq!(defi_pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(uri_totp("Aplomb", "alice", b"12345678901234567890").contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    }

    fn sso() -> ConfigSso {
        serde_yaml::from_str(
            "{emetteur: 'https://idp', client_id: aplomb, autorisation: 'https://idp/auth', jeton: 'https://idp/token', redirection: 'https://aplomb/sso/retour', roles: {secops: [operateur], dsi: [approbateur, lecteur]}}",
        )
        .unwrap()
    }

    fn jwt(c: Value) -> String {
        format!("e30.{}.sig", base64url(c.to_string().as_bytes()))
    }

    #[test]
    fn jeton_d_identite() {
        let cfg = sso();
        let t = 1_800_000_000_000u64;
        let bon = serde_json::json!({"iss": "https://idp", "aud": ["aplomb"], "exp": 1_800_000_600u64, "iat": 1_800_000_000u64, "nonce": "n1", "email": "paul@ex.fr", "groups": ["secops", "autre"], "amr": ["pwd", "mfa"]});
        let id = valider_id_token(&cfg, &jwt(bon.clone()), "n1", t).unwrap();
        assert_eq!(id.compte, "sso:paul@ex.fr");
        assert_eq!(id.roles, vec![Role::Operateur]);
        assert!(id.mfa);
        let cas = [("iss", serde_json::json!("https://autre"), "émetteur"), ("aud", serde_json::json!("x"), "client"), ("exp", serde_json::json!(1u64), "expiré"), ("nonce", serde_json::json!("n2"), "nonce"), ("groups", serde_json::json!(["x"]), "aucun de ses groupes")];
        for (k, v, attendu) in cas {
            let mut c = bon.clone();
            c[k] = v;
            let e = valider_id_token(&cfg, &jwt(c), "n1", t).unwrap_err();
            assert!(e.contains(attendu), "{k} → {e}");
        }
        let u = url_autorisation(&cfg, "e1", "n1", "v");
        assert!(u.starts_with("https://idp/auth?response_type=code&client_id=aplomb&redirect_uri=https%3A%2F%2Faplomb%2Fsso%2Fretour"));
        assert!(u.contains("code_challenge_method=S256"));
    }

    #[test]
    fn configuration() {
        assert!(ConfigIdentite::default().est_vide());
        let mut s = sso();
        s.jeton = "http://idp.exemple/token".into();
        assert!(s.verifier().unwrap_err().contains("https"));
        let mut s = sso();
        s.roles.clear();
        assert!(s.verifier().is_err());
        let c: ConfigIdentite = serde_yaml::from_str("{mfa: {}, revue: {inactivite_jours: 90}}").unwrap();
        assert!(c.mfa_exigee());
        assert!(c.verifier().is_ok());
        assert!(serde_yaml::from_str::<ConfigIdentite>("{mfa: {}, scim: {}}").is_err());
    }

    #[test]
    fn revue() {
        let mut a = HashMap::new();
        a.insert("alice".to_string(), 1_000u64);
        a.insert("bob".to_string(), 90 * 86_400_000u64);
        let v = inactifs(["alice", "bob", "carole"].into_iter(), &a, 100 * 86_400_000, 30);
        assert_eq!(v, vec![("alice".to_string(), 1_000)]);
    }
}
