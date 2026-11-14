//! **Identité** côté service et ligne de commande (EF-N3 à EF-N5) : secrets TOTP enveloppés,
//! activité des comptes et suspension, connexion SSO (OpenID Connect).
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aplomb_core::autorite::{Autorite, FichierComptes};
use aplomb_core::confidentiel::{envelopper, lire_secret, Cle};
use aplomb_core::identite::{self, ConfigSso, IdentiteSso};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ------------------------------------------------------------------ TOTP

fn dossier_mfa() -> PathBuf {
    crate::cle_maitresse::dossier_config().join("mfa")
}

fn etiquette(compte: &str) -> String {
    format!("totp:{compte}")
}

fn chemin_secret(compte: &str, attente: bool) -> PathBuf {
    dossier_mfa().join(format!("{compte}.totp{}", if attente { ".attente" } else { "" }))
}

fn ecrire(chemin: &Path, texte: &str) -> Result<(), String> {
    use std::io::Write;
    std::fs::create_dir_all(chemin.parent().expect("parent")).map_err(|e| e.to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(chemin).and_then(|mut f| f.write_all(texte.as_bytes())).map_err(|e| format!("{} : {e}", chemin.display()))
}

/// `aplomb compte mfa --compte <id>` : crée le secret (en attente), affiche l'adresse à
/// donner à l'application ; avec `--code`, confirme et active le second facteur.
pub fn enroler(compte: &str, code: Option<&str>) -> Result<(), String> {
    let maitre = crate::cle_maitresse::cle_maitresse()?;
    let attente = chemin_secret(compte, true);
    match code {
        None => {
            let mut secret = [0u8; 20];
            getrandom::getrandom(&mut secret).map_err(|e| e.to_string())?;
            ecrire(&attente, &envelopper(&maitre, &etiquette(compte), &secret))?;
            println!("Ajouter ce compte à l'application d'authentification (Aegis, FreeOTP, Google Authenticator…) :");
            println!("  {}", identite::uri_totp("Aplomb", compte, &secret));
            println!("  ou saisir la clé : {}", identite::base32(&secret));
            println!("Puis confirmer : aplomb compte mfa --compte {compte} --code <code affiché>");
            Ok(())
        }
        Some(c) => {
            let texte = std::fs::read_to_string(&attente).map_err(|_| format!("aucun second facteur en attente : aplomb compte mfa --compte {compte}"))?;
            let secret = lire_secret(&texte, Some(&maitre), &etiquette(compte))?;
            if identite::verifier_totp(&secret, c, maintenant(), None).is_none() {
                return Err("code incorrect : vérifier l'heure du téléphone, et saisir le code affiché maintenant".into());
            }
            std::fs::rename(&attente, chemin_secret(compte, false)).map_err(|e| e.to_string())?;
            println!("second facteur actif pour {compte} (empreinte {})", identite::empreinte_secret(&secret));
            println!("redémarrer `aplomb serve` pour le prendre en compte");
            Ok(())
        }
    }
}

/// Secrets TOTP actifs des comptes, et dernier pas utilisé (pas de rejeu d'un code).
#[derive(Default)]
pub struct Mfa {
    secrets: HashMap<String, (Vec<u8>, Option<u64>)>,
}

impl Mfa {
    pub fn charger(maitre: &Cle, comptes: &[String]) -> Result<Self, String> {
        let mut secrets = HashMap::new();
        for c in comptes {
            if let Ok(texte) = std::fs::read_to_string(chemin_secret(c, false)) {
                secrets.insert(c.clone(), (lire_secret(&texte, Some(maitre), &etiquette(c))?, None));
            }
        }
        Ok(Self { secrets })
    }

    pub fn enroles(&self) -> usize {
        self.secrets.len()
    }

    /// Vérifie un code ; retient le pas utilisé.
    pub fn verifier(&mut self, compte: &str, code: &str) -> bool {
        let Some((secret, dernier)) = self.secrets.get_mut(compte) else { return false };
        match identite::verifier_totp(secret, code, maintenant(), *dernier) {
            Some(p) => {
                *dernier = Some(p);
                true
            }
            None => false,
        }
    }
}

// ------------------------------------------------------------------ activité des comptes

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EtatCompte {
    /// Dernière activité (ms) : requête signée, connexion, approbation. À la première
    /// lecture d'un compte, l'heure où il a été vu.
    pub derniere: u64,
    #[serde(default)]
    pub suspendu: bool,
}

/// Fichier d'activité de l'instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Activite {
    #[serde(flatten)]
    pub comptes: HashMap<String, EtatCompte>,
    #[serde(skip)]
    chemin: PathBuf,
}

impl Activite {
    pub fn charger(chemin: &Path) -> Result<Self, String> {
        let mut a: Activite = match std::fs::read(chemin) {
            Ok(o) => serde_json::from_slice(&o).map_err(|e| format!("{} : {e}", chemin.display()))?,
            Err(_) => Activite::default(),
        };
        a.chemin = chemin.to_path_buf();
        Ok(a)
    }

    pub fn enregistrer(&self) -> Result<(), String> {
        let tmp = self.chemin.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.comptes).expect("JSON")).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.chemin).map_err(|e| e.to_string())
    }

    /// Note une activité (comptes déclarés seulement ; le SSO a sa propre gestion).
    pub fn noter(&mut self, compte: &str, t: u64) {
        if let Some(e) = self.comptes.get_mut(compte) {
            e.derniere = t;
            let _ = self.enregistrer();
        }
    }

    /// Comptes connus de l'autorité : nouveaux enregistrés « vus maintenant », suspendus
    /// réappliqués, puis suspension de ceux devenus inactifs. Rend les nouvelles suspensions.
    pub fn appliquer(&mut self, autorite: &mut Autorite, t: u64) -> Vec<(String, u64)> {
        for c in autorite.comptes() {
            self.comptes.entry(c).or_insert(EtatCompte { derniere: t, suspendu: false });
        }
        for (c, e) in &self.comptes {
            if e.suspendu {
                autorite.suspendre(c);
            }
        }
        let mut nouvelles = Vec::new();
        if let Some(r) = &autorite.identite().revue {
            let activite: HashMap<String, u64> = self.comptes.iter().filter(|(_, e)| !e.suspendu).map(|(c, e)| (c.clone(), e.derniere)).collect();
            let comptes = autorite.comptes();
            for (c, derniere) in identite::inactifs(comptes.iter().map(String::as_str), &activite, t, r.inactivite_jours) {
                autorite.suspendre(&c);
                self.comptes.get_mut(&c).expect("présent").suspendu = true;
                nouvelles.push((c, derniere));
            }
        }
        if !nouvelles.is_empty() || self.chemin.exists() || !self.comptes.is_empty() {
            let _ = self.enregistrer();
        }
        nouvelles
    }

    pub fn reactiver(&mut self, compte: &str, t: u64) {
        if let Some(e) = self.comptes.get_mut(compte) {
            e.suspendu = false;
            e.derniere = t;
        }
        let _ = self.enregistrer();
    }
}

/// `aplomb compte revue` : comptes, rôles, dernière activité, statut ; avec `--attestation`,
/// écrit la campagne de revue à faire cosigner (`aplomb cosigner`), versée au dossier de
/// preuves (EF-N5).
pub fn revue(comptes: &Path, activite: &Path, attestation: Option<&Path>) -> Result<(), String> {
    let f: FichierComptes = serde_yaml::from_str(&std::fs::read_to_string(comptes).map_err(|e| format!("{} : {e}", comptes.display()))?)
        .map_err(|e| e.to_string())?;
    let a = Activite::charger(activite)?;
    let t = maintenant();
    let seuil = f.identite.revue.as_ref().map(|r| r.inactivite_jours);
    println!("Revue des comptes — {} ; seuil d'inactivité : {}", comptes.display(), seuil.map(|j| format!("{j} jours")).unwrap_or_else(|| "non activé (identite.revue)".into()));
    let mut lignes = Vec::new();
    for c in &f.comptes {
        let e = a.comptes.get(&c.id);
        let jours = e.map(|e| t.saturating_sub(e.derniere) / 86_400_000);
        let statut = match (e, seuil) {
            (Some(e), _) if e.suspendu => "suspendu",
            (Some(_), Some(s)) if jours.unwrap_or(0) >= s => "à suspendre",
            (None, _) => "jamais vu",
            _ => "actif",
        };
        let roles: Vec<String> = c.roles.iter().map(|r| format!("{r:?}").to_lowercase()).collect();
        println!(
            "  {:<16} {:<28} {:<22} {statut}{}",
            c.id,
            roles.join(", "),
            jours.map(|j| format!("il y a {j} j")).unwrap_or_else(|| "—".into()),
            if c.roles.len() > 1 { "  (cumul de rôles)" } else { "" }
        );
        lignes.push(serde_json::json!({"id": c.id, "roles": roles, "inactif_depuis_jours": jours, "statut": statut, "mfa": chemin_secret(&c.id, false).exists()}));
    }
    if let Some(p) = attestation {
        let campagne = serde_json::json!({
            "campagne": {"date": jiff::Timestamp::from_millisecond(t as i64).map(|x| x.to_string()).unwrap_or_default(),
                         "fichier_comptes": comptes.display().to_string(), "seuil_jours": seuil,
                         "mfa_exigee": f.identite.mfa_exigee(), "sso": f.identite.sso.is_some(), "comptes": lignes,
                         "constat": "À compléter par les réviseurs : comptes à retirer, rôles à réduire."}
        });
        if let Some(d) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        std::fs::write(p, serde_yaml::to_string(&campagne).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        println!("campagne écrite : {} — la compléter, puis la faire cosigner : aplomb cosigner {} --compte <id> --compte <id>", p.display(), p.display());
    }
    Ok(())
}

// ------------------------------------------------------------------ SSO

/// Connexions SSO en cours : état → (nonce, vérificateur PKCE, échéance).
#[derive(Default)]
pub struct AttentesSso(HashMap<String, (String, String, u64)>);

fn aleatoire() -> String {
    let mut o = [0u8; 32];
    getrandom::getrandom(&mut o).expect("aléa");
    identite::base64url(&o)
}

impl AttentesSso {
    /// Prépare une connexion : adresse du fournisseur d'identité.
    pub fn debut(&mut self, cfg: &ConfigSso, t: u64) -> String {
        self.0.retain(|_, (_, _, e)| *e > t);
        let (etat, nonce, verif) = (aleatoire(), aleatoire(), aleatoire());
        let url = identite::url_autorisation(cfg, &etat, &nonce, &verif);
        self.0.insert(etat, (nonce, verif, t + 600_000));
        url
    }

    /// Consomme l'état (usage unique) : (nonce, vérificateur).
    pub fn prendre(&mut self, etat: &str, t: u64) -> Option<(String, String)> {
        self.0.retain(|_, (_, _, e)| *e > t);
        self.0.remove(etat).map(|(n, v, _)| (n, v))
    }
}

fn encoder(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Échange le code contre le jeton d'identité, puis le valide.
pub async fn retour(cfg: &ConfigSso, code: &str, nonce: &str, verificateur: &str) -> Result<IdentiteSso, String> {
    let mut corps = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        encoder(code),
        encoder(&cfg.redirection),
        encoder(&cfg.client_id),
        encoder(verificateur)
    );
    if !cfg.secret_env.is_empty() {
        let s = std::env::var(&cfg.secret_env).map_err(|_| format!("variable {} absente", cfg.secret_env))?;
        corps.push_str(&format!("&client_secret={}", encoder(&s)));
    }
    let r = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?
        .post(&cfg.jeton)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(corps)
        .send()
        .await
        .map_err(|_| "fournisseur d'identité injoignable".to_string())?;
    if !r.status().is_success() {
        return Err(format!("fournisseur d'identité : réponse {}", r.status().as_u16()));
    }
    let v: Value = serde_json::from_slice(&r.bytes().await.map_err(|e| e.to_string())?).map_err(|_| "réponse du fournisseur illisible")?;
    let jwt = v.get("id_token").and_then(Value::as_str).ok_or("réponse du fournisseur sans id_token")?;
    identite::valider_id_token(cfg, jwt, nonce, maintenant())
}

/// Vérifie au démarrage que le secret du client SSO est défini.
pub fn verifier_sso(cfg: &ConfigSso) -> Result<(), String> {
    if !cfg.secret_env.is_empty() && std::env::var(&cfg.secret_env).map(|s| s.is_empty()).unwrap_or(true) {
        return Err(format!("SSO : variable {} absente (secret du client)", cfg.secret_env));
    }
    Ok(())
}

pub fn maintenant() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Page de saisie du code, à la connexion à la vue avec la MFA.
pub fn page_code(ticket: &str, erreur: Option<&str>) -> String {
    let ticket: String = ticket.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aplomb — second facteur</title>
<style>body{{font-family:system-ui,sans-serif;max-width:360px;margin:15vh auto;padding:0 16px;color:#1b1f24;background:#f6f7f9}}input{{font-size:1.4rem;letter-spacing:.3em;width:100%;padding:.5rem;box-sizing:border-box}}button{{margin-top:1rem;width:100%;padding:.6rem;font-size:1rem}}.e{{color:#b42318}}</style></head>
<body><h1>Second facteur</h1><p>Saisir le code à 6 chiffres de l'application d'authentification.</p>{}
<form method="post" action="/connexion"><input type="hidden" name="ticket" value="{ticket}"><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" maxlength="6" autofocus required><button>Ouvrir Aplomb Watch</button></form></body></html>"#,
        erreur.map(|e| format!(r#"<p class="e">{e}</p>"#)).unwrap_or_default()
    )
}
