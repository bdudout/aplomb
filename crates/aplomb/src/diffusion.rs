//! **Diffusion** du journal vers le SIEM (EF-N1, EF-N2), option désactivée par défaut.
//!
//! Le journal lui-même sert de file persistante : chaque destination garde, par fichier de
//! session, l'endroit jusqu'où elle a reçu (`<journal>/diffusion/<id>.json`). Un SIEM
//! coupé rattrape son retard à son retour, même après un redémarrage d'Aplomb ; rien n'est
//! perdu. Le curseur n'avance qu'après un envoi réussi : en cas d'arrêt brutal entre
//! l'envoi et l'écriture du curseur, un lot peut être renvoyé, avec les mêmes identifiants
//! (dédoublonnés par Elastic, et par l'identifiant `event.id` / `aplomb.event_id` ailleurs).
use std::collections::BTreeMap;
use std::io::{BufRead, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aplomb_core::diffusion::{self, ConfigDiffusion, ContexteSession, Destination, Format};
use aplomb_core::journal::Entree;
use jiff::tz::TimeZone;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

/// Où en est une destination pour un fichier de session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Curseur {
    octets: u64,
    #[serde(default)]
    ctx: ContexteSession,
}

type Curseurs = BTreeMap<String, Curseur>;

/// État d'une destination, affiché dans Aplomb Watch et au démarrage.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EtatDestination {
    pub id: String,
    pub format: String,
    pub cible: String,
    pub envoyes: u64,
    pub lots: u64,
    pub echecs_consecutifs: u32,
    pub derniere_erreur: Option<String>,
    pub dernier_succes_ms: Option<u64>,
    /// Vrai si des entrées attendaient encore au dernier passage.
    pub en_retard: bool,
}

pub type Etats = Arc<Mutex<Vec<EtatDestination>>>;

/// Lit `diffusion.yaml` : `None` si le fichier n'existe pas (option non activée).
pub fn charger(chemin: &Path) -> Result<Option<ConfigDiffusion>, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => ConfigDiffusion::depuis_yaml(&t).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} : {e}", chemin.display())),
    }
}

/// Nom de l'instance : celui du fichier, ou le nom de la machine.
pub fn instance(c: &ConfigDiffusion) -> String {
    if !c.instance.is_empty() {
        return c.instance.clone();
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "aplomb".into())
}

fn cible(d: &Destination) -> String {
    if !d.url.is_empty() {
        d.url.clone()
    } else if !d.adresse.is_empty() {
        format!("{}{}", if d.tls { "tls://" } else { "tcp://" }, d.adresse)
    } else {
        d.fichier.clone()
    }
}

fn chemin_curseurs(journal: &Path, id: &str) -> PathBuf {
    journal.join("diffusion").join(format!("{id}.json"))
}

fn lire_curseurs(journal: &Path, id: &str) -> Curseurs {
    std::fs::read(chemin_curseurs(journal, id)).ok().and_then(|o| serde_json::from_slice(&o).ok()).unwrap_or_default()
}

fn ecrire_curseurs(journal: &Path, id: &str, c: &Curseurs) -> Result<(), String> {
    let chemin = chemin_curseurs(journal, id);
    std::fs::create_dir_all(chemin.parent().expect("parent")).map_err(|e| e.to_string())?;
    let tmp = chemin.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
    f.write_all(&serde_json::to_vec(c).expect("JSON")).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &chemin).map_err(|e| e.to_string())
}

/// Un lot à envoyer et les curseurs qu'il fera avancer.
struct Lot {
    evenements: Vec<Value>,
    curseurs: Curseurs,
    reste: bool,
}

/// Lit les entrées nouvelles du journal pour une destination (lignes complètes seulement).
fn lire_lot(journal: &Path, d: &Destination, curseurs: &Curseurs, inst: &str, tz: &TimeZone) -> Result<Lot, String> {
    let types = d.types_retenus();
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(journal)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    fichiers.sort();
    let mut nouveaux = curseurs.clone();
    let mut evenements = Vec::new();
    let mut reste = false;
    for f in fichiers {
        let nom = f.file_name().unwrap_or_default().to_string_lossy().to_string();
        let mut c = nouveaux.get(&nom).cloned().unwrap_or_default();
        let taille = std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
        if taille <= c.octets {
            continue;
        }
        if evenements.len() >= d.lot {
            reste = true;
            break;
        }
        let mut fichier = std::fs::File::open(&f).map_err(|e| e.to_string())?;
        fichier.seek(SeekFrom::Start(c.octets)).map_err(|e| e.to_string())?;
        let mut lecteur = std::io::BufReader::new(fichier);
        let mut ligne = String::new();
        loop {
            if evenements.len() >= d.lot {
                reste = true;
                break;
            }
            ligne.clear();
            let n = lecteur.read_line(&mut ligne).map_err(|e| e.to_string())?;
            if n == 0 || !ligne.ends_with('\n') {
                break; // ligne en cours d'écriture : au prochain passage
            }
            c.octets += n as u64;
            let Ok(e) = serde_json::from_str::<Entree>(&ligne) else { continue };
            if e.type_ == "session" {
                c.ctx = ContexteSession::depuis_entete(&e);
            }
            if types.contains(&e.type_) {
                evenements.push(diffusion::pivot(&e, &c.ctx, inst, tz));
            }
        }
        nouveaux.insert(nom, c);
    }
    Ok(Lot { evenements, curseurs: nouveaux, reste })
}

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .expect("client HTTP")
    })
}

fn client_ca(ca: &str) -> Result<reqwest::Client, String> {
    let pem = std::fs::read(ca).map_err(|e| format!("ca {ca} : {e}"))?;
    let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| format!("ca {ca} : {e}"))?;
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .add_root_certificate(cert)
        .build()
        .map_err(|e| e.to_string())
}

fn jeton(d: &Destination) -> Result<Option<String>, String> {
    if d.jeton_env.is_empty() {
        return Ok(None);
    }
    match std::env::var(&d.jeton_env) {
        Ok(v) if !v.is_empty() => Ok(Some(v)),
        _ => Err(format!("variable {} absente : la définir avant de lancer aplomb serve", d.jeton_env)),
    }
}

fn maintenant_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

async fn envoyer_http(d: &Destination, evts: &[Value]) -> Result<(), String> {
    let jeton = jeton(d)?;
    let c = if d.ca.is_empty() { client().clone() } else { client_ca(&d.ca)? };
    let mut r = c.post(&d.url);
    let corps: Vec<u8> = match d.format {
        Format::Ecs => {
            r = r.header("content-type", "application/x-ndjson");
            if let Some(j) = &jeton {
                r = r.header("authorization", format!("ApiKey {j}"));
            }
            diffusion::ecs_bulk(evts, if d.index.is_empty() { "aplomb" } else { &d.index }).into_bytes()
        }
        Format::SplunkHec => {
            r = r.header("content-type", "application/json");
            if let Some(j) = &jeton {
                r = r.header("authorization", format!("Splunk {j}"));
            }
            diffusion::splunk_hec(evts).into_bytes()
        }
        Format::Otlp => {
            r = r.header("content-type", "application/json");
            if let Some(j) = &jeton {
                r = r.header("authorization", format!("Bearer {j}"));
            }
            diffusion::otlp(evts).to_string().into_bytes()
        }
        Format::Webhook => {
            let corps = serde_json::to_vec(evts).expect("JSON");
            let t = maintenant_ms() / 1000;
            let secret = jeton.ok_or("secret du webhook absent")?;
            r = r
                .header("content-type", "application/json")
                .header("x-aplomb-schema", diffusion::SCHEMA)
                .header("x-aplomb-horodatage", t.to_string())
                .header("x-aplomb-signature", diffusion::signer_webhook(secret.as_bytes(), t, &corps));
            corps
        }
        f => return Err(format!("format {} : pas d'envoi HTTP", f.nom())),
    };
    let rep = r.body(corps).send().await.map_err(|e| if e.is_timeout() { "délai dépassé".into() } else { format!("injoignable ({e})") })?;
    let statut = rep.status();
    if !statut.is_success() {
        return Err(format!("réponse {}", statut.as_u16()));
    }
    if d.format == Format::Ecs {
        // _bulk répond 200 même si des documents sont refusés : un doublon (409) est
        // attendu après un renvoi, toute autre erreur fait échouer le lot.
        let v: Value = serde_json::from_slice(&rep.bytes().await.map_err(|e| e.to_string())?).unwrap_or_default();
        if v.get("errors").and_then(Value::as_bool) == Some(true) {
            let refus = v["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i.get("create").and_then(|c| c.get("status")).and_then(Value::as_u64))
                .find(|s| !(200..300).contains(s) && *s != 409);
            if let Some(s) = refus {
                return Err(format!("Elastic refuse des documents (statut {s})"));
            }
        }
    }
    Ok(())
}

fn config_tls(ca: &str) -> Result<Arc<tokio_rustls::rustls::ClientConfig>, String> {
    use tokio_rustls::rustls::{self, pki_types::pem::PemObject, pki_types::CertificateDer, RootCertStore};
    let mut racines = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    if !ca.is_empty() {
        for c in CertificateDer::pem_file_iter(ca).map_err(|e| format!("ca {ca} : {e}"))? {
            racines.add(c.map_err(|e| format!("ca {ca} : {e}"))?).map_err(|e| format!("ca {ca} : {e}"))?;
        }
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(racines)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Syslog sur TCP (RFC 6587) ou TLS (RFC 5425), trames préfixées par leur longueur.
async fn envoyer_syslog(d: &Destination, evts: &[Value]) -> Result<(), String> {
    let mut trames = Vec::new();
    for p in evts {
        let l = diffusion::ligne(d.format, p);
        trames.extend_from_slice(format!("{} {l}", l.len()).as_bytes());
    }
    let flux = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&d.adresse))
        .await
        .map_err(|_| "délai dépassé".to_string())?
        .map_err(|e| format!("injoignable ({e})"))?;
    if d.tls {
        let hote = d.adresse.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']'])).unwrap_or(&d.adresse).to_string();
        let nom = tokio_rustls::rustls::pki_types::ServerName::try_from(hote).map_err(|e| e.to_string())?;
        let mut tls = tokio_rustls::TlsConnector::from(config_tls(&d.ca)?)
            .connect(nom, flux)
            .await
            .map_err(|e| format!("TLS : {e}"))?;
        tls.write_all(&trames).await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let _ = tls.shutdown().await;
    } else {
        let mut flux = flux;
        flux.write_all(&trames).await.map_err(|e| e.to_string())?;
        flux.flush().await.map_err(|e| e.to_string())?;
        let _ = flux.shutdown().await;
    }
    Ok(())
}

fn ecrire_fichier(d: &Destination, evts: &[Value]) -> Result<(), String> {
    if let Some(p) = Path::new(&d.fichier).parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&d.fichier).map_err(|e| format!("{} : {e}", d.fichier))?;
    let mut tampon = String::new();
    for p in evts {
        tampon.push_str(&diffusion::ligne(d.format, p));
        tampon.push('\n');
    }
    f.write_all(tampon.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_data().map_err(|e| e.to_string())
}

/// Envoie un lot à une destination.
pub async fn envoyer(d: &Destination, evts: &[Value]) -> Result<(), String> {
    if evts.is_empty() {
        return Ok(());
    }
    if !d.fichier.is_empty() {
        ecrire_fichier(d, evts)
    } else if !d.adresse.is_empty() {
        envoyer_syslog(d, evts).await
    } else {
        envoyer_http(d, evts).await
    }
}

/// Un passage : lit, envoie, avance les curseurs. Rend (envoyés, reste-t-il des entrées).
async fn passage(journal: &Path, d: &Destination, curseurs: &mut Curseurs, inst: &str, tz: &TimeZone) -> Result<(usize, bool), String> {
    let lot = lire_lot(journal, d, curseurs, inst, tz)?;
    envoyer(d, &lot.evenements).await?;
    if lot.curseurs.iter().any(|(k, c)| curseurs.get(k).map(|x| x.octets) != Some(c.octets)) {
        ecrire_curseurs(journal, &d.id, &lot.curseurs)?;
        *curseurs = lot.curseurs;
    }
    Ok((lot.evenements.len(), lot.reste))
}

/// Lance une tâche par destination, et la surveillance de l'horloge. `alerte` journalise
/// un événement d'administration (dérive d'horloge, destination en échec prolongé).
pub fn lancer(cfg: ConfigDiffusion, journal: PathBuf, alerte: Arc<dyn Fn(Value) + Send + Sync>) -> Etats {
    let inst = instance(&cfg);
    let tz = cfg.fuseau().unwrap_or_else(|_| TimeZone::system());
    let etats: Etats = Arc::new(Mutex::new(
        cfg.destinations
            .iter()
            .map(|d| EtatDestination { id: d.id.clone(), format: d.format.nom().into(), cible: cible(d), ..Default::default() })
            .collect(),
    ));
    for (i, d) in cfg.destinations.into_iter().enumerate() {
        let (journal, inst, tz, etats, alerte) = (journal.clone(), inst.clone(), tz.clone(), etats.clone(), alerte.clone());
        tokio::spawn(async move {
            let mut curseurs = lire_curseurs(&journal, &d.id);
            let mut attente = Duration::from_millis(500);
            loop {
                let issue = passage(&journal, &d, &mut curseurs, &inst, &tz).await;
                let mut signaler = None;
                {
                    let mut e = etats.lock().expect("verrou");
                    let e = &mut e[i];
                    match &issue {
                        Ok((n, reste)) => {
                            if *n > 0 {
                                e.envoyes += *n as u64;
                                e.lots += 1;
                                e.dernier_succes_ms = Some(maintenant_ms());
                            }
                            if e.echecs_consecutifs >= 5 {
                                signaler = Some(json!({"action": "diffusion-retablie", "destination": d.id}));
                            }
                            e.echecs_consecutifs = 0;
                            e.derniere_erreur = None;
                            e.en_retard = *reste;
                        }
                        Err(err) => {
                            e.echecs_consecutifs += 1;
                            e.derniere_erreur = Some(err.clone());
                            e.en_retard = true;
                            if e.echecs_consecutifs == 5 {
                                signaler = Some(json!({"action": "diffusion-en-echec", "destination": d.id, "erreur": err}));
                            }
                        }
                    }
                }
                if let Some(s) = signaler {
                    alerte(s);
                }
                attente = match issue {
                    Ok((_, true)) => Duration::from_millis(0),
                    Ok(_) => Duration::from_millis(500),
                    Err(_) => (attente * 2).clamp(Duration::from_millis(500), Duration::from_secs(30)),
                };
                tokio::time::sleep(attente).await;
            }
        });
    }
    // Dérive d'horloge (EF-N2) : l'horloge murale doit avancer comme le temps monotone.
    tokio::spawn(async move {
        let mut mur = maintenant_ms();
        let mut mono = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let (m2, i2) = (maintenant_ms(), Instant::now());
            if let Some(ecart) = diffusion::derive_horloge(mur, m2, i2.duration_since(mono).as_millis() as u64, 2000) {
                alerte(json!({"action": "derive-horloge", "ecart_ms": ecart}));
            }
            (mur, mono) = (m2, i2);
        }
    });
    etats
}

/// Ligne de démarrage.
pub fn annonce(cfg: Option<&ConfigDiffusion>) -> String {
    match cfg {
        None => "aucune (option : aplomb diffusion exemple > diffusion.yaml)".into(),
        Some(c) if c.destinations.is_empty() => "aucune destination dans diffusion.yaml".into(),
        Some(c) => {
            let fuseau = c.fuseau().ok().and_then(|t| t.iana_name().map(String::from)).unwrap_or_else(|| "système".into());
            let d: Vec<String> = c.destinations.iter().map(|d| format!("{} ({})", d.id, d.format.nom())).collect();
            format!("{} ; fuseau {fuseau}", d.join(", "))
        }
    }
}

/// Vérifie que les variables des jetons sont définies (au démarrage de serve).
pub fn jetons_presents(c: &ConfigDiffusion) -> Result<(), String> {
    for d in &c.destinations {
        jeton(d).map_err(|e| format!("diffusion, destination « {} » : {e}", d.id))?;
    }
    Ok(())
}

// ---------------------------------------------------------------- commandes

/// `aplomb diffusion verifier` : le fichier, les variables, et ce qui partira.
pub fn verifier(config: &Path) -> Result<(), String> {
    let Some(c) = charger(config)? else {
        return Err(format!("{} absent : la diffusion n'est pas activée (aplomb diffusion exemple > {})", config.display(), config.display()));
    };
    let tz = c.fuseau()?;
    println!("instance : {}", instance(&c));
    println!("fuseau   : {} (UTC toujours joint)", tz.iana_name().unwrap_or("système"));
    let mut manque = Vec::new();
    for d in &c.destinations {
        let types: Vec<String> = d.types_retenus().into_iter().collect();
        println!("- {} : {} vers {} ; types {}", d.id, d.format.nom(), cible(d), types.join(", "));
        if let Err(e) = jeton(d) {
            manque.push(format!("{} : {e}", d.id));
        }
    }
    if !manque.is_empty() {
        return Err(manque.join("\n"));
    }
    println!("configuration valide");
    Ok(())
}

/// `aplomb diffusion apercu` : la dernière décision du journal dans chaque format.
pub fn apercu(config: &Path, journal: &Path) -> Result<(), String> {
    let c = charger(config)?.unwrap_or_default();
    let tz = c.fuseau()?;
    let mut derniere: Option<(Entree, ContexteSession)> = None;
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(journal)
        .map_err(|e| format!("{} : {e}", journal.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    fichiers.sort();
    for f in fichiers {
        let texte = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
        let mut ctx = ContexteSession::default();
        for l in texte.lines() {
            let Ok(e) = serde_json::from_str::<Entree>(l) else { continue };
            if e.type_ == "session" {
                ctx = ContexteSession::depuis_entete(&e);
            }
            if e.type_ == "decision" && derniere.as_ref().is_none_or(|(d, _)| e.horodatage >= d.horodatage) {
                derniere = Some((e, ctx.clone()));
            }
        }
    }
    let (e, ctx) = derniere.ok_or("aucune décision dans le journal")?;
    let p = diffusion::pivot(&e, &ctx, &instance(&c), &tz);
    println!("{}", serde_json::to_string_pretty(&Value::Object(diffusion::apercu(&p))).expect("JSON"));
    Ok(())
}

/// `aplomb diffusion tester` : envoie un événement de test à une destination.
pub fn tester(config: &Path, id: &str) -> Result<(), String> {
    let c = charger(config)?.ok_or_else(|| format!("{} absent", config.display()))?;
    let d = c.destinations.iter().find(|d| d.id == id).ok_or_else(|| {
        let ids: Vec<&str> = c.destinations.iter().map(|d| d.id.as_str()).collect();
        format!("destination « {id} » inconnue ({})", ids.join(", "))
    })?;
    let t = maintenant_ms();
    let e = Entree {
        seq: 0,
        horodatage: t,
        session: "aplomb-test-diffusion".into(),
        type_: "administration".into(),
        contenu: json!({"action": "test-diffusion"}),
        precedent: aplomb_core::journal::GENESE.into(),
        empreinte: format!("test-{t}"),
    };
    let p = diffusion::pivot(&e, &ContexteSession::default(), &instance(&c), &c.fuseau()?);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(envoyer(d, &[p]))?;
    println!("événement de test envoyé à {} ({})", d.id, cible(d));
    Ok(())
}

/// État des destinations pour `GET /admin/diffusion`.
pub fn etat_json(etats: Option<&Etats>) -> Value {
    match etats {
        None => json!({"active": false, "destinations": []}),
        Some(e) => json!({"active": true, "destinations": *e.lock().expect("verrou")}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecrire(dossier: &Path, nom: &str, lignes: &[Value]) {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dossier.join(nom)).unwrap();
        for l in lignes {
            writeln!(f, "{l}").unwrap();
        }
    }

    fn entree(seq: u64, type_: &str, contenu: Value) -> Value {
        json!({"seq": seq, "horodatage": 1_763_114_400_000u64 + seq, "session": "s", "type": type_, "contenu": contenu, "precedent": "p", "empreinte": format!("e{seq}")})
    }

    #[test]
    fn file_sans_perte_ni_doublon() {
        let d = std::env::temp_dir().join(format!("aplomb-diff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        ecrire(&d, "s.jsonl", &[entree(1, "session", json!({"mandat": "m1", "agent": "a"})), entree(2, "decision", json!({"verdict": "allow"}))]);
        let dest: Destination = serde_yaml::from_str("{id: t, format: json, fichier: x, lot: 2}").unwrap();
        let tz = TimeZone::UTC;
        let mut c = Curseurs::new();
        let l = lire_lot(&d, &dest, &c, "i", &tz).unwrap();
        assert_eq!(l.evenements.len(), 2);
        assert_eq!(l.evenements[1]["systeme"], "m1", "contexte de l'en-tête");
        c = l.curseurs;
        // Une ligne en cours d'écriture n'est pas lue.
        std::fs::OpenOptions::new().append(true).open(d.join("s.jsonl")).unwrap().write_all(b"{\"seq\":3").unwrap();
        assert!(lire_lot(&d, &dest, &c, "i", &tz).unwrap().evenements.is_empty());
        std::fs::OpenOptions::new()
            .append(true)
            .open(d.join("s.jsonl"))
            .unwrap()
            .write_all(b",\"horodatage\":1,\"session\":\"s\",\"type\":\"observation\",\"contenu\":{},\"precedent\":\"p\",\"empreinte\":\"e3\"}\n")
            .unwrap();
        ecrire(&d, "s.jsonl", &[entree(4, "decision", json!({})), entree(5, "decision", json!({})), entree(6, "decision", json!({}))]);
        let l = lire_lot(&d, &dest, &c, "i", &tz).unwrap();
        assert_eq!(l.evenements.iter().map(|e| e["seq"].as_u64().unwrap()).collect::<Vec<_>>(), vec![4, 5], "observation filtrée, lot de 2");
        assert!(l.reste);
        assert_eq!(l.evenements[0]["systeme"], "m1", "contexte gardé par le curseur");
        ecrire_curseurs(&d, "t", &l.curseurs).unwrap();
        let c = lire_curseurs(&d, "t");
        let l = lire_lot(&d, &dest, &c, "i", &tz).unwrap();
        assert_eq!(l.evenements.len(), 1);
        assert_eq!(l.evenements[0]["seq"], 6);
        let _ = std::fs::remove_dir_all(&d);
    }
}
