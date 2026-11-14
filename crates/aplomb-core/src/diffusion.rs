//! **Diffusion** du journal vers les outils de l'entreprise (étape 8, EF-N1, EF-N2) :
//! Elastic (ECS), Splunk (HEC), syslog RFC 5424, CEF, LEEF, OpenTelemetry (OTLP/JSON),
//! webhook signé, ou fichier pour un agent de collecte.
//!
//! Option désactivée par défaut : sans fichier `diffusion.yaml`, rien ne sort (EF-N6).
//!
//! Chaque entrée du journal devient un **événement pivot** versionné (`aplomb/1`), puis
//! il est mis au format de la destination. Le pivot ne reprend que les champs en clair du
//! journal : les contenus chiffrés par session (commande, chemin, domaine…) ne sortent
//! jamais. L'identifiant de l'événement est l'empreinte de l'entrée : un SIEM peut
//! dédoublonner, et Elastic le fait de lui-même (`_id`).
//!
//! Horodatage (EF-N2) : RFC 3339 avec le décalage du fuseau IANA choisi, et l'heure UTC
//! toujours jointe.
use std::collections::BTreeSet;

use hmac::{Hmac, Mac};
use jiff::tz::TimeZone;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::journal::Entree;

/// Version du schéma pivot.
pub const SCHEMA: &str = "aplomb/1";
/// Numéro d'entreprise privé utilisé dans les données structurées syslog (exemple IANA
/// réservé à la documentation, RFC 5612).
pub const PEN: u32 = 32473;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Format d'une destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// Elastic Common Schema, envoyé par l'API `_bulk` (dédoublonné par `_id`).
    Ecs,
    /// Splunk HTTP Event Collector.
    SplunkHec,
    /// Syslog RFC 5424 (sur TLS, RFC 5425).
    Syslog,
    /// ArcSight Common Event Format.
    Cef,
    /// IBM QRadar Log Event Extended Format 2.0.
    Leef,
    /// OpenTelemetry, logs OTLP/HTTP en JSON.
    Otlp,
    /// Webhook : lot d'événements pivots signé par HMAC-SHA256.
    Webhook,
    /// Événement pivot brut, une ligne JSON par événement.
    Json,
}

impl Format {
    pub const TOUS: [Format; 8] =
        [Format::Ecs, Format::SplunkHec, Format::Syslog, Format::Cef, Format::Leef, Format::Otlp, Format::Webhook, Format::Json];

    pub fn nom(self) -> &'static str {
        match self {
            Format::Ecs => "ecs",
            Format::SplunkHec => "splunk-hec",
            Format::Syslog => "syslog",
            Format::Cef => "cef",
            Format::Leef => "leef",
            Format::Otlp => "otlp",
            Format::Webhook => "webhook",
            Format::Json => "json",
        }
    }

    /// Formats qui partent en lignes de texte (syslog, fichier).
    pub fn en_lignes(self) -> bool {
        matches!(self, Format::Syslog | Format::Cef | Format::Leef | Format::Json)
    }
}

/// Fichier `diffusion.yaml` de l'instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDiffusion {
    /// Nom de l'instance dans le SIEM (défaut : nom de la machine).
    #[serde(default)]
    pub instance: String,
    /// Fuseau IANA des horodatages (défaut : celui du système). L'UTC est toujours joint.
    #[serde(default)]
    pub fuseau: String,
    #[serde(default)]
    pub destinations: Vec<Destination>,
}

/// Une destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub id: String,
    pub format: Format,
    /// URL (ecs, splunk-hec, otlp, webhook).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// `hôte:port` (syslog, cef, leef par syslog).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub adresse: String,
    /// Fichier local (tout format en lignes) : pour Filebeat, Splunk UF, Fluent Bit…
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fichier: String,
    /// TLS pour syslog (défaut : oui ; en clair, seulement vers la machine elle-même).
    #[serde(default = "vrai")]
    pub tls: bool,
    /// Autorité de certification supplémentaire (PEM), pour un SIEM à certificat interne.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca: String,
    /// Variable d'environnement qui porte le jeton (Splunk, Elastic, OTLP) ou le secret
    /// du webhook. Jamais le jeton lui-même dans le fichier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jeton_env: String,
    /// Index Elastic (défaut : aplomb).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub index: String,
    /// Types d'entrées envoyés (défaut : session, decision, administration).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
    /// Événements par envoi (défaut 200).
    #[serde(default = "lot")]
    pub lot: usize,
}

fn vrai() -> bool {
    true
}
fn lot() -> usize {
    200
}

pub const TYPES_DEFAUT: [&str; 3] = ["session", "decision", "administration"];

fn hote_local(h: &str) -> bool {
    let h = h.trim_start_matches('[').split(']').next().unwrap_or(h);
    matches!(h, "localhost" | "127.0.0.1" | "::1") || h.starts_with("127.")
}

/// Hôte d'une URL `http(s)://hôte[:port]/…`.
pub fn hote_url(url: &str) -> Option<(&str, &str)> {
    let (schema, reste) = url.split_once("://")?;
    let autorite = reste.split('/').next()?;
    let hote = if autorite.starts_with('[') {
        autorite.split(']').next().map(|h| &h[1..])?
    } else {
        autorite.rsplit_once(':').map(|(h, _)| h).unwrap_or(autorite)
    };
    Some((schema, hote))
}

impl Destination {
    pub fn types_retenus(&self) -> BTreeSet<String> {
        if self.types.is_empty() {
            TYPES_DEFAUT.iter().map(|s| s.to_string()).collect()
        } else {
            self.types.iter().cloned().collect()
        }
    }

    /// Ce qu'il faut corriger, dit avec les mots de l'utilisateur.
    pub fn verifier(&self) -> Result<(), String> {
        let ou = format!("diffusion, destination « {} »", self.id);
        if self.id.is_empty() || !self.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("{ou} : id fait de lettres, chiffres, - et _"));
        }
        let cibles = [!self.url.is_empty(), !self.adresse.is_empty(), !self.fichier.is_empty()].iter().filter(|x| **x).count();
        if cibles != 1 {
            return Err(format!("{ou} : indiquer une seule cible, url, adresse (syslog) ou fichier"));
        }
        if !self.url.is_empty() {
            if self.format.en_lignes() {
                return Err(format!("{ou} : le format {} part par adresse (syslog) ou fichier, pas par url", self.format.nom()));
            }
            let Some((schema, hote)) = hote_url(&self.url) else { return Err(format!("{ou} : url illisible : {}", self.url)) };
            match schema {
                "https" => {}
                "http" if hote_local(hote) => {}
                "http" => return Err(format!("{ou} : HTTP en clair seulement vers la machine elle-même ; utiliser https://")),
                _ => return Err(format!("{ou} : url en http:// ou https://")),
            }
        }
        if !self.adresse.is_empty() {
            if !matches!(self.format, Format::Syslog | Format::Cef | Format::Leef) {
                return Err(format!("{ou} : une adresse syslog sert aux formats syslog, cef ou leef"));
            }
            let Some((hote, port)) = self.adresse.rsplit_once(':') else {
                return Err(format!("{ou} : adresse attendue sous la forme hôte:port (6514 pour syslog sur TLS)"));
            };
            if port.parse::<u16>().is_err() {
                return Err(format!("{ou} : port invalide dans {}", self.adresse));
            }
            if !self.tls && !hote_local(hote) {
                return Err(format!("{ou} : syslog en clair seulement vers la machine elle-même ; laisser tls: true"));
            }
        }
        if !self.fichier.is_empty() && !self.format.en_lignes() {
            return Err(format!("{ou} : un fichier reçoit les formats json, syslog, cef ou leef"));
        }
        if self.format == Format::Webhook && self.jeton_env.is_empty() {
            return Err(format!("{ou} : un webhook est signé ; indiquer jeton_env (variable qui porte le secret)"));
        }
        if self.lot == 0 || self.lot > 5000 {
            return Err(format!("{ou} : lot entre 1 et 5000"));
        }
        for t in &self.types {
            if !["session", "decision", "observation", "administration", "modele"].contains(&t.as_str()) {
                return Err(format!("{ou} : type « {t} » inconnu (session, decision, observation, administration, modele)"));
            }
        }
        Ok(())
    }
}

impl ConfigDiffusion {
    /// Lit et vérifie le fichier.
    pub fn depuis_yaml(texte: &str) -> Result<Self, String> {
        let c: ConfigDiffusion = serde_yaml::from_str(texte).map_err(|e| format!("diffusion.yaml : {e}"))?;
        c.verifier()?;
        Ok(c)
    }

    pub fn verifier(&self) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        for d in &self.destinations {
            d.verifier()?;
            if !ids.insert(&d.id) {
                return Err(format!("diffusion : destination « {} » déclarée deux fois", d.id));
            }
        }
        self.fuseau()?;
        Ok(())
    }

    /// Fuseau choisi, ou celui du système.
    pub fn fuseau(&self) -> Result<TimeZone, String> {
        if self.fuseau.is_empty() {
            Ok(TimeZone::system())
        } else {
            TimeZone::get(&self.fuseau).map_err(|_| format!("diffusion : fuseau « {} » inconnu (exemple : Europe/Paris, UTC)", self.fuseau))
        }
    }
}

/// Horodatages d'un événement (EF-N2).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Horodatage {
    /// RFC 3339 dans le fuseau choisi, à la milliseconde.
    pub local: String,
    /// RFC 3339 en UTC (suffixe Z).
    pub utc: String,
    /// Nom IANA du fuseau, ou décalage s'il n'en a pas.
    pub fuseau: String,
    pub epoch_ms: u64,
}

pub fn horodater(ms: u64, tz: &TimeZone) -> Horodatage {
    let ts = Timestamp::from_millisecond(ms as i64).unwrap_or(Timestamp::UNIX_EPOCH);
    let z = ts.to_zoned(tz.clone());
    Horodatage {
        local: z.strftime("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string(),
        utc: ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        fuseau: z.strftime("%:Q").to_string(),
        epoch_ms: ms,
    }
}

/// Dérive d'horloge (EF-N2) : écart entre le temps écoulé à l'horloge murale et au temps
/// monotone, au-delà de `seuil_ms`.
pub fn derive_horloge(mur_avant_ms: u64, mur_apres_ms: u64, monotone_ms: u64, seuil_ms: u64) -> Option<i64> {
    let ecart = (mur_apres_ms as i64 - mur_avant_ms as i64) - monotone_ms as i64;
    (ecart.unsigned_abs() > seuil_ms).then_some(ecart)
}

/// Contexte d'une session, lu dans son en-tête.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContexteSession {
    #[serde(default)]
    pub systeme: String,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub profil: String,
}

impl ContexteSession {
    pub fn depuis_entete(e: &Entree) -> Self {
        let s = |k: &str| e.contenu.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        ContexteSession { systeme: s("mandat"), agent: s("agent"), profil: s("profil") }
    }
}

/// Gravité de 0 à 10.
fn gravite(type_: &str, verdict: &str, action: &str) -> u8 {
    match (type_, verdict) {
        ("decision", "gel") => 10,
        ("decision", "deny") => 7,
        ("decision", "review") => 5,
        ("decision", _) => 1,
        ("administration", _) if action.contains("gel") => 8,
        ("administration", _) => 3,
        _ => 1,
    }
}

/// Événement pivot `aplomb/1` d'une entrée du journal. N'emploie que les champs en clair.
pub fn pivot(e: &Entree, ctx: &ContexteSession, instance: &str, tz: &TimeZone) -> Value {
    let h = horodater(e.horodatage, tz);
    let c = &e.contenu;
    let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let verdict = s("verdict");
    let action = s("action");
    let mut v = json!({
        "schema": SCHEMA, "id": e.empreinte,
        "horodatage": h.local, "horodatage_utc": h.utc, "fuseau": h.fuseau, "epoch_ms": h.epoch_ms,
        "instance": instance, "systeme": ctx.systeme, "agent": ctx.agent, "profil": ctx.profil,
        "session": e.session, "seq": e.seq, "type": e.type_,
        "gravite": gravite(&e.type_, &verdict, &action),
        "empreinte": e.empreinte, "precedent": e.precedent,
    });
    let o = v.as_object_mut().expect("objet");
    for k in ["verdict", "regle", "outil", "verbe", "motif", "action", "compte", "demandeur", "approbateur", "mode", "deploiement"] {
        if let Some(x) = c.get(k).filter(|x| x.is_string()) {
            o.insert(k.to_string(), x.clone());
        }
    }
    if let Some(d) = c.get("durci").and_then(Value::as_bool) {
        o.insert("durci".into(), json!(d));
    }
    // Moniteurs qui ont relevé quelque chose (noms et niveaux, sans leurs motifs).
    let alertes: Vec<Value> = c
        .get("avis")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| a.get("niveau").and_then(Value::as_str).is_some_and(|n| n != "conforme"))
        .map(|a| json!({"moniteur": a.get("moniteur"), "niveau": a.get("niveau")}))
        .collect();
    if !alertes.is_empty() {
        o.insert("moniteurs".into(), json!(alertes));
    }
    if e.type_ == "session" {
        if let Some(m) = c.get("modules") {
            o.insert("modules".into(), m.clone());
        }
    }
    v
}

fn texte(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn nombre(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or_default()
}

/// Résumé lisible d'un événement.
pub fn resume(p: &Value) -> String {
    match texte(p, "type").as_str() {
        "decision" => format!("{} {} ({}) : {}", texte(p, "verdict"), texte(p, "outil"), texte(p, "regle"), texte(p, "motif")),
        "session" => format!("ouverture de session, système {}, agent {}", texte(p, "systeme"), texte(p, "agent")),
        "administration" => format!("administration : {}", texte(p, "action")),
        t => t.to_string(),
    }
}

/// Événement au format ECS (Elastic).
pub fn ecs(p: &Value) -> Value {
    let verdict = texte(p, "verdict");
    let issue = match verdict.as_str() {
        "allow" => "success",
        "deny" | "gel" => "failure",
        _ => "unknown",
    };
    json!({
        "@timestamp": texte(p, "horodatage_utc"),
        "ecs": {"version": "8.11.0"},
        "message": resume(p),
        "event": {
            "id": texte(p, "id"), "kind": "event", "category": ["process"], "type": ["info"],
            "action": if texte(p, "type") == "decision" { verdict.clone() } else { texte(p, "type") },
            "outcome": issue, "severity": nombre(p, "gravite"), "dataset": "aplomb.journal",
            "module": "aplomb", "timezone": texte(p, "fuseau"), "sequence": nombre(p, "seq"),
        },
        "rule": {"name": texte(p, "regle")},
        "observer": {"name": texte(p, "instance"), "product": "Aplomb", "vendor": "Aplomb", "type": "supervisor", "version": VERSION},
        "labels": {"systeme": texte(p, "systeme"), "session": texte(p, "session")},
        "aplomb": p,
    })
}

/// Lot pour l'API `_bulk` d'Elastic : `create` avec l'identifiant de l'événement.
pub fn ecs_bulk(evts: &[Value], index: &str) -> String {
    let mut s = String::new();
    for p in evts {
        s.push_str(&json!({"create": {"_index": index, "_id": texte(p, "id")}}).to_string());
        s.push('\n');
        s.push_str(&ecs(p).to_string());
        s.push('\n');
    }
    s
}

/// Lot Splunk HEC : objets JSON concaténés.
pub fn splunk_hec(evts: &[Value]) -> String {
    evts.iter()
        .map(|p| {
            json!({
                "time": format!("{:.3}", nombre(p, "epoch_ms") as f64 / 1000.0).parse::<f64>().unwrap_or_default(),
                "host": texte(p, "instance"), "source": "aplomb", "sourcetype": "aplomb:journal",
                "fields": {"systeme": texte(p, "systeme"), "verdict": texte(p, "verdict"), "event_id": texte(p, "id")},
                "event": p,
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn severite_syslog(gravite: u64) -> u8 {
    match gravite {
        10 => 2, // critique
        8.. => 3,
        7 => 4,  // avertissement
        5 => 5,  // notice
        _ => 6,  // info
    }
}

fn echapper_sd(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace(']', "\\]")
}

fn nom_syslog(s: &str, max: usize) -> String {
    let n: String = s.chars().filter(|c| c.is_ascii_graphic()).take(max).collect();
    if n.is_empty() {
        "-".into()
    } else {
        n
    }
}

/// Ligne syslog RFC 5424 (facilité local0), le pivot en message.
pub fn syslog(p: &Value) -> String {
    let pri = 16 * 8 + severite_syslog(nombre(p, "gravite")) as u32;
    let mut sd = format!("[aplomb@{PEN} schema=\"{}\" session=\"{}\" seq=\"{}\"", SCHEMA, echapper_sd(&texte(p, "session")), nombre(p, "seq"));
    for k in ["systeme", "verdict", "regle", "fuseau"] {
        let v = texte(p, k);
        if !v.is_empty() {
            sd.push_str(&format!(" {k}=\"{}\"", echapper_sd(&v)));
        }
    }
    sd.push(']');
    format!(
        "<{pri}>1 {} {} aplomb - {} {sd} {}",
        texte(p, "horodatage"),
        nom_syslog(&texte(p, "instance"), 255),
        nom_syslog(&texte(p, "type"), 32),
        p
    )
}

fn cef_entete(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn cef_ext(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=").replace('\n', "\\n").replace('\r', "\\r")
}

/// Ligne CEF (ArcSight).
pub fn cef(p: &Value) -> String {
    let type_ = texte(p, "type");
    let classe = if type_ == "decision" { format!("decision:{}", texte(p, "verdict")) } else { type_.clone() };
    let mut ext = vec![
        format!("rt={}", nombre(p, "epoch_ms")),
        format!("dtz={}", cef_ext(&texte(p, "fuseau"))),
        format!("externalId={}", cef_ext(&texte(p, "id"))),
        format!("cs1Label=session cs1={}", cef_ext(&texte(p, "session"))),
        format!("cs2Label=systeme cs2={}", cef_ext(&texte(p, "systeme"))),
        format!("cn1Label=seq cn1={}", nombre(p, "seq")),
        format!("dvchost={}", cef_ext(&texte(p, "instance"))),
    ];
    for (k, cle) in [("verdict", "act"), ("regle", "cs3"), ("outil", "cs4"), ("motif", "msg"), ("compte", "suser")] {
        let v = texte(p, k);
        if !v.is_empty() {
            match cle {
                "cs3" => ext.push(format!("cs3Label=regle cs3={}", cef_ext(&v))),
                "cs4" => ext.push(format!("cs4Label=outil cs4={}", cef_ext(&v))),
                _ => ext.push(format!("{cle}={}", cef_ext(&v))),
            }
        }
    }
    format!(
        "CEF:0|Aplomb|Aplomb|{VERSION}|{}|{}|{}|{}",
        cef_entete(&classe),
        cef_entete(&resume(p).chars().take(512).collect::<String>()),
        nombre(p, "gravite"),
        ext.join(" ")
    )
}

/// Ligne LEEF 2.0 (QRadar), séparateur `^`.
pub fn leef(p: &Value) -> String {
    let type_ = texte(p, "type");
    let classe = if type_ == "decision" { format!("decision:{}", texte(p, "verdict")) } else { type_ };
    let net = |s: String| s.replace(['^', '\n', '\r', '\t'], " ");
    let mut champs = vec![
        format!("devTime={}", texte(p, "horodatage")),
        "devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSXXX".to_string(),
        format!("sev={}", nombre(p, "gravite")),
        format!("externalId={}", net(texte(p, "id"))),
        format!("session={}", net(texte(p, "session"))),
        format!("seq={}", nombre(p, "seq")),
        format!("systeme={}", net(texte(p, "systeme"))),
        format!("fuseau={}", net(texte(p, "fuseau"))),
    ];
    for k in ["verdict", "regle", "outil", "motif", "compte"] {
        let v = texte(p, k);
        if !v.is_empty() {
            champs.push(format!("{k}={}", net(v)));
        }
    }
    format!("LEEF:2.0|Aplomb|Aplomb|{VERSION}|{}|^|{}", net(classe), champs.join("^"))
}

fn attribut(k: &str, v: Value) -> Value {
    let valeur = match v {
        Value::Number(n) if n.is_u64() => json!({"intValue": n.to_string()}),
        Value::Bool(b) => json!({"boolValue": b}),
        Value::String(s) => json!({"stringValue": s}),
        autre => json!({"stringValue": autre.to_string()}),
    };
    json!({"key": k, "value": valeur})
}

/// Lot OTLP/HTTP JSON (logs).
pub fn otlp(evts: &[Value]) -> Value {
    let instance = evts.first().map(|p| texte(p, "instance")).unwrap_or_default();
    let records: Vec<Value> = evts
        .iter()
        .map(|p| {
            let g = nombre(p, "gravite");
            let (num, txt) = match g {
                10 => (21, "FATAL"),
                7..=9 => (17, "ERROR"),
                5 | 6 => (13, "WARN"),
                _ => (9, "INFO"),
            };
            let mut attrs = vec![
                attribut("aplomb.schema", json!(SCHEMA)),
                attribut("aplomb.event_id", json!(texte(p, "id"))),
                attribut("aplomb.session", json!(texte(p, "session"))),
                attribut("aplomb.seq", json!(nombre(p, "seq"))),
                attribut("aplomb.type", json!(texte(p, "type"))),
                attribut("aplomb.systeme", json!(texte(p, "systeme"))),
                attribut("aplomb.fuseau", json!(texte(p, "fuseau"))),
            ];
            for k in ["verdict", "regle", "outil", "verbe", "action", "compte"] {
                let v = texte(p, k);
                if !v.is_empty() {
                    attrs.push(attribut(&format!("aplomb.{k}"), json!(v)));
                }
            }
            let ns = (nombre(p, "epoch_ms") as u128 * 1_000_000).to_string();
            json!({
                "timeUnixNano": ns, "observedTimeUnixNano": ns,
                "severityNumber": num, "severityText": txt,
                "body": {"stringValue": resume(p)}, "attributes": attrs,
            })
        })
        .collect();
    json!({"resourceLogs": [{
        "resource": {"attributes": [attribut("service.name", json!("aplomb")), attribut("service.instance.id", json!(instance)), attribut("service.version", json!(VERSION))]},
        "scopeLogs": [{"scope": {"name": "aplomb.journal", "version": SCHEMA}, "logRecords": records}],
    }]})
}

/// Signature d'un webhook : `sha256=` HMAC-SHA256 de `horodatage.corps`.
pub fn signer_webhook(secret: &[u8], horodatage: u64, corps: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepte toute clé");
    m.update(horodatage.to_string().as_bytes());
    m.update(b".");
    m.update(corps);
    format!("sha256={}", hex::encode(m.finalize().into_bytes()))
}

/// Ligne au format demandé, pour les formats en lignes.
pub fn ligne(format: Format, p: &Value) -> String {
    match format {
        Format::Syslog => syslog(p),
        Format::Cef => cef(p),
        Format::Leef => leef(p),
        _ => p.to_string(),
    }
}

/// Exemple de chaque format pour un événement (aplomb diffusion apercu).
pub fn apercu(p: &Value) -> Map<String, Value> {
    let mut m = Map::new();
    for f in Format::TOUS {
        let v = match f {
            Format::Ecs => ecs(p),
            Format::SplunkHec => serde_json::from_str(&splunk_hec(std::slice::from_ref(p))).unwrap_or_default(),
            Format::Otlp => otlp(std::slice::from_ref(p)),
            Format::Webhook | Format::Json => p.clone(),
            _ => json!(ligne(f, p)),
        };
        m.insert(f.nom().into(), v);
    }
    m
}

/// Modèle commenté de `diffusion.yaml` (aplomb diffusion exemple).
pub const EXEMPLE: &str = r#"# Diffusion du journal d'Aplomb vers vos outils (option, désactivée sans ce fichier).
# Seuls les champs en clair du journal sortent ; les contenus chiffrés restent ici.
# Après modification : redémarrer aplomb serve. Vérifier : aplomb diffusion verifier.
instance: aplomb-prod            # nom de l'instance dans le SIEM (défaut : nom de la machine)
fuseau: Europe/Paris             # fuseau IANA des horodatages ; l'UTC est toujours joint
destinations:
# Elastic / OpenSearch (ECS, API _bulk, dédoublonné par identifiant)
- id: elastic
  format: ecs
  url: https://elastic.exemple.fr:9200/_bulk
  index: aplomb
  jeton_env: APLOMB_ELASTIC_CLE    # clé d'API (en-tête « ApiKey »)
# Splunk HTTP Event Collector
# - id: splunk
#   format: splunk-hec
#   url: https://splunk.exemple.fr:8088/services/collector/event
#   jeton_env: APLOMB_SPLUNK_HEC
# Syslog RFC 5424 sur TLS (rsyslog, syslog-ng, Sentinel via AMA…)
# - id: syslog
#   format: syslog           # ou cef (ArcSight), leef (QRadar)
#   adresse: siem.exemple.fr:6514
#   ca: /etc/aplomb/ca-interne.pem   # si le SIEM a un certificat interne
# OpenTelemetry (collecteur OTLP/HTTP)
# - id: otel
#   format: otlp
#   url: https://otel.exemple.fr:4318/v1/logs
# Webhook signé (HMAC-SHA256, en-tête X-Aplomb-Signature)
# - id: alertes
#   format: webhook
#   url: https://hooks.exemple.fr/aplomb
#   jeton_env: APLOMB_WEBHOOK_SECRET
#   types: [decision]
# Fichier pour un agent de collecte (Filebeat, Splunk UF, Fluent Bit)
# - id: fichier
#   format: json
#   fichier: /var/log/aplomb/evenements.jsonl
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn entree(type_: &str, contenu: Value) -> Entree {
        Entree {
            seq: 3,
            horodatage: 1_763_114_400_123, // 2025-11-14T10:00:00.123Z
            session: "s1".into(),
            type_: type_.into(),
            contenu,
            precedent: "p".into(),
            empreinte: "e".repeat(64),
        }
    }

    fn ctx() -> ContexteSession {
        ContexteSession { systeme: "assistant-code".into(), agent: "claude-code".into(), profil: "code".into() }
    }

    fn paris() -> TimeZone {
        TimeZone::get("Europe/Paris").unwrap()
    }

    #[test]
    fn horodatage_avec_fuseau_et_utc() {
        let h = horodater(1_763_114_400_123, &paris());
        assert_eq!(h.local, "2025-11-14T11:00:00.123+01:00");
        assert_eq!(h.utc, "2025-11-14T10:00:00.123Z");
        assert_eq!(h.fuseau, "Europe/Paris");
        // Heure d'été : décalage +02:00.
        assert!(horodater(1_752_480_000_000, &paris()).local.ends_with("+02:00"));
        assert_eq!(horodater(0, &TimeZone::UTC).local, "1970-01-01T00:00:00.000+00:00");
    }

    #[test]
    fn pivot_sans_contenus_chiffres() {
        let e = entree(
            "decision",
            json!({"outil": "Bash", "verbe": "reseau", "verdict": "gel", "regle": "r1", "motif": "m",
                   "avis": [{"moniteur": "filtre:bancaire", "niveau": "critique", "motif": "IBAN"}, {"moniteur": "secrets", "niveau": "conforme"}],
                   "chiffre": {"nonce": "x", "donnees": "SECRET"}, "durci": true}),
        );
        let p = pivot(&e, &ctx(), "inst", &paris());
        assert_eq!(p["schema"], SCHEMA);
        assert_eq!(p["id"], "e".repeat(64));
        assert_eq!(p["gravite"], 10);
        assert_eq!(p["systeme"], "assistant-code");
        assert_eq!(p["moniteurs"].as_array().unwrap().len(), 1);
        assert!(!p.to_string().contains("SECRET"), "les contenus chiffrés ne sortent pas");
        assert!(!p.to_string().contains("IBAN"), "motifs des moniteurs non repris");
    }

    #[test]
    fn formats() {
        let p = pivot(&entree("decision", json!({"outil": "Bash", "verdict": "review", "regle": "r|1", "motif": "a=b"})), &ctx(), "inst", &paris());
        let s = syslog(&p);
        assert!(s.starts_with("<133>1 2025-11-14T11:00:00.123+01:00 inst aplomb - decision [aplomb@32473 "), "{s}");
        assert!(s.contains("fuseau=\"Europe/Paris\""));
        let c = cef(&p);
        assert!(c.starts_with("CEF:0|Aplomb|Aplomb|"), "{c}");
        assert!(c.contains("|decision:review|"));
        assert!(c.contains("msg=a\\=b"), "{c}");
        assert!(c.contains("rt=1763114400123"));
        let l = leef(&p);
        assert!(l.starts_with("LEEF:2.0|Aplomb|Aplomb|") && l.contains("|^|devTime=2025-11-14T11:00:00.123+01:00^"), "{l}");
        let e = ecs(&p);
        assert_eq!(e["@timestamp"], "2025-11-14T10:00:00.123Z");
        assert_eq!(e["event"]["timezone"], "Europe/Paris");
        assert_eq!(e["event"]["id"], p["id"]);
        let b = ecs_bulk(std::slice::from_ref(&p), "aplomb");
        assert_eq!(b.lines().count(), 2);
        assert!(b.contains("\"_id\""));
        let h: Value = serde_json::from_str(&splunk_hec(std::slice::from_ref(&p))).unwrap();
        assert_eq!(h["time"], 1763114400.123);
        assert_eq!(h["sourcetype"], "aplomb:journal");
        let o = otlp(std::slice::from_ref(&p));
        let r = &o["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(r["timeUnixNano"], "1763114400123000000");
        assert_eq!(r["severityText"], "WARN");
        assert_eq!(apercu(&p).len(), 8);
    }

    #[test]
    fn webhook_signe() {
        let s = signer_webhook(b"secret", 1700000000, b"[]");
        assert!(s.starts_with("sha256=") && s.len() == 7 + 64);
        assert_ne!(s, signer_webhook(b"autre", 1700000000, b"[]"));
    }

    #[test]
    fn configuration() {
        assert!(ConfigDiffusion::depuis_yaml("destinations: []").unwrap().destinations.is_empty());
        let ok = "fuseau: Europe/Paris\ndestinations:\n- {id: s, format: splunk-hec, url: 'https://s:8088/services/collector/event', jeton_env: T}\n- {id: l, format: syslog, adresse: 'siem:6514'}\n- {id: f, format: cef, fichier: /tmp/x.cef}\n";
        let c = ConfigDiffusion::depuis_yaml(ok).unwrap();
        assert!(c.destinations[1].tls);
        let erreurs = [
            ("destinations: [{id: a, format: ecs, url: 'http://siem:9200/_bulk'}]", "en clair"),
            ("destinations: [{id: a, format: syslog, adresse: 'siem:514', tls: false}]", "en clair"),
            ("destinations: [{id: a, format: syslog, url: 'https://x'}]", "adresse"),
            ("destinations: [{id: a, format: webhook, url: 'https://x'}]", "jeton_env"),
            ("destinations: [{id: a, format: ecs}]", "une seule cible"),
            ("destinations: [{id: a, format: json, fichier: x}, {id: a, format: json, fichier: y}]", "deux fois"),
            ("fuseau: Mars/Olympus\ndestinations: []", "fuseau"),
            ("destinations: [{id: a, format: inconnu, fichier: x}]", "unknown variant"),
            ("destinations: [{id: a, format: json, fichier: x, types: [tout]}]", "inconnu"),
        ];
        for (y, attendu) in erreurs {
            let e = ConfigDiffusion::depuis_yaml(y).unwrap_err();
            assert!(e.contains(attendu), "{y} → {e}");
        }
        assert!(ConfigDiffusion::depuis_yaml("destinations: [{id: a, format: syslog, adresse: '127.0.0.1:514', tls: false}]").is_ok());
        assert!(ConfigDiffusion::depuis_yaml(EXEMPLE).is_ok(), "l'exemple est valide");
    }

    #[test]
    fn derive() {
        assert_eq!(derive_horloge(1000, 2000, 1000, 2000), None);
        assert_eq!(derive_horloge(1000, 10_000, 1000, 2000), Some(8000));
        assert_eq!(derive_horloge(10_000, 1000, 1000, 2000), Some(-10_000));
    }
}
