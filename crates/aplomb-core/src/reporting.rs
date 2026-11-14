//! **Reporting MCP** : Aplomb se laisse interroger, en lecture seule, par un outil de
//! gouvernance cyber (ACRA, un GRC, ou tout client MCP piloté par un LLM) qui vient
//! collecter l'état de conformité et les indicateurs de l'agent supervisé.
//!
//! - **Clients** (`reporting.yaml`) : chaque outil reçoit un jeton `aplomb-rapport-<id>-…`
//!   affiché une seule fois ; le fichier n'en garde que l'empreinte. Un client peut être
//!   retiré à tout moment, sans redémarrer le service.
//! - **Lecture seule par construction** : le protocole ne connaît que `initialize`, `ping`,
//!   `tools/list` et `tools/call` sur les outils ci-dessous, tous annotés `readOnlyHint`.
//!   Aucun ne gèle, ne dégèle, n'approuve ni n'écrit quoi que ce soit, hors le journal de
//!   ses propres appels.
//! - **Rien de nominatif** (EF-P3) : les réponses sont des agrégats, des statuts et des
//!   comptes ; ni identifiant de session, ni utilisateur, ni compte, ni ressource.
//!
//! Ce module est pur (protocole et jetons) ; le binaire branche les outils sur l'état du
//! superviseur.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Préfixe des jetons de reporting.
pub const PREFIXE: &str = "aplomb-rapport-";
/// Version du protocole MCP que sert Aplomb.
pub const VERSION_PROTOCOLE: &str = "2025-06-18";
/// Versions acceptées d'un client (la plus récente d'abord).
const VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

// ---------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientsReporting {
    #[serde(default)]
    pub clients: Vec<Client>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    /// À quoi sert ce client (affiché par `aplomb reporting liste`).
    #[serde(default)]
    pub description: String,
    /// SHA-256 du jeton : le jeton lui-même n'est jamais conservé.
    pub empreinte: String,
}

fn empreinte(jeton: &str) -> String {
    hex::encode(Sha256::digest(jeton.as_bytes()))
}

impl ClientsReporting {
    /// Crée un client ; rend son jeton. `alea` : 24 octets aléatoires.
    pub fn creer(&mut self, id: &str, description: &str, alea: [u8; 24]) -> Result<String, String> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("identifiant de client : lettres, chiffres, - et _ seulement (exemple : acra)".into());
        }
        if self.clients.iter().any(|c| c.id == id) {
            return Err(format!("le client {id} existe déjà : aplomb reporting retirer --id {id} pour le remplacer"));
        }
        let jeton = format!("{PREFIXE}{id}-{}", hex::encode(alea));
        self.clients.push(Client { id: id.into(), description: description.into(), empreinte: empreinte(&jeton) });
        Ok(jeton)
    }

    pub fn retirer(&mut self, id: &str) -> Result<(), String> {
        let avant = self.clients.len();
        self.clients.retain(|c| c.id != id);
        if self.clients.len() == avant {
            return Err(format!("aucun client {id} : aplomb reporting liste"));
        }
        Ok(())
    }

    /// Client du jeton présenté (`Authorization: Bearer …`), s'il existe.
    pub fn identifier(&self, jeton: &str) -> Option<&Client> {
        let e = empreinte(jeton.trim());
        self.clients.iter().find(|c| c.empreinte == e)
    }
}

// ---------------------------------------------------------------------------------------
// Outils
// ---------------------------------------------------------------------------------------

/// Outils exposés, tous en lecture seule.
pub const OUTILS: &[&str] = &[
    "lister_systemes",
    "etat_conformite",
    "indicateurs",
    "integrite_journal",
    "etat_supervision",
    "correspondance_referentiels",
    "rapport_reglementaire",
    "modules",
    "revues_en_attente",
];

fn schema_heures() -> Value {
    json!({"type": "object", "properties": {
        "heures": {"type": "integer", "minimum": 1, "description": "Ne garder que les dernières heures (défaut : tout le journal)."}
    }, "additionalProperties": false})
}

/// Définitions des outils pour `tools/list`.
pub fn definitions() -> Value {
    let lecture = json!({"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false});
    let outil = |nom: &str, titre: &str, description: &str, schema: Value| {
        json!({"name": nom, "title": titre, "description": description, "inputSchema": schema, "annotations": lecture})
    };
    let vide = json!({"type": "object", "properties": {}, "additionalProperties": false});
    json!([
        outil("lister_systemes", "Systèmes supervisés",
              "Systèmes d'IA supervisés par cette instance d'Aplomb : identifiant du mandat, version, profil, agent, intention déclarée, empreinte, nombre de cosignataires.",
              vide.clone()),
        outil("etat_conformite", "État de conformité AI Act",
              "Statut constaté, article par article de l'AI Act (couvert, partiel, hors périmètre), avec le constat mesuré sur l'instance et ce qui reste à l'organisation. Correspondances indicatives.",
              schema_heures()),
        outil("indicateurs", "Indicateurs de supervision",
              "Indicateurs agrégés, sans rien de nominatif : décisions par verdict, taux de revue, de refus et de gel, règles, moniteurs, juge, revues humaines, jetons. `signer: true` rend l'agrégat signé par l'instance.",
              json!({"type": "object", "properties": {
                  "heures": {"type": "integer", "minimum": 1, "description": "Ne garder que les dernières heures (défaut : tout le journal)."},
                  "signer": {"type": "boolean", "description": "Agrégat signé par l'instance, vérifiable par aplomb gouvernance federer."}
              }, "additionalProperties": false})),
        outil("integrite_journal", "Intégrité du journal",
              "Intégrité du journal probatoire : sessions intactes ou rompues, scellés signés, ancre hors de la machine, plus ancienne et plus récente entrée (conservation).",
              vide.clone()),
        outil("etat_supervision", "État de la supervision",
              "État courant du superviseur : gel global, nombre de sessions gelées, revues humaines en attente, décisions depuis le démarrage, activité du juge et du protocole AI control.",
              vide.clone()),
        outil("correspondance_referentiels", "Correspondance des référentiels",
              "Correspondance des familles d'exigences d'Aplomb avec l'AI Act, le NIST AI RMF, l'ISO/IEC 42001, l'OWASP, l'ANSSI et le CRA.",
              vide.clone()),
        outil("rapport_reglementaire", "Rapport réglementaire",
              "Statut exigence par exigence pour DORA, ISO/IEC 42001 (annexe A) ou NIS 2 (art. 20, 21 § 2, 23) : apport d'Aplomb, constat mesuré, reste à l'organisation. Correspondances indicatives.",
              json!({"type": "object", "properties": {
                  "referentiel": {"type": "string", "enum": ["dora", "iso42001", "nis2"]},
                  "heures": {"type": "integer", "minimum": 1, "description": "Ne garder que les dernières heures (défaut : tout le journal)."}
              }, "required": ["referentiel"], "additionalProperties": false})),
        outil("modules", "Modules actifs",
              "Modules de l'instance, étape par étape (filtrage, moniteurs, décision, approbation, journal, diffusion, reporting, visualisation, identité) : actif ou disponible, ce que chacun voit.",
              vide.clone()),
        outil("revues_en_attente", "Revues humaines en attente",
              "Nombre de revues humaines en attente, par priorité, et âge de la plus ancienne. Rien de nominatif ni de contenu.",
              vide),
    ])
}

/// Erreur d'un outil, rendue au client comme résultat d'outil en erreur.
pub type ResultatOutil = Result<Value, String>;

fn reponse(id: &Value, resultat: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": resultat})
}

fn erreur(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Résultat MCP d'un outil : texte JSON lisible, et contenu structuré.
pub fn resultat(valeur: ResultatOutil) -> Value {
    match valeur {
        Ok(v) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}],
                        "structuredContent": v, "isError": false}),
        Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
    }
}

/// Traite un message JSON-RPC. Rend `None` pour une notification (aucune réponse due).
/// `appeler` exécute un outil connu de [`OUTILS`].
pub fn traiter(message: &Value, appeler: &mut dyn FnMut(&str, &Value) -> ResultatOutil) -> Option<Value> {
    let methode = message.get("method").and_then(Value::as_str);
    let Some(id) = message.get("id").cloned() else {
        // Notification (`notifications/initialized`…) : rien à répondre.
        return None;
    };
    let Some(methode) = methode else { return Some(erreur(&id, -32600, "requête invalide")) };
    Some(match methode {
        "initialize" => {
            let demandee = message.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or(VERSION_PROTOCOLE);
            let version = VERSIONS.iter().find(|v| **v == demandee).copied().unwrap_or(VERSION_PROTOCOLE);
            reponse(&id, json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "aplomb-reporting", "title": "Aplomb — reporting de conformité (lecture seule)", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Serveur en lecture seule d'Aplomb, superviseur d'alignement d'agents d'IA. Commencer par lister_systemes, puis etat_conformite pour le statut AI Act, et indicateurs pour les chiffres. Aucune donnée nominative.",
            }))
        }
        "ping" => reponse(&id, json!({})),
        "tools/list" => reponse(&id, json!({"tools": definitions()})),
        "tools/call" => {
            let nom = message.pointer("/params/name").and_then(Value::as_str).unwrap_or_default();
            if !OUTILS.contains(&nom) {
                return Some(erreur(&id, -32602, &format!("outil inconnu « {nom} » : voir tools/list")));
            }
            let args = message.pointer("/params/arguments").cloned().unwrap_or(json!({}));
            reponse(&id, resultat(appeler(nom, &args)))
        }
        "resources/list" => reponse(&id, json!({"resources": []})),
        "prompts/list" => reponse(&id, json!({"prompts": []})),
        autre => erreur(&id, -32601, &format!("méthode non prise en charge par un serveur en lecture seule : {autre}")),
    })
}

/// Heures demandées dans les arguments d'un outil (entier positif), ou tout le journal.
pub fn heures(args: &Value) -> Result<Option<u64>, String> {
    match args.get("heures") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().filter(|h| *h > 0).map(Some).ok_or_else(|| "heures : entier positif attendu".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_par_empreinte() {
        let mut c = ClientsReporting::default();
        let j = c.creer("acra", "ACRA", [3; 24]).unwrap();
        assert!(j.starts_with("aplomb-rapport-acra-"));
        assert!(!serde_yaml::to_string(&c).unwrap().contains(&j), "le jeton ne doit pas être conservé");
        assert_eq!(c.identifier(&j).unwrap().id, "acra");
        assert!(c.identifier("aplomb-rapport-acra-faux").is_none());
        assert!(c.creer("acra", "", [4; 24]).is_err());
        assert!(c.creer("a b", "", [4; 24]).is_err());
        c.retirer("acra").unwrap();
        assert!(c.identifier(&j).is_none());
    }

    #[test]
    fn protocole_lecture_seule() {
        let mut appels = Vec::new();
        let mut f = |nom: &str, _: &Value| {
            appels.push(nom.to_string());
            Ok(json!({"ok": true}))
        };
        let init = traiter(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}), &mut f).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert!(traiter(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), &mut f).is_none());
        let liste = traiter(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}), &mut f).unwrap();
        let outils = liste["result"]["tools"].as_array().unwrap();
        assert_eq!(outils.len(), OUTILS.len());
        assert!(outils.iter().all(|o| o["annotations"]["readOnlyHint"] == true));
        let r = traiter(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "indicateurs", "arguments": {}}}), &mut f).unwrap();
        assert_eq!(r["result"]["structuredContent"]["ok"], true);
        let inconnu = traiter(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "geler"}}), &mut f).unwrap();
        assert_eq!(inconnu["error"]["code"], -32602);
        let autre = traiter(&json!({"jsonrpc": "2.0", "id": 5, "method": "resources/subscribe"}), &mut f).unwrap();
        assert_eq!(autre["error"]["code"], -32601);
        assert_eq!(appels, vec!["indicateurs"]);
    }

    #[test]
    fn heures_valides() {
        assert_eq!(heures(&json!({})).unwrap(), None);
        assert_eq!(heures(&json!({"heures": 24})).unwrap(), Some(24));
        assert!(heures(&json!({"heures": -1})).is_err());
        assert!(heures(&json!({"heures": "24"})).is_err());
    }
}
