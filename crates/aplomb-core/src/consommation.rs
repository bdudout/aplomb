//! **Consommation du modèle** : jetons et contexte, par utilisateur, compte technique,
//! prompt et session d'agent.
//!
//! - Un **compte technique** est la clé qu'un agent présente au proxy LLM (`x-api-key` ou
//!   `Authorization: Bearer`). Il appartient à un **utilisateur** (une personne) et peut
//!   porter un quota de jetons par jour. Le fichier des comptes ne garde que l'empreinte
//!   des clés.
//! - Un **prompt** est le dernier message de l'utilisateur dans la requête : texte seul,
//!   sans résultats d'outils ni rappels système. Tous les appels qu'une demande entraîne
//!   (boucle d'outils) s'y rattachent.
//! - Le **contexte** d'un appel est ce que le modèle a reçu : jetons d'entrée, cache compris.
//!   Une forte baisse d'un appel au suivant dans une session est une **compaction**.
//!
//! Sans I/O : le proxy fournit les relevés, ce module les agrège.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Préfixe des clés d'agent délivrées par Aplomb.
pub const PREFIXE: &str = "aplomb-agent-";

/// Fichier des comptes techniques (`agents.yaml`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ComptesAgents {
    #[serde(default)]
    pub agents: Vec<CompteAgent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompteAgent {
    pub id: String,
    /// Personne responsable de l'agent.
    pub utilisateur: String,
    /// SHA-256 de la clé (hexadécimal) : la clé elle-même n'est jamais conservée.
    pub empreinte: String,
    /// Jetons (entrée, cache compris, et sortie) par jour UTC ; au-delà, refus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jetons_par_jour: Option<u64>,
}

fn empreinte(cle: &str) -> String {
    hex::encode(Sha256::digest(cle.as_bytes()))
}

impl ComptesAgents {
    /// Crée un compte ; rend la clé, à donner une fois à l'agent. `alea` : 16 octets aléatoires.
    pub fn creer(&mut self, id: &str, utilisateur: &str, jetons_par_jour: Option<u64>, alea: [u8; 16]) -> Result<String, String> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("identifiant de compte : lettres, chiffres, - et _ seulement".into());
        }
        if self.agents.iter().any(|a| a.id == id) {
            return Err(format!("le compte technique {id} existe déjà"));
        }
        let cle = format!("{PREFIXE}{id}-{}", hex::encode(alea));
        self.agents.push(CompteAgent { id: id.into(), utilisateur: utilisateur.into(), empreinte: empreinte(&cle), jetons_par_jour });
        Ok(cle)
    }

    /// Compte de la clé présentée, s'il existe.
    pub fn identifier(&self, cle: &str) -> Option<&CompteAgent> {
        let e = empreinte(cle);
        self.agents.iter().find(|a| a.empreinte == e)
    }
}

/// Clé présentée par l'agent au proxy : `x-api-key`, sinon `Authorization: Bearer`.
pub fn cle_presentee(entetes: &[(String, String)]) -> Option<String> {
    let valeur = |nom: &str| entetes.iter().find(|(n, _)| n.eq_ignore_ascii_case(nom)).map(|(_, v)| v.trim().to_string());
    valeur("x-api-key").or_else(|| valeur("authorization").and_then(|v| v.strip_prefix("Bearer ").map(String::from)))
}

/// Prompt de l'utilisateur dans une requête de l'API Messages : dernier message `user` qui
/// porte du texte et aucun résultat d'outil. Les rappels système (`<system-reminder>`) sont
/// écartés.
pub fn prompt(requete: &Value) -> Option<String> {
    let messages = requete.get("messages")?.as_array()?;
    messages.iter().rev().filter(|m| m["role"] == "user").find_map(|m| match &m["content"] {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Array(blocs) => {
            if blocs.iter().any(|b| b["type"] == "tool_result") {
                return None;
            }
            let texte: Vec<&str> = blocs
                .iter()
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str())
                .map(str::trim)
                .filter(|t| !t.is_empty() && !t.starts_with("<system-reminder>"))
                .collect();
            (!texte.is_empty()).then(|| texte.join("\n"))
        }
        _ => None,
    })
}

/// Extrait montré dans Aplomb Watch : début du prompt, secrets masqués.
pub fn extrait(prompt: &str) -> String {
    let (m, _) = crate::moniteurs::masquer(prompt);
    let une_ligne = m.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut e: String = une_ligne.chars().take(100).collect();
    if une_ligne.chars().count() > 100 {
        e.push('…');
    }
    e
}

/// Un appel au modèle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Releve {
    pub horodatage: u64,
    pub compte: String,
    pub utilisateur: String,
    pub session_agent: Option<String>,
    /// Empreinte du prompt (en mémoire seulement : le journal garde le prompt scellé).
    pub prompt: Option<String>,
    pub extrait: Option<String>,
    pub modele: String,
    /// Contexte reçu par le modèle : entrée, cache compris.
    pub entree: u64,
    pub cache_lu: u64,
    pub cache_ecrit: u64,
    pub sortie: u64,
}

impl Releve {
    pub fn total(&self) -> u64 {
        self.entree + self.sortie
    }
}

pub fn empreinte_prompt(prompt: &str) -> String {
    empreinte(prompt)[..16].to_string()
}

const JOUR_MS: u64 = 86_400_000;

/// Relevés en mémoire, reconstruits depuis le journal au démarrage.
#[derive(Debug, Default)]
pub struct Consommation {
    releves: Vec<Releve>,
}

#[derive(Debug, Default, Clone, Serialize)]
struct Cumul {
    appels: u64,
    entree: u64,
    cache_lu: u64,
    sortie: u64,
    total: u64,
    contexte_max: u64,
}

impl Cumul {
    fn ajouter(&mut self, r: &Releve) {
        self.appels += 1;
        self.entree += r.entree;
        self.cache_lu += r.cache_lu;
        self.sortie += r.sortie;
        self.total += r.total();
        self.contexte_max = self.contexte_max.max(r.entree);
    }
}

impl Consommation {
    pub fn ajouter(&mut self, r: Releve) {
        self.releves.push(r);
    }

    /// Jetons consommés par un compte le jour (UTC) de `maintenant`.
    pub fn jetons_du_jour(&self, compte: &str, maintenant: u64) -> u64 {
        let jour = maintenant / JOUR_MS;
        self.releves.iter().filter(|r| r.compte == compte && r.horodatage / JOUR_MS == jour).map(Releve::total).sum()
    }

    /// Synthèse depuis `depuis` (ms) : par utilisateur, compte technique, prompt et session.
    pub fn synthese(&self, depuis: u64, maintenant: u64, comptes: &ComptesAgents) -> Value {
        let releves: Vec<&Releve> = self.releves.iter().filter(|r| r.horodatage >= depuis).collect();
        let mut total = Cumul::default();
        let mut par_utilisateur: BTreeMap<&str, Cumul> = BTreeMap::new();
        let mut par_compte: BTreeMap<&str, Cumul> = BTreeMap::new();
        let mut par_modele: BTreeMap<&str, Cumul> = BTreeMap::new();
        // Un prompt appartient à un compte : même texte, deux comptes, deux lignes.
        let mut par_prompt: BTreeMap<(&str, &str), (Cumul, &Releve, u64)> = BTreeMap::new();
        let mut par_session: BTreeMap<&str, Vec<&Releve>> = BTreeMap::new();
        for r in &releves {
            total.ajouter(r);
            par_utilisateur.entry(&r.utilisateur).or_default().ajouter(r);
            par_compte.entry(&r.compte).or_default().ajouter(r);
            par_modele.entry(&r.modele).or_default().ajouter(r);
            if let Some(p) = &r.prompt {
                let e = par_prompt.entry((&r.compte, p)).or_insert((Cumul::default(), r, r.horodatage));
                e.0.ajouter(r);
            }
            par_session.entry(r.session_agent.as_deref().unwrap_or("(sans session)")).or_default().push(r);
        }
        let liste = |m: BTreeMap<&str, Cumul>, cle: &str| -> Vec<Value> {
            let mut v: Vec<(&str, Cumul)> = m.into_iter().collect();
            v.sort_by(|a, b| b.1.total.cmp(&a.1.total));
            v.into_iter().map(|(k, c)| { let mut o = json!(c); o[cle] = json!(k); o }).collect()
        };
        let comptes_v: Vec<Value> = liste(par_compte, "compte")
            .into_iter()
            .map(|mut o| {
                let id = o["compte"].as_str().unwrap_or_default().to_string();
                if let Some(a) = comptes.agents.iter().find(|a| a.id == id) {
                    o["utilisateur"] = json!(a.utilisateur);
                    o["jetons_par_jour"] = json!(a.jetons_par_jour);
                } else {
                    // Compte « anonyme », ou retiré du fichier : l'utilisateur des relevés.
                    o["utilisateur"] = json!(releves.iter().rev().find(|r| r.compte == id).map(|r| &r.utilisateur));
                }
                o["aujourd_hui"] = json!(self.jetons_du_jour(&id, maintenant));
                o
            })
            .collect();
        let mut prompts: Vec<Value> = par_prompt
            .into_iter()
            .map(|((_, p), (c, r, debut))| {
                let mut o = json!(c);
                o["prompt"] = json!(p);
                o["extrait"] = json!(r.extrait);
                o["compte"] = json!(r.compte);
                o["utilisateur"] = json!(r.utilisateur);
                o["session_agent"] = json!(r.session_agent);
                o["debut"] = json!(debut);
                o
            })
            .collect();
        prompts.sort_by(|a, b| b["total"].as_u64().cmp(&a["total"].as_u64()));
        prompts.truncate(50);
        let sessions: Vec<Value> = par_session
            .into_iter()
            .map(|(s, rs)| {
                let mut c = Cumul::default();
                rs.iter().for_each(|r| c.ajouter(r));
                // Compaction : le contexte chute de plus de 40 % d'un appel au suivant.
                let compactions = rs.windows(2).filter(|w| w[0].entree > 20_000 && w[1].entree * 10 < w[0].entree * 6).count();
                let mut o = json!(c);
                o["session_agent"] = json!(s);
                o["contexte_dernier"] = json!(rs.last().map(|r| r.entree));
                o["contextes"] = json!(rs.iter().rev().take(60).rev().map(|r| r.entree).collect::<Vec<_>>());
                o["compactions"] = json!(compactions);
                o["compte"] = json!(rs.last().map(|r| &r.compte));
                o
            })
            .collect();
        json!({
            "depuis": depuis, "total": total,
            "par_utilisateur": liste(par_utilisateur, "utilisateur"),
            "par_compte": comptes_v,
            "par_modele": liste(par_modele, "modele"),
            "par_prompt": prompts,
            "par_session": sessions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn releve(t: u64, compte: &str, prompt: &str, entree: u64) -> Releve {
        Releve {
            horodatage: t,
            compte: compte.into(),
            utilisateur: format!("u-{compte}"),
            session_agent: Some("s1".into()),
            prompt: Some(empreinte_prompt(prompt)),
            extrait: Some(extrait(prompt)),
            modele: "m".into(),
            entree,
            cache_lu: entree / 2,
            cache_ecrit: 0,
            sortie: 10,
        }
    }

    #[test]
    fn comptes_et_cles() {
        let mut c = ComptesAgents::default();
        let cle = c.creer("ci", "brice", Some(1000), [7; 16]).unwrap();
        assert!(cle.starts_with("aplomb-agent-ci-"));
        assert_eq!(c.identifier(&cle).unwrap().utilisateur, "brice");
        assert!(c.identifier("aplomb-agent-ci-faux").is_none());
        assert!(c.creer("ci", "x", None, [1; 16]).is_err());
        assert!(c.creer("a b", "x", None, [1; 16]).is_err());
        assert!(!serde_yaml::to_string(&c).unwrap().contains(&cle), "la clé n'est jamais écrite");
        let e = |n: &str, v: &str| (n.to_string(), v.to_string());
        assert_eq!(cle_presentee(&[e("X-Api-Key", "k1")]).as_deref(), Some("k1"));
        assert_eq!(cle_presentee(&[e("authorization", "Bearer k2")]).as_deref(), Some("k2"));
    }

    #[test]
    fn prompt_de_l_utilisateur() {
        let r = json!({"messages": [
            {"role": "user", "content": [{"type": "text", "text": "<system-reminder>x</system-reminder>"}, {"type": "text", "text": "Ajoute un test"}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "Bash", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "ok"}]},
        ]});
        assert_eq!(prompt(&r).as_deref(), Some("Ajoute un test"));
        assert_eq!(prompt(&json!({"messages": [{"role": "user", "content": "ls"}]})).as_deref(), Some("ls"));
        assert_eq!(extrait("voici AKIAZ7Q2M4K8T3V6W9XB"), "voici [secret masqué par Aplomb]");
    }

    #[test]
    fn synthese_et_quota() {
        let mut c = Consommation::default();
        let jour = 20_000 * JOUR_MS;
        c.ajouter(releve(jour + 1, "ci", "corrige le bug", 30_000));
        c.ajouter(releve(jour + 2, "ci", "corrige le bug", 40_000));
        c.ajouter(releve(jour + 3, "ci", "corrige le bug", 9_000)); // compaction
        c.ajouter(releve(jour + 4, "dev", "ajoute un test", 1_000));
        c.ajouter(releve(jour + 5, "dev", "corrige le bug", 1_000));
        c.ajouter(releve(jour - JOUR_MS, "ci", "hier", 5_000));
        assert_eq!(c.jetons_du_jour("ci", jour + 10), 30_010 + 40_010 + 9_010);
        let s = c.synthese(jour, jour + 10, &ComptesAgents::default());
        assert_eq!(s["total"]["appels"], 5);
        assert_eq!(s["par_prompt"].as_array().unwrap().len(), 3, "même prompt, deux comptes : deux lignes");
        assert_eq!(s["par_compte"][0]["compte"], "ci");
        assert_eq!(s["par_compte"][0]["utilisateur"], "u-ci");
        assert_eq!(s["par_prompt"][0]["extrait"], "corrige le bug");
        assert_eq!(s["par_prompt"][0]["appels"], 3);
        assert_eq!(s["par_prompt"][0]["contexte_max"], 40_000);
        assert_eq!(s["par_session"][0]["compactions"], 1);
        assert_eq!(s["par_utilisateur"].as_array().unwrap().len(), 2);
    }
}
