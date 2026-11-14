//! **Profils déclaratifs** (ENF-8) : un domaine se décrit dans un fichier YAML, sans
//! recompiler Aplomb. Le fichier est lié au mandat par son empreinte, posée à la
//! cosignature (comme les règles Cedar et les filtres) : le modifier sans recosigner
//! empêche `serve` de démarrer.
//!
//! ```yaml
//! nom: rh
//! description: Agent RH, dossiers du personnel
//! referentiels: ["RGPD, art. 9 (données de santé)"]
//! outils:
//! - {outil: "mcp__sirh__lire_dossier", verbe: lire, ressource: matricule, sensible: true}
//! - {outil: "mcp__sirh__exporter", verbe: exporter, ressource: destinataire, envoi: true, domaine: destinataire}
//! - {outil: "mcp__web__*", verbe: lire_web, source_non_fiable: true}
//! attributs: [montant, motif]          # copiés de l'entrée dans le contexte Cedar
//! sensibles_a_l_influence: [exporter]  # relevés en revue après un contenu non fiable
//! ```
//!
//! Le profil ne décide rien : il nomme les verbes et les attributs que lisent ses règles
//! Cedar. Un outil qu'il ne déclare pas reçoit le verbe `autre`, que les règles d'exemple
//! refusent, et que le juge examine toujours.
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{Profil, Signaux};
use crate::action::{Action, EvenementOutil};
use crate::mandat::Mandat;

/// Référence au fichier, dans le mandat (`profil_declaratif:`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefProfil {
    /// Chemin relatif au fichier du mandat.
    pub fichier: String,
    /// Empreinte posée à la cosignature.
    #[serde(default)]
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutilDeclare {
    /// Nom exact, ou préfixe suivi de `*` (`mcp__sirh__*`).
    pub outil: String,
    pub verbe: String,
    /// Champ de l'entrée qui désigne la ressource (défaut : le nom de l'outil).
    #[serde(default)]
    pub ressource: String,
    /// Lit une donnée sensible.
    #[serde(default)]
    pub sensible: bool,
    /// Fait sortir des données de la machine.
    #[serde(default)]
    pub envoi: bool,
    /// Champ de l'entrée qui porte la destination (domaine ou adresse).
    #[serde(default)]
    pub domaine: String,
    /// Son résultat est un contenu non fiable (page web, courriel reçu…).
    #[serde(default)]
    pub source_non_fiable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub nom: String,
    pub description: String,
    #[serde(default)]
    pub referentiels: Vec<String>,
    pub outils: Vec<OutilDeclare>,
    #[serde(default)]
    pub attributs: Vec<String>,
    #[serde(default)]
    pub sensibles_a_l_influence: Vec<String>,
}

/// Noms réservés aux profils intégrés et attributs que le socle pose lui-même.
const RESERVES: &[&str] = &["outil", "envoi_externe", "donnee_sensible", "reseau", "domaine", "influence_externe"];

impl Definition {
    pub fn depuis_yaml(t: &str) -> Result<Self, String> {
        let d: Definition = serde_yaml::from_str(t).map_err(|e| format!("profil déclaratif : {e}"))?;
        let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        if !ok(&d.nom) {
            return Err(format!("profil déclaratif : nom « {} » invalide (minuscules, chiffres, - et _)", d.nom));
        }
        if super::PROFILS.iter().any(|p| p.nom() == d.nom) || d.nom == "inconnu" {
            return Err(format!("profil déclaratif : « {} » est le nom d'un profil intégré", d.nom));
        }
        if d.outils.is_empty() {
            return Err("profil déclaratif : aucun outil déclaré".into());
        }
        let mut vus = BTreeSet::new();
        for o in &d.outils {
            if o.outil.is_empty() || !vus.insert(&o.outil) {
                return Err(format!("profil déclaratif : outil « {} » vide ou déclaré deux fois", o.outil));
            }
            if !ok(&o.verbe) || o.verbe == "autre" || o.verbe == "profil_inconnu" {
                return Err(format!("profil déclaratif, outil {} : verbe « {} » invalide", o.outil, o.verbe));
            }
        }
        for a in &d.attributs {
            if !ok(a) || RESERVES.contains(&a.as_str()) {
                return Err(format!("profil déclaratif : attribut « {a} » invalide ou réservé"));
            }
        }
        Ok(d)
    }

    fn outil(&self, nom: &str) -> Option<&OutilDeclare> {
        // Nom exact d'abord, puis le préfixe le plus long.
        self.outils.iter().find(|o| o.outil == nom).or_else(|| {
            self.outils
                .iter()
                .filter(|o| o.outil.strip_suffix('*').is_some_and(|p| nom.starts_with(p)))
                .max_by_key(|o| o.outil.len())
        })
    }
}

/// Profil construit depuis une [`Definition`].
pub struct ProfilDeclaratif {
    nom: &'static str,
    description: &'static str,
    referentiels: &'static [&'static str],
    def: Definition,
}

fn champ(entree: &Value, k: &str) -> String {
    match entree.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","),
        Some(v) if !v.is_null() => v.to_string(),
        _ => String::new(),
    }
}

impl Profil for ProfilDeclaratif {
    fn nom(&self) -> &'static str {
        self.nom
    }
    fn description(&self) -> &'static str {
        self.description
    }
    fn normaliser(&self, evt: &EvenementOutil, _mandat: &Mandat) -> Action {
        let o = self.def.outil(&evt.outil);
        let verbe = o.map_or("autre".to_string(), |o| o.verbe.clone());
        let ressource = o.filter(|o| !o.ressource.is_empty()).map(|o| champ(&evt.entree, &o.ressource)).filter(|r| !r.is_empty()).unwrap_or_else(|| evt.outil.clone());
        let domaine = o.filter(|o| !o.domaine.is_empty()).map(|o| champ(&evt.entree, &o.domaine)).unwrap_or_default();
        let mut contexte = Map::new();
        contexte.insert("outil".into(), json!(evt.outil));
        contexte.insert("envoi_externe".into(), json!(o.is_some_and(|o| o.envoi)));
        contexte.insert("donnee_sensible".into(), json!(o.is_some_and(|o| o.sensible)));
        contexte.insert("reseau".into(), json!(false));
        contexte.insert("domaine".into(), json!(domaine));
        contexte.insert("influence_externe".into(), json!(false));
        // Attributs déclarés : toujours présents (Cedar), du type de l'entrée.
        for a in &self.def.attributs {
            let v = match evt.entree.get(a) {
                Some(v @ (Value::Bool(_) | Value::Number(_) | Value::String(_))) => v.clone(),
                Some(v) if !v.is_null() => json!(v.to_string()),
                _ => json!(""),
            };
            contexte.insert(a.clone(), v);
        }
        Action { session: evt.session.clone(), agent: evt.agent.clone(), verbe, ressource, contexte }
    }
    fn source_non_fiable(&self, action: &Action, _mandat: &Mandat) -> bool {
        let outil = action.contexte.get("outil").and_then(Value::as_str).unwrap_or_default();
        self.def.outil(outil).is_some_and(|o| o.source_non_fiable)
    }
    fn sensible_a_l_influence(&self, action: &Action) -> bool {
        self.def.sensibles_a_l_influence.contains(&action.verbe) || super::attribut_vrai(action, "envoi_externe")
    }
    fn signaux(&self, _evt: &EvenementOutil, action: &Action) -> Signaux {
        let envoi = super::attribut_vrai(action, "envoi_externe");
        Signaux {
            juge: action.verbe == "autre" || self.sensible_a_l_influence(action),
            sortante: envoi,
            envoi,
            lit_sensible: super::attribut_vrai(action, "donnee_sensible"),
            destination: action.contexte.get("domaine").and_then(Value::as_str).unwrap_or_default().to_string(),
            ..Signaux::default()
        }
    }
    fn resume(&self, _mandat: &Mandat) -> Vec<String> {
        vec![format!("profil déclaratif : {} outil(s) déclarés, attributs {}", self.def.outils.len(), self.def.attributs.join(", "))]
    }
    fn referentiels(&self) -> &'static [&'static str] {
        self.referentiels
    }
}

/// Profils déclaratifs chargés dans ce processus.
static CHARGES: RwLock<Vec<(&'static ProfilDeclaratif, String)>> = RwLock::new(Vec::new());

pub fn trouver(nom: &str) -> Option<&'static dyn Profil> {
    CHARGES.read().ok()?.iter().find(|(p, _)| p.nom == nom).map(|(p, _)| *p as &'static dyn Profil)
}

pub fn noms() -> Vec<&'static str> {
    CHARGES.read().map(|v| v.iter().map(|(p, _)| p.nom).collect()).unwrap_or_default()
}

fn fuir(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Charge le profil déclaré par le mandat, s'il en déclare un, et l'inscrit au registre.
/// `exiger_empreinte` : en service, le fichier doit correspondre à l'empreinte cosignée.
/// Rend l'empreinte du fichier.
pub fn enregistrer(mandat: &Mandat, dossier: &Path, exiger_empreinte: bool) -> Result<Option<String>, String> {
    let Some(r) = &mandat.profil_declaratif else { return Ok(None) };
    let chemin = dossier.join(&r.fichier);
    let octets = std::fs::read(&chemin).map_err(|e| format!("profil déclaratif {} : {e}", chemin.display()))?;
    let e = crate::preuves::sha256_hex(&octets);
    if exiger_empreinte && r.sha256.is_empty() {
        return Err(format!("profil déclaratif {} non lié au mandat : faire cosigner le mandat (aplomb cosigner)", r.fichier));
    }
    if !r.sha256.is_empty() && r.sha256 != e {
        return Err(format!("profil déclaratif {} modifié depuis la cosignature : faire recosigner le mandat", chemin.display()));
    }
    let def = Definition::depuis_yaml(&String::from_utf8_lossy(&octets))?;
    if def.nom != mandat.profil {
        return Err(format!("le mandat déclare « profil: {} », le fichier {} décrit « {} »", mandat.profil, r.fichier, def.nom));
    }
    let mut charges = CHARGES.write().map_err(|_| "registre des profils indisponible")?;
    if let Some((_, empreinte)) = charges.iter().find(|(p, _)| p.nom == def.nom) {
        // Déjà chargé dans ce processus : même contenu exigé.
        return if *empreinte == e { Ok(Some(e)) } else { Err(format!("profil « {} » déjà chargé avec un autre contenu", def.nom)) };
    }
    let referentiels: &'static [&'static str] = Box::leak(def.referentiels.iter().map(|x| fuir(x.clone())).collect::<Vec<_>>().into_boxed_slice());
    let p: &'static ProfilDeclaratif = Box::leak(Box::new(ProfilDeclaratif { nom: fuir(def.nom.clone()), description: fuir(def.description.clone()), referentiels, def }));
    charges.push((p, e.clone()));
    Ok(Some(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RH: &str = "nom: rh-test\ndescription: Agent RH\noutils:\n- {outil: mcp__sirh__lire_dossier, verbe: lire, ressource: matricule, sensible: true}\n- {outil: mcp__sirh__exporter, verbe: exporter, ressource: destinataire, envoi: true, domaine: destinataire}\n- {outil: \"mcp__web__*\", verbe: lire_web, source_non_fiable: true}\nattributs: [montant]\nsensibles_a_l_influence: [exporter]\n";

    #[test]
    fn validation() {
        assert!(Definition::depuis_yaml(RH).is_ok());
        assert!(Definition::depuis_yaml(&RH.replace("rh-test", "code")).unwrap_err().contains("intégré"));
        assert!(Definition::depuis_yaml(&RH.replace("verbe: lire,", "verbe: autre,")).is_err());
        assert!(Definition::depuis_yaml(&RH.replace("[montant]", "[envoi_externe]")).is_err());
        assert!(Definition::depuis_yaml(&format!("{RH}inconnu: 1\n")).is_err());
    }

    #[test]
    fn normalisation() {
        let def = Definition::depuis_yaml(RH).unwrap();
        let p = ProfilDeclaratif { nom: "rh-test", description: "", referentiels: &[], def };
        let m: Mandat = serde_yaml::from_str("id: m\nversion: 1\nprofil: rh-test\nagent: a\nintention: i\nperimetre: {racine: /tmp}\npolitique: {regles: r, revue: v}\n").unwrap();
        let evt = |outil: &str, entree: Value| EvenementOutil {
            session: "s".into(), agent: "a".into(), mode: "m".into(), cwd: "/".into(), outil: outil.into(), entree,
            phase: crate::action::Phase::Avant, chemin_reel: None, contenu_execute: None, nonce: None, appel: None, delegation: None,
        };
        let a = p.normaliser(&evt("mcp__sirh__exporter", json!({"destinataire": "x@y.fr", "montant": 3})), &m);
        assert_eq!((a.verbe.as_str(), a.ressource.as_str(), a.contexte["montant"].as_i64()), ("exporter", "x@y.fr", Some(3)));
        let s = p.signaux(&evt("mcp__sirh__exporter", json!({})), &a);
        assert!(s.envoi && s.juge && s.destination == "x@y.fr");
        let w = p.normaliser(&evt("mcp__web__lire", json!({})), &m);
        assert!(w.verbe == "lire_web" && p.source_non_fiable(&w, &m));
        let x = p.normaliser(&evt("Bash", json!({"command": "ls"})), &m);
        assert_eq!((x.verbe.as_str(), x.contexte["montant"].as_str()), ("autre", Some("")));
    }
}
