//! **Bornes cumulées par session** (EF-A6) et **quota de revues** (EF-J5).
//!
//! Chaque action prise isolément peut être permise, alors que leur suite ne l'est pas :
//! escalade progressive (*frog boiling*), agent qui insiste après des refus, rafale de
//! demandes qui épuise les approbateurs. Les bornes comptent par session et, au
//! dépassement, rendent un avis `Critique` : l'algèbre de décision impose alors le gel.
//! C'est un moniteur **déterministe** : il ne peut que durcir (EF-K1).
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::action::Action;
use crate::decision::{Avis, Niveau, Verdict};

/// Bornes déclarées dans le mandat (toutes facultatives, valeurs par défaut prudentes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Bornes {
    /// Refus de la politique tolérés avant gel (un agent qui insiste).
    pub refus: u32,
    /// Demandes de revue humaine par session (EF-J5).
    pub revues: u32,
    /// Domaines réseau distincts contactés (élargissement progressif du périmètre).
    pub domaines: u32,
    /// Envois de données vers l'extérieur (EF-C4).
    pub envois: u32,
    /// Actions au total (emballement).
    pub actions: u32,
}

impl Default for Bornes {
    fn default() -> Self {
        Self { refus: 5, revues: 20, domaines: 10, envois: 3, actions: 2000 }
    }
}

#[derive(Debug, Default)]
struct Compteurs {
    refus: u32,
    revues: u32,
    domaines: HashSet<String>,
    envois: u32,
    actions: u32,
}

/// Compteurs de toutes les sessions.
#[derive(Debug, Default)]
pub struct Suivi {
    bornes: Bornes,
    sessions: HashMap<String, Compteurs>,
}

fn attribut(action: &Action, cle: &str) -> bool {
    action.contexte.get(cle).and_then(|v| v.as_bool()).unwrap_or(false)
}

impl Suivi {
    pub fn nouveau(bornes: Bornes) -> Self {
        Self { bornes, sessions: HashMap::new() }
    }

    /// Compte l'action (avec le verdict de la politique) et rend un avis `Critique` pour
    /// chaque borne dépassée.
    pub fn observer(&mut self, action: &Action, politique: Verdict) -> Vec<Avis> {
        let c = self.sessions.entry(action.session.clone()).or_default();
        c.actions += 1;
        match politique {
            Verdict::Deny | Verdict::Gel => c.refus += 1,
            Verdict::Review => c.revues += 1,
            Verdict::Allow => {}
        }
        if attribut(action, "envoi_externe") {
            c.envois += 1;
        }
        if attribut(action, "reseau") {
            if let Some(d) = action.contexte.get("domaine").and_then(|v| v.as_str()).filter(|d| !d.is_empty()) {
                c.domaines.insert(d.to_string());
            }
        }
        let b = &self.bornes;
        let mut avis = Vec::new();
        let mut verifier = |nom: &str, valeur: u32, max: u32, sens: &str| {
            if valeur > max {
                avis.push(Avis {
                    moniteur: format!("borne-{nom}"),
                    niveau: Niveau::Critique,
                    score: 1.0,
                    motif: format!("{valeur} {sens} dans la session (borne : {max})"),
                });
            }
        };
        verifier("refus", c.refus, b.refus, "refus");
        verifier("revues", c.revues, b.revues, "demandes de revue");
        verifier("domaines", c.domaines.len() as u32, b.domaines, "domaines distincts");
        verifier("envois", c.envois, b.envois, "envois externes");
        verifier("actions", c.actions, b.actions, "actions");
        avis
    }

    /// L'opérateur qui dégèle une session repart de zéro pour elle (il a pris acte).
    pub fn reinitialiser(&mut self, session: Option<&str>) {
        match session {
            Some(s) => {
                self.sessions.remove(s);
            }
            None => self.sessions.clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};

    fn action(session: &str, contexte: serde_json::Value) -> Action {
        let contexte: Map<String, serde_json::Value> = contexte.as_object().cloned().unwrap_or_default();
        Action { session: session.into(), agent: "a".into(), verbe: "executer".into(), ressource: "r".into(), contexte }
    }

    #[test]
    fn refus_repetes_gelent() {
        let mut s = Suivi::nouveau(Bornes { refus: 2, ..Bornes::default() });
        let a = action("s", json!({}));
        assert!(s.observer(&a, Verdict::Deny).is_empty());
        assert!(s.observer(&a, Verdict::Deny).is_empty());
        let avis = s.observer(&a, Verdict::Deny);
        assert_eq!(avis.len(), 1);
        assert_eq!(avis[0].niveau, Niveau::Critique);
        assert_eq!(avis[0].moniteur, "borne-refus");
        // Une autre session n'est pas concernée.
        assert!(s.observer(&action("t", json!({})), Verdict::Deny).is_empty());
    }

    #[test]
    fn domaines_distincts_et_non_repetes() {
        let mut s = Suivi::nouveau(Bornes { domaines: 2, ..Bornes::default() });
        let d = |n: &str| action("s", json!({"reseau": true, "domaine": n}));
        for n in ["a.org", "b.org", "a.org", "b.org"] {
            assert!(s.observer(&d(n), Verdict::Allow).is_empty(), "{n}");
        }
        assert_eq!(s.observer(&d("c.org"), Verdict::Allow)[0].moniteur, "borne-domaines");
    }

    #[test]
    fn quota_de_revues_et_envois() {
        let mut s = Suivi::nouveau(Bornes { revues: 1, envois: 1, ..Bornes::default() });
        let e = action("s", json!({"envoi_externe": true}));
        assert!(s.observer(&e, Verdict::Review).is_empty());
        let noms: Vec<String> = s.observer(&e, Verdict::Review).into_iter().map(|a| a.moniteur).collect();
        assert_eq!(noms, vec!["borne-revues", "borne-envois"]);
    }

    #[test]
    fn degel_reinitialise() {
        let mut s = Suivi::nouveau(Bornes { refus: 0, ..Bornes::default() });
        let a = action("s", json!({}));
        assert!(!s.observer(&a, Verdict::Deny).is_empty());
        s.reinitialiser(Some("s"));
        assert!(s.observer(&a, Verdict::Allow).is_empty());
    }
}
