//! **Politique** déterministe en Cedar (ADR 0001).
//!
//! Deux ensembles de règles issus du mandat :
//! - `regles` : `permit` / `forbid`, refus par défaut, `forbid` prioritaire ;
//!   une règle `forbid` annotée `@verdict("gel")` gèle la session (EF-C2) ;
//! - `revue` : `permit` dont la correspondance impose une revue humaine.
//!
//! **Fail-closed** : toute erreur d'évaluation donne `Deny`. Sans cela, une erreur
//! sur un attribut manquant ferait simplement ignorer un `forbid`.
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as DecisionCedar, Entities, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request,
};
use thiserror::Error;

use crate::action::Action;
use crate::decision::{Decision, Verdict};

#[derive(Debug, Error)]
pub enum ErreurPolitique {
    #[error("règles Cedar invalides ({0}) : {1}")]
    Syntaxe(&'static str, String),
}

pub struct Politique {
    regles: PolicySet,
    revue: PolicySet,
}

fn uid(type_: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(type_).expect("nom de type Cedar valide"),
        EntityId::new(id),
    )
}

/// Identifiants (annotation `@id`, sinon identifiant Cedar) des règles déterminantes.
fn ids(set: &PolicySet, raisons: impl Iterator<Item = cedar_policy::PolicyId>) -> Vec<(String, bool)> {
    raisons
        .map(|pid| {
            let p = set.policy(&pid);
            let nom = p
                .and_then(|p| p.annotation("id").map(str::to_string))
                .unwrap_or_else(|| pid.to_string());
            let gel = p.and_then(|p| p.annotation("verdict")) == Some("gel");
            (nom, gel)
        })
        .collect()
}

impl Politique {
    pub fn nouvelle(regles: &str, revue: &str) -> Result<Self, ErreurPolitique> {
        Ok(Self {
            regles: PolicySet::from_str(regles)
                .map_err(|e| ErreurPolitique::Syntaxe("regles", e.to_string()))?,
            revue: PolicySet::from_str(revue)
                .map_err(|e| ErreurPolitique::Syntaxe("revue", e.to_string()))?,
        })
    }

    pub fn evaluer(&self, action: &Action) -> Decision {
        let refus = |regle: &str, motif: String| Decision {
            verdict: Verdict::Deny,
            regle: regle.into(),
            motif,
        };
        let contexte = match Context::from_json_value(
            serde_json::Value::Object(action.contexte.clone()),
            None,
        ) {
            Ok(c) => c,
            Err(e) => return refus("erreur-contexte", format!("contexte invalide : {e}")),
        };
        let requete = match Request::new(
            uid("Agent", &action.agent),
            uid("Action", &action.verbe),
            uid("Ressource", &action.ressource),
            contexte,
            None,
        ) {
            Ok(r) => r,
            Err(e) => return refus("erreur-requete", format!("requête invalide : {e}")),
        };
        let autorisateur = Authorizer::new();
        let entites = Entities::empty();

        let rep = autorisateur.is_authorized(&requete, &self.regles, &entites);
        let erreurs: Vec<String> = rep.diagnostics().errors().map(|e| e.to_string()).collect();
        if !erreurs.is_empty() {
            return refus("erreur-evaluation", format!("évaluation en échec : {}", erreurs.join(" ; ")));
        }
        let determinantes = ids(&self.regles, rep.diagnostics().reason().cloned());
        if rep.decision() == DecisionCedar::Deny {
            if determinantes.is_empty() {
                return refus("refus-par-defaut", format!("aucune règle n'autorise « {} »", action.verbe));
            }
            let gel = determinantes.iter().any(|(_, g)| *g);
            let noms: Vec<&str> = determinantes.iter().map(|(n, _)| n.as_str()).collect();
            return Decision {
                verdict: if gel { Verdict::Gel } else { Verdict::Deny },
                regle: noms.join(","),
                motif: format!("interdit par {}", noms.join(", ")),
            };
        }

        let rep_revue = autorisateur.is_authorized(&requete, &self.revue, &entites);
        if rep_revue.diagnostics().errors().next().is_some() {
            return Decision {
                verdict: Verdict::Review,
                regle: "erreur-revue".into(),
                motif: "évaluation des règles de revue en échec".into(),
            };
        }
        if rep_revue.decision() == DecisionCedar::Allow {
            let noms: Vec<String> =
                ids(&self.revue, rep_revue.diagnostics().reason().cloned()).into_iter().map(|(n, _)| n).collect();
            return Decision {
                verdict: Verdict::Review,
                regle: noms.join(","),
                motif: format!("revue humaine requise ({})", noms.join(", ")),
            };
        }
        let noms: Vec<String> = determinantes.into_iter().map(|(n, _)| n).collect();
        Decision {
            verdict: Verdict::Allow,
            regle: noms.join(","),
            motif: format!("autorisé par {}", noms.join(", ")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn action(verbe: &str, contexte: serde_json::Value) -> Action {
        Action {
            session: "s".into(),
            agent: "claude-code".into(),
            verbe: verbe.into(),
            ressource: "/depot/a.txt".into(),
            contexte: contexte.as_object().unwrap().clone(),
        }
    }

    const REGLES: &str = r#"
        @id("lire") permit(principal, action == Action::"lire", resource);
        @id("secret") forbid(principal, action, resource) when { context.sensible };
        @id("superviseur") @verdict("gel") forbid(principal, action, resource) when { context.attaque };
    "#;
    const REVUE: &str = r#"
        @id("hors-depot") permit(principal, action == Action::"lire", resource) unless { context.dans_depot };
    "#;

    fn p() -> Politique {
        Politique::nouvelle(REGLES, REVUE).unwrap()
    }

    fn ctx(sensible: bool, attaque: bool, dans_depot: bool) -> serde_json::Value {
        json!({"sensible": sensible, "attaque": attaque, "dans_depot": dans_depot})
    }

    #[test]
    fn autorise() {
        let d = p().evaluer(&action("lire", ctx(false, false, true)));
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.regle, "lire");
    }

    #[test]
    fn forbid_prioritaire() {
        let d = p().evaluer(&action("lire", ctx(true, false, true)));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.regle, "secret");
    }

    #[test]
    fn refus_par_defaut() {
        let d = p().evaluer(&action("ecrire", ctx(false, false, true)));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.regle, "refus-par-defaut");
    }

    #[test]
    fn gel_sur_regle_critique() {
        let d = p().evaluer(&action("lire", ctx(false, true, true)));
        assert_eq!(d.verdict, Verdict::Gel);
    }

    #[test]
    fn revue() {
        let d = p().evaluer(&action("lire", ctx(false, false, false)));
        assert_eq!(d.verdict, Verdict::Review);
        assert_eq!(d.regle, "hors-depot");
    }

    /// Un attribut manquant ne doit jamais faire sauter un `forbid`.
    #[test]
    fn attribut_manquant_fail_closed() {
        let d = p().evaluer(&action("lire", json!({"dans_depot": true})));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.regle, "erreur-evaluation");
    }
}
