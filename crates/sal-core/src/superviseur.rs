//! **Superviseur** : enchaîne normalisation (profil), politique (Cedar) et combinaison,
//! et tient l'état de gel (global et par session). Sans I/O : le journal est écrit par
//! l'appelant.
use std::collections::HashSet;

use crate::action::{Action, EvenementOutil};
use crate::decision::{combiner, DecisionFinale, Verdict};
use crate::mandat::MandatCharge;
use crate::politique::{ErreurPolitique, Politique};
use crate::profils;

pub struct Superviseur {
    pub mandat: MandatCharge,
    politique: Politique,
    gel_global: bool,
    sessions_gelees: HashSet<String>,
}

impl Superviseur {
    pub fn nouveau(mandat: MandatCharge) -> Result<Self, ErreurPolitique> {
        let politique = Politique::nouvelle(&mandat.regles, &mandat.revue)?;
        Ok(Self { mandat, politique, gel_global: false, sessions_gelees: HashSet::new() })
    }

    pub fn normaliser(&self, evt: &EvenementOutil) -> Action {
        // Seul profil du MVP ; un profil inconnu est refusé au démarrage (`sal serve`).
        profils::code::normaliser(evt, &self.mandat.mandat)
    }

    /// Décide d'une action. Un verdict `Gel` gèle la session pour la suite (EF-J4).
    pub fn decider(&mut self, evt: &EvenementOutil) -> (Action, DecisionFinale) {
        let action = self.normaliser(evt);
        let politique = if evt.agent != self.mandat.mandat.agent {
            crate::decision::Decision {
                verdict: Verdict::Deny,
                regle: "agent-hors-mandat".into(),
                motif: format!("agent « {} » non couvert par le mandat", evt.agent),
            }
        } else {
            self.politique.evaluer(&action)
        };
        let gele = self.gel_global || self.sessions_gelees.contains(&evt.session);
        let finale = combiner(politique, Vec::new(), gele);
        if finale.verdict == Verdict::Gel {
            self.sessions_gelees.insert(evt.session.clone());
        }
        (action, finale)
    }

    pub fn geler(&mut self, session: Option<&str>) {
        match session {
            Some(s) => {
                self.sessions_gelees.insert(s.to_string());
            }
            None => self.gel_global = true,
        }
    }

    pub fn degeler(&mut self, session: Option<&str>) {
        match session {
            Some(s) => {
                self.sessions_gelees.remove(s);
            }
            None => {
                self.gel_global = false;
                self.sessions_gelees.clear();
            }
        }
    }

    pub fn etat_gel(&self) -> (bool, Vec<String>) {
        let mut s: Vec<String> = self.sessions_gelees.iter().cloned().collect();
        s.sort();
        (self.gel_global, s)
    }
}
