//! **Superviseur** : enchaîne normalisation (profil), politique (Cedar) et combinaison,
//! et tient l'état de gel (global et par session). Sans I/O : le journal est écrit par
//! l'appelant.
//!
//! - **Provenance** (EF-B5, EF-D2) : dès qu'une session a reçu un contenu non fiable (page
//!   web, résultat d'outil MCP, fichier hors du dépôt, sortie de sous-agent), ce contenu
//!   reste dans le contexte du modèle. Les actions sensibles de la session passent alors
//!   au moins en revue : un contenu non fiable ne déclenche jamais seul une action Allow.
//! - **Délégation** (EF-B6) : l'action d'un sous-agent qui a un mandat enfant est jugée par
//!   l'enfant **et** par le parent ; le verdict le plus sévère l'emporte.
//! - **Moniteurs** (EF-E) : secrets, puis juge si le mandat en déclare un. Le juge fait de
//!   l'I/O : [`Superviseur::preparer`] dit s'il faut le consulter et rédige la saisine,
//!   l'appelant l'interroge hors verrou, puis [`Superviseur::decider_avec`] combine son avis.
use std::collections::{HashMap, HashSet, VecDeque};

use crate::action::{Action, EvenementOutil};
use crate::bornes::Suivi;
use crate::decision::{combiner, Avis, Decision, DecisionFinale, Niveau, Verdict};
use crate::mandat::MandatCharge;
use crate::moniteurs::{self, ConfigJuge, Raison, Saisir, Trace};
use crate::politique::{ErreurPolitique, Politique};
use crate::profils;

pub struct Superviseur {
    pub mandat: MandatCharge,
    politique: Politique,
    gel_global: bool,
    sessions_gelees: HashSet<String>,
    suivi: Suivi,
    /// Contenus non fiables reçus, par session (outil et ressource de l'action source).
    influences: HashMap<String, Vec<String>>,
    /// Mandats enfants, par type de sous-agent.
    enfants: HashMap<String, Superviseur>,
    /// Dernières actions de chaque session, montrées au juge (EF-E4).
    traces: HashMap<String, VecDeque<Trace>>,
    /// Consultations du juge par session (budget, EF-E5).
    appels_juge: HashMap<String, u32>,
}

/// Actions passées montrées au juge.
const TRACES_MAX: usize = 20;

/// Consultation du juge à faire pour une action.
#[derive(Debug, Clone)]
pub enum Consultation {
    Juge { raison: Raison, consigne: String, message: String },
    /// Action sensible, budget épuisé : avis de revue sans appel.
    BudgetEpuise(Avis),
}

impl Superviseur {
    pub fn nouveau(mandat: MandatCharge) -> Result<Self, ErreurPolitique> {
        let politique = Politique::nouvelle(&mandat.regles, &mandat.revue)?;
        let suivi = Suivi::nouveau(mandat.mandat.bornes.clone().unwrap_or_default());
        Ok(Self {
            mandat,
            politique,
            gel_global: false,
            sessions_gelees: HashSet::new(),
            suivi,
            influences: HashMap::new(),
            enfants: HashMap::new(),
            traces: HashMap::new(),
            appels_juge: HashMap::new(),
        })
    }

    /// Ajoute le mandat d'un type de sous-agent, après vérification d'inclusion (EF-B6).
    pub fn ajouter_enfant(&mut self, enfant: MandatCharge) -> Result<String, String> {
        crate::delegation::verifier_inclusion(&self.mandat, &enfant).map_err(|e| e.join(" ; "))?;
        let type_agent = crate::delegation::type_agent(&self.mandat.mandat, &enfant.mandat)
            .ok_or("agent du mandat enfant : <agent du parent>/<type de sous-agent> attendu")?;
        let s = Superviseur::nouveau(enfant).map_err(|e| e.to_string())?;
        self.enfants.insert(type_agent.clone(), s);
        Ok(type_agent)
    }

    /// Mandat enfant qui s'applique à cet événement, s'il y en a un.
    pub fn mandat_enfant(&self, evt: &EvenementOutil) -> Option<&MandatCharge> {
        evt.delegation.as_ref().and_then(|d| self.enfants.get(&d.type_agent)).map(|s| &s.mandat)
    }

    /// Après exécution : retient si l'action a apporté un contenu non fiable. Rend la
    /// source retenue.
    pub fn observer(&mut self, evt: &EvenementOutil) -> Option<String> {
        let action = self.normaliser(evt);
        if !profils::code::source_non_fiable(&action, &self.mandat.mandat) {
            return None;
        }
        let source = evt.outil.clone();
        let liste = self.influences.entry(evt.session.clone()).or_default();
        if !liste.contains(&source) {
            liste.push(source.clone());
        }
        Some(source)
    }

    /// Contenus non fiables reçus par la session.
    pub fn influences(&self, session: &str) -> &[String] {
        self.influences.get(session).map_or(&[], Vec::as_slice)
    }

    pub fn normaliser(&self, evt: &EvenementOutil) -> Action {
        // Seul profil du MVP ; un profil inconnu est refusé au démarrage (`aplomb serve`).
        profils::code::normaliser(evt, &self.mandat.mandat)
    }

    /// Juge déclaré au mandat.
    pub fn juge(&self) -> Option<&ConfigJuge> {
        self.mandat.mandat.moniteurs.as_ref().and_then(|m| m.juge.as_ref())
    }

    /// Faut-il consulter le juge pour cette action ? Sans effet sur l'état : l'appelant
    /// consulte le juge hors verrou, puis appelle [`Self::decider_avec`]. `tirage` est
    /// uniforme dans `[0, 1)` (échantillon), `nonce` imprévisible (enveloppe des données).
    pub fn preparer(&self, evt: &EvenementOutil, tirage: f64, nonce: &str) -> Option<Consultation> {
        let cfg = self.juge()?;
        let action = self.normaliser(evt);
        let politique = if evt.agent != self.mandat.mandat.agent { Verdict::Deny } else { self.politique.evaluer(&action).verdict };
        // Un secret ou la provenance décident déjà : inutile de payer le juge.
        let mut verdict = moniteurs::avis_secrets(evt, &action).map_or(politique, |a| politique.max(a.niveau.plancher()));
        if !self.influences(&evt.session).is_empty() && profils::code::sensible_a_l_influence(&action) {
            verdict = verdict.max(Verdict::Review);
        }
        let appels = self.appels_juge.get(&evt.session).copied().unwrap_or(0);
        match moniteurs::saisir(cfg, &action, verdict, appels, tirage) {
            Saisir::Non => None,
            Saisir::BudgetEpuise => Some(Consultation::BudgetEpuise(moniteurs::avis_budget(cfg))),
            Saisir::Oui(raison) => {
                let historique: Vec<Trace> = self.traces.get(&evt.session).map(|t| t.iter().cloned().collect()).unwrap_or_default();
                let (consigne, message) =
                    moniteurs::saisine(&self.mandat.mandat.intention, evt, &action, &historique, self.influences(&evt.session), nonce);
                Some(Consultation::Juge { raison, consigne, message })
            }
        }
    }

    /// Compte une consultation du juge dans le budget de la session.
    pub fn noter_appel_juge(&mut self, session: &str) -> u32 {
        let n = self.appels_juge.entry(session.to_string()).or_default();
        *n += 1;
        *n
    }

    /// Décide d'une action. Un verdict `Gel` gèle la session pour la suite (EF-J4).
    pub fn decider(&mut self, evt: &EvenementOutil) -> (Action, DecisionFinale) {
        self.decider_avec(evt, Vec::new())
    }

    /// Décide d'une action, avec les avis de moniteurs extérieurs (juge).
    pub fn decider_avec(&mut self, evt: &EvenementOutil, externes: Vec<Avis>) -> (Action, DecisionFinale) {
        let mut action = self.normaliser(evt);
        let sources = self.influences(&evt.session).to_vec();
        action.contexte.insert("influence_externe".into(), serde_json::json!(!sources.is_empty()));
        let mut politique = if evt.agent != self.mandat.mandat.agent {
            Decision {
                verdict: Verdict::Deny,
                regle: "agent-hors-mandat".into(),
                motif: format!("agent « {} » non couvert par le mandat", evt.agent),
            }
        } else {
            self.politique.evaluer(&action)
        };
        // Délégation : le mandat enfant juge aussi ; le plus sévère l'emporte (EF-B6).
        if let Some(enfant) = evt.delegation.as_ref().and_then(|d| self.enfants.get(&d.type_agent)) {
            let mut a = enfant.normaliser(evt);
            a.contexte.insert("influence_externe".into(), serde_json::json!(!sources.is_empty()));
            let d = enfant.politique.evaluer(&a);
            if d.verdict > politique.verdict {
                politique = Decision {
                    verdict: d.verdict,
                    regle: format!("{}:{}", enfant.mandat.mandat.id, d.regle),
                    motif: format!("mandat enfant {} : {}", enfant.mandat.mandat.id, d.motif),
                };
            }
        }
        let gele = self.gel_global || self.sessions_gelees.contains(&evt.session);
        // Bornes cumulées : moniteur déterministe, qui ne peut que durcir (EF-A6, EF-K1).
        let mut avis = self.suivi.observer(&action, politique.verdict);
        // Provenance : moniteur déterministe lui aussi.
        if !sources.is_empty() && profils::code::sensible_a_l_influence(&action) {
            avis.push(Avis {
                moniteur: "provenance".into(),
                niveau: Niveau::Suspect,
                score: 0.5,
                motif: format!("session influencée par un contenu non fiable ({})", sources.join(", ")),
            });
        }
        // Secrets : moniteur déterministe (EF-D1).
        avis.extend(moniteurs::avis_secrets(evt, &action));
        avis.extend(externes);
        let finale = combiner(politique, avis, gele);
        if finale.verdict == Verdict::Gel {
            self.sessions_gelees.insert(evt.session.clone());
        }
        let traces = self.traces.entry(evt.session.clone()).or_default();
        traces.push_back(Trace { verbe: action.verbe.clone(), ressource: action.ressource.clone(), verdict: finale.verdict });
        if traces.len() > TRACES_MAX {
            traces.pop_front();
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
        self.suivi.reinitialiser(session);
        match session {
            Some(s) => {
                self.appels_juge.remove(s);
            }
            None => self.appels_juge.clear(),
        }
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
