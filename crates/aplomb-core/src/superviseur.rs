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
    /// Moniteurs propres au profil du mandat (cumuls de session…).
    etat_profil: Option<Box<dyn profils::Suivi>>,
    /// Consultations de la sonde par session (EF-F).
    appels_sonde: HashMap<String, u32>,
    /// Filtres de contenu du mandat (EF-D1) ; les fichiers sont chargés par
    /// [`Self::charger_filtres`].
    filtres: Vec<crate::filtres::PackCompile>,
    /// Consultations des moniteurs externes, par (moniteur, session).
    appels_externes: HashMap<(String, String), u32>,
}

/// Actions passées montrées au juge.
const TRACES_MAX: usize = 20;

/// Consultation du juge à faire pour une action.
#[derive(Debug, Clone)]
pub enum Consultation {
    Juge { raison: Raison, consigne: String, message: String },
    /// Action sensible, budget épuisé : avis de revue sans appel.
    BudgetEpuise(Avis),
    /// Moniteur interne (EF-F) : texte produit par le modèle, à rejouer par le serveur
    /// d'activations dans le contexte de l'intention.
    Sonde { intention: String, texte: String },
    /// Moniteur externe déclaré au mandat (EF-M1) : requête du contrat v1 à lui envoyer.
    Externe { id: String, requete: serde_json::Value },
}

impl Superviseur {
    pub fn nouveau(mandat: MandatCharge) -> Result<Self, ErreurPolitique> {
        let politique = Politique::nouvelle(&mandat.regles, &mandat.revue)?;
        let suivi = Suivi::nouveau(mandat.mandat.bornes.clone().unwrap_or_default());
        let etat_profil = profils::pour(&mandat.mandat.profil).suivi();
        // Packs intégrés tout de suite ; les fichiers attendent le dossier du mandat.
        let integres: Vec<crate::filtres::Filtre> = mandat
            .mandat
            .moniteurs
            .as_ref()
            .map(|m| m.filtres.iter().filter(|f| matches!(f, crate::filtres::Filtre::Pack { .. })).cloned().collect())
            .unwrap_or_default();
        let filtres = crate::filtres::charger(&integres, None, false).map_err(ErreurPolitique::Mandat)?;
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
            etat_profil,
            appels_sonde: HashMap::new(),
            appels_externes: HashMap::new(),
            filtres,
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
        if !self.profil().source_non_fiable(&action, &self.mandat.mandat) {
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

    /// Profil du mandat, par le registre (un profil inconnu refuse tout ; `aplomb serve`
    /// l'a déjà refusé au démarrage).
    pub fn profil(&self) -> &'static dyn profils::Profil {
        profils::pour(&self.mandat.mandat.profil)
    }

    pub fn normaliser(&self, evt: &EvenementOutil) -> Action {
        self.profil().normaliser(evt, &self.mandat.mandat)
    }

    /// Juge déclaré au mandat.
    pub fn juge(&self) -> Option<&ConfigJuge> {
        self.mandat.mandat.moniteurs.as_ref().and_then(|m| m.juge.as_ref())
    }

    /// Faut-il consulter le juge pour cette action ? Sans effet sur l'état : l'appelant
    /// consulte le juge hors verrou, puis appelle [`Self::decider_avec`]. `tirage` est
    /// uniforme dans `[0, 1)` (échantillon), `nonce` imprévisible (enveloppe des données).
    pub fn preparer(&self, evt: &EvenementOutil, tirage: f64, nonce: &str) -> Option<Consultation> {
        self.preparer_avec(evt, tirage, nonce, None)
    }

    /// Verdict des moniteurs déterministes (politique, secrets, provenance), sans effet sur
    /// l'état : ce que deviendrait l'action si l'agent la présentait maintenant.
    pub fn examiner(&self, evt: &EvenementOutil) -> (Action, Verdict) {
        let action = self.normaliser(evt);
        let signaux = self.profil().signaux(evt, &action);
        let politique = if evt.agent != self.mandat.mandat.agent { Verdict::Deny } else { self.politique.evaluer(&action).verdict };
        let mut verdict = moniteurs::avis_secrets(evt, signaux.sortante).map_or(politique, |a| politique.max(a.niveau.plancher()));
        if !self.influences(&evt.session).is_empty() && self.profil().sensible_a_l_influence(&action) {
            verdict = verdict.max(Verdict::Review);
        }
        if self.avis_enchainement(evt, &action, &signaux).is_some() {
            verdict = verdict.max(Verdict::Review);
        }
        for a in self.avis_filtres(evt, signaux.sortante) {
            verdict = verdict.max(a.niveau.plancher());
        }
        for a in self.etat_profil.iter().flat_map(|s| s.avis(&self.mandat.mandat, evt, &action)) {
            verdict = verdict.max(a.niveau.plancher());
        }
        (action, verdict)
    }

    fn avis_enchainement(&self, evt: &EvenementOutil, action: &Action, signaux: &profils::Signaux) -> Option<Avis> {
        let historique: Vec<Trace> = self.traces.get(&evt.session).map(|t| t.iter().cloned().collect()).unwrap_or_default();
        moniteurs::avis_enchainement(&historique, evt, action, signaux)
    }

    /// Comme [`Self::preparer`], avec le raisonnement du modèle qui a demandé l'action,
    /// quand le proxy LLM l'a vu (EF-E3) : le juge le reçoit, enveloppé comme donnée.
    pub fn preparer_avec(&self, evt: &EvenementOutil, tirage: f64, nonce: &str, raisonnement: Option<&str>) -> Option<Consultation> {
        let cfg = self.juge()?;
        // Un secret ou la provenance décident déjà : inutile de payer le juge.
        let (action, verdict) = self.examiner(evt);
        let appels = self.appels_juge.get(&evt.session).copied().unwrap_or(0);
        let sensible = self.profil().signaux(evt, &action).juge;
        match moniteurs::saisir(cfg, sensible, verdict, appels, tirage) {
            Saisir::Non => None,
            Saisir::BudgetEpuise => Some(Consultation::BudgetEpuise(moniteurs::avis_budget(cfg))),
            Saisir::Oui(raison) => {
                let historique: Vec<Trace> = self.traces.get(&evt.session).map(|t| t.iter().cloned().collect()).unwrap_or_default();
                let (consigne, message) =
                    moniteurs::saisine(&self.mandat.mandat.intention, evt, &action, &historique, self.influences(&evt.session), raisonnement, nonce);
                Some(Consultation::Juge { raison, consigne, message })
            }
        }
    }

    /// Sonde déclarée au mandat (moniteur interne, EF-F).
    pub fn sonde(&self) -> Option<&crate::sonde::ConfigSonde> {
        self.mandat.mandat.moniteurs.as_ref().and_then(|m| m.sonde.as_ref())
    }

    /// Faut-il consulter la sonde ? Seulement pour une action encore permise (un refus ou une
    /// revue n'ont rien à gagner d'un signal d'appoint), dans le budget de la session. Sans
    /// effet sur l'état : l'appelant consulte hors verrou, puis [`Self::noter_appel_sonde`].
    pub fn preparer_sonde(&self, evt: &EvenementOutil, raisonnement: Option<&str>) -> Option<Consultation> {
        let cfg = self.sonde()?;
        if self.appels_sonde.get(&evt.session).copied().unwrap_or(0) >= cfg.appels_max || self.examiner(evt).1 != Verdict::Allow {
            return None;
        }
        Some(Consultation::Sonde { intention: self.mandat.mandat.intention.clone(), texte: crate::sonde::texte(evt, raisonnement) })
    }

    /// Charge tous les filtres du mandat, fichiers compris (relatifs à `dossier`, celui du
    /// mandat). `exiger_empreinte` : en service, un fichier non lié par la cosignature est
    /// refusé (EF-M3).
    pub fn charger_filtres(&mut self, dossier: &std::path::Path, exiger_empreinte: bool) -> Result<(), String> {
        let tous = self.mandat.mandat.moniteurs.as_ref().map(|m| m.filtres.clone()).unwrap_or_default();
        self.filtres = crate::filtres::charger(&tous, Some(dossier), exiger_empreinte)?;
        Ok(())
    }

    /// Avis des filtres de contenu sur l'événement.
    fn avis_filtres(&self, evt: &EvenementOutil, sortante: bool) -> Vec<Avis> {
        if self.filtres.is_empty() {
            return Vec::new();
        }
        let mut texte = evt.entree.to_string();
        if let Some(s) = &evt.contenu_execute {
            texte.push('\n');
            texte.push_str(s);
        }
        self.filtres.iter().filter_map(|f| f.avis(&texte, sortante)).collect()
    }

    /// Moniteurs externes à consulter pour cette action (EF-M1) : seulement si elle est
    /// encore permise, selon leur déclenchement, dans leur budget. `tirage(i)` est uniforme
    /// dans `[0, 1)` pour le i-ème moniteur. Sans effet sur l'état.
    pub fn preparer_externes(&self, evt: &EvenementOutil, tirage: &mut dyn FnMut() -> f64) -> Vec<Consultation> {
        let Some(m) = self.mandat.mandat.moniteurs.as_ref().filter(|m| !m.externes.is_empty()) else { return Vec::new() };
        let (action, verdict) = self.examiner(evt);
        if verdict != Verdict::Allow {
            return Vec::new();
        }
        let sensible = self.profil().signaux(evt, &action).juge;
        let historique: Vec<serde_json::Value> =
            self.traces.get(&evt.session).map(|t| t.iter().filter_map(|x| serde_json::to_value(x).ok()).collect()).unwrap_or_default();
        m.externes
            .iter()
            .filter(|c| {
                let appels = self.appels_externes.get(&(c.id.clone(), evt.session.clone())).copied().unwrap_or(0);
                let t = tirage();
                appels < c.appels_max && (c.quand == crate::modules::Declenchement::Toujours || sensible || t < c.echantillon)
            })
            .map(|c| Consultation::Externe { id: c.id.clone(), requete: crate::modules::requete(c, &self.mandat.mandat.intention, evt, &action, &historique) })
            .collect()
    }

    /// Déclaration d'un moniteur externe du mandat.
    pub fn moniteur_externe(&self, id: &str) -> Option<&crate::modules::ConfigMoniteurExterne> {
        self.mandat.mandat.moniteurs.as_ref()?.externes.iter().find(|c| c.id == id)
    }

    pub fn noter_appel_externe(&mut self, id: &str, session: &str) {
        *self.appels_externes.entry((id.to_string(), session.to_string())).or_default() += 1;
    }

    pub fn noter_appel_sonde(&mut self, session: &str) -> u32 {
        let n = self.appels_sonde.entry(session.to_string()).or_default();
        *n += 1;
        *n
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
        let signaux = self.profil().signaux(evt, &action);
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
        if !sources.is_empty() && self.profil().sensible_a_l_influence(&action) {
            avis.push(Avis {
                moniteur: "provenance".into(),
                niveau: Niveau::Suspect,
                score: 0.5,
                motif: format!("session influencée par un contenu non fiable ({})", sources.join(", ")),
            });
        }
        // Secrets : moniteur déterministe (EF-D1).
        avis.extend(moniteurs::avis_secrets(evt, signaux.sortante));
        avis.extend(self.avis_filtres(evt, signaux.sortante));
        // Enchaînements : les actions précédentes de la session (EF-E4).
        avis.extend(self.avis_enchainement(evt, &action, &signaux));
        // Moniteurs spécialisés du profil : ils ne peuvent que durcir (§8).
        avis.extend(self.profil().avis(evt, &action, &self.mandat.mandat));
        // Moniteurs à état de session du profil (cumuls…).
        avis.extend(self.etat_profil.iter().flat_map(|s| s.avis(&self.mandat.mandat, evt, &action)));
        // Agrégation des avis probabilistes (EF-K2) : un plancher de plus, jamais de moins.
        let agregation = crate::modules::avis_agregation(self.mandat.mandat.moniteurs.as_ref().and_then(|m| m.agregation.as_ref()), &externes);
        avis.extend(externes);
        avis.extend(agregation);
        let finale = combiner(politique, avis, gele);
        if let Some(s) = self.etat_profil.as_mut() {
            s.noter(evt, &action, finale.verdict);
        }
        if finale.verdict == Verdict::Gel {
            self.sessions_gelees.insert(evt.session.clone());
        }
        let traces = self.traces.entry(evt.session.clone()).or_default();
        traces.push_back(Trace::depuis(evt, &action, &signaux, finale.verdict));
        if traces.len() > TRACES_MAX {
            traces.pop_front();
        }
        (action, finale)
    }

    /// Proposition du modèle écartée par un protocole avant d'atteindre l'agent (EF-E2) :
    /// elle compte comme un refus dans les bornes et reste dans les enchaînements de la
    /// session (EF-E4) — l'intention qu'elle trahit ne disparaît pas avec elle. Rend vrai si
    /// une borne est dépassée : la session est alors gelée.
    pub fn ecarter(&mut self, evt: &EvenementOutil) -> bool {
        let action = self.normaliser(evt);
        let signaux = self.profil().signaux(evt, &action);
        let gel = self.suivi.observer(&action, Verdict::Deny).iter().any(|a| a.niveau == Niveau::Critique);
        if gel {
            self.sessions_gelees.insert(evt.session.clone());
        }
        let traces = self.traces.entry(evt.session.clone()).or_default();
        traces.push_back(Trace::depuis(evt, &action, &signaux, Verdict::Deny));
        if traces.len() > TRACES_MAX {
            traces.pop_front();
        }
        gel
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
        if let Some(s) = self.etat_profil.as_mut() {
            s.reinitialiser(session);
        }
        match session {
            Some(s) => {
                self.appels_juge.remove(s);
                self.appels_sonde.remove(s);
                self.appels_externes.retain(|(_, x), _| x != s);
            }
            None => {
                self.appels_juge.clear();
                self.appels_sonde.clear();
                self.appels_externes.clear();
            }
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

    /// Aligne les gels sur ceux d'un stockage partagé entre instances. Le stockage fait
    /// foi : une session gelée ici mais absente du stockage a été dégelée ailleurs, à
    /// quatre yeux ; elle est dégelée ici aussi, compteurs remis à zéro. Rend les dégels
    /// ainsi propagés (`None` : le gel global).
    pub fn aligner_gel(&mut self, global: bool, sessions: &HashSet<String>) -> Vec<Option<String>> {
        let mut degeles = Vec::new();
        if self.gel_global && !global {
            self.degeler(None);
            degeles.push(None);
        }
        let mut locales: Vec<String> = self.sessions_gelees.difference(sessions).cloned().collect();
        locales.sort();
        for s in locales {
            self.degeler(Some(&s));
            degeles.push(Some(s));
        }
        self.gel_global |= global;
        self.sessions_gelees.extend(sessions.iter().cloned());
        degeles
    }

    pub fn etat_gel(&self) -> (bool, Vec<String>) {
        let mut s: Vec<String> = self.sessions_gelees.iter().cloned().collect();
        s.sort();
        (self.gel_global, s)
    }
}
