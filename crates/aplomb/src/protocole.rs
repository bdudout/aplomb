//! **Protocoles AI control au proxy LLM** (EF-E2) et **lecture du raisonnement** (EF-E3).
//!
//! En mode `report` ou `reechantillonnage`, la réponse du modèle est retenue (plus de flux au
//! fil de l'eau) et chacun de ses appels d'outils est examiné avant que l'agent le reçoive :
//! moniteurs déterministes (règles, secrets, provenance), raisonnement, juge du mandat. Une
//! réponse suspecte est remplacée (modèle de confiance, ou autre échantillon du modèle). Ce
//! que le protocole a vu suit l'appel jusqu'à la décision du hook (`Annonce`) : le juge n'y
//! est pas consulté une seconde fois, et ses avis y sont repris.
use std::collections::HashMap;

use aplomb_core::action::{EvenementOutil, Phase};
use aplomb_core::decision::{Avis, Niveau, Verdict};
use aplomb_core::modele::reconstituer;
use aplomb_core::moniteurs::{avis_raisonnement, extrait_raisonnement, ModeProtocole, Moniteurs, Protocole};
use serde_json::Value;

use crate::serveur::{consulter_juge, Etat};

/// Réglages du proxy LLM tirés de la section `moniteurs` du mandat.
pub struct Reglages {
    /// Protocole qui retient les réponses ; `None` en surveillance (flux au fil de l'eau).
    pub protocole: Option<Protocole>,
    /// Hôte du modèle de confiance (`report`), validé comme `domaines_modele`.
    pub fiable: Option<String>,
    pub raisonnement: bool,
    agent: String,
    racine: String,
}

impl Reglages {
    pub fn depuis(m: Option<&Moniteurs>, agent: &str, racine: &str) -> Result<Self, String> {
        let protocole = m.and_then(|m| m.protocole.clone()).filter(|p| p.mode != ModeProtocole::Surveillance);
        if let Some(p) = &protocole {
            p.verifier()?;
        }
        let fiable = match protocole.as_ref().and_then(|p| p.fiable.as_ref()) {
            Some(f) => Some(aplomb_core::modele::amont(&f.url).map_err(|e| format!("moniteurs.protocole.fiable.url : {e}"))?),
            None => None,
        };
        Ok(Self { protocole, fiable, raisonnement: m.is_none_or(|m| m.raisonnement), agent: agent.into(), racine: racine.into() })
    }

    pub fn description(&self) -> String {
        let lecture = if self.raisonnement { "raisonnement lu" } else { "raisonnement non lu" };
        match &self.protocole {
            None => format!("surveillance (réponses relayées au fil de l'eau), {lecture}"),
            Some(p) if p.mode == ModeProtocole::Report => format!(
                "report vers le modèle de confiance {} ({}), seuil {}, {lecture}",
                p.fiable.as_ref().map(|f| f.modele.as_str()).unwrap_or("?"),
                self.fiable.as_deref().unwrap_or("?"),
                p.seuil
            ),
            Some(p) => format!("rééchantillonnage ({} échantillon(s) de plus), seuil {}, {lecture}", p.echantillons, p.seuil),
        }
    }

    /// Avis du raisonnement d'une réponse, et son extrait pour le juge.
    pub fn lire_raisonnement(&self, corps: &[u8]) -> (Option<String>, Option<Avis>) {
        if !self.raisonnement {
            return (None, None);
        }
        let r = reconstituer(corps).raisonnement;
        if r.trim().is_empty() {
            return (None, None);
        }
        (Some(extrait_raisonnement(&r)), avis_raisonnement(&r))
    }
}

/// Ce que le protocole a vu d'une réponse du modèle.
#[derive(Default)]
pub struct Examen {
    pub suspect: bool,
    /// Avis par identifiant d'appel d'outil, et si le juge l'a jugé.
    pub par_outil: HashMap<String, (Vec<Avis>, bool)>,
    pub raisonnement: Option<String>,
    /// Pour le journal : pourquoi la réponse est suspecte.
    pub motifs: Vec<String>,
}

/// Examine les appels d'outils d'une réponse, comme si l'agent les présentait maintenant.
pub async fn examiner(etat: &Etat, r: &Reglages, p: &Protocole, session: &str, corps: &[u8]) -> Examen {
    let contenu = reconstituer(corps);
    let (raisonnement, avis_r) = r.lire_raisonnement(corps);
    let mut ex = Examen { raisonnement, ..Default::default() };
    for (id, nom, entree) in contenu.outils {
        let evt = EvenementOutil {
            session: session.into(),
            agent: r.agent.clone(),
            mode: "proxy-llm".into(),
            cwd: r.racine.clone(),
            outil: nom.clone(),
            entree,
            phase: Phase::Avant,
            chemin_reel: None,
            contenu_execute: None,
            nonce: None,
            appel: Some(id.clone()),
            delegation: None,
        };
        let verdict = etat.examiner(&evt);
        let (mut avis, trace) = consulter_juge(etat, &evt, ex.raisonnement.as_deref()).await;
        let juge = trace.as_ref().is_some_and(|t| t.get("raison").is_some());
        avis.extend(avis_r.clone());
        if verdict >= Verdict::Deny {
            ex.motifs.push(format!("{nom} : refusé par les règles"));
        }
        for a in avis.iter().filter(|a| p.suspect(std::slice::from_ref(a))) {
            ex.motifs.push(format!("{nom} : {} ({})", a.motif, a.moniteur));
        }
        ex.suspect |= verdict >= Verdict::Deny || p.suspect(&avis);
        ex.par_outil.insert(id, (avis, juge));
    }
    ex
}

/// Avis ajouté à chaque appel d'une réponse suspecte que le protocole n'a pas pu remplacer :
/// l'humain tranche.
pub fn avis_non_remplacee(motif: &str) -> Avis {
    Avis { moniteur: "protocole".into(), niveau: Niveau::Suspect, score: 1.0, motif: motif.into() }
}

/// Corps de la requête pour le modèle de confiance : même conversation, son modèle.
pub fn requete_fiable(corps: &[u8], modele: &str) -> Option<Vec<u8>> {
    let mut v: Value = serde_json::from_slice(corps).ok()?;
    v["model"] = Value::String(modele.into());
    // Le raisonnement étendu dépend du modèle : le modèle de confiance répond sans.
    if let Some(o) = v.as_object_mut() {
        o.remove("thinking");
    }
    serde_json::to_vec(&v).ok()
}
