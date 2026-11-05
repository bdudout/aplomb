//! `aplomb evaluer` — banc rouge/bleu (EF-H1) : joue le jeu d'évaluation du profil avec le
//! mandat (signé ou candidat), son juge compris, et rend sûreté, utilité et coût. Avec
//! `--reference`, échoue si une attaque passe moins bien qu'avant (EF-H4).
//!
//! La cosignature d'un mandat rejoue le même jeu, sans juge (déterministe) : voir
//! [`controler_avant_cosignature`].
use std::path::{Path, PathBuf};

use aplomb_core::decision::Avis;
use aplomb_core::evaluation::{effets_utilite, evaluer, regressions, Issue, Jeu, Lieux, MesureJuge, Nature, Rapport};
use aplomb_core::mandat::MandatCharge;
use aplomb_core::superviseur::{Consultation, Superviseur};

pub struct Options {
    pub mandat: PathBuf,
    pub jeu: Option<PathBuf>,
    pub sans_juge: bool,
    pub budget_audit: f64,
    pub reference: Option<PathBuf>,
    pub sortie: Option<PathBuf>,
}

/// Jeu du profil : `evaluation.yaml` à côté des règles du mandat.
fn chemin_jeu(mandat: &Path, m: &MandatCharge) -> PathBuf {
    let dossier = mandat.parent().unwrap_or(Path::new("."));
    dossier.join(&m.mandat.politique.regles).with_file_name("evaluation.yaml")
}

fn lire_jeu(chemin: &Path) -> Result<Jeu, String> {
    let texte = std::fs::read_to_string(chemin).map_err(|e| format!("jeu d'évaluation {} : {e}", chemin.display()))?;
    serde_yaml::from_str(&texte).map_err(|e| format!("jeu d'évaluation {} : {e}", chemin.display()))
}

fn lieux(m: &MandatCharge) -> Lieux {
    Lieux {
        racine: m.mandat.perimetre.racine.clone(),
        home: std::env::var("HOME").unwrap_or_else(|_| "/home/utilisateur".into()),
        domaine: m.mandat.perimetre.domaines_autorises.first().cloned(),
    }
}

fn jouer(m: MandatCharge, jeu: &Jeu, budget: f64, juge: Option<&crate::juge::Juge>) -> Result<Rapport, String> {
    if jeu.profil != m.mandat.profil {
        return Err(format!("jeu du profil « {} », mandat du profil « {} »", jeu.profil, m.mandat.profil));
    }
    let l = lieux(&m);
    let mut sup = Superviseur::nouveau(m).map_err(|e| e.to_string())?;
    if juge.is_none() {
        // Évaluation déterministe : le juge du mandat n'est pas consulté.
        sup.mandat.mandat.moniteurs = None;
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    let mut consulter = |c: &Consultation| -> (Vec<Avis>, Option<MesureJuge>) {
        match (c, juge) {
            (Consultation::BudgetEpuise(a), _) => (vec![a.clone()], None),
            (Consultation::Juge { consigne, message, .. }, Some(j)) => {
                let (issue, latence_ms) = rt.block_on(j.consulter(consigne, message));
                let indisponible = issue.is_err();
                let avis = issue.unwrap_or_else(|e| aplomb_core::moniteurs::avis_indisponible(&e));
                (vec![avis], Some(MesureJuge { latence_ms, indisponible }))
            }
            (Consultation::Juge { .. }, None) => (Vec::new(), None),
        }
    };
    Ok(evaluer(&mut sup, jeu, &l, budget, &mut consulter))
}

fn pourcent(x: f64) -> String {
    format!("{:.0} %", x * 100.0)
}

fn afficher(r: &Rapport) {
    let attaques = r.scenarios.iter().filter(|s| s.nature == Nature::Attaque && s.issue != Issue::NonApplicable).count();
    let legitimes = r.scenarios.iter().filter(|s| s.nature == Nature::Legitime && s.issue != Issue::NonApplicable).count();
    println!("Banc rouge/bleu — mandat {} — juge : {}", r.mandat, r.juge.as_deref().unwrap_or("aucun"));
    println!();
    for s in &r.scenarios {
        let issue = match s.issue {
            Issue::Fluide => "fluide",
            Issue::AvecRevue => "avec revue",
            Issue::Bloque => "BLOQUÉ",
            Issue::Bloquee => "bloquée",
            Issue::Detectee => "détectée",
            Issue::Manquee => "MANQUÉE",
            Issue::NonApplicable => "sans objet",
        };
        let nature = if s.nature == Nature::Attaque { "rouge" } else { "bleu " };
        let cible = s.cible.as_deref().map(|c| format!(" [{c}]")).unwrap_or_default();
        println!("  {nature} {:<12} {}{cible}", issue, s.id);
        if matches!(s.issue, Issue::Manquee | Issue::Bloque) {
            println!("        {}", s.motif);
        }
    }
    println!();
    println!("  sûreté            : {} des {attaques} attaques bloquées ou mises en revue ({} sans humain)", pourcent(r.surete), pourcent(r.surete_sans_humain));
    println!("  utilité           : {} des {legitimes} tâches légitimes sans humain ({} revues comprises)", pourcent(r.utilite), pourcent(r.utilite_avec_revue));
    println!(
        "  budget d'audit    : {} revues pour {} actions légitimes ({}), budget {} — {}",
        r.revues,
        r.actions,
        pourcent(r.taux_revue),
        pourcent(r.budget_audit),
        if r.budget_respecte { "respecté" } else { "DÉPASSÉ : toutes les revues ne seront pas faites" }
    );
    if r.juge.is_some() {
        let c = &r.cout_juge;
        println!("  coût du juge      : {} consultations, {} indisponibles, {} ms en moyenne", c.consultations, c.indisponible, c.latence_moyenne_ms);
    }
}

fn lire_rapport(chemin: &Path) -> Result<Rapport, String> {
    let t = std::fs::read_to_string(chemin).map_err(|e| format!("référence {} : {e}", chemin.display()))?;
    serde_json::from_str(&t).map_err(|e| format!("référence {} : {e}", chemin.display()))
}

fn ecrire_rapport(chemin: &Path, r: &Rapport) -> Result<(), String> {
    std::fs::write(chemin, serde_json::to_string_pretty(r).map_err(|e| e.to_string())?).map_err(|e| format!("{} : {e}", chemin.display()))
}

/// Affiche les régressions et les effets sur l'utilité ; rend vrai s'il y a régression.
fn comparer(reference: &Rapport, r: &Rapport) -> bool {
    let reg = regressions(reference, r);
    let effets = effets_utilite(reference, r);
    println!();
    if reg.is_empty() {
        println!("  non-régression    : aucune attaque ne passe mieux qu'avec la référence ({})", reference.mandat);
    } else {
        println!("  RÉGRESSION DE SÛRETÉ par rapport à la référence ({}) :", reference.mandat);
        for x in &reg {
            println!("    - {x}");
        }
    }
    for x in &effets {
        println!("    utilité : {x}");
    }
    !reg.is_empty()
}

pub fn lancer(o: Options) -> Result<(), String> {
    let m = aplomb_core::mandat::charger_candidat(&o.mandat).map_err(|e| format!("mandat {} : {e}", o.mandat.display()))?;
    let jeu = lire_jeu(&o.jeu.clone().unwrap_or_else(|| chemin_jeu(&o.mandat, &m)))?;
    let juge = match (o.sans_juge, m.mandat.moniteurs.as_ref().and_then(|x| x.juge.clone())) {
        (false, Some(cfg)) => {
            // Le jeton n'est lu (phrase ou déverrouillage) que pour un juge sur l'API Messages.
            let jeton = if cfg.api == aplomb_core::moniteurs::ApiJuge::Anthropic { crate::cle_maitresse::jeton_modele()? } else { None };
            Some(crate::juge::Juge::nouveau(cfg, jeton)?)
        }
        _ => None,
    };
    let r = jouer(m, &jeu, o.budget_audit, juge.as_ref())?;
    afficher(&r);
    let regression = match &o.reference {
        Some(c) => comparer(&lire_rapport(c)?, &r),
        None => false,
    };
    if let Some(c) = &o.sortie {
        ecrire_rapport(c, &r)?;
        println!("  rapport           : {}", c.display());
    }
    if regression {
        return Err("régression de sûreté : voir ci-dessus".into());
    }
    Ok(())
}

/// Référence d'évaluation d'un mandat, à côté de lui (non versionnée, comme le mandat).
pub fn chemin_reference(mandat: &Path) -> PathBuf {
    mandat.with_extension("evaluation.json")
}

/// Avant de cosigner un mandat (EF-H4) : rejoue le jeu du profil sans juge et refuse si une
/// attaque passe moins bien qu'à la dernière cosignature. Sans jeu pour le profil, rien.
/// Rend le rapport, à enregistrer comme nouvelle référence une fois la signature posée.
pub fn controler_avant_cosignature(mandat: &Path, accepter_regression: bool) -> Result<Option<Rapport>, String> {
    let m = aplomb_core::mandat::charger_candidat(mandat).map_err(|e| e.to_string())?;
    let chemin = chemin_jeu(mandat, &m);
    if !chemin.exists() {
        return Ok(None);
    }
    let r = jouer(m, &lire_jeu(&chemin)?, 1.0, None)?;
    let attaques = r.scenarios.iter().filter(|s| s.nature == Nature::Attaque && s.issue != Issue::NonApplicable).count();
    println!(
        "évaluation (sans juge) : sûreté {} sur {attaques} attaques, utilité {} ({} revues comprises)",
        pourcent(r.surete),
        pourcent(r.utilite),
        pourcent(r.utilite_avec_revue)
    );
    let reference = chemin_reference(mandat);
    if reference.exists() {
        let ancien = lire_rapport(&reference)?;
        if comparer(&ancien, &r) && !accepter_regression {
            return Err(format!(
                "cosignature refusée : le mandat laisse passer des attaques que la version précédente arrêtait. \
                 Détail : aplomb evaluer --mandat {} --reference {} ; accepter quand même : --accepter-regression",
                mandat.display(),
                reference.display()
            ));
        }
    }
    Ok(Some(r))
}

pub fn enregistrer_reference(mandat: &Path, r: &Rapport) -> Result<(), String> {
    ecrire_rapport(&chemin_reference(mandat), r)
}
