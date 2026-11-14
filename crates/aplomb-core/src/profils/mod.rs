//! **Profils de domaine** (contrat de profil, §8). Un profil traduit un événement
//! d'outil en action normalisée et calcule les attributs utilisés par ses règles Cedar.
//! Il ne décide rien : la décision appartient à la politique.
pub mod code;
pub mod metier;

// --- Aiguillage par profil (J7) ------------------------------------------------------
// Le superviseur passe par ces fonctions plutôt que par un profil précis. Un registre de
// profils pourra les remplacer : chaque fonction n'a qu'un `match` sur le nom du profil.

use crate::action::{Action, EvenementOutil};
use crate::decision::{Avis, Verdict};
use crate::mandat::Mandat;

/// Profils pris en charge.
pub const PROFILS: &[&str] = &["code", "metier"];

/// Vérifie qu'un mandat peut être supervisé : profil connu et extension de schéma valide.
pub fn verifier(mandat: &Mandat) -> Result<(), String> {
    match mandat.profil.as_str() {
        "code" => Ok(()),
        "metier" => metier::verifier(mandat),
        autre => Err(format!("profil « {autre} » inconnu (profils : {})", PROFILS.join(", "))),
    }
}

pub fn normaliser(evt: &EvenementOutil, mandat: &Mandat) -> Action {
    match mandat.profil.as_str() {
        "metier" => metier::normaliser(evt, mandat),
        _ => code::normaliser(evt, mandat),
    }
}

/// Le résultat de cette action apporte-t-il un contenu non fiable (EF-B5) ?
pub fn source_non_fiable(action: &Action, mandat: &Mandat) -> bool {
    match mandat.profil.as_str() {
        "metier" => metier::source_non_fiable(action),
        _ => code::source_non_fiable(action, mandat),
    }
}

/// Action qu'un contenu non fiable ne déclenche pas seul (EF-D2).
pub fn sensible_a_l_influence(action: &Action, mandat: &Mandat) -> bool {
    match mandat.profil.as_str() {
        "metier" => metier::sensible_a_l_influence(action),
        _ => code::sensible_a_l_influence(action),
    }
}

/// État des moniteurs propres aux profils (cumuls de session…).
#[derive(Debug, Default)]
pub struct Etat {
    metier: metier::Suivi,
}

impl Etat {
    /// Avis des moniteurs du profil, sans changer l'état.
    pub fn avis(&self, mandat: &Mandat, evt: &EvenementOutil, action: &Action) -> Vec<Avis> {
        match mandat.profil.as_str() {
            "metier" => self.metier.avis(mandat, evt, action),
            _ => Vec::new(),
        }
    }

    /// Après la décision.
    pub fn noter(&mut self, mandat: &Mandat, evt: &EvenementOutil, action: &Action, verdict: Verdict) {
        if mandat.profil == "metier" {
            self.metier.noter(evt, action, verdict);
        }
    }

    pub fn reinitialiser(&mut self, session: Option<&str>) {
        self.metier.reinitialiser(session);
    }
}
