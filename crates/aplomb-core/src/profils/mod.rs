//! **Profils de domaine** (contrat de profil, §8). Un profil traduit un événement
//! d'outil en action normalisée et calcule les attributs utilisés par ses règles Cedar.
//! Il ne décide rien : la décision appartient à la politique.
//!
//! **Registre** : le socle ne connaît aucun profil par son nom. Il demande au registre le
//! profil déclaré par le mandat ([`pour`]) et ne passe que par le trait [`Profil`]. Ajouter
//! un profil, c'est écrire son module, ses règles et son jeu d'évaluation dans
//! `profils/<nom>/`, puis l'inscrire dans [`PROFILS`] : le socle ne change pas (ENF-8).
//!
//! Un profil ne peut rien affaiblir : ses moniteurs ne font que durcir (algèbre de décision),
//! un profil inconnu refuse tout, et `aplomb serve` refuse de démarrer sans lui.
use serde_json::{json, Map};

use crate::action::{Action, EvenementOutil};
use crate::decision::{Avis, Verdict};
use crate::mandat::Mandat;

pub mod code;
pub mod metier;
pub mod pentest;

/// Contrat de profil (§8), vu du socle.
pub trait Profil: Sync {
    /// Nom déclaré dans le mandat (`profil: <nom>`).
    fn nom(&self) -> &'static str;
    /// Une ligne pour l'aide et les messages.
    fn description(&self) -> &'static str;
    /// Traduit un événement d'outil en action normalisée (verbe du profil, ressource réelle,
    /// attributs toujours présents).
    fn normaliser(&self, evt: &EvenementOutil, mandat: &Mandat) -> Action;
    /// Le résultat de cette action apporte-t-il un contenu non fiable (EF-B5) ?
    fn source_non_fiable(&self, action: &Action, mandat: &Mandat) -> bool;
    /// Action que le contenu non fiable ne doit pas déclencher seul (relevée en revue).
    fn sensible_a_l_influence(&self, action: &Action) -> bool;
    /// Moniteurs spécialisés du profil (EF-E1) : des avis qui ne peuvent que durcir.
    fn avis(&self, _evt: &EvenementOutil, _action: &Action, _mandat: &Mandat) -> Vec<Avis> {
        Vec::new()
    }
    /// Vérifie l'extension de schéma du mandat propre au profil. Le message dit quoi corriger.
    fn valider(&self, _mandat: &Mandat) -> Result<(), String> {
        Ok(())
    }
    /// Valeurs substituées dans le jeu d'évaluation du profil, en plus de `{racine}`,
    /// `{home}` et `{domaine}` (par exemple une cible du périmètre).
    fn substitutions(&self, _mandat: &Mandat) -> Vec<(String, String)> {
        Vec::new()
    }
    /// Ce que le mandat impose, en quelques lignes lisibles (affiché par `aplomb serve`).
    fn resume(&self, _mandat: &Mandat) -> Vec<String> {
        Vec::new()
    }
    /// Ce que le socle doit savoir de l'action pour ses moniteurs génériques (juge, secrets,
    /// enchaînements). Le socle ne connaît aucun verbe : il ne lit que ces signaux (EF-M7).
    /// Par défaut : juge pour toute action sensible à l'influence ou non déclarée, envoi
    /// d'après l'attribut `envoi_externe`, destination d'après `domaine`.
    fn signaux(&self, _evt: &EvenementOutil, action: &Action) -> Signaux {
        let envoi = attribut_vrai(action, "envoi_externe");
        Signaux {
            juge: action.verbe == "autre" || self.sensible_a_l_influence(action),
            sortante: envoi,
            envoi,
            destination: action.contexte.get("domaine").and_then(serde_json::Value::as_str).unwrap_or_default().to_string(),
            ..Signaux::default()
        }
    }
    /// Moniteurs à état de session (cumuls de paiements, dossiers lus…). Chaque superviseur
    /// en reçoit un neuf ; aucun par défaut.
    fn suivi(&self) -> Option<Box<dyn Suivi>> {
        None
    }
    /// Référentiels sectoriels du profil (§9).
    fn referentiels(&self) -> &'static [&'static str];
}

/// Signaux d'une action, fournis par son profil (voir [`Profil::signaux`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signaux {
    /// L'action justifie le juge à chaque fois ; sinon il n'est consulté que par échantillon.
    pub juge: bool,
    /// L'action fait sortir des données hors de la machine : un secret y est critique.
    pub sortante: bool,
    /// L'action peut emporter des données lues auparavant (« lecture sensible puis envoi »).
    pub envoi: bool,
    /// L'action lit une donnée sensible.
    pub lit_sensible: bool,
    /// Nom du fichier qu'écrit un téléchargement.
    pub telecharge: Option<String>,
    /// Noms des fichiers que l'action exécute.
    pub executes: Vec<String>,
    /// Destination visée (domaine), pour « refus puis détour ».
    pub destination: String,
}

/// Attribut booléen du contexte d'une action (faux s'il est absent).
pub fn attribut_vrai(action: &Action, cle: &str) -> bool {
    action.contexte.get(cle).and_then(serde_json::Value::as_bool).unwrap_or(false)
}

/// État des moniteurs d'un profil, propre à un superviseur. Ses avis ne peuvent que durcir.
pub trait Suivi: Send + Sync + std::fmt::Debug {
    /// Avis sur l'action, sans changer l'état.
    fn avis(&self, mandat: &Mandat, evt: &EvenementOutil, action: &Action) -> Vec<Avis>;
    /// Après la décision finale.
    fn noter(&mut self, evt: &EvenementOutil, action: &Action, verdict: Verdict);
    /// Au dégel d'une session (ou de toutes).
    fn reinitialiser(&mut self, session: Option<&str>);
}

/// Profils connus d'Aplomb. Ajouter un profil : une ligne ici.
pub static PROFILS: &[&dyn Profil] = &[&code::ProfilCode, &pentest::ProfilPentest, &metier::ProfilMetier];

/// Profil déclaré par son nom, s'il existe.
pub fn trouver(nom: &str) -> Option<&'static dyn Profil> {
    PROFILS.iter().copied().find(|p| p.nom() == nom)
}

/// Noms des profils connus, pour les messages d'erreur et l'aide.
pub fn noms() -> Vec<&'static str> {
    PROFILS.iter().map(|p| p.nom()).collect()
}

/// Profil d'un mandat. Un profil inconnu donne [`Inconnu`], qui refuse tout (fail-closed) ;
/// `aplomb serve` l'a déjà refusé au démarrage.
pub fn pour(nom: &str) -> &'static dyn Profil {
    trouver(nom).unwrap_or(&Inconnu)
}

/// Vérifie qu'un mandat déclare un profil connu et que son extension est valide.
pub fn verifier_mandat(mandat: &Mandat) -> Result<&'static dyn Profil, String> {
    let p = trouver(&mandat.profil).ok_or_else(|| {
        format!("profil « {} » inconnu : choisir parmi {}", mandat.profil, noms().join(", "))
    })?;
    p.valider(mandat).map_err(|e| format!("mandat {} (profil {}) : {e}", mandat.id, p.nom()))?;
    if let Some(a) = &mandat.approbation {
        a.verifier().map_err(|e| format!("mandat {} : {e}", mandat.id))?;
    }
    // Modules déclarés au mandat (EF-M1) : chaque moniteur externe est valide et nommé une fois.
    if let Some(m) = &mandat.moniteurs {
        for f in &m.filtres {
            if let crate::filtres::Filtre::Pack { pack, sortant, local } = f {
                crate::filtres::pack_integre(pack, *sortant, *local).map_err(|e| format!("mandat {} : {e}", mandat.id))?;
            }
        }
        let mut vus = std::collections::HashSet::new();
        for c in &m.externes {
            c.verifier().map_err(|e| format!("mandat {} : {e}", mandat.id))?;
            if !vus.insert(c.id.as_str()) {
                return Err(format!("mandat {} : moniteurs.externes « {} » déclaré deux fois", mandat.id, c.id));
            }
        }
    }
    Ok(p)
}

/// Profil de repli : verbe que nulle règle ne permet, donc refus par défaut.
pub struct Inconnu;

impl Profil for Inconnu {
    fn nom(&self) -> &'static str {
        "inconnu"
    }
    fn description(&self) -> &'static str {
        "profil non reconnu : tout est refusé"
    }
    fn normaliser(&self, evt: &EvenementOutil, _mandat: &Mandat) -> Action {
        let mut contexte = Map::new();
        contexte.insert("outil".into(), json!(evt.outil));
        Action {
            session: evt.session.clone(),
            agent: evt.agent.clone(),
            verbe: "profil_inconnu".into(),
            ressource: evt.outil.clone(),
            contexte,
        }
    }
    fn source_non_fiable(&self, _action: &Action, _mandat: &Mandat) -> bool {
        true
    }
    fn sensible_a_l_influence(&self, _action: &Action) -> bool {
        true
    }
    fn referentiels(&self) -> &'static [&'static str] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registre() {
        assert_eq!(noms(), vec!["code", "pentest", "metier"]);
        assert_eq!(pour("metier").nom(), "metier");
        assert_eq!(pour("code").nom(), "code");
        assert_eq!(pour("pentest").nom(), "pentest");
        assert_eq!(pour("nimporte").nom(), "inconnu");
        for p in PROFILS {
            assert!(!p.referentiels().is_empty(), "{} sans référentiel", p.nom());
            assert!(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profils").join(p.nom()).join("evaluation.yaml").exists(),
                "profil {} sans jeu d'évaluation (EF-H3)",
                p.nom()
            );
        }
    }
}
