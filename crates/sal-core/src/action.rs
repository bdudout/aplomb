//! **Événement d'outil** (ce que reçoit le superviseur) et **action normalisée**
//! (ce que juge la politique).
//!
//! Un mode de branchement (hook, proxy, passerelle MCP…) produit des
//! [`EvenementOutil`] ; un profil de domaine les traduit en [`Action`].
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Moment de l'événement par rapport à l'exécution de l'outil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Avant exécution : une décision est attendue.
    Avant,
    /// Après exécution : observation journalisée.
    Apres,
}

/// Événement brut transmis par un mode de branchement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvenementOutil {
    /// Identifiant de session de l'agent.
    pub session: String,
    /// Agent émetteur (ex. `claude-code`).
    pub agent: String,
    /// Mode de branchement déclaré (ex. `hook-claude-code`).
    pub mode: String,
    /// Répertoire de travail de l'agent.
    pub cwd: String,
    /// Nom de l'outil (ex. `Bash`, `Edit`).
    pub outil: String,
    /// Paramètres de l'outil, tels qu'émis par l'agent.
    pub entree: Value,
    pub phase: Phase,
    /// Chemin réel (liens symboliques résolus) calculé par l'adaptateur, s'il existe.
    #[serde(default)]
    pub chemin_reel: Option<String>,
    /// Contenu des scripts locaux que la commande exécute, lu par l'adaptateur (ressource
    /// réelle, EF-B4) : la décision porte sur ce que fait le script, pas sur son nom.
    #[serde(default)]
    pub contenu_execute: Option<String>,
}

/// Action normalisée, indépendante du mode de branchement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub session: String,
    pub agent: String,
    /// Verbe du vocabulaire du profil (devient l'action Cedar).
    pub verbe: String,
    /// Ressource réelle visée (chemin canonique, domaine, ou commande).
    pub ressource: String,
    /// Attributs calculés par le profil ; tous présents, jamais manquants (sinon une
    /// erreur Cedar pourrait faire sauter un `forbid`).
    pub contexte: Map<String, Value>,
}
