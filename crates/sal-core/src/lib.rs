//! **sal-core** — cœur de confiance du Superviseur d'Alignement Local.
//!
//! Bibliothèque pure : aucune I/O réseau, aucun appel de modèle sur le chemin
//! d'autorisation (ENF-1). Le binaire `sal` l'expose en service réseau.
//!
//! Chaîne de traitement d'une action :
//! `profils::code::normaliser` → `politique::Politique::evaluer` →
//! `decision::combiner` → `journal::Journal::ajouter`.
#![forbid(unsafe_code)]

pub mod action;
pub mod autorite;
pub mod bornes;
pub mod confidentiel;
pub mod decision;
pub mod journal;
pub mod mandat;
pub mod mermaid;
pub mod politique;
pub mod profils;
pub mod superviseur;
