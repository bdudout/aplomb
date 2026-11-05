//! **aplomb-core** — cœur de confiance du superviseur d'alignement pour agents d'IA.
//!
//! Bibliothèque pure : aucune I/O réseau, aucun appel de modèle sur le chemin
//! d'autorisation (ENF-1). Le binaire `aplomb` l'expose en service réseau.
//!
//! Chaîne de traitement d'une action :
//! `profils::code::normaliser` → `politique::Politique::evaluer` →
//! `decision::combiner` → `journal::Journal::ajouter`.
#![forbid(unsafe_code)]

pub mod action;
pub mod autorite;
pub mod bornes;
pub mod chaine;
pub mod confidentiel;
pub mod delegation;
pub mod decision;
pub mod gouvernance;
pub mod journal;
pub mod mandat;
pub mod mcp;
pub mod mermaid;
pub mod modele;
pub mod moniteurs;
pub mod passerelle;
pub mod politique;
pub mod profils;
pub mod reponse;
pub mod scellement;
pub mod superviseur;
