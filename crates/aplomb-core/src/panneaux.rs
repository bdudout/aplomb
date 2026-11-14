//! **Panneaux déclaratifs** d'Aplomb Watch (étape 10, visualisation, option) : un fichier
//! `panneaux.yaml` décrit des tableaux de bord sans écrire de code. Chaque panneau lit une
//! mesure des **indicateurs agrégés** (non nominatifs, seuil k appliqué), jamais le journal
//! brut : un panneau ne peut montrer ni une session, ni un compte, ni un contenu.
//!
//! ```yaml
//! panneaux:
//! - {titre: Refus et gels, type: compteur, mesure: decisions.deny, heures: 24}
//! - {titre: Règles déclenchées, type: repartition, mesure: regles, heures: 168}
//! - {titre: Revues par jour, type: serie, mesure: decisions.review, heures: 168, points: 7}
//! ```
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::indicateurs::Agregat;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypePanneau {
    /// Une valeur.
    Compteur,
    /// Une table (règles, outils, moniteurs, branchements…), triée par valeur.
    Repartition,
    /// Une valeur sur `points` intervalles successifs.
    Serie,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Panneau {
    pub titre: String,
    #[serde(rename = "type")]
    pub type_: TypePanneau,
    /// Chemin dans l'agrégat (`decisions.deny`, `revues.expirees`, `regles`) ou dans les taux
    /// (`taux.refus`).
    pub mesure: String,
    /// Période observée (défaut : 24 h).
    #[serde(default = "vingt_quatre")]
    pub heures: u64,
    /// Série : nombre d'intervalles (défaut : 12).
    #[serde(default = "douze")]
    pub points: u32,
    /// Répartition : nombre de lignes montrées (défaut : 10).
    #[serde(default = "dix")]
    pub lignes: usize,
}

fn vingt_quatre() -> u64 {
    24
}
fn douze() -> u32 {
    12
}
fn dix() -> usize {
    10
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigPanneaux {
    #[serde(default)]
    pub panneaux: Vec<Panneau>,
}

/// Tables de l'agrégat qu'une répartition peut montrer.
pub const REPARTITIONS: &[&str] = &[
    "regles",
    "moniteurs",
    "outils",
    "branchements",
    "decisions",
    "revues",
    "administration",
];

fn valeur<'a>(a: &'a Value, chemin: &str) -> Option<&'a Value> {
    chemin.split('.').try_fold(a, |v, k| v.get(k))
}

/// L'agrégat et ses taux, en une seule valeur où chercher les mesures.
pub fn source(a: &Agregat) -> Value {
    let mut v = serde_json::to_value(a).unwrap_or_default();
    v["taux"] = json!(crate::indicateurs::taux(a));
    v
}

impl ConfigPanneaux {
    pub fn depuis_yaml(t: &str) -> Result<Self, String> {
        let c: Self = serde_yaml::from_str(t).map_err(|e| format!("panneaux.yaml : {e}"))?;
        let exemple = source(&Agregat::default());
        for p in &c.panneaux {
            let x = format!("panneau « {} »", p.titre);
            if p.titre.trim().is_empty() {
                return Err("panneau sans titre".into());
            }
            if p.heures == 0 || p.heures > 24 * 366 {
                return Err(format!("{x} : heures entre 1 et 8784"));
            }
            match p.type_ {
                TypePanneau::Repartition => {
                    if !REPARTITIONS.contains(&p.mesure.as_str()) {
                        return Err(format!(
                            "{x} : répartition de {} inconnue ({})",
                            p.mesure,
                            REPARTITIONS.join(", ")
                        ));
                    }
                }
                _ => {
                    if !valeur(&exemple, &p.mesure).is_some_and(Value::is_number) {
                        return Err(format!("{x} : mesure {} inconnue (exemples : decisions.deny, revues.expirees, jetons, taux.refus)", p.mesure));
                    }
                    if p.type_ == TypePanneau::Serie && !(2..=48).contains(&p.points) {
                        return Err(format!("{x} : points entre 2 et 48"));
                    }
                }
            }
        }
        Ok(c)
    }
}

/// Valeur d'un compteur ou d'un point de série.
pub fn nombre(a: &Value, mesure: &str) -> f64 {
    valeur(a, mesure).and_then(Value::as_f64).unwrap_or(0.0)
}

/// Lignes d'une répartition, triées par valeur décroissante.
pub fn repartition(a: &Value, mesure: &str, lignes: usize) -> Vec<(String, f64)> {
    let mut v: Vec<(String, f64)> = valeur(a, mesure)
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, x)| x.as_f64().map(|n| (k.clone(), n)))
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|x, y| y.1.total_cmp(&x.1).then(x.0.cmp(&y.0)));
    v.truncate(lignes);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert!(ConfigPanneaux::depuis_yaml("panneaux:\n- {titre: A, type: compteur, mesure: decisions.deny}\n- {titre: B, type: repartition, mesure: regles}\n- {titre: C, type: serie, mesure: taux.refus, points: 6}\n").is_ok());
        assert!(ConfigPanneaux::depuis_yaml(
            "panneaux:\n- {titre: A, type: compteur, mesure: sessions_par_compte}\n"
        )
        .unwrap_err()
        .contains("inconnue"));
        assert!(ConfigPanneaux::depuis_yaml(
            "panneaux:\n- {titre: A, type: repartition, mesure: mandats}\n"
        )
        .is_err());
        assert!(ConfigPanneaux::depuis_yaml(
            "panneaux:\n- {titre: A, type: serie, mesure: jetons, points: 1}\n"
        )
        .is_err());
        assert!(ConfigPanneaux::depuis_yaml(
            "panneaux:\n- {titre: A, type: compteur, mesure: jetons, sql: x}\n"
        )
        .is_err());
    }

    #[test]
    fn lecture() {
        let mut a = Agregat::default();
        a.decisions.deny = 3;
        a.regles.insert("r1".into(), 2);
        a.regles.insert("r2".into(), 5);
        let s = source(&a);
        assert_eq!(nombre(&s, "decisions.deny"), 3.0);
        assert_eq!(repartition(&s, "regles", 1), vec![("r2".to_string(), 5.0)]);
    }
}
