//! **Algèbre de décision** (EF-K).
//!
//! Treillis totalement ordonné `Allow < Review < Deny < Gel`. La décision finale est le
//! **maximum** de la décision de politique (déterministe) et des planchers imposés par
//! les moniteurs. Un moniteur ne peut donc que **durcir** une décision, jamais
//! l'assouplir (EF-K1) — généralisation de `clusa-judge::combiner`.
use serde::{Deserialize, Serialize};

/// Issue d'une décision. L'ordre de déclaration fixe l'ordre de sévérité.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Exécution automatique (palier Vert).
    Allow,
    /// Approbation humaine requise (palier Orange).
    Review,
    /// Refus (palier Rouge).
    Deny,
    /// Refus et gel de la session.
    Gel,
}

/// Décision déterministe : verdict, règle déclenchée et motif.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub regle: String,
    pub motif: String,
}

/// Niveau d'alignement rendu par un moniteur, du moins au plus sévère.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Niveau {
    Conforme,
    Suspect,
    Critique,
}

impl Niveau {
    /// Plancher de verdict exigé par ce niveau.
    pub fn plancher(self) -> Verdict {
        match self {
            Niveau::Conforme => Verdict::Allow,
            Niveau::Suspect => Verdict::Review,
            Niveau::Critique => Verdict::Gel,
        }
    }
}

/// Avis normalisé d'un moniteur (contrat de moniteur, §8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Avis {
    pub moniteur: String,
    pub niveau: Niveau,
    /// Score de désalignement dans `[0, 1]`.
    pub score: f32,
    pub motif: String,
}

/// Décision finale, avec la décision de politique d'origine pour la traçabilité.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionFinale {
    pub verdict: Verdict,
    pub politique: Decision,
    pub avis: Vec<Avis>,
    /// Vrai si un moniteur ou le gel a durci la décision de politique.
    pub durci: bool,
    pub motif: String,
}

/// Combine politique, avis des moniteurs et état de gel.
///
/// **Invariant** : `resultat.verdict >= politique.verdict`, et `>= plancher` de chaque avis.
pub fn combiner(politique: Decision, avis: Vec<Avis>, gele: bool) -> DecisionFinale {
    let mut verdict = politique.verdict;
    let mut motifs = Vec::new();
    for a in &avis {
        if a.niveau.plancher() > verdict {
            verdict = a.niveau.plancher();
            motifs.push(format!("{} ({:?}) : {}", a.moniteur, a.niveau, a.motif));
        }
    }
    if gele && verdict < Verdict::Gel {
        verdict = Verdict::Gel;
        motifs.push("session gelée par l'opérateur".into());
    }
    let durci = verdict > politique.verdict;
    let motif = if durci {
        format!("durci — {} ; politique : {}", motifs.join(" ; "), politique.motif)
    } else {
        politique.motif.clone()
    };
    DecisionFinale { verdict, politique, avis, durci, motif }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![
            Just(Verdict::Allow),
            Just(Verdict::Review),
            Just(Verdict::Deny),
            Just(Verdict::Gel)
        ]
    }

    fn niveau() -> impl Strategy<Value = Niveau> {
        prop_oneof![Just(Niveau::Conforme), Just(Niveau::Suspect), Just(Niveau::Critique)]
    }

    fn decision(v: Verdict) -> Decision {
        Decision { verdict: v, regle: "r".into(), motif: "m".into() }
    }

    fn avis(n: Niveau) -> Avis {
        Avis { moniteur: "test".into(), niveau: n, score: 0.5, motif: "a".into() }
    }

    proptest! {
        /// EF-K1 : aucun moniteur ne peut assouplir la décision de politique.
        #[test]
        fn ne_peut_que_durcir(v in verdict(), ns in prop::collection::vec(niveau(), 0..6), gele in any::<bool>()) {
            let r = combiner(decision(v), ns.iter().map(|n| avis(*n)).collect(), gele);
            prop_assert!(r.verdict >= v);
            for n in &ns {
                prop_assert!(r.verdict >= n.plancher());
            }
            if gele { prop_assert_eq!(r.verdict, Verdict::Gel); }
        }

        /// Le résultat est exactement le maximum : la combinaison ne durcit pas sans raison.
        #[test]
        fn est_le_maximum(v in verdict(), ns in prop::collection::vec(niveau(), 0..6)) {
            let attendu = ns.iter().map(|n| n.plancher()).fold(v, std::cmp::max);
            let r = combiner(decision(v), ns.iter().map(|n| avis(*n)).collect(), false);
            prop_assert_eq!(r.verdict, attendu);
            prop_assert_eq!(r.durci, attendu > v);
        }

        /// L'ordre des avis n'a aucune influence.
        #[test]
        fn independant_de_l_ordre(v in verdict(), mut ns in prop::collection::vec(niveau(), 0..6)) {
            let a = combiner(decision(v), ns.iter().map(|n| avis(*n)).collect(), false).verdict;
            ns.reverse();
            let b = combiner(decision(v), ns.iter().map(|n| avis(*n)).collect(), false).verdict;
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn ordre_du_treillis() {
        assert!(Verdict::Allow < Verdict::Review);
        assert!(Verdict::Review < Verdict::Deny);
        assert!(Verdict::Deny < Verdict::Gel);
    }
}
