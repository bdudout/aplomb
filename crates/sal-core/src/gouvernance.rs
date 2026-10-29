//! **Gouvernance à quatre yeux** (EF-S2) : aucun artefact de confiance (mandat, fichier de
//! comptes) n'est accepté sur la seule signature d'une personne.
//!
//! Le **fichier de confiance** fixe les clés publiques de gouvernance et un **seuil** (au
//! moins 2). Un artefact porte une liste de signatures nominatives ; il n'est accepté que
//! si au moins `seuil` membres **distincts** l'ont signé tel quel. Modifier l'artefact
//! invalide toutes les signatures déjà posées.
//!
//! Le fichier de confiance est l'ancre : il se modifie hors bande (en déploiement, il
//! appartient à root, comme le binaire et les paramètres gérés).
use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::mandat::cle_publique;

/// Seuil minimal : en dessous, ce ne sont plus quatre yeux.
pub const SEUIL_MIN: usize = 2;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureNommee {
    pub id: String,
    /// Signature ed25519 (hex).
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membre {
    pub id: String,
    pub cle_publique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FichierConfiance {
    pub seuil: usize,
    pub membres: Vec<Membre>,
}

pub struct Confiance {
    seuil: usize,
    membres: Vec<(String, VerifyingKey)>,
}

/// Signe des octets au nom d'un membre.
pub fn signer(id: &str, cle: &SigningKey, octets: &[u8]) -> SignatureNommee {
    SignatureNommee { id: id.into(), signature: hex::encode(cle.sign(octets).to_bytes()) }
}

impl Confiance {
    pub fn nouvelle(f: FichierConfiance) -> Result<Self, String> {
        if f.seuil < SEUIL_MIN {
            return Err(format!("seuil {} : au moins {SEUIL_MIN} signataires distincts exigés", f.seuil));
        }
        if f.seuil > f.membres.len() {
            return Err(format!("seuil {} supérieur au nombre de membres ({})", f.seuil, f.membres.len()));
        }
        let (mut ids, mut cles, mut membres) = (HashSet::new(), HashSet::new(), Vec::new());
        for m in f.membres {
            let cle = cle_publique(&m.cle_publique).map_err(|e| format!("{} : {e}", m.id))?;
            if !ids.insert(m.id.clone()) || !cles.insert(cle.to_bytes()) {
                return Err(format!("{} : membre ou clé en double", m.id));
            }
            membres.push((m.id, cle));
        }
        Ok(Self { seuil: f.seuil, membres })
    }

    pub fn depuis_yaml(texte: &str) -> Result<Self, String> {
        Self::nouvelle(serde_yaml::from_str(texte).map_err(|e| format!("fichier de confiance : {e}"))?)
    }

    pub fn seuil(&self) -> usize {
        self.seuil
    }

    /// Membres dont la signature sur ces octets est valide (sans doublon, ordre stable).
    pub fn signataires_valides(&self, octets: &[u8], signatures: &[SignatureNommee]) -> Vec<String> {
        let mut valides: Vec<String> = Vec::new();
        for s in signatures {
            if valides.contains(&s.id) {
                continue;
            }
            let Some((_, cle)) = self.membres.iter().find(|(id, _)| *id == s.id) else { continue };
            let Some(tab) = hex::decode(&s.signature).ok().and_then(|o| <[u8; 64]>::try_from(o).ok()) else {
                continue;
            };
            if cle.verify(octets, &Signature::from_bytes(&tab)).is_ok() {
                valides.push(s.id.clone());
            }
        }
        valides
    }

    /// Accepte si au moins `seuil` membres distincts ont signé ; sinon dit qui manque.
    pub fn verifier(&self, octets: &[u8], signatures: &[SignatureNommee]) -> Result<Vec<String>, String> {
        let valides = self.signataires_valides(octets, signatures);
        if valides.len() >= self.seuil {
            Ok(valides)
        } else {
            Err(format!(
                "{}/{} signature(s) valide(s) ({}) : quatre yeux non atteints",
                valides.len(),
                self.seuil,
                if valides.is_empty() { "aucune".to_string() } else { valides.join(", ") }
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cle(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn confiance(seuil: usize) -> Result<Confiance, String> {
        let m = |id: &str, n: u8| Membre { id: id.into(), cle_publique: hex::encode(cle(n).verifying_key().to_bytes()) };
        Confiance::nouvelle(FichierConfiance { seuil, membres: vec![m("alice", 1), m("bob", 2), m("dan", 4)] })
    }

    #[test]
    fn seuil_de_deux_au_moins() {
        assert!(confiance(1).is_err());
        assert!(confiance(4).is_err());
        assert!(confiance(2).is_ok());
    }

    #[test]
    fn deux_signataires_distincts() {
        let c = confiance(2).unwrap();
        let o = b"mandat v4";
        let a = signer("alice", &cle(1), o);
        assert!(c.verifier(o, &[a.clone()]).unwrap_err().contains("1/2"));
        // La même personne deux fois ne compte qu'une fois.
        assert!(c.verifier(o, &[a.clone(), a.clone()]).is_err());
        // Signer au nom d'un autre avec sa propre clé ne vaut rien.
        assert!(c.verifier(o, &[a.clone(), signer("bob", &cle(1), o)]).is_err());
        // Un inconnu ne compte pas.
        assert!(c.verifier(o, &[a.clone(), signer("eve", &cle(9), o)]).is_err());
        assert_eq!(c.verifier(o, &[a.clone(), signer("bob", &cle(2), o)]).unwrap(), vec!["alice", "bob"]);
        // Contenu modifié après signature : plus rien ne tient.
        assert!(c.verifier(b"mandat v5", &[a, signer("bob", &cle(2), o)]).unwrap_err().contains("0/2"));
    }

    #[test]
    fn membres_en_double_refuses() {
        let k = hex::encode(cle(1).verifying_key().to_bytes());
        let f = FichierConfiance {
            seuil: 2,
            membres: vec![Membre { id: "a".into(), cle_publique: k.clone() }, Membre { id: "b".into(), cle_publique: k }],
        };
        assert!(Confiance::nouvelle(f).is_err());
    }
}
