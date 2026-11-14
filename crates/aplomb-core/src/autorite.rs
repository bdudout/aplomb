//! **Autorité d'administration** (EF-S1, EF-S2) : qui peut faire quoi sur le superviseur.
//!
//! - **Comptes nominatifs** déclarés dans un fichier, chacun avec ses rôles et sa clé
//!   publique ed25519. L'authentification est la possession de la clé privée : chaque
//!   requête est **signée**, **horodatée** (±60 s) et porte un **nonce** à usage unique
//!   (pas de rejeu).
//! - **Rôles** : `lecteur` (consulter, vérifier le journal), `operateur` (geler,
//!   demander un dégel), `approbateur` (approuver un dégel).
//! - **Asymétrie, comme l'algèbre de décision** : durcir se fait seul (geler), assouplir
//!   exige **deux comptes distincts** (dégeler). Un compte ne peut jamais approuver sa
//!   propre demande.
//! - **Vue technique** : une requête signée `connexion` délivre un ticket à usage unique,
//!   échangé contre une session de navigateur (cookie) de durée bornée.
//!
//! Le module est pur (aucune I/O) : l'horloge est passée par l'appelant.
use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::mandat::cle_publique;

/// Tolérance d'horloge pour une requête signée.
pub const FENETRE_MS: u64 = 60_000;
/// Durée de vie d'un ticket de connexion.
pub const TICKET_MS: u64 = 120_000;
/// Durée d'une session de navigateur.
pub const SESSION_WEB_MS: u64 = 8 * 3600 * 1000;
/// Durée de validité d'une demande de dégel en attente d'approbation.
pub const DEMANDE_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Lecteur,
    Operateur,
    Approbateur,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compte {
    pub id: String,
    pub roles: Vec<Role>,
    /// Clé publique ed25519 (hex).
    pub cle_publique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FichierComptes {
    pub comptes: Vec<Compte>,
    /// Options d'identité (MFA, SSO, revue des comptes), cosignées avec les comptes :
    /// personne ne peut retirer seul le second facteur.
    #[serde(default, skip_serializing_if = "crate::identite::ConfigIdentite::est_vide")]
    pub identite: crate::identite::ConfigIdentite,
    /// Signatures de la gouvernance sur la liste des comptes (quatre yeux, EF-S2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<crate::gouvernance::SignatureNommee>,
}

impl FichierComptes {
    /// Octets couverts par les signatures : la liste des comptes, sans les signatures.
    pub fn octets_signes(&self) -> Vec<u8> {
        if self.identite.est_vide() {
            // Forme d'origine : les signatures existantes restent valables.
            serde_json::to_vec(&self.comptes).expect("sérialisation JSON")
        } else {
            serde_json::to_vec(&serde_json::json!({"comptes": self.comptes, "identite": self.identite})).expect("sérialisation JSON")
        }
    }
}

/// Action d'administration demandée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Connexion,
    Gel,
    Degel,
    /// Réactiver un compte suspendu pour inactivité (quatre yeux, EF-N5).
    Reactiver,
}

/// Corps signé d'une requête d'administration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Corps {
    pub compte: String,
    pub operation: Operation,
    /// Session visée ; absente = toutes les sessions (gel ou dégel global).
    #[serde(default)]
    pub session: Option<String>,
    /// Millisecondes depuis l'époque Unix.
    pub horodatage: u64,
    pub nonce: String,
    /// Code du second facteur (TOTP), pour les actions qui assouplissent quand la MFA est
    /// exigée (EF-N4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Compte visé (réactivation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cible: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequeteSignee {
    #[serde(flatten)]
    pub corps: Corps,
    /// Signature ed25519 (hex) du corps sérialisé en JSON.
    pub signature: String,
}

impl Corps {
    fn octets(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("sérialisation JSON")
    }

    pub fn signer(self, cle: &SigningKey) -> RequeteSignee {
        let signature = hex::encode(cle.sign(&self.octets()).to_bytes());
        RequeteSignee { corps: self, signature }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Refus {
    #[error("compte inconnu")]
    CompteInconnu,
    #[error("signature invalide")]
    Signature,
    #[error("requête périmée ou datée dans le futur")]
    Horodatage,
    #[error("nonce déjà utilisé (rejeu)")]
    Rejeu,
    #[error("rôle insuffisant : {0:?} requis")]
    Role(&'static [Role]),
    #[error("quatre yeux : la demande doit être approuvée par un autre compte")]
    QuatreYeux,
    #[error("ticket ou session invalide ou expiré")]
    Session,
    #[error("fichier de comptes invalide : {0}")]
    Fichier(String),
    #[error("compte suspendu pour inactivité : le faire réactiver par deux autres comptes (aplomb admin … reactiver --cible <compte>)")]
    Suspendu,
    #[error("second facteur requis : ajouter --code <code de l'application d'authentification>")]
    CodeRequis,
    #[error("code du second facteur invalide ou déjà utilisé")]
    CodeInvalide,
    #[error("{0}")]
    Cible(String),
}

/// Issue d'une requête d'administration acceptée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// Ticket de connexion à échanger contre une session de navigateur.
    Ticket(String),
    /// Gel appliqué.
    Gel,
    /// Dégel demandé, en attente d'un second compte.
    DegelEnAttente,
    /// Dégel approuvé par un second compte : à appliquer. (demandeur, approbateur)
    Degel { demandeur: String, approbateur: String },
    /// Réactivation demandée, en attente d'un second compte.
    ReactivationEnAttente,
    /// Réactivation approuvée par un second compte : à appliquer.
    Reactivation { cible: String, demandeur: String, approbateur: String },
}

/// Second facteur : vérifie le code d'un compte (rend faux s'il manque ou ne va pas).
pub type VerifCode<'a> = &'a mut dyn FnMut(&str, &str) -> bool;

struct Demande {
    compte: String,
    expire: u64,
}

pub struct Autorite {
    comptes: HashMap<String, (Compte, VerifyingKey)>,
    nonces: HashMap<String, u64>,
    demandes: HashMap<Option<String>, Demande>,
    tickets: HashMap<String, (String, u64)>,
    sessions_web: HashMap<String, (String, u64)>,
    /// Identités venues du SSO et leurs rôles (le temps de leur session).
    externes: HashMap<String, Vec<Role>>,
    /// Comptes suspendus pour inactivité.
    suspendus: HashSet<String>,
    identite: crate::identite::ConfigIdentite,
}

fn aleatoire() -> String {
    let mut o = [0u8; 32];
    getrandom::getrandom(&mut o).expect("source d'aléa");
    hex::encode(o)
}

impl Autorite {
    pub fn nouvelle(fichier: FichierComptes) -> Result<Self, Refus> {
        let mut comptes = HashMap::new();
        let mut cles = HashSet::new();
        for c in fichier.comptes.iter().cloned() {
            let cle = cle_publique(&c.cle_publique).map_err(|e| Refus::Fichier(format!("{} : {e}", c.id)))?;
            // Deux comptes avec la même clé annuleraient les quatre yeux.
            if !cles.insert(cle.to_bytes()) {
                return Err(Refus::Fichier(format!("{} : clé déjà utilisée par un autre compte", c.id)));
            }
            if c.roles.is_empty() {
                return Err(Refus::Fichier(format!("{} : aucun rôle", c.id)));
            }
            if comptes.insert(c.id.clone(), (c.clone(), cle)).is_some() {
                return Err(Refus::Fichier(format!("{} : compte en double", c.id)));
            }
        }
        if comptes.is_empty() {
            return Err(Refus::Fichier("aucun compte".into()));
        }
        fichier.identite.verifier().map_err(Refus::Fichier)?;
        Ok(Self {
            comptes,
            nonces: HashMap::new(),
            demandes: HashMap::new(),
            tickets: HashMap::new(),
            sessions_web: HashMap::new(),
            externes: HashMap::new(),
            suspendus: HashSet::new(),
            identite: fichier.identite,
        })
    }

    pub fn depuis_yaml(texte: &str) -> Result<Self, Refus> {
        let f: FichierComptes = serde_yaml::from_str(texte).map_err(|e| Refus::Fichier(e.to_string()))?;
        Self::nouvelle(f)
    }

    /// Comme `depuis_yaml`, mais exige que la liste des comptes soit cosignée (EF-S2) :
    /// personne ne peut s'ajouter un compte seul.
    pub fn depuis_yaml_cosigne(texte: &str, confiance: &crate::gouvernance::Confiance) -> Result<(Self, Vec<String>), Refus> {
        let f: FichierComptes = serde_yaml::from_str(texte).map_err(|e| Refus::Fichier(e.to_string()))?;
        let signataires = confiance.verifier(&f.octets_signes(), &f.signatures).map_err(Refus::Fichier)?;
        Ok((Self::nouvelle(f)?, signataires))
    }

    pub fn roles(&self, compte: &str) -> Vec<Role> {
        if self.suspendus.contains(compte) {
            return Vec::new();
        }
        self.comptes
            .get(compte)
            .map(|(c, _)| c.roles.clone())
            .or_else(|| self.externes.get(compte).cloned())
            .unwrap_or_default()
    }

    /// Options d'identité cosignées.
    pub fn identite(&self) -> &crate::identite::ConfigIdentite {
        &self.identite
    }

    /// Comptes déclarés (hors SSO).
    pub fn comptes(&self) -> Vec<String> {
        let mut v: Vec<String> = self.comptes.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn suspendre(&mut self, compte: &str) {
        self.suspendus.insert(compte.to_string());
        self.sessions_web.retain(|_, (c, _)| c != compte);
    }

    pub fn est_suspendu(&self, compte: &str) -> bool {
        self.suspendus.contains(compte)
    }

    pub fn reactiver(&mut self, compte: &str) {
        self.suspendus.remove(compte);
    }

    /// Opérations qui assouplissent : second facteur exigé quand la MFA est active.
    fn exige_code(&self, operation: Operation) -> bool {
        self.identite.mfa_exigee() && matches!(operation, Operation::Degel | Operation::Reactiver)
    }

    fn exiger(&self, compte: &str, roles: &'static [Role]) -> Result<(), Refus> {
        let possedes = self.roles(compte);
        if roles.iter().any(|r| possedes.contains(r)) {
            Ok(())
        } else {
            Err(Refus::Role(roles))
        }
    }

    fn purger(&mut self, maintenant: u64) {
        self.nonces.retain(|_, t| *t + 2 * FENETRE_MS > maintenant);
        self.demandes.retain(|_, d| d.expire > maintenant);
        self.tickets.retain(|_, (_, e)| *e > maintenant);
        self.sessions_web.retain(|_, (_, e)| *e > maintenant);
    }

    /// Authentifie une requête signée : compte connu, signature, fraîcheur, nonce neuf.
    fn authentifier(&mut self, r: &RequeteSignee, maintenant: u64) -> Result<(), Refus> {
        self.purger(maintenant);
        let (_, cle) = self.comptes.get(&r.corps.compte).ok_or(Refus::CompteInconnu)?;
        if self.suspendus.contains(&r.corps.compte) {
            return Err(Refus::Suspendu);
        }
        let octets = hex::decode(&r.signature).map_err(|_| Refus::Signature)?;
        let tab: [u8; 64] = octets.try_into().map_err(|_| Refus::Signature)?;
        cle.verify(&r.corps.octets(), &Signature::from_bytes(&tab)).map_err(|_| Refus::Signature)?;
        if r.corps.horodatage.abs_diff(maintenant) > FENETRE_MS {
            return Err(Refus::Horodatage);
        }
        if r.corps.nonce.len() < 16 || self.nonces.contains_key(&r.corps.nonce) {
            return Err(Refus::Rejeu);
        }
        self.nonces.insert(r.corps.nonce.clone(), maintenant);
        Ok(())
    }

    /// Traite une requête signée (outil en ligne de commande), sans second facteur.
    pub fn traiter(&mut self, r: &RequeteSignee, maintenant: u64) -> Result<Issue, Refus> {
        self.traiter_avec(r, maintenant, &mut |_, _| false)
    }

    /// Traite une requête signée ; `verif` contrôle le code du second facteur quand
    /// l'opération l'exige (après l'authentification par la clé, jamais avant).
    pub fn traiter_avec(&mut self, r: &RequeteSignee, maintenant: u64, verif: VerifCode) -> Result<Issue, Refus> {
        self.authentifier(r, maintenant)?;
        let compte = r.corps.compte.clone();
        if self.exige_code(r.corps.operation) {
            let code = r.corps.code.as_deref().ok_or(Refus::CodeRequis)?;
            if !verif(&compte, code) {
                return Err(Refus::CodeInvalide);
            }
        }
        if r.corps.operation == Operation::Reactiver {
            return self.demander_reactivation(&compte, r.corps.cible.as_deref().unwrap_or_default(), maintenant);
        }
        self.agir(&compte, r.corps.operation, r.corps.session.clone(), maintenant)
    }

    /// Réactivation d'un compte suspendu : un compte la demande, un autre l'approuve ;
    /// ni l'un ni l'autre ne peut être le compte visé.
    pub fn demander_reactivation(&mut self, compte: &str, cible: &str, maintenant: u64) -> Result<Issue, Refus> {
        self.purger(maintenant);
        self.exiger(compte, &[Role::Operateur, Role::Approbateur])?;
        if !self.comptes.contains_key(cible) {
            return Err(Refus::Cible(format!("compte « {cible} » inconnu")));
        }
        if !self.suspendus.contains(cible) {
            return Err(Refus::Cible(format!("le compte {cible} n'est pas suspendu")));
        }
        if compte == cible {
            return Err(Refus::QuatreYeux);
        }
        let cle = Some(format!("reactiver:{cible}"));
        match self.demandes.get(&cle) {
            Some(d) if d.compte == compte => Err(Refus::QuatreYeux),
            Some(_) => {
                let d = self.demandes.remove(&cle).expect("présente");
                self.suspendus.remove(cible);
                Ok(Issue::Reactivation { cible: cible.to_string(), demandeur: d.compte, approbateur: compte.to_string() })
            }
            None => {
                self.demandes.insert(cle, Demande { compte: compte.to_string(), expire: maintenant + DEMANDE_MS });
                Ok(Issue::ReactivationEnAttente)
            }
        }
    }

    /// Applique une opération pour un compte déjà authentifié (requête signée ou session
    /// de navigateur).
    pub fn agir(
        &mut self,
        compte: &str,
        operation: Operation,
        session: Option<String>,
        maintenant: u64,
    ) -> Result<Issue, Refus> {
        self.purger(maintenant);
        match operation {
            Operation::Connexion => {
                self.exiger(compte, &[Role::Lecteur, Role::Operateur, Role::Approbateur])?;
                let ticket = aleatoire();
                self.tickets.insert(ticket.clone(), (compte.to_string(), maintenant + TICKET_MS));
                Ok(Issue::Ticket(ticket))
            }
            Operation::Gel => {
                self.exiger(compte, &[Role::Operateur])?;
                Ok(Issue::Gel)
            }
            Operation::Reactiver => {
                Err(Refus::Cible("réactivation : par requête signée (aplomb admin … reactiver --cible <compte>)".into()))
            }
            Operation::Degel => {
                self.exiger(compte, &[Role::Operateur, Role::Approbateur])?;
                match self.demandes.get(&session) {
                    Some(d) if d.compte == compte => Err(Refus::QuatreYeux),
                    Some(_) => {
                        let d = self.demandes.remove(&session).expect("présente");
                        Ok(Issue::Degel { demandeur: d.compte, approbateur: compte.to_string() })
                    }
                    None => {
                        // Seul un opérateur ouvre une demande ; l'approbateur ne fait qu'approuver.
                        self.exiger(compte, &[Role::Operateur])?;
                        self.demandes
                            .insert(session, Demande { compte: compte.to_string(), expire: maintenant + DEMANDE_MS });
                        Ok(Issue::DegelEnAttente)
                    }
                }
            }
        }
    }

    /// Vrai si l'ouverture d'une session de la vue demande le second facteur.
    pub fn mfa_a_la_connexion(&self) -> bool {
        self.identite.mfa_exigee()
    }

    /// Échange un ticket (usage unique) contre un jeton de session de navigateur, sans
    /// second facteur.
    pub fn ouvrir_session_web(&mut self, ticket: &str, maintenant: u64) -> Result<(String, String), Refus> {
        self.ouvrir_session_web_avec(ticket, None, maintenant, &mut |_, _| false)
    }

    /// Échange un ticket contre une session ; avec la MFA, le code est exigé. Un code faux
    /// consomme le ticket (pas d'essais répétés).
    pub fn ouvrir_session_web_avec(&mut self, ticket: &str, code: Option<&str>, maintenant: u64, verif: VerifCode) -> Result<(String, String), Refus> {
        self.purger(maintenant);
        let (compte, _) = self.tickets.remove(ticket).ok_or(Refus::Session)?;
        if self.suspendus.contains(&compte) {
            return Err(Refus::Suspendu);
        }
        if self.identite.mfa_exigee() {
            let code = code.ok_or(Refus::CodeRequis)?;
            if !verif(&compte, code) {
                return Err(Refus::CodeInvalide);
            }
        }
        let jeton = aleatoire();
        self.sessions_web.insert(jeton.clone(), (compte.clone(), maintenant + SESSION_WEB_MS));
        Ok((jeton, compte))
    }

    /// Compte associé à un jeton de session de navigateur valide.
    /// Session ouverte par le SSO pour une identité de l'annuaire et ses rôles.
    pub fn ouvrir_session_sso(&mut self, compte: &str, roles: Vec<Role>, maintenant: u64) -> String {
        self.purger(maintenant);
        self.externes.insert(compte.to_string(), roles);
        let jeton = aleatoire();
        self.sessions_web.insert(jeton.clone(), (compte.to_string(), maintenant + SESSION_WEB_MS));
        jeton
    }

    pub fn session_web(&mut self, jeton: &str, maintenant: u64) -> Result<String, Refus> {
        self.purger(maintenant);
        self.sessions_web.get(jeton).map(|(c, _)| c.clone()).ok_or(Refus::Session)
    }

    pub fn fermer_session_web(&mut self, jeton: &str) {
        self.sessions_web.remove(jeton);
    }

    /// Demandes de dégel en attente : (session visée, demandeur).
    pub fn demandes_en_attente(&self) -> Vec<(Option<String>, String)> {
        let mut v: Vec<_> = self.demandes.iter().map(|(s, d)| (s.clone(), d.compte.clone())).collect();
        v.sort();
        v
    }
}

/// Fabrique une requête signée (côté client).
pub fn requete(compte: &str, cle: &SigningKey, operation: Operation, session: Option<String>, maintenant: u64) -> RequeteSignee {
    Corps { compte: compte.into(), operation, session, horodatage: maintenant, nonce: aleatoire(), code: None, cible: None }.signer(cle)
}

/// Requête signée avec code du second facteur et compte visé.
pub fn requete_complete(
    compte: &str,
    cle: &SigningKey,
    operation: Operation,
    session: Option<String>,
    code: Option<String>,
    cible: Option<String>,
    maintenant: u64,
) -> RequeteSignee {
    Corps { compte: compte.into(), operation, session, horodatage: maintenant, nonce: aleatoire(), code, cible }.signer(cle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_800_000_000_000;

    fn cle(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn autorite() -> Autorite {
        let compte = |id: &str, n: u8, roles: Vec<Role>| Compte {
            id: id.into(),
            roles,
            cle_publique: hex::encode(cle(n).verifying_key().to_bytes()),
        };
        Autorite::nouvelle(FichierComptes {
            signatures: Vec::new(),
            identite: Default::default(),
            comptes: vec![
                compte("alice", 1, vec![Role::Operateur]),
                compte("bob", 2, vec![Role::Approbateur]),
                compte("carla", 3, vec![Role::Lecteur]),
                compte("dan", 4, vec![Role::Operateur]),
            ],
        })
        .unwrap()
    }

    fn req(compte: &str, n: u8, op: Operation) -> RequeteSignee {
        requete(compte, &cle(n), op, Some("s".into()), T)
    }

    #[test]
    fn signature_fraicheur_rejeu() {
        let mut a = autorite();
        // Mauvaise clé pour le compte.
        assert_eq!(a.traiter(&req("alice", 9, Operation::Gel), T), Err(Refus::Signature));
        // Corps modifié après signature.
        let mut r = req("alice", 1, Operation::Gel);
        r.corps.operation = Operation::Degel;
        assert_eq!(a.traiter(&r, T), Err(Refus::Signature));
        // Requête trop ancienne.
        assert_eq!(a.traiter(&req("alice", 1, Operation::Gel), T + FENETRE_MS + 1), Err(Refus::Horodatage));
        // Rejeu d'une requête valide.
        let r = req("alice", 1, Operation::Gel);
        assert_eq!(a.traiter(&r, T), Ok(Issue::Gel));
        assert_eq!(a.traiter(&r, T), Err(Refus::Rejeu));
        assert_eq!(a.traiter(&req("zoe", 1, Operation::Gel), T), Err(Refus::CompteInconnu));
    }

    #[test]
    fn roles() {
        let mut a = autorite();
        assert!(matches!(a.traiter(&req("carla", 3, Operation::Gel), T), Err(Refus::Role(_))));
        assert!(matches!(a.traiter(&req("bob", 2, Operation::Gel), T), Err(Refus::Role(_))));
        // Un lecteur peut se connecter à la vue technique.
        assert!(matches!(a.traiter(&req("carla", 3, Operation::Connexion), T), Ok(Issue::Ticket(_))));
        // Un approbateur ne peut pas ouvrir une demande de dégel, seulement approuver.
        assert!(matches!(a.traiter(&req("bob", 2, Operation::Degel), T), Err(Refus::Role(_))));
    }

    #[test]
    fn degel_a_quatre_yeux() {
        let mut a = autorite();
        assert_eq!(a.traiter(&req("alice", 1, Operation::Degel), T), Ok(Issue::DegelEnAttente));
        // Le même compte ne peut pas s'approuver.
        assert_eq!(a.traiter(&req("alice", 1, Operation::Degel), T), Err(Refus::QuatreYeux));
        assert_eq!(a.demandes_en_attente(), vec![(Some("s".into()), "alice".into())]);
        // Un second compte approuve : le dégel est exécuté et la demande consommée.
        assert_eq!(
            a.traiter(&req("bob", 2, Operation::Degel), T),
            Ok(Issue::Degel { demandeur: "alice".into(), approbateur: "bob".into() })
        );
        assert!(a.demandes_en_attente().is_empty());
        // Un autre opérateur peut aussi approuver.
        assert_eq!(a.traiter(&req("alice", 1, Operation::Degel), T), Ok(Issue::DegelEnAttente));
        assert!(matches!(a.traiter(&req("dan", 4, Operation::Degel), T), Ok(Issue::Degel { .. })));
    }

    #[test]
    fn demande_expiree() {
        let mut a = autorite();
        assert_eq!(a.traiter(&req("alice", 1, Operation::Degel), T), Ok(Issue::DegelEnAttente));
        let tard = T + DEMANDE_MS + 1;
        let r = requete("bob", &cle(2), Operation::Degel, Some("s".into()), tard);
        // La demande a expiré : bob, approbateur, ne peut pas en ouvrir une nouvelle.
        assert!(matches!(a.traiter(&r, tard), Err(Refus::Role(_))));
    }

    #[test]
    fn ticket_a_usage_unique_et_session_bornee() {
        let mut a = autorite();
        let Ok(Issue::Ticket(t)) = a.traiter(&req("carla", 3, Operation::Connexion), T) else { panic!() };
        let (jeton, compte) = a.ouvrir_session_web(&t, T).unwrap();
        assert_eq!(compte, "carla");
        assert_eq!(a.ouvrir_session_web(&t, T), Err(Refus::Session));
        assert_eq!(a.session_web(&jeton, T + 1).unwrap(), "carla");
        assert_eq!(a.session_web(&jeton, T + SESSION_WEB_MS + 1), Err(Refus::Session));
    }

    #[test]
    fn mfa_suspension_reactivation() {
        let mut a = autorite();
        a.identite = serde_yaml::from_str("{mfa: {}}").unwrap();
        let mut verif = |c: &str, code: &str| c == "alice" && code == "123456";
        // Durcir reste possible seul et sans code ; assouplir exige le code.
        assert_eq!(a.traiter_avec(&req("alice", 1, Operation::Gel), T, &mut verif), Ok(Issue::Gel));
        assert_eq!(a.traiter_avec(&req("alice", 1, Operation::Degel), T, &mut verif), Err(Refus::CodeRequis));
        let avec = |code: &str| requete_complete("alice", &cle(1), Operation::Degel, Some("s".into()), Some(code.into()), None, T);
        assert_eq!(a.traiter_avec(&avec("000000"), T, &mut verif), Err(Refus::CodeInvalide));
        assert_eq!(a.traiter_avec(&avec("123456"), T, &mut verif), Ok(Issue::DegelEnAttente));
        // Connexion à la vue : ticket puis code.
        let Ok(Issue::Ticket(t)) = a.traiter(&req("carla", 3, Operation::Connexion), T) else { panic!() };
        assert_eq!(a.ouvrir_session_web(&t, T), Err(Refus::CodeRequis));
        // Suspension : plus de requête, plus de rôle, sessions fermées.
        a.suspendre("dan");
        assert_eq!(a.traiter(&req("dan", 4, Operation::Gel), T), Err(Refus::Suspendu));
        assert!(a.roles("dan").is_empty());
        let reac = |qui: &str, n: u8, cible: &str| requete_complete(qui, &cle(n), Operation::Reactiver, None, Some("123456".into()), Some(cible.into()), T);
        let mut tout = |_: &str, code: &str| code == "123456";
        assert!(matches!(a.traiter_avec(&reac("alice", 1, "carla"), T, &mut tout), Err(Refus::Cible(_))), "carla n'est pas suspendue");
        assert_eq!(a.traiter_avec(&reac("alice", 1, "dan"), T, &mut tout), Ok(Issue::ReactivationEnAttente));
        assert_eq!(a.traiter_avec(&reac("alice", 1, "dan"), T, &mut tout), Err(Refus::QuatreYeux));
        assert_eq!(
            a.traiter_avec(&reac("bob", 2, "dan"), T, &mut tout),
            Ok(Issue::Reactivation { cible: "dan".into(), demandeur: "alice".into(), approbateur: "bob".into() })
        );
        assert!(!a.est_suspendu("dan"));
        // SSO : rôles le temps de la session, quatre yeux inchangés.
        let j = a.ouvrir_session_sso("sso:paul@ex.fr", vec![Role::Operateur], T);
        assert_eq!(a.session_web(&j, T).unwrap(), "sso:paul@ex.fr");
        assert_eq!(a.agir("sso:paul@ex.fr", Operation::Degel, Some("x".into()), T), Ok(Issue::DegelEnAttente));
        assert_eq!(a.agir("sso:paul@ex.fr", Operation::Degel, Some("x".into()), T), Err(Refus::QuatreYeux));
    }

    #[test]
    fn signature_des_comptes_inchangee_sans_identite() {
        let f: FichierComptes = serde_yaml::from_str("comptes: []").unwrap();
        assert_eq!(f.octets_signes(), b"[]");
        let g: FichierComptes = serde_yaml::from_str("comptes: []\nidentite: {mfa: {}}").unwrap();
        assert!(String::from_utf8(g.octets_signes()).unwrap().contains("identite"));
        assert!(!serde_yaml::to_string(&f).unwrap().contains("identite"));
    }

    #[test]
    fn fichier_de_comptes_controle() {
        let c = hex::encode(cle(1).verifying_key().to_bytes());
        let deux_fois = format!(
            "comptes:\n- {{id: a, roles: [operateur], cle_publique: {c}}}\n- {{id: b, roles: [approbateur], cle_publique: {c}}}\n"
        );
        assert!(matches!(Autorite::depuis_yaml(&deux_fois), Err(Refus::Fichier(_))));
        assert!(matches!(Autorite::depuis_yaml("comptes: []"), Err(Refus::Fichier(_))));
        let sans_role = format!("comptes:\n- {{id: a, roles: [], cle_publique: {c}}}\n");
        assert!(matches!(Autorite::depuis_yaml(&sans_role), Err(Refus::Fichier(_))));
    }
}
