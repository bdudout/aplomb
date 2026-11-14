//! **État partagé entre instances** (ENF-10), en option. Sans l'option, rien ne change :
//! l'état vit en mémoire.
//!
//! Deux stockages, même contrat :
//! - **SQLite** (`--etat-partage etat.sqlite`) : plusieurs instances sur **une machine**.
//!   Rien à installer, le moteur est compilé avec le binaire ;
//! - **PostgreSQL** (`--etat-partage postgres://compte@hote/base?sslmode=require`) :
//!   instances sur **plusieurs machines**, base en haute disponibilité (voir
//!   `docs/ARCHITECTURES.md`).
//!
//! Ce qui est partagé :
//! - les **gels** (global et par session) : un gel posé sur une instance s'applique à
//!   toutes **avant leur décision suivante**, car chaque décision relit les gels ;
//! - les **compteurs des bornes** de chaque session : une session répartie sur plusieurs
//!   instances est bornée comme si elle n'en voyait qu'une ;
//! - les **demandes en attente** (dégel, réactivation) : une demande ouverte sur une
//!   instance s'approuve sur une autre, toujours par un second compte ;
//! - les **nonces** des requêtes signées : une requête ne se rejoue pas sur une autre
//!   instance.
//!
//! Chaque décision et chaque opération d'administration passent dans une transaction
//! exclusive entre instances. **En cas de doute, on refuse** : stockage illisible, verrou
//! trop long, gel ou compteur qui n'a pas pu être écrit.
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::Connection;

/// Attente maximale d'un verrou tenu par une autre instance, avant de refuser.
const ATTENTE_MS: u64 = 2_000;
/// Une instance qui ne s'est pas manifestée depuis ce délai n'est plus comptée active.
pub const ACTIVE_MS: u64 = 60_000;
/// Fréquence de mise à jour de la présence d'une instance.
const PRESENCE_MS: u64 = 10_000;
/// Clé du gel global dans la table des gels.
const GLOBAL: &str = "*";

/// Schéma, écrit pour les deux moteurs (`ENTIER` : INTEGER ou BIGINT).
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gels(session TEXT PRIMARY KEY, depuis ENTIER NOT NULL, instance TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS demandes(cle TEXT PRIMARY KEY, compte TEXT NOT NULL, expire ENTIER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, t ENTIER NOT NULL);
CREATE TABLE IF NOT EXISTS instances(id TEXT PRIMARY KEY, adresse TEXT NOT NULL, vu ENTIER NOT NULL);
CREATE TABLE IF NOT EXISTS bornes(session TEXT PRIMARY KEY, refus ENTIER NOT NULL, revues ENTIER NOT NULL,
  envois ENTIER NOT NULL, actions ENTIER NOT NULL, domaines TEXT NOT NULL);
";

/// Valeur passée au stockage ou lue dans le stockage.
#[derive(Debug, Clone, PartialEq)]
pub enum Valeur {
    T(String),
    E(i64),
}

impl Valeur {
    fn texte(&self) -> String {
        match self {
            Valeur::T(s) => s.clone(),
            Valeur::E(n) => n.to_string(),
        }
    }
    fn entier(&self) -> i64 {
        match self {
            Valeur::E(n) => *n,
            Valeur::T(s) => s.parse().unwrap_or(0),
        }
    }
}

impl From<&str> for Valeur {
    fn from(s: &str) -> Self {
        Valeur::T(s.into())
    }
}
impl From<String> for Valeur {
    fn from(s: String) -> Self {
        Valeur::T(s)
    }
}
impl From<u64> for Valeur {
    fn from(n: u64) -> Self {
        Valeur::E(n as i64)
    }
}
impl From<u32> for Valeur {
    fn from(n: u32) -> Self {
        Valeur::E(n as i64)
    }
}

impl rusqlite::ToSql for Valeur {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self {
            Valeur::T(s) => ToSqlOutput::Borrowed(ValueRef::Text(s.as_bytes())),
            Valeur::E(n) => ToSqlOutput::Borrowed(ValueRef::Integer(*n)),
        })
    }
}

macro_rules! p {
    ($($v:expr),* $(,)?) => { vec![$(Valeur::from($v)),*] };
}

fn err(e: rusqlite::Error) -> String {
    format!("état partagé : {e}")
}

/// Moteur de stockage. Les requêtes sont écrites une fois, paramètres `$1, $2…`.
enum Moteur {
    Sqlite(Connection),
    #[cfg(feature = "postgres")]
    Postgres { fil: crate::etat_pg::Fil, verrou: i64 },
}

impl Moteur {
    fn sqlite(sql: &str) -> String {
        sql.replace('$', "?")
    }

    fn lot(&self, sql: &str) -> Result<(), String> {
        match self {
            Moteur::Sqlite(c) => c.execute_batch(&sql.replace("ENTIER", "INTEGER")).map_err(err),
            #[cfg(feature = "postgres")]
            Moteur::Postgres { fil, .. } => fil.lot(&sql.replace("ENTIER", "BIGINT")),
        }
    }

    fn executer(&self, sql: &str, p: Vec<Valeur>) -> Result<u64, String> {
        match self {
            Moteur::Sqlite(c) => c.execute(&Self::sqlite(sql), rusqlite::params_from_iter(p.iter())).map(|n| n as u64).map_err(err),
            #[cfg(feature = "postgres")]
            Moteur::Postgres { fil, .. } => fil.executer(sql, p),
        }
    }

    fn lignes(&self, sql: &str, p: Vec<Valeur>) -> Result<Vec<Vec<Valeur>>, String> {
        match self {
            Moteur::Sqlite(c) => {
                let mut st = c.prepare(&Self::sqlite(sql)).map_err(err)?;
                let n = st.column_count();
                let v = st
                    .query_map(rusqlite::params_from_iter(p.iter()), |r| {
                        (0..n)
                            .map(|i| {
                                Ok(match r.get_ref(i)? {
                                    ValueRef::Integer(x) => Valeur::E(x),
                                    ValueRef::Text(t) => Valeur::T(String::from_utf8_lossy(t).into_owned()),
                                    _ => Valeur::T(String::new()),
                                })
                            })
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .map_err(err)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(err)?;
                Ok(v)
            }
            #[cfg(feature = "postgres")]
            Moteur::Postgres { fil, .. } => fil.lignes(sql, p),
        }
    }

    fn debut(&self) -> Result<(), String> {
        match self {
            Moteur::Sqlite(c) => c.execute_batch("BEGIN IMMEDIATE").map_err(err),
            #[cfg(feature = "postgres")]
            Moteur::Postgres { fil, verrou } => fil.debut(*verrou),
        }
    }

    fn fin(&self) -> Result<(), String> {
        match self {
            Moteur::Sqlite(c) => c.execute_batch("COMMIT").map_err(err),
            #[cfg(feature = "postgres")]
            Moteur::Postgres { fil, .. } => fil.fin(),
        }
    }

    fn annuler(&self) {
        match self {
            Moteur::Sqlite(c) => {
                let _ = c.execute_batch("ROLLBACK");
            }
            #[cfg(feature = "postgres")]
            Moteur::Postgres { fil, .. } => fil.annuler(),
        }
    }
}

/// Instance vue dans le stockage partagé.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Instance {
    pub id: String,
    pub adresse: String,
    pub vu: u64,
}

pub struct Partage {
    moteur: Moteur,
    cible: String,
    pub instance: String,
    adresse: String,
    /// Un gel local n'a pas pu être écrit : l'écrire avant toute autre décision.
    a_ecrire: bool,
    presence: u64,
}

/// Clé d'une demande : `*` pour le gel global, `=<session>` sinon (session ou
/// `reactiver:<compte>`).
fn cle_demande(s: &Option<String>) -> String {
    match s {
        None => GLOBAL.into(),
        Some(s) => format!("={s}"),
    }
}

fn demande_de_cle(c: &str) -> Option<String> {
    c.strip_prefix('=').map(String::from)
}

/// Adresse PostgreSQL plutôt que chemin de fichier SQLite ?
pub fn est_postgres(cible: &str) -> bool {
    cible.starts_with("postgres://") || cible.starts_with("postgresql://")
}

fn moteur(cible: &str, _ca: Option<&Path>, _mandat: &str) -> Result<(Moteur, String), String> {
    if est_postgres(cible) {
        #[cfg(feature = "postgres")]
        {
            use sha2::Digest;
            let fil = crate::etat_pg::Fil::ouvrir(cible, _ca)?;
            // Verrou consultatif propre au mandat : deux mandats d'une même base ne
            // s'attendent pas.
            let h = sha2::Sha256::digest(format!("aplomb:{_mandat}").as_bytes());
            let verrou = i64::from_be_bytes(h[..8].try_into().expect("8 octets"));
            let c = fil.cible().to_string();
            return Ok((Moteur::Postgres { fil, verrou }, c));
        }
        #[cfg(not(feature = "postgres"))]
        return Err("ce binaire est compilé sans PostgreSQL (cargo build --features postgres) ; sur une seule machine, --etat-partage etat.sqlite suffit".into());
    }
    let chemin = PathBuf::from(cible);
    let cnx = Connection::open(&chemin).map_err(|e| format!("état partagé {} : {e}", chemin.display()))?;
    cnx.busy_timeout(std::time::Duration::from_millis(ATTENTE_MS)).map_err(err)?;
    cnx.pragma_update(None, "journal_mode", "WAL").map_err(err)?;
    cnx.pragma_update(None, "synchronous", "FULL").map_err(err)?;
    Ok((Moteur::Sqlite(cnx), chemin.display().to_string()))
}

impl Partage {
    /// Ouvre (ou crée) le stockage : chemin d'un fichier SQLite, ou adresse PostgreSQL
    /// (`ca` : autorité de certification de la base, en plus des racines publiques).
    /// Refuse un stockage qui sert un autre mandat, ou une autre version du mandat tant
    /// qu'une instance de cette version est active.
    pub fn ouvrir(cible: &str, ca: Option<&Path>, mandat: &str, empreinte: &str, adresse: &str, maintenant: u64) -> Result<Self, String> {
        let (moteur, cible) = moteur(cible, ca, mandat)?;
        let mut o = [0u8; 8];
        getrandom::getrandom(&mut o).map_err(|e| e.to_string())?;
        let mut p = Self { moteur, cible, instance: hex::encode(o), adresse: adresse.into(), a_ecrire: false, presence: 0 };
        p.debut()?;
        let r = p.moteur.lot(SCHEMA).and_then(|_| p.verifier_mandat(mandat, empreinte, maintenant));
        match r.and_then(|_| p.noter_presence(maintenant)) {
            Ok(()) => {
                p.fin()?;
                Ok(p)
            }
            Err(e) => {
                p.annuler();
                Err(e)
            }
        }
    }

    fn meta(&self, cle: &str) -> Result<Option<String>, String> {
        Ok(self.moteur.lignes("SELECT valeur FROM meta WHERE cle = $1", p![cle])?.first().map(|l| l[0].texte()))
    }

    fn verifier_mandat(&mut self, mandat: &str, empreinte: &str, maintenant: u64) -> Result<(), String> {
        match self.meta("mandat")? {
            Some(m) if m != mandat => {
                return Err(format!("{} sert le mandat « {m} », pas « {mandat} » : un état partagé par mandat", self.cible))
            }
            Some(_) => {}
            None => {
                self.moteur.executer("INSERT INTO meta(cle, valeur) VALUES ('mandat', $1)", p![mandat])?;
            }
        }
        match self.meta("empreinte")? {
            Some(e) if e != empreinte => {
                let actives = self.instances_actives(maintenant)?;
                if !actives.is_empty() {
                    let liste: Vec<String> = actives.iter().map(|i| i.adresse.clone()).collect();
                    return Err(format!(
                        "les instances actives ({}) servent une autre version du mandat : arrêtez-les, ou démarrez-les toutes sur ce mandat",
                        liste.join(", ")
                    ));
                }
                self.moteur.executer("UPDATE meta SET valeur = $1 WHERE cle = 'empreinte'", p![empreinte])?;
            }
            Some(_) => {}
            None => {
                self.moteur.executer("INSERT INTO meta(cle, valeur) VALUES ('empreinte', $1)", p![empreinte])?;
            }
        }
        Ok(())
    }

    /// Fichier SQLite ou adresse PostgreSQL, sans secret.
    pub fn cible(&self) -> &str {
        &self.cible
    }

    /// Moteur : « sqlite » ou « postgresql ».
    pub fn moteur(&self) -> &'static str {
        match self.moteur {
            Moteur::Sqlite(_) => "sqlite",
            #[cfg(feature = "postgres")]
            Moteur::Postgres { .. } => "postgresql",
        }
    }

    /// Transaction exclusive : les décisions et les opérations d'administration de toutes
    /// les instances passent l'une après l'autre (pas de double approbation, pas de
    /// compteur perdu).
    pub fn debut(&mut self) -> Result<(), String> {
        self.moteur.debut()
    }

    pub fn fin(&mut self) -> Result<(), String> {
        self.moteur.fin().inspect_err(|_| self.annuler())
    }

    pub fn annuler(&mut self) {
        self.moteur.annuler();
    }

    fn noter_presence(&mut self, maintenant: u64) -> Result<(), String> {
        self.moteur.executer(
            "INSERT INTO instances(id, adresse, vu) VALUES ($1, $2, $3) ON CONFLICT(id) DO UPDATE SET vu = excluded.vu",
            p![self.instance.clone(), self.adresse.clone(), maintenant],
        )?;
        self.moteur.executer("DELETE FROM instances WHERE vu < $1", p![maintenant.saturating_sub(24 * 3600 * 1000)])?;
        self.presence = maintenant;
        Ok(())
    }

    /// Instances actives autres que celle-ci.
    pub fn instances_actives(&self, maintenant: u64) -> Result<Vec<Instance>, String> {
        let l = self.moteur.lignes(
            "SELECT id, adresse, vu FROM instances WHERE vu >= $1 AND id != $2 ORDER BY adresse",
            p![maintenant.saturating_sub(ACTIVE_MS), self.instance.clone()],
        )?;
        Ok(l.iter().map(|r| Instance { id: r[0].texte(), adresse: r[1].texte(), vu: r[2].entier() as u64 }).collect())
    }

    /// Gels du stockage : (global, sessions).
    pub fn gels(&self) -> Result<(bool, HashSet<String>), String> {
        let mut sessions: HashSet<String> = self.moteur.lignes("SELECT session FROM gels", p![])?.iter().map(|r| r[0].texte()).collect();
        let global = sessions.remove(GLOBAL);
        Ok((global, sessions))
    }

    /// Écrit les gels locaux (ajout seulement : seul un dégel à quatre yeux en retire).
    fn ecrire_gels(&mut self, global: bool, sessions: &[String], maintenant: u64) -> Result<(), String> {
        let globale = global.then(|| GLOBAL.to_string());
        for s in sessions.iter().chain(globale.iter()) {
            self.moteur.executer(
                "INSERT INTO gels(session, depuis, instance) VALUES ($1, $2, $3) ON CONFLICT(session) DO NOTHING",
                p![s.clone(), maintenant, self.instance.clone()],
            )?;
        }
        Ok(())
    }

    /// Avant une décision : écrit un gel resté en attente, puis aligne les gels locaux sur
    /// le stockage. Rend les dégels faits ailleurs. Une erreur impose le refus.
    pub fn synchroniser(&mut self, sup: &mut aplomb_core::superviseur::Superviseur, maintenant: u64) -> Result<Vec<Option<String>>, String> {
        if self.a_ecrire {
            let (g, s) = sup.etat_gel();
            self.ecrire_gels(g, &s, maintenant)?;
            self.a_ecrire = false;
        }
        if maintenant >= self.presence + PRESENCE_MS {
            self.noter_presence(maintenant)?;
        }
        let (global, sessions) = self.gels()?;
        Ok(sup.aligner_gel(global, &sessions))
    }

    /// Dans la transaction d'une décision : les compteurs des bornes de la session.
    pub fn compteurs(&self, session: &str) -> Result<Option<aplomb_core::bornes::Compteurs>, String> {
        let l = self.moteur.lignes("SELECT refus, revues, envois, actions, domaines FROM bornes WHERE session = $1", p![session])?;
        let Some(r) = l.first() else { return Ok(None) };
        let domaines: HashSet<String> = serde_json::from_str(&r[4].texte()).map_err(|e| format!("état partagé : compteurs de {session} illisibles ({e})"))?;
        Ok(Some(aplomb_core::bornes::Compteurs {
            refus: r[0].entier() as u32,
            revues: r[1].entier() as u32,
            envois: r[2].entier() as u32,
            actions: r[3].entier() as u32,
            domaines,
        }))
    }

    /// Dans la transaction d'une décision : écrit les compteurs de la session et les gels
    /// que la décision a posés (borne dépassée, verdict de gel).
    pub fn ecrire_decision(
        &mut self,
        session: &str,
        compteurs: Option<&aplomb_core::bornes::Compteurs>,
        avant: &(bool, Vec<String>),
        apres: &(bool, Vec<String>),
        maintenant: u64,
    ) -> Result<(), String> {
        match compteurs {
            None => {
                self.moteur.executer("DELETE FROM bornes WHERE session = $1", p![session])?;
            }
            Some(c) => {
                let mut d: Vec<&String> = c.domaines.iter().collect();
                d.sort();
                self.moteur.executer(
                    "INSERT INTO bornes(session, refus, revues, envois, actions, domaines) VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT(session) DO UPDATE SET refus = excluded.refus, revues = excluded.revues,
                     envois = excluded.envois, actions = excluded.actions, domaines = excluded.domaines",
                    p![session, c.refus, c.revues, c.envois, c.actions, serde_json::to_string(&d).unwrap_or_else(|_| "[]".into())],
                )?;
            }
        }
        if apres != avant {
            self.ecrire_gels(apres.0, &apres.1, maintenant)?;
        }
        Ok(())
    }

    /// Une écriture a échoué : la décision suivante réécrit les gels locaux avant tout.
    pub fn retenir_gels(&mut self) {
        self.a_ecrire = true;
    }

    /// Dans une transaction : consomme le nonce d'une requête signée. Déjà vu (sur une
    /// instance quelconque) : rejeu.
    pub fn consommer_nonce(&mut self, nonce: &str, maintenant: u64) -> Result<bool, String> {
        let fenetre = 2 * aplomb_core::autorite::FENETRE_MS;
        self.moteur.executer("DELETE FROM nonces WHERE t < $1", p![maintenant.saturating_sub(fenetre)])?;
        let n = self.moteur.executer("INSERT INTO nonces(nonce, t) VALUES ($1, $2) ON CONFLICT(nonce) DO NOTHING", p![nonce, maintenant])?;
        Ok(n == 1)
    }

    /// Dans une transaction : les demandes en attente du stockage (non expirées).
    pub fn demandes(&self, maintenant: u64) -> Result<Vec<(Option<String>, String, u64)>, String> {
        let l = self.moteur.lignes("SELECT cle, compte, expire FROM demandes WHERE expire > $1", p![maintenant])?;
        Ok(l.iter().map(|r| (demande_de_cle(&r[0].texte()), r[1].texte(), r[2].entier() as u64)).collect())
    }

    /// Dans une transaction : remplace les demandes par celles de l'autorité.
    pub fn ecrire_demandes(&mut self, demandes: &[(Option<String>, String, u64)]) -> Result<(), String> {
        self.moteur.executer("DELETE FROM demandes", p![])?;
        for (s, c, e) in demandes {
            self.moteur.executer("INSERT INTO demandes(cle, compte, expire) VALUES ($1, $2, $3)", p![cle_demande(s), c.clone(), *e])?;
        }
        Ok(())
    }

    /// Dans une transaction : gel posé par un opérateur.
    pub fn geler(&mut self, session: Option<&str>, maintenant: u64) -> Result<(), String> {
        let s: Vec<String> = session.map(String::from).into_iter().collect();
        self.ecrire_gels(session.is_none(), &s, maintenant)
    }

    /// Dans une transaction : dégel approuvé (global : tout est dégelé, comme en local).
    /// Les compteurs des bornes repartent de zéro, comme en local.
    pub fn degeler(&mut self, session: Option<&str>) -> Result<(), String> {
        match session {
            Some(s) => {
                self.moteur.executer("DELETE FROM gels WHERE session = $1", p![s])?;
                self.moteur.executer("DELETE FROM bornes WHERE session = $1", p![s])?;
            }
            None => {
                self.moteur.executer("DELETE FROM gels", p![])?;
                self.moteur.executer("DELETE FROM bornes", p![])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier() -> PathBuf {
        let mut o = [0u8; 6];
        getrandom::getrandom(&mut o).unwrap();
        let d = std::env::temp_dir().join(format!("aplomb-partage-{}", hex::encode(o)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn deux_instances_un_fichier() {
        let d = dossier();
        let f = d.join("etat.sqlite");
        let f = f.to_str().unwrap();
        let t = 1_800_000_000_000;
        let mut a = Partage::ouvrir(f, None, "m", "e1", "a", t).unwrap();
        let mut b = Partage::ouvrir(f, None, "m", "e1", "b", t).unwrap();
        // Autre mandat : refusé.
        assert!(Partage::ouvrir(f, None, "autre", "e1", "c", t).err().unwrap().contains("un état partagé par mandat"));
        // Autre version du mandat tant que des instances sont actives : refusé.
        assert!(Partage::ouvrir(f, None, "m", "e2", "c", t).err().unwrap().contains("autre version"));
        assert_eq!(a.instances_actives(t).unwrap().len(), 1);
        // Gel sur a, vu par b.
        a.debut().unwrap();
        a.geler(Some("s"), t).unwrap();
        a.fin().unwrap();
        assert_eq!(b.gels().unwrap(), (false, ["s".to_string()].into()));
        // Nonce consommé sur a : rejeu sur b.
        a.debut().unwrap();
        assert!(a.consommer_nonce("n1", t).unwrap());
        a.ecrire_demandes(&[(Some("s".into()), "alice".into(), t + 1000), (None, "dan".into(), t + 1000)]).unwrap();
        a.fin().unwrap();
        b.debut().unwrap();
        assert!(!b.consommer_nonce("n1", t).unwrap());
        let mut v = b.demandes(t).unwrap();
        v.sort();
        assert_eq!(v, vec![(None, "dan".into(), t + 1000), (Some("s".into()), "alice".into(), t + 1000)]);
        assert!(b.demandes(t + 1000).unwrap().is_empty());
        b.degeler(Some("s")).unwrap();
        b.fin().unwrap();
        assert_eq!(a.gels().unwrap(), (false, HashSet::new()));
        // Compteurs des bornes : écrits par a, repris par b ; le dégel les efface.
        let sans_gel = (false, Vec::new());
        let c = aplomb_core::bornes::Compteurs { refus: 2, domaines: ["a.org".to_string()].into(), ..Default::default() };
        a.debut().unwrap();
        a.ecrire_decision("s", Some(&c), &sans_gel, &(false, vec!["s".into()]), t).unwrap();
        a.fin().unwrap();
        assert_eq!(b.compteurs("s").unwrap(), Some(c));
        assert_eq!(b.gels().unwrap(), (false, ["s".to_string()].into()));
        b.debut().unwrap();
        b.degeler(None).unwrap();
        b.fin().unwrap();
        assert_eq!(a.compteurs("s").unwrap(), None);
        // Plus d'instance active : la nouvelle version du mandat est adoptée.
        drop((a, b));
        assert!(Partage::ouvrir(f, None, "m", "e2", "c", t + ACTIVE_MS + 1).is_ok());
        let _ = std::fs::remove_dir_all(d);
    }
}
