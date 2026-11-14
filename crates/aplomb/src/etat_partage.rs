//! **État partagé entre instances** (ENF-10), en option : `aplomb serve --etat-partage
//! etat.sqlite`. Sans l'option, rien ne change : l'état vit en mémoire.
//!
//! Plusieurs instances d'un même mandat, sur une machine, partagent un fichier SQLite :
//! - les **gels** (global et par session) : un gel posé sur une instance s'applique à
//!   toutes **avant leur décision suivante**, car chaque décision relit les gels ;
//! - les **demandes en attente** (dégel, réactivation) : une demande ouverte sur une
//!   instance s'approuve sur une autre, toujours par un second compte ;
//! - les **nonces** des requêtes signées : une requête ne se rejoue pas sur une autre
//!   instance.
//!
//! **En cas de doute, on refuse** : stockage illisible, verrou trop long, gel qui n'a pas
//! pu être écrit. La décision est alors un refus, et l'opération d'administration échoue.
//!
//! Chaque instance garde son journal, son coffre et ses compteurs de bornes. Les bornes
//! comptent donc par instance : router une session vers une même instance (affinité). Un
//! gel posé par une borne, lui, s'applique partout.
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

/// Attente maximale d'un verrou tenu par une autre instance, avant de refuser.
const ATTENTE_MS: u64 = 2_000;
/// Une instance qui ne s'est pas manifestée depuis ce délai n'est plus comptée active.
pub const ACTIVE_MS: u64 = 60_000;
/// Fréquence de mise à jour de la présence d'une instance.
const PRESENCE_MS: u64 = 10_000;
/// Clé du gel global dans la table des gels.
const GLOBAL: &str = "*";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gels(session TEXT PRIMARY KEY, depuis INTEGER NOT NULL, instance TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS demandes(cle TEXT PRIMARY KEY, compte TEXT NOT NULL, expire INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, t INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS instances(id TEXT PRIMARY KEY, adresse TEXT NOT NULL, vu INTEGER NOT NULL);
";

/// Instance vue dans le stockage partagé.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Instance {
    pub id: String,
    pub adresse: String,
    pub vu: u64,
}

pub struct Partage {
    cnx: Connection,
    chemin: PathBuf,
    pub instance: String,
    adresse: String,
    /// Un gel local n'a pas pu être écrit : l'écrire avant toute autre décision.
    a_ecrire: bool,
    presence: u64,
}

fn err(e: rusqlite::Error) -> String {
    format!("état partagé : {e}")
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

impl Partage {
    /// Ouvre (ou crée) le stockage. Refuse un fichier qui sert un autre mandat, ou une
    /// autre version du mandat tant qu'une instance de cette version est active.
    pub fn ouvrir(chemin: &Path, mandat: &str, empreinte: &str, adresse: &str, maintenant: u64) -> Result<Self, String> {
        let cnx = Connection::open(chemin).map_err(|e| format!("état partagé {} : {e}", chemin.display()))?;
        cnx.busy_timeout(std::time::Duration::from_millis(ATTENTE_MS)).map_err(err)?;
        cnx.pragma_update(None, "journal_mode", "WAL").map_err(err)?;
        cnx.pragma_update(None, "synchronous", "FULL").map_err(err)?;
        cnx.execute_batch(SCHEMA).map_err(err)?;
        let mut o = [0u8; 8];
        getrandom::getrandom(&mut o).map_err(|e| e.to_string())?;
        let mut p = Self {
            cnx,
            chemin: chemin.to_path_buf(),
            instance: hex::encode(o),
            adresse: adresse.into(),
            a_ecrire: false,
            presence: 0,
        };
        p.debut()?;
        let r = p.verifier_mandat(mandat, empreinte, maintenant);
        match r {
            Ok(()) => {
                p.noter_presence(maintenant)?;
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
        self.cnx.query_row("SELECT valeur FROM meta WHERE cle = ?1", [cle], |r| r.get(0)).optional().map_err(err)
    }

    fn verifier_mandat(&mut self, mandat: &str, empreinte: &str, maintenant: u64) -> Result<(), String> {
        match self.meta("mandat")? {
            Some(m) if m != mandat => {
                return Err(format!(
                    "{} sert le mandat « {m} », pas « {mandat} » : un fichier d'état partagé par mandat",
                    self.chemin.display()
                ))
            }
            Some(_) => {}
            None => {
                self.cnx.execute("INSERT INTO meta(cle, valeur) VALUES ('mandat', ?1)", [mandat]).map_err(err)?;
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
                self.cnx.execute("UPDATE meta SET valeur = ?1 WHERE cle = 'empreinte'", [empreinte]).map_err(err)?;
            }
            Some(_) => {}
            None => {
                self.cnx.execute("INSERT INTO meta(cle, valeur) VALUES ('empreinte', ?1)", [empreinte]).map_err(err)?;
            }
        }
        Ok(())
    }

    pub fn chemin(&self) -> &Path {
        &self.chemin
    }

    /// Transaction exclusive : les opérations d'administration de toutes les instances
    /// passent l'une après l'autre (pas de double approbation).
    pub fn debut(&mut self) -> Result<(), String> {
        self.cnx.execute_batch("BEGIN IMMEDIATE").map_err(err)
    }

    pub fn fin(&mut self) -> Result<(), String> {
        self.cnx.execute_batch("COMMIT").map_err(|e| {
            self.annuler();
            err(e)
        })
    }

    pub fn annuler(&mut self) {
        let _ = self.cnx.execute_batch("ROLLBACK");
    }

    fn noter_presence(&mut self, maintenant: u64) -> Result<(), String> {
        self.cnx
            .execute(
                "INSERT INTO instances(id, adresse, vu) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET vu = excluded.vu",
                params![self.instance, self.adresse, maintenant as i64],
            )
            .map_err(err)?;
        self.cnx.execute("DELETE FROM instances WHERE vu < ?1", [(maintenant.saturating_sub(24 * 3600 * 1000)) as i64]).map_err(err)?;
        self.presence = maintenant;
        Ok(())
    }

    /// Instances actives autres que celle-ci.
    pub fn instances_actives(&self, maintenant: u64) -> Result<Vec<Instance>, String> {
        let mut st = self.cnx.prepare("SELECT id, adresse, vu FROM instances WHERE vu >= ?1 AND id != ?2 ORDER BY adresse").map_err(err)?;
        let v = st
            .query_map(params![maintenant.saturating_sub(ACTIVE_MS) as i64, self.instance], |r| {
                Ok(Instance { id: r.get(0)?, adresse: r.get(1)?, vu: r.get::<_, i64>(2)? as u64 })
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(v)
    }

    /// Gels du stockage : (global, sessions).
    pub fn gels(&self) -> Result<(bool, HashSet<String>), String> {
        let mut st = self.cnx.prepare("SELECT session FROM gels").map_err(err)?;
        let mut sessions: HashSet<String> =
            st.query_map([], |r| r.get(0)).map_err(err)?.collect::<Result<_, _>>().map_err(err)?;
        let global = sessions.remove(GLOBAL);
        Ok((global, sessions))
    }

    /// Écrit les gels locaux (ajout seulement : seul un dégel à quatre yeux en retire).
    fn ecrire_gels(&mut self, global: bool, sessions: &[String], maintenant: u64) -> Result<(), String> {
        let mut st = self
            .cnx
            .prepare("INSERT OR IGNORE INTO gels(session, depuis, instance) VALUES (?1, ?2, ?3)")
            .map_err(err)?;
        let globale = global.then(|| GLOBAL.to_string());
        for s in sessions.iter().chain(globale.iter()) {
            st.execute(params![s, maintenant as i64, self.instance]).map_err(err)?;
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

    /// Après une décision : écrit les gels qu'elle a posés (borne dépassée, verdict de
    /// gel). Un échec est retenu : la décision suivante refusera tant qu'il n'est pas écrit.
    pub fn apres(&mut self, avant: &(bool, Vec<String>), sup: &aplomb_core::superviseur::Superviseur, maintenant: u64) {
        let apres = sup.etat_gel();
        if &apres != avant && self.ecrire_gels(apres.0, &apres.1, maintenant).is_err() {
            self.a_ecrire = true;
        }
    }

    /// Dans une transaction : consomme le nonce d'une requête signée. Déjà vu (sur une
    /// instance quelconque) : rejeu.
    pub fn consommer_nonce(&mut self, nonce: &str, maintenant: u64) -> Result<bool, String> {
        let fenetre = 2 * aplomb_core::autorite::FENETRE_MS;
        self.cnx.execute("DELETE FROM nonces WHERE t < ?1", [maintenant.saturating_sub(fenetre) as i64]).map_err(err)?;
        let n = self.cnx.execute("INSERT OR IGNORE INTO nonces(nonce, t) VALUES (?1, ?2)", params![nonce, maintenant as i64]).map_err(err)?;
        Ok(n == 1)
    }

    /// Dans une transaction : les demandes en attente du stockage (non expirées).
    pub fn demandes(&self, maintenant: u64) -> Result<Vec<(Option<String>, String, u64)>, String> {
        let mut st = self.cnx.prepare("SELECT cle, compte, expire FROM demandes WHERE expire > ?1").map_err(err)?;
        let v = st
            .query_map([maintenant as i64], |r| {
                let cle: String = r.get(0)?;
                Ok((demande_de_cle(&cle), r.get(1)?, r.get::<_, i64>(2)? as u64))
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(v)
    }

    /// Dans une transaction : remplace les demandes par celles de l'autorité.
    pub fn ecrire_demandes(&mut self, demandes: &[(Option<String>, String, u64)]) -> Result<(), String> {
        self.cnx.execute("DELETE FROM demandes", []).map_err(err)?;
        let mut st = self.cnx.prepare("INSERT INTO demandes(cle, compte, expire) VALUES (?1, ?2, ?3)").map_err(err)?;
        for (s, c, e) in demandes {
            st.execute(params![cle_demande(s), c, *e as i64]).map_err(err)?;
        }
        Ok(())
    }

    /// Dans une transaction : gel posé par un opérateur.
    pub fn geler(&mut self, session: Option<&str>, maintenant: u64) -> Result<(), String> {
        let s: Vec<String> = session.map(String::from).into_iter().collect();
        self.ecrire_gels(session.is_none(), &s, maintenant)
    }

    /// Dans une transaction : dégel approuvé (global : tout est dégelé, comme en local).
    pub fn degeler(&mut self, session: Option<&str>) -> Result<(), String> {
        match session {
            Some(s) => self.cnx.execute("DELETE FROM gels WHERE session = ?1", [s]),
            None => self.cnx.execute("DELETE FROM gels", []),
        }
        .map(|_| ())
        .map_err(err)
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
        let t = 1_800_000_000_000;
        let mut a = Partage::ouvrir(&f, "m", "e1", "a", t).unwrap();
        let mut b = Partage::ouvrir(&f, "m", "e1", "b", t).unwrap();
        // Autre mandat : refusé.
        assert!(Partage::ouvrir(&f, "autre", "e1", "c", t).err().unwrap().contains("un fichier d'état partagé par mandat"));
        // Autre version du mandat tant que des instances sont actives : refusé.
        assert!(Partage::ouvrir(&f, "m", "e2", "c", t).err().unwrap().contains("autre version"));
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
        // Plus d'instance active : la nouvelle version du mandat est adoptée.
        drop((a, b));
        assert!(Partage::ouvrir(&f, "m", "e2", "c", t + ACTIVE_MS + 1).is_ok());
        let _ = std::fs::remove_dir_all(d);
    }
}
