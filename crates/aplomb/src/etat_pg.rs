//! **Moteur PostgreSQL de l'état partagé** (`--etat-partage postgres://…`), pour des
//! instances sur plusieurs machines. Compilé avec la fonctionnalité `postgres` (par défaut).
//!
//! Le client PostgreSQL synchrone ne tourne pas dans un exécuteur tokio : il vit dans un
//! fil à lui, qui reçoit les requêtes par un canal. Les décisions l'attendent comme elles
//! attendent SQLite. Pas de réponse dans le délai : erreur, donc refus.
//!
//! - **Une transaction à la fois entre instances** : `BEGIN`, puis un verrou consultatif
//!   de transaction (`pg_advisory_xact_lock`) propre au mandat, l'équivalent du
//!   `BEGIN IMMEDIATE` de SQLite.
//! - **Connexion perdue** : reconnexion à la requête suivante (adresse multi-hôtes et
//!   `target_session_attrs=read-write` pour suivre une bascule). Une transaction en cours
//!   est perdue avec la connexion : elle échoue jusqu'au bout, rien n'est appliqué à moitié.
//! - **TLS obligatoire hors de la machine** : un hôte qui n'est pas la boucle locale ou un
//!   socket Unix exige `sslmode=require`. Le certificat du serveur et son nom sont toujours
//!   vérifiés (racines publiques, plus l'autorité de `--etat-partage-ca`).
//! - **Mot de passe** : jamais dans l'adresse (visible dans la liste des processus). Il est
//!   lu dans `PGPASSWORD`.
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use postgres::config::{Host, SslMode};
use postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};
use postgres::types::{ToSql, Type};
use postgres::{Client, Socket};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls;

use crate::etat_partage::Valeur;

/// Délai maximal d'une réponse du fil PostgreSQL, connexion comprise.
const REPONSE_S: u64 = 10;

enum Op {
    Lot(String),
    Executer(String, Vec<Valeur>),
    Lignes(String, Vec<Valeur>),
    Debut(i64),
    Fin,
    Annuler,
}

enum Reponse {
    Fait,
    Nombre(u64),
    Lignes(Vec<Vec<Valeur>>),
}

type Demande = (Op, mpsc::Sender<Result<Reponse, String>>);

/// Fil qui tient la connexion PostgreSQL.
pub struct Fil {
    tx: mpsc::Sender<Demande>,
    cible: String,
}

fn local(h: &Host) -> bool {
    match h {
        Host::Tcp(n) => matches!(n.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]"),
        #[cfg(unix)]
        Host::Unix(_) => true,
    }
}

/// Adresse sans secret, pour l'affichage et le journal.
fn cible(cfg: &postgres::Config) -> String {
    let hotes: Vec<String> = cfg
        .get_hosts()
        .iter()
        .map(|h| match h {
            Host::Tcp(n) => n.clone(),
            #[cfg(unix)]
            Host::Unix(p) => p.display().to_string(),
        })
        .collect();
    let base = cfg.get_dbname().unwrap_or("");
    format!("postgres://{}@{}/{base}", cfg.get_user().unwrap_or(""), hotes.join(","))
}

impl Fil {
    /// Lit l'adresse, vérifie TLS et mot de passe, démarre le fil et se connecte une
    /// première fois (une base injoignable au démarrage est une erreur de démarrage).
    pub fn ouvrir(adresse: &str, ca: Option<&Path>) -> Result<Self, String> {
        let mut cfg: postgres::Config = adresse.parse().map_err(|e| format!("adresse PostgreSQL : {e}"))?;
        if cfg.get_password().is_some() {
            return Err("adresse PostgreSQL : pas de mot de passe dans l'adresse (visible dans la liste des processus) ; le mettre dans PGPASSWORD".into());
        }
        if let Ok(m) = std::env::var("PGPASSWORD") {
            cfg.password(m);
        }
        if cfg.get_hosts().is_empty() {
            return Err("adresse PostgreSQL : hôte manquant (postgres://compte@hote/base)".into());
        }
        let distant = cfg.get_hosts().iter().any(|h| !local(h));
        if distant && cfg.get_ssl_mode() != SslMode::Require {
            return Err("adresse PostgreSQL : un serveur hors de cette machine exige TLS ; ajouter ?sslmode=require à l'adresse".into());
        }
        if cfg.get_connect_timeout().is_none() {
            cfg.connect_timeout(Duration::from_secs(5));
        }
        cfg.application_name("aplomb");
        let tls = Tls::nouveau(ca)?;
        let cible = cible(&cfg);
        let (tx, rx) = mpsc::channel::<Demande>();
        std::thread::Builder::new()
            .name("aplomb-postgres".into())
            .spawn(move || servir(cfg, tls, rx))
            .map_err(|e| format!("état partagé : {e}"))?;
        let fil = Self { tx, cible };
        fil.lot("SELECT 1")?;
        Ok(fil)
    }

    pub fn cible(&self) -> &str {
        &self.cible
    }

    fn demander(&self, op: Op) -> Result<Reponse, String> {
        let (tx, rx) = mpsc::channel();
        self.tx.send((op, tx)).map_err(|_| "état partagé : fil PostgreSQL arrêté".to_string())?;
        rx.recv_timeout(Duration::from_secs(REPONSE_S)).map_err(|_| "état partagé : PostgreSQL ne répond pas".to_string())?
    }

    pub fn lot(&self, sql: &str) -> Result<(), String> {
        self.demander(Op::Lot(sql.into())).map(|_| ())
    }

    pub fn executer(&self, sql: &str, p: Vec<Valeur>) -> Result<u64, String> {
        match self.demander(Op::Executer(sql.into(), p))? {
            Reponse::Nombre(n) => Ok(n),
            _ => Ok(0),
        }
    }

    pub fn lignes(&self, sql: &str, p: Vec<Valeur>) -> Result<Vec<Vec<Valeur>>, String> {
        match self.demander(Op::Lignes(sql.into(), p))? {
            Reponse::Lignes(l) => Ok(l),
            _ => Ok(Vec::new()),
        }
    }

    pub fn debut(&self, verrou: i64) -> Result<(), String> {
        self.demander(Op::Debut(verrou)).map(|_| ())
    }

    pub fn fin(&self) -> Result<(), String> {
        self.demander(Op::Fin).map(|_| ())
    }

    pub fn annuler(&self) {
        let _ = self.demander(Op::Annuler);
    }
}

fn err(e: postgres::Error) -> String {
    format!("état partagé : {e}")
}

/// État du fil : la connexion, et si la transaction en cours est encore valable.
struct Etat {
    client: Option<Client>,
    transaction: bool,
    rompue: bool,
}

fn servir(cfg: postgres::Config, tls: Tls, rx: mpsc::Receiver<Demande>) {
    let mut e = Etat { client: None, transaction: false, rompue: false };
    for (op, tx) in rx {
        let r = traiter(&cfg, &tls, &mut e, op);
        if e.client.as_ref().is_some_and(|c| c.is_closed()) {
            e.client = None;
        }
        let _ = tx.send(r);
    }
}

fn connecter<'a>(cfg: &postgres::Config, tls: &Tls, e: &'a mut Etat) -> Result<&'a mut Client, String> {
    if e.client.as_ref().map_or(true, |c| c.is_closed()) {
        let mut c = cfg.connect(tls.clone()).map_err(err)?;
        // Un verrou tenu trop longtemps ailleurs : refus plutôt qu'attente.
        c.batch_execute("SET lock_timeout = '2s'; SET statement_timeout = '5s'").map_err(err)?;
        e.client = Some(c);
    }
    Ok(e.client.as_mut().expect("connexion"))
}

fn parametres(p: &[Valeur]) -> Vec<&(dyn ToSql + Sync)> {
    p.iter()
        .map(|v| match v {
            Valeur::T(s) => s as &(dyn ToSql + Sync),
            Valeur::E(n) => n as &(dyn ToSql + Sync),
        })
        .collect()
}

fn traiter(cfg: &postgres::Config, tls: &Tls, e: &mut Etat, op: Op) -> Result<Reponse, String> {
    match op {
        Op::Annuler => {
            if let Some(c) = e.client.as_mut().filter(|c| !c.is_closed()) {
                let _ = c.batch_execute("ROLLBACK");
            }
            e.transaction = false;
            e.rompue = false;
            Ok(Reponse::Fait)
        }
        Op::Fin => {
            let rompue = e.rompue || e.client.as_ref().map_or(true, |c| c.is_closed());
            e.transaction = false;
            e.rompue = false;
            if rompue {
                if let Some(c) = e.client.as_mut().filter(|c| !c.is_closed()) {
                    let _ = c.batch_execute("ROLLBACK");
                }
                return Err("état partagé : transaction interrompue, rien n'est appliqué".into());
            }
            e.client.as_mut().expect("connexion").batch_execute("COMMIT").map_err(err)?;
            Ok(Reponse::Fait)
        }
        Op::Debut(verrou) => {
            e.transaction = false;
            e.rompue = false;
            let c = connecter(cfg, tls, e)?;
            c.batch_execute("BEGIN").map_err(err)?;
            if let Err(x) = c.execute("SELECT pg_advisory_xact_lock($1)", &[&verrou]) {
                let _ = c.batch_execute("ROLLBACK");
                return Err(err(x));
            }
            e.transaction = true;
            Ok(Reponse::Fait)
        }
        op => {
            // Dans une transaction, une connexion perdue ne se remplace pas : la suite
            // s'exécuterait hors transaction.
            if e.transaction && (e.rompue || e.client.as_ref().map_or(true, |c| c.is_closed())) {
                e.rompue = true;
                return Err("état partagé : connexion PostgreSQL perdue pendant la transaction".into());
            }
            let r = requete(connecter(cfg, tls, e)?, op);
            if r.is_err() && e.transaction {
                e.rompue = true;
            }
            r
        }
    }
}

fn requete(c: &mut Client, op: Op) -> Result<Reponse, String> {
    match op {
        Op::Lot(sql) => c.batch_execute(&sql).map(|_| Reponse::Fait).map_err(err),
        Op::Executer(sql, p) => c.execute(sql.as_str(), &parametres(&p)).map(Reponse::Nombre).map_err(err),
        Op::Lignes(sql, p) => {
            let lignes = c.query(sql.as_str(), &parametres(&p)).map_err(err)?;
            let mut v = Vec::with_capacity(lignes.len());
            for l in &lignes {
                let mut ligne = Vec::with_capacity(l.len());
                for (i, col) in l.columns().iter().enumerate() {
                    ligne.push(match *col.type_() {
                        Type::INT8 => Valeur::E(l.try_get::<_, i64>(i).map_err(err)?),
                        Type::INT4 => Valeur::E(l.try_get::<_, i32>(i).map_err(err)? as i64),
                        _ => Valeur::T(l.try_get::<_, String>(i).map_err(err)?),
                    });
                }
                v.push(ligne);
            }
            Ok(Reponse::Lignes(v))
        }
        _ => Ok(Reponse::Fait),
    }
}

/// TLS par rustls (le fournisseur `ring` du reste du binaire) : certificat et nom du
/// serveur vérifiés.
#[derive(Clone)]
struct Tls(Arc<rustls::ClientConfig>);

impl Tls {
    fn nouveau(ca: Option<&Path>) -> Result<Self, String> {
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        let mut racines = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        if let Some(ca) = ca {
            let nom = ca.display();
            for c in CertificateDer::pem_file_iter(ca).map_err(|e| format!("ca {nom} : {e}"))? {
                racines.add(c.map_err(|e| format!("ca {nom} : {e}"))?).map_err(|e| format!("ca {nom} : {e}"))?;
            }
        }
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(racines)
            .with_no_client_auth();
        Ok(Self(Arc::new(cfg)))
    }
}

pub struct Connecteur {
    cfg: Arc<rustls::ClientConfig>,
    nom: rustls::pki_types::ServerName<'static>,
}

impl MakeTlsConnect<Socket> for Tls {
    type Stream = Flux;
    type TlsConnect = Connecteur;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domaine: &str) -> Result<Connecteur, io::Error> {
        let nom = rustls::pki_types::ServerName::try_from(domaine.to_string()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Connecteur { cfg: self.0.clone(), nom })
    }
}

impl TlsConnect<Socket> for Connecteur {
    type Stream = Flux;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Flux, io::Error>> + Send>>;

    fn connect(self, flux: Socket) -> Self::Future {
        Box::pin(async move {
            let c = tokio_rustls::TlsConnector::from(self.cfg).connect(self.nom, flux).await?;
            Ok(Flux(c))
        })
    }
}

/// Flux TLS vers PostgreSQL.
pub struct Flux(tokio_rustls::client::TlsStream<Socket>);

impl TlsStream for Flux {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

impl AsyncRead for Flux {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Flux {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresses_refusees() {
        let e = |a: &str| Fil::ouvrir(a, None).err().unwrap();
        assert!(e("postgres://aplomb:secret@127.0.0.1/aplomb").contains("PGPASSWORD"));
        assert!(e("postgres://aplomb@db.interne/aplomb").contains("sslmode=require"));
        assert!(e("postgres://aplomb@db1,db2/aplomb?sslmode=prefer").contains("sslmode=require"));
    }
}
