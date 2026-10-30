//! **Passerelle réseau sortante** : proxy HTTP (`CONNECT` et requêtes en clair) que
//! l'agent utilise via `HTTPS_PROXY` / `HTTP_PROXY`.
//!
//! Pour chaque connexion :
//! 1. la destination est jugée comme une action `reseau` (mandat, bornes, gel) et la
//!    décision est journalisée, comme pour les outils de l'agent ;
//! 2. le nom est résolu et **chaque** adresse obtenue est contrôlée : une adresse interne
//!    (dont la boucle locale, donc l'API d'administration de SAL) est refusée ;
//! 3. le volume envoyé est **plafonné** : un tunnel chiffré ne laisse pas voir la méthode,
//!    mais un envoi massif vers un domaine autorisé en lecture coupe la connexion (EF-C4) ;
//! 4. le bilan (octets envoyés, reçus, coupure) est journalisé.
//!
//! Une décision « revue » est un refus : la passerelle n'a aucun moyen de demander à un
//! humain. Au niveau 1, l'agent peut ignorer `HTTPS_PROXY` ; au niveau 3 (conteneur), la
//! passerelle est sa seule sortie.
use std::time::Duration;

use sal_core::decision::Verdict;
use sal_core::passerelle::{adresse_interne, analyser, evenement, OUTIL};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::serveur::{constater, juger, Etat};

/// Session du journal pour le trafic de la passerelle.
const SESSION: &str = "passerelle";
const TETE_MAX: usize = 16 * 1024;
const DELAI: Duration = Duration::from_secs(10);

pub async fn servir(ecoute: TcpListener, etat: Etat, agent: String, plafond: u64) {
    loop {
        let Ok((flux, _)) = ecoute.accept().await else { continue };
        let (etat, agent) = (etat.clone(), agent.clone());
        tokio::spawn(async move {
            let _ = traiter(flux, etat, agent, plafond).await;
        });
    }
}

/// Lit l'en-tête de la requête (jusqu'à la ligne vide), et ce qui a pu suivre.
async fn lire_tete(flux: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut tampon = Vec::new();
    let mut morceau = [0u8; 4096];
    while !tampon.windows(4).any(|f| f == b"\r\n\r\n") {
        let n = tokio::time::timeout(DELAI, flux.read(&mut morceau)).await??;
        if n == 0 || tampon.len() + n > TETE_MAX {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        tampon.extend_from_slice(&morceau[..n]);
    }
    Ok(tampon)
}

async fn refuser(flux: &mut TcpStream, statut: &str, motif: &str) -> std::io::Result<()> {
    let corps = format!("SAL : {motif}\n");
    let reponse = format!(
        "HTTP/1.1 {statut}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}",
        corps.len()
    );
    flux.write_all(reponse.as_bytes()).await?;
    flux.shutdown().await
}

async fn traiter(mut client: TcpStream, etat: Etat, agent: String, plafond: u64) -> std::io::Result<()> {
    let tete = lire_tete(&mut client).await?;
    let premiere = String::from_utf8_lossy(&tete).lines().next().unwrap_or("").to_string();
    let Some(cible) = analyser(&premiere) else {
        return refuser(&mut client, "400 Bad Request", "requête non reconnue (proxy HTTP attendu)").await;
    };
    let evt = evenement(&cible, SESSION, &agent, "");

    // 1. Décision, journalisée avant toute connexion (fail-closed).
    let decision = match juger(&etat, &evt) {
        Ok((d, _)) => d,
        Err(e) => return refuser(&mut client, "503 Service Unavailable", &format!("{e} — fail-closed")).await,
    };
    match decision.verdict {
        Verdict::Allow => {}
        Verdict::Review => {
            let motif = format!("{} — la passerelle ne peut pas demander à un humain : refus", decision.motif);
            return refuser(&mut client, "403 Forbidden", &motif).await;
        }
        _ => return refuser(&mut client, "403 Forbidden", &decision.motif).await,
    }

    // 2. Ressource réelle : toutes les adresses résolues doivent être publiques.
    let adresses: Vec<std::net::SocketAddr> = match tokio::net::lookup_host((cible.hote.as_str(), cible.port)).await {
        Ok(a) => a.collect(),
        Err(_) => return refuser(&mut client, "502 Bad Gateway", "nom introuvable").await,
    };
    if adresses.is_empty() || adresses.iter().any(|a| adresse_interne(a.ip())) {
        let _ = constater(&etat, &evt, json!({"outil": OUTIL, "verbe": "reseau", "ressource": cible.url(),
            "refus": "adresse interne"}));
        return refuser(&mut client, "403 Forbidden", "adresse interne refusée (ressource réelle)").await;
    }
    let mut serveur = match tokio::time::timeout(DELAI, TcpStream::connect(&adresses[..])).await {
        Ok(Ok(s)) => s,
        _ => return refuser(&mut client, "502 Bad Gateway", "destination injoignable").await,
    };

    // 3. Relais, avec plafond d'envoi.
    let deja_envoye = if cible.methode == "CONNECT" {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        // Octets éventuellement envoyés par le client avant la réponse.
        let fin = tete.windows(4).position(|f| f == b"\r\n\r\n").map_or(tete.len(), |p| p + 4);
        serveur.write_all(&tete[fin..]).await?;
        (tete.len() - fin) as u64
    } else {
        // Requête en clair, en forme absolue : un serveur HTTP/1.1 doit l'accepter.
        serveur.write_all(&tete).await?;
        tete.len() as u64
    };
    let (envoye, recu, coupe) = relayer(client, serveur, plafond, deja_envoye).await;

    // 4. Bilan.
    let _ = constater(&etat, &evt, json!({"outil": OUTIL, "verbe": "reseau", "ressource": cible.url(),
        "envoye": envoye, "recu": recu, "coupe_plafond": coupe}));
    Ok(())
}

/// Relaie dans les deux sens ; coupe tout si le client envoie plus que le plafond.
async fn relayer(client: TcpStream, serveur: TcpStream, plafond: u64, deja: u64) -> (u64, u64, bool) {
    use std::sync::atomic::{AtomicU64, Ordering};
    let envoye = std::sync::Arc::new(AtomicU64::new(deja));
    let (mut cl, mut ce) = client.into_split();
    let (mut sl, mut se) = serveur.into_split();
    let compteur = envoye.clone();
    let montant = async move {
        let mut morceau = [0u8; 16 * 1024];
        loop {
            let n = match cl.read(&mut morceau).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if compteur.fetch_add(n as u64, Ordering::Relaxed) + n as u64 > plafond {
                return true;
            }
            if se.write_all(&morceau[..n]).await.is_err() {
                break;
            }
        }
        let _ = se.shutdown().await;
        false
    };
    let descendant = async move { tokio::io::copy(&mut sl, &mut ce).await.unwrap_or(0) };
    tokio::pin!(montant, descendant);
    let (recu, coupe) = tokio::select! {
        coupe = &mut montant => {
            // Plafond atteint : on sort, ce qui ferme les deux moitiés.
            let recu = if coupe { 0 } else {
                tokio::time::timeout(Duration::from_secs(60), &mut descendant).await.unwrap_or(0)
            };
            (recu, coupe)
        }
        recu = &mut descendant => (recu, false),
    };
    (envoye.load(Ordering::Relaxed), recu, coupe)
}
