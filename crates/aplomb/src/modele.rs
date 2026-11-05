//! **Aplomb Gate, proxy LLM** (niveau d'assurance 2) : l'agent parle à son modèle par
//! Aplomb (`ANTHROPIC_BASE_URL`), jamais directement.
//!
//! 1. Seuls les appels de conversation passent (`aplomb_core::modele::chemin_permis`).
//! 2. Gel : plus rien ne part vers le modèle.
//! 3. Journal avant envoi (fail-closed), puis bilan à la fin de la réponse : modèle,
//!    volumes, jetons, outils demandés par le modèle.
//! 4. La clé de l'agent est retirée, celle d'Aplomb injectée : le canal modèle ne peut pas
//!    servir à exfiltrer vers un autre compte.
//! 5. Les secrets de la requête (clés privées, jetons d'API…) sont masqués avant envoi :
//!    lus par l'agent dans un fichier ou une sortie de commande, ils ne partent pas chez le
//!    fournisseur du modèle (moniteur « secrets », EF-D1). Le journal dit lesquels, jamais
//!    leur valeur.
//!
//! 6. Protocoles (EF-E2) et raisonnement (EF-E3) : voir `crate::protocole`. En
//!    surveillance, le raisonnement lu au fil de l'eau accompagne chaque appel d'outil
//!    annoncé jusqu'à la décision ; en `report` ou `reechantillonnage`, la réponse est
//!    retenue, examinée, et remplacée si elle est suspecte.
//! 7. Consommation : la clé présentée par l'agent désigne son compte technique
//!    (`aplomb agent`) ; clé inconnue : 401, quota du jour atteint : 429. Chaque bilan dit
//!    le compte, l'utilisateur, le prompt (scellé au journal) et les jetons, cache compris.
//!
//! La réponse est relayée au fil de l'eau (flux SSE compris) et lue au passage.
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use aplomb_core::action::{EvenementOutil, Phase};
use aplomb_core::consommation::{cle_presentee, empreinte_prompt, extrait, prompt, Releve};
use aplomb_core::modele::{analyser_reponse, chemin_permis, entetes_amont, Annonce};
use aplomb_core::moniteurs::ModeProtocole;
use futures_util::StreamExt;
use serde_json::{json, Value};

use crate::serveur::{constater, Etat};

/// Session du journal pour les échanges avec le modèle.
pub(crate) const SESSION: &str = "modele";
const OUTIL: &str = "Modele";
/// Taille maximale d'une requête (contexte long, images).
const REQUETE_MAX: usize = 64 * 1024 * 1024;
/// Part de la réponse conservée pour le bilan.
const REPONSE_LUE_MAX: usize = 16 * 1024 * 1024;
/// Numéro d'échange : relie l'envoi au bilan dans le journal.
static ECHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub struct Reglages {
    pub agent: String,
    /// Amont, ex. `https://api.anthropic.com` ; `None` si le mandat ne déclare aucun modèle.
    pub amont: Option<String>,
    pub jeton: Option<String>,
    pub protocole: crate::protocole::Reglages,
}

type Partage = (Etat, Arc<Reglages>);

pub fn routeur(etat: Etat, reglages: Reglages) -> Router {
    Router::new()
        .fallback(relayer)
        .layer(DefaultBodyLimit::max(REQUETE_MAX))
        .with_state((etat, Arc::new(reglages)))
}

fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client HTTP")
    })
}

/// Erreur au format de l'API Messages, pour que l'agent l'affiche telle quelle.
fn refus(statut: StatusCode, motif: &str) -> Response {
    let corps = json!({"type": "error", "error": {"type": "permission_error", "message": format!("Aplomb : {motif}")}});
    (statut, axum::Json(corps)).into_response()
}

fn evenement(agent: &str, ressource: &str, methode: &str) -> EvenementOutil {
    EvenementOutil {
        session: SESSION.into(),
        agent: agent.into(),
        mode: "proxy-llm".into(),
        cwd: String::new(),
        outil: OUTIL.into(),
        entree: json!({"url": ressource, "methode": methode}),
        phase: Phase::Avant,
        chemin_reel: None,
        contenu_execute: None,
        nonce: None,
        appel: None,
        delegation: None,
    }
}

async fn relayer(State((etat, r)): State<Partage>, methode: Method, uri: Uri, entetes: HeaderMap, corps: Bytes) -> Response {
    let chemin = uri.path();
    let evt = evenement(&r.agent, chemin, methode.as_str());
    let echange = ECHANGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    // Session de l'agent, s'il la donne (Claude Code : en-tête x-claude-code-session-id).
    let session_agent = entetes
        .iter()
        .find(|(n, _)| n.as_str().contains("session-id"))
        .and_then(|(_, v)| v.to_str().ok())
        .map(String::from);
    let base = json!({"outil": OUTIL, "verbe": "modele", "ressource": chemin, "methode": methode.as_str(),
        "echange": echange, "session_agent": session_agent});
    let journaliser = |mut detail: Value, extra: Value| {
        if let (Some(d), Some(e)) = (detail.as_object_mut(), extra.as_object()) {
            d.extend(e.clone());
        }
        constater(&etat, &evt, detail)
    };

    if !chemin_permis(methode.as_str(), chemin) {
        let _ = journaliser(base, json!({"refus": "chemin non permis"}));
        return refus(StatusCode::FORBIDDEN, &format!("{methode} {chemin} non permis : seuls les appels de conversation passent"));
    }
    if etat.gele(SESSION) {
        return refus(StatusCode::FORBIDDEN, "superviseur gelé : plus aucun appel au modèle");
    }
    let entrants: Vec<(String, String)> = entetes
        .iter()
        .filter_map(|(n, v)| v.to_str().ok().map(|v| (n.as_str().to_string(), v.to_string())))
        .collect();
    let imputation = match etat.imputer(cle_presentee(&entrants).as_deref()) {
        Ok(i) => i,
        Err((statut, motif)) => {
            let _ = journaliser(base, json!({"refus": motif}));
            return refus(statut, &motif);
        }
    };
    let base = {
        let mut b = base;
        b["compte"] = json!(imputation.compte);
        b["utilisateur"] = json!(imputation.utilisateur);
        b
    };
    let (Some(amont), Some(jeton)) = (&r.amont, &r.jeton) else {
        let motif = if r.amont.is_none() {
            "aucun modèle dans le mandat (perimetre.domaines_modele)"
        } else {
            "aucun jeton du modèle : lancer aplomb modele jeton, puis redémarrer aplomb serve"
        };
        return refus(StatusCode::SERVICE_UNAVAILABLE, motif);
    };
    // Secrets masqués avant tout envoi ; la marque garde le JSON valide.
    let (corps, masques) = match std::str::from_utf8(&corps).map(aplomb_core::moniteurs::masquer) {
        Ok((texte, sortes)) if !sortes.is_empty() => (Bytes::from(texte), sortes),
        _ => (corps, Vec::new()),
    };
    let requete_json = serde_json::from_slice::<Value>(&corps).ok();
    let modele = requete_json.as_ref().and_then(|v| v.get("model").and_then(Value::as_str).map(String::from)).unwrap_or_default();
    // Prompt de l'utilisateur, secrets déjà masqués ; seuls les appels de conversation comptent.
    let prompt = requete_json.as_ref().filter(|_| chemin == "/v1/messages").and_then(prompt);
    // Journalisé avant tout envoi : sans journal, rien ne part.
    let mut envoi = json!({"modele": modele, "envoye": corps.len()});
    if !masques.is_empty() {
        envoi["secrets_masques"] = json!(masques);
    }
    if let Err(e) = journaliser(base.clone(), envoi) {
        return refus(StatusCode::SERVICE_UNAVAILABLE, &format!("{e} — fail-closed"));
    }

    let cible = uri.path_and_query().map_or(chemin, |p| p.as_str()).to_string();
    let reponse = match envoyer(amont, &cible, &methode, &entrants, jeton, corps.clone()).await {
        Ok(r) => r,
        Err(e) => {
            let _ = journaliser(base, json!({"erreur": "amont injoignable"}));
            return refus(StatusCode::BAD_GATEWAY, &format!("modèle injoignable : {e}"));
        }
    };
    let releve = (chemin == "/v1/messages").then(|| Releve {
        horodatage: 0,
        compte: imputation.compte,
        utilisateur: imputation.utilisateur,
        session_agent: session_agent.clone(),
        prompt: prompt.as_deref().map(empreinte_prompt),
        extrait: prompt.as_deref().map(extrait),
        modele,
        entree: 0,
        cache_lu: 0,
        cache_ecrit: 0,
        sortie: 0,
    });
    let annonce = Annonce { echange, session_agent: session_agent.clone(), ..Default::default() };

    // Protocole : la réponse est retenue et examinée avant que l'agent la reçoive (EF-E2).
    if let Some(p) = r.protocole.protocole.as_ref().filter(|_| chemin == "/v1/messages" && reponse.status().is_success()) {
        let session = session_agent.clone().unwrap_or_else(|| SESSION.into());
        let debut = std::time::Instant::now();
        let Some(mut retenue) = lire(reponse).await else { return refus(StatusCode::BAD_GATEWAY, "réponse du modèle interrompue") };
        let mut examen = crate::protocole::examiner(&etat, &r.protocole, p, &session, &retenue.2).await;
        let mut ecartees: Vec<Bytes> = Vec::new();
        let mut issue = Value::Null;
        if examen.suspect {
            let motifs = examen.motifs.clone();
            match p.mode {
                ModeProtocole::Report => {
                    let fiable = p.fiable.as_ref().zip(r.protocole.fiable.as_ref());
                    let corps_fiable = fiable.and_then(|(f, _)| crate::protocole::requete_fiable(&corps, &f.modele));
                    let reponse_fiable = match (fiable, corps_fiable) {
                        (Some((_, hote)), Some(c)) => match envoyer(hote, &cible, &methode, &entrants, jeton, Bytes::from(c)).await {
                            Ok(rf) if rf.status().is_success() => lire(rf).await,
                            _ => None,
                        },
                        _ => None,
                    };
                    match reponse_fiable {
                        Some(f) => {
                            // Le modèle de confiance n'est pas soumis au protocole ; ses actions
                            // passent par le hook comme toutes les autres.
                            let gel = crate::protocole::ecarter(&etat, &examen);
                            let (raisonnement, avis_r) = r.protocole.lire_raisonnement(&f.2);
                            ecartees.push(std::mem::replace(&mut retenue, f).2);
                            examen = crate::protocole::Examen { raisonnement, ..Default::default() };
                            if let Some(a) = avis_r {
                                for (id, _, _) in aplomb_core::modele::reconstituer(&retenue.2).outils {
                                    examen.par_outil.insert(id, (vec![a.clone()], false));
                                }
                            }
                            issue = json!({"protocole": "report", "suspecte": motifs, "issue": "remplacée par la réponse du modèle de confiance", "gel": gel});
                            etat.noter_protocole(|s| s.remplacees += 1);
                        }
                        None => {
                            let motif = "réponse suspecte, modèle de confiance indisponible : revue";
                            for (avis, _) in examen.par_outil.values_mut() {
                                avis.push(crate::protocole::avis_non_remplacee(motif));
                            }
                            issue = json!({"protocole": "report", "suspecte": motifs, "issue": motif});
                            etat.noter_protocole(|s| s.fiable_indisponible += 1);
                        }
                    }
                }
                ModeProtocole::Reechantillonnage => {
                    let mut retenu = None;
                    for k in 1..=p.echantillons {
                        etat.noter_protocole(|s| s.reechantillonnages += 1);
                        let Ok(rk) = envoyer(amont, &cible, &methode, &entrants, jeton, corps.clone()).await else { break };
                        if !rk.status().is_success() {
                            break;
                        }
                        let Some(ek) = lire(rk).await else { break };
                        let examen_k = crate::protocole::examiner(&etat, &r.protocole, p, &session, &ek.2).await;
                        if !examen_k.suspect {
                            crate::protocole::ecarter(&etat, &examen);
                            ecartees.push(std::mem::replace(&mut retenue, ek).2);
                            examen = examen_k;
                            retenu = Some(k);
                            break;
                        }
                        crate::protocole::ecarter(&etat, &examen_k);
                        ecartees.push(ek.2);
                    }
                    issue = match retenu {
                        Some(k) => json!({"protocole": "reechantillonnage", "suspecte": motifs, "issue": format!("échantillon {k} retenu, non suspect")}),
                        None => {
                            let n = ecartees.len() + 1;
                            let motif = format!("rééchantillonnage : {n} échantillon(s) suspect(s) sur {n} — incrimination, revue");
                            for (avis, _) in examen.par_outil.values_mut() {
                                avis.push(crate::protocole::avis_non_remplacee(&motif));
                            }
                            etat.noter_protocole(|s| s.incriminations += 1);
                            json!({"protocole": "reechantillonnage", "suspecte": motifs, "issue": motif})
                        }
                    };
                }
                ModeProtocole::Surveillance => {}
            }
        }
        let latence = debut.elapsed().as_millis() as u64;
        let suspecte = !issue.is_null();
        etat.noter_protocole(|s| {
            s.examinees += 1;
            s.suspectes += u64::from(suspecte);
            s.latence_ms += latence;
        });
        if suspecte {
            issue["latence_ms"] = json!(latence);
            let _ = journaliser(base.clone(), issue);
        }
        for (id, (avis, juge)) in examen.par_outil {
            etat.annoncer(&id, Annonce { raisonnement: examen.raisonnement.clone(), avis, juge, ..annonce.clone() });
        }
        // Réponses écartées : payées, donc comptées.
        if let Some(rl) = &releve {
            for e in &ecartees {
                let a = analyser_reponse(e);
                etat.relever(Releve {
                    horodatage: maintenant(),
                    entree: a.jetons_entree.unwrap_or(0),
                    sortie: a.jetons_sortie.unwrap_or(0),
                    cache_lu: a.cache_lu.unwrap_or(0),
                    cache_ecrit: a.cache_ecrit.unwrap_or(0),
                    ..rl.clone()
                });
            }
        }
        let (statut, entetes_r, octets) = retenue;
        let mut sortie = Response::builder().status(statut);
        for (n, v) in entetes_r {
            sortie = sortie.header(n, v);
        }
        drop(Bilan { etat: etat.clone(), evt: evt.clone(), base, statut, recu: octets.len() as u64, lu: octets.to_vec(), releve });
        return sortie.body(Body::from(octets)).unwrap_or_else(|_| refus(StatusCode::BAD_GATEWAY, "réponse du modèle illisible"));
    }

    let statut = reponse.status();
    let mut sortie = Response::builder().status(statut.as_u16());
    for (n, v) in entetes_relayes(reponse.headers()) {
        sortie = sortie.header(n, v);
    }
    // Bilan journalisé quand le flux se termine (ou que l'agent coupe).
    let bilan = Arc::new(Mutex::new(Bilan { etat: etat.clone(), evt: evt.clone(), base, statut: statut.as_u16(), lu: Vec::new(), recu: 0, releve }));
    let protocole = Arc::clone(&r);
    let flux = reponse.bytes_stream().map(move |morceau| {
        if let Ok(m) = &morceau {
            let mut b = bilan.lock().expect("verrou");
            b.recu += m.len() as u64;
            if b.lu.len() + m.len() <= REPONSE_LUE_MAX {
                b.lu.extend_from_slice(m);
            }
            // Annonce au fil de l'eau : l'agent peut exécuter l'outil dès la fin du flux,
            // avant même que le bilan soit écrit. Le raisonnement précède l'appel dans le
            // flux : il est déjà là (EF-E3).
            if m.windows(8).any(|f| f == b"tool_use") {
                let (raisonnement, avis_r) = protocole.protocole.lire_raisonnement(&b.lu);
                for o in analyser_reponse(&b.lu).outils {
                    let a = Annonce { raisonnement: raisonnement.clone(), avis: avis_r.clone().into_iter().collect(), ..annonce.clone() };
                    b.etat.annoncer(&o.id, a);
                }
            }
        }
        morceau
    });
    sortie.body(Body::from_stream(flux)).unwrap_or_else(|_| refus(StatusCode::BAD_GATEWAY, "réponse du modèle illisible"))
}

fn maintenant() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Envoie la requête de l'agent à un amont (modèle de l'agent, ou modèle de confiance).
async fn envoyer(
    amont: &str,
    cible: &str,
    methode: &Method,
    entrants: &[(String, String)],
    jeton: &str,
    corps: Bytes,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut requete = client().request(methode.clone(), format!("{amont}{cible}"));
    for (n, v) in entetes_amont(entrants, jeton) {
        requete = requete.header(n, v);
    }
    requete.body(corps).send().await
}

/// En-têtes de la réponse à relayer à l'agent (sans ceux de saut à saut).
fn entetes_relayes(entetes: &reqwest::header::HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    entetes
        .iter()
        .filter(|(n, _)| !matches!(n.as_str(), "connection" | "keep-alive" | "transfer-encoding" | "content-length"))
        .filter_map(|(n, v)| Some((HeaderName::from_bytes(n.as_str().as_bytes()).ok()?, HeaderValue::from_bytes(v.as_bytes()).ok()?)))
        .collect()
}

/// Lit une réponse entière (protocole) : statut, en-têtes à relayer, corps.
async fn lire(reponse: reqwest::Response) -> Option<(u16, Vec<(HeaderName, HeaderValue)>, Bytes)> {
    let statut = reponse.status().as_u16();
    let entetes = entetes_relayes(reponse.headers());
    let octets = reponse.bytes().await.ok()?;
    (octets.len() <= REPONSE_LUE_MAX).then_some((statut, entetes, octets))
}

struct Bilan {
    etat: Etat,
    evt: EvenementOutil,
    base: Value,
    statut: u16,
    lu: Vec<u8>,
    recu: u64,
    /// Relevé de consommation à compléter par les jetons de la réponse.
    releve: Option<Releve>,
}

impl Drop for Bilan {
    fn drop(&mut self) {
        let a = analyser_reponse(&self.lu);
        let mut detail = self.base.clone();
        if let Some(d) = detail.as_object_mut() {
            d.insert("statut".into(), json!(self.statut));
            d.insert("recu".into(), json!(self.recu));
            for o in &a.outils {
                let annonce = Annonce { echange: d["echange"].as_u64().unwrap_or(0), session_agent: d["session_agent"].as_str().map(String::from), ..Default::default() };
                self.etat.annoncer(&o.id, annonce);
            }
            d.insert("outils".into(), json!(a.outils));
            d.insert("jetons_entree".into(), json!(a.jetons_entree));
            d.insert("jetons_sortie".into(), json!(a.jetons_sortie));
            d.insert("cache_lu".into(), json!(a.cache_lu));
            d.insert("cache_ecrit".into(), json!(a.cache_ecrit));
        }
        let releve = self.releve.take().filter(|_| a.jetons_entree.is_some() || a.jetons_sortie.is_some()).map(|mut r| {
            r.horodatage = maintenant();
            r.entree = a.jetons_entree.unwrap_or(0);
            r.sortie = a.jetons_sortie.unwrap_or(0);
            r.cache_lu = a.cache_lu.unwrap_or(0);
            r.cache_ecrit = a.cache_ecrit.unwrap_or(0);
            r
        });
        if let (Some(r), Some(d)) = (&releve, detail.as_object_mut()) {
            d.insert("modele".into(), json!(r.modele));
            // Scellé au journal (champ sensible) : extrait masqué et empreinte de regroupement.
            if r.prompt.is_some() {
                d.insert("prompt".into(), json!({"extrait": r.extrait, "empreinte": r.prompt}));
            }
        }
        let _ = constater(&self.etat, &self.evt, detail);
        if let Some(r) = releve {
            self.etat.relever(r);
        }
    }
}

/// Relevé de consommation d'un bilan du journal (contenu déchiffré, ou scellé : sans prompt).
pub(crate) fn releve_du_journal(horodatage: u64, c: &Value) -> Option<Releve> {
    if c.get("ressource").and_then(Value::as_str).is_some_and(|r| r != "/v1/messages") {
        return None;
    }
    let n = |k: &str| c.get(k).and_then(Value::as_u64);
    let (entree, sortie) = (n("jetons_entree"), n("jetons_sortie"));
    if entree.is_none() && sortie.is_none() {
        return None;
    }
    let s = |k: &str| c.get(k).and_then(Value::as_str).map(String::from);
    Some(Releve {
        horodatage,
        compte: s("compte").unwrap_or_else(|| "anonyme".into()),
        utilisateur: s("utilisateur").unwrap_or_else(|| "?".into()),
        session_agent: s("session_agent"),
        prompt: c.pointer("/prompt/empreinte").and_then(Value::as_str).map(String::from),
        extrait: c.pointer("/prompt/extrait").and_then(Value::as_str).map(String::from),
        modele: s("modele").unwrap_or_default(),
        entree: entree.unwrap_or(0),
        cache_lu: n("cache_lu").unwrap_or(0),
        cache_ecrit: n("cache_ecrit").unwrap_or(0),
        sortie: sortie.unwrap_or(0),
    })
}
