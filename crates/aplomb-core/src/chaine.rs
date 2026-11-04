//! **Vue chaînée** (Aplomb Watch) : relie, pour une session d'agent, chaque appel au
//! modèle (niveau 2, proxy LLM), les outils que le modèle y demande, les actions que le
//! hook présente au superviseur (niveau 3) et le trafic d'Aplomb Gate qui suit.
//!
//! Le lien entre demande et action est exact : c'est l'identifiant d'appel d'outil
//! (`toolu_…`) que le modèle attribue et que le hook retransmet. Le rattachement des
//! appels au modèle à une session se fait par l'identifiant de session que l'agent donne
//! au proxy s'il le donne, sinon par l'horaire (un seul agent à la fois).
//!
//! Écarts relevés (contrôle croisé) :
//! - une action présentée au superviseur sans demande du modèle correspondante ;
//! - un outil demandé par le modèle qui n'a jamais été présenté au superviseur (refus de
//!   l'utilisateur dans Claude Code, ou action qui contourne le hook).
use serde::Serialize;
use serde_json::Value;

use crate::journal::Entree;
use crate::modele::OutilDemande;

/// Marge autour d'une session pour lui rattacher des appels au modèle par l'horaire.
const MARGE_MS: u64 = 120_000;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Echange {
    pub numero: u64,
    pub debut: u64,
    pub fin: Option<u64>,
    pub modele: String,
    pub envoye: u64,
    pub recu: u64,
    pub statut: Option<u64>,
    pub jetons_entree: Option<u64>,
    pub jetons_sortie: Option<u64>,
    pub outils: Vec<OutilDemande>,
    pub session_agent: Option<String>,
    pub refus: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Action {
    pub appel: Option<String>,
    pub horodatage: u64,
    pub outil: String,
    pub verbe: String,
    /// Référence chiffrée de la ressource (le clair exige les clés de session).
    pub ref_ressource: Option<String>,
    pub verdict: String,
    pub regle: String,
    pub execute: bool,
    /// Contenus non fiables reçus par la session avant l'action (EF-B5).
    pub provenance: Vec<String>,
    /// Type de sous-agent, si l'action vient d'un agent délégué (EF-B6).
    pub sous_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Reseau {
    pub horodatage: u64,
    pub verdict: String,
    pub regle: String,
    pub ref_ressource: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tour {
    pub echange: Echange,
    pub actions: Vec<Action>,
    /// Outils demandés par le modèle et jamais présentés au superviseur.
    pub non_presentes: Vec<OutilDemande>,
    /// Trafic d'Aplomb Gate entre la fin de cet échange et le début du suivant.
    pub reseau: Vec<Reseau>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Chaine {
    pub session: String,
    pub mode: String,
    pub niveau: Option<u64>,
    /// `session` (identifiant donné par l'agent au proxy) ou `horaire`.
    pub rattachement: String,
    pub tours: Vec<Tour>,
    /// Actions sans demande du modèle correspondante.
    pub hors_demande: Vec<Action>,
    pub ecarts: Vec<String>,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn n(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

/// Échanges avec le modèle, reconstitués depuis la session `modele` du journal.
pub fn echanges(modele: &[Entree]) -> Vec<Echange> {
    let mut liste: Vec<Echange> = Vec::new();
    for e in modele.iter().filter(|e| e.type_ == "observation") {
        let c = &e.contenu;
        let Some(numero) = n(c, "echange") else { continue };
        let i = match liste.iter().position(|x| x.numero == numero) {
            Some(i) => i,
            None => {
                liste.push(Echange {
                    numero, debut: e.horodatage, fin: None, modele: String::new(), envoye: 0, recu: 0,
                    statut: None, jetons_entree: None, jetons_sortie: None, outils: Vec::new(),
                    session_agent: None, refus: None,
                });
                liste.len() - 1
            }
        };
        let x = &mut liste[i];
        if let Some(m) = c.get("modele").and_then(Value::as_str) {
            x.modele = m.to_string();
        }
        x.envoye = n(c, "envoye").unwrap_or(x.envoye);
        x.session_agent = c.get("session_agent").and_then(Value::as_str).map(String::from).or(x.session_agent.take());
        if let Some(r) = c.get("refus").and_then(Value::as_str) {
            x.refus = Some(r.to_string());
            x.fin = Some(e.horodatage);
        }
        if let Some(st) = n(c, "statut") {
            x.statut = Some(st);
            x.fin = Some(e.horodatage);
            x.recu = n(c, "recu").unwrap_or(0);
            x.jetons_entree = n(c, "jetons_entree");
            x.jetons_sortie = n(c, "jetons_sortie");
            x.outils = serde_json::from_value(c.get("outils").cloned().unwrap_or_default()).unwrap_or_default();
        }
    }
    liste.sort_by_key(|x| x.debut);
    liste
}

fn actions(session: &[Entree]) -> Vec<Action> {
    let executes: Vec<String> = session
        .iter()
        .filter(|e| e.type_ == "observation")
        .filter_map(|e| e.contenu.get("appel").and_then(Value::as_str).map(String::from))
        .collect();
    session
        .iter()
        .filter(|e| e.type_ == "decision")
        .map(|e| {
            let c = &e.contenu;
            let appel = c.get("appel").and_then(Value::as_str).map(String::from);
            Action {
                execute: appel.as_ref().is_some_and(|a| executes.contains(a)),
                appel,
                horodatage: e.horodatage,
                outil: s(c, "outil"),
                verbe: s(c, "verbe"),
                ref_ressource: c.get("ref").and_then(Value::as_str).map(String::from),
                verdict: s(c, "verdict"),
                regle: s(c, "regle"),
                provenance: c.get("provenance").and_then(Value::as_array).into_iter().flatten()
                    .filter_map(|v| v.as_str().map(String::from)).collect(),
                sous_agent: c.pointer("/delegation/type_agent").and_then(Value::as_str).map(String::from),
            }
        })
        .collect()
}

/// Assemble la vue chaînée d'une session d'agent.
pub fn chainer(session: &[Entree], modele: &[Entree], passerelle: &[Entree]) -> Chaine {
    let id = session.first().map(|e| e.session.clone()).unwrap_or_default();
    let tete = session.iter().find(|e| e.type_ == "session").map(|e| e.contenu.clone()).unwrap_or_default();
    let toutes = echanges(modele);
    let par_session: Vec<Echange> = toutes.iter().filter(|x| x.session_agent.as_deref() == Some(&id)).cloned().collect();
    let (rattachement, mut retenus) = if !par_session.is_empty() {
        ("session", par_session)
    } else {
        let debut = session.first().map_or(0, |e| e.horodatage).saturating_sub(MARGE_MS);
        let fin = session.last().map_or(0, |e| e.horodatage) + MARGE_MS;
        ("horaire", toutes.into_iter().filter(|x| x.debut >= debut && x.debut <= fin).collect())
    };
    retenus.sort_by_key(|x| x.debut);

    let mut restantes = actions(session);
    let mut tours = Vec::new();
    for (i, echange) in retenus.iter().enumerate() {
        let ids: Vec<&str> = echange.outils.iter().map(|o| o.id.as_str()).collect();
        let (liees, autres): (Vec<Action>, Vec<Action>) =
            restantes.into_iter().partition(|a| a.appel.as_deref().is_some_and(|x| ids.contains(&x)));
        restantes = autres;
        let non_presentes = echange
            .outils
            .iter()
            .filter(|o| !liees.iter().any(|a| a.appel.as_deref() == Some(o.id.as_str())))
            .cloned()
            .collect();
        let de = echange.fin.unwrap_or(echange.debut);
        let jusqu_a = retenus.get(i + 1).map_or(u64::MAX, |x| x.debut);
        let reseau = passerelle
            .iter()
            .filter(|e| e.type_ == "decision" && e.horodatage >= de && e.horodatage < jusqu_a)
            .map(|e| Reseau {
                horodatage: e.horodatage,
                verdict: s(&e.contenu, "verdict"),
                regle: s(&e.contenu, "regle"),
                ref_ressource: e.contenu.get("ref").and_then(Value::as_str).map(String::from),
            })
            .collect();
        tours.push(Tour { echange: echange.clone(), actions: liees, non_presentes, reseau });
    }

    let mut ecarts = Vec::new();
    for a in &restantes {
        ecarts.push(format!(
            "action {} ({}) {}",
            a.outil,
            a.verdict,
            a.appel.as_deref().map(|x| format!("présentée au superviseur sans demande du modèle correspondante ({x})"))
                .unwrap_or_else(|| "non rattachable : aucun identifiant d'appel (hook ancien ou agent hors conteneur)".into())
        ));
    }
    for t in &tours {
        for o in &t.non_presentes {
            ecarts.push(format!(
                "outil {} demandé par le modèle (échange {}) jamais présenté au superviseur : refusé dans l'agent, ou hors hook",
                o.nom, t.echange.numero
            ));
        }
    }
    Chaine {
        session: id,
        mode: s(&tete, "mode"),
        niveau: n(&tete, "niveau_assurance"),
        rattachement: rattachement.into(),
        tours,
        hors_demande: restantes,
        ecarts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn e(session: &str, t: u64, type_: &str, contenu: Value) -> Entree {
        Entree { seq: 0, horodatage: t, session: session.into(), type_: type_.into(), contenu, precedent: String::new(), empreinte: String::new() }
    }

    fn modele() -> Vec<Entree> {
        vec![
            e("modele", 1_000, "observation", json!({"echange": 1, "modele": "m", "envoye": 50})),
            e("modele", 2_000, "observation", json!({"echange": 1, "statut": 200, "recu": 9,
                "outils": [{"nom": "Bash", "id": "toolu_a"}, {"nom": "Write", "id": "toolu_b"}]})),
            e("modele", 5_000, "observation", json!({"echange": 2, "modele": "m", "envoye": 60})),
            e("modele", 6_000, "observation", json!({"echange": 2, "statut": 200, "recu": 4, "outils": []})),
        ]
    }

    #[test]
    fn demandes_actions_et_reseau_relies() {
        let session = vec![
            e("s1", 2_100, "session", json!({"mode": "conteneur-isole", "niveau_assurance": 3})),
            e("s1", 2_100, "decision", json!({"appel": "toolu_a", "outil": "Bash", "verbe": "executer", "verdict": "allow", "regle": "r", "ref": "x"})),
            e("s1", 2_300, "observation", json!({"appel": "toolu_a", "outil": "Bash"})),
        ];
        let passerelle = vec![
            e("passerelle", 2_200, "decision", json!({"verdict": "allow", "regle": "reseau-autorise"})),
            e("passerelle", 7_000, "decision", json!({"verdict": "deny", "regle": "reseau-non-autorise"})),
        ];
        let c = chainer(&session, &modele(), &passerelle);
        assert_eq!(c.rattachement, "horaire");
        assert_eq!(c.tours.len(), 2);
        let t = &c.tours[0];
        assert_eq!(t.actions.len(), 1);
        assert!(t.actions[0].execute);
        assert_eq!(t.non_presentes, vec![OutilDemande { nom: "Write".into(), id: "toolu_b".into() }]);
        assert_eq!(t.reseau.len(), 1, "le trafic se range dans l'intervalle de son échange");
        assert_eq!(c.tours[1].reseau.len(), 1);
        assert!(c.hors_demande.is_empty());
        assert_eq!(c.ecarts.len(), 1, "{:?}", c.ecarts);
        assert!(c.ecarts[0].contains("Write"));
    }

    #[test]
    fn action_sans_demande_signalee() {
        let session = vec![
            e("s1", 2_100, "session", json!({"mode": "conteneur-isole"})),
            e("s1", 2_100, "decision", json!({"appel": "toolu_inconnu", "outil": "Bash", "verdict": "allow"})),
            e("s1", 2_200, "decision", json!({"outil": "Read", "verdict": "allow"})),
        ];
        let c = chainer(&session, &modele(), &[]);
        assert_eq!(c.hors_demande.len(), 2);
        assert!(c.ecarts.iter().any(|x| x.contains("toolu_inconnu")));
        assert!(c.ecarts.iter().any(|x| x.contains("aucun identifiant")));
    }

    #[test]
    fn rattachement_par_session_quand_l_agent_la_donne() {
        let mut m = modele();
        m.push(e("modele", 1_000_000, "observation", json!({"echange": 3, "modele": "m", "session_agent": "s1"})));
        let session = vec![e("s1", 2_100, "session", json!({}))];
        let c = chainer(&session, &m, &[]);
        assert_eq!(c.rattachement, "session");
        assert_eq!(c.tours.len(), 1);
        assert_eq!(c.tours[0].echange.numero, 3);
    }
}
