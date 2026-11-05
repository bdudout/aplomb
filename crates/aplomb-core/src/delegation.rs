//! **Délégation entre agents** (EF-B6) : un mandat enfant, celui d'un type de sous-agent,
//! est toujours **inclus** dans son mandat parent.
//!
//! Vérifié au chargement, champ par champ : même profil, racine sous celle du parent,
//! domaines, modèles et serveurs MCP couverts par le parent, branches protégées et bornes
//! au moins aussi strictes. Les règles Cedar ne se comparent pas en général : l'enfant peut
//! avoir les siennes, et ses actions sont jugées par les deux mandats (le plus sévère
//! l'emporte), ce qui garantit l'inclusion à l'exécution.
use std::path::Path;

use crate::mandat::{Mandat, MandatCharge};
use crate::profils::code::domaine_autorise;

/// Type de sous-agent d'un mandat enfant : son `agent` est `<agent du parent>/<type>`.
pub fn type_agent(parent: &Mandat, enfant: &Mandat) -> Option<String> {
    let t = enfant.agent.strip_prefix(&parent.agent)?.strip_prefix('/')?;
    (!t.is_empty()).then(|| t.to_string())
}

/// Écarts d'inclusion de l'enfant dans le parent ; vide : inclus.
pub fn verifier_inclusion(parent: &MandatCharge, enfant: &MandatCharge) -> Result<(), Vec<String>> {
    let (p, e) = (&parent.mandat, &enfant.mandat);
    let mut ecarts = Vec::new();
    let mut exiger = |ok: bool, motif: String| {
        if !ok {
            ecarts.push(motif);
        }
    };
    exiger(e.parent.as_deref() == Some(p.id.as_str()), format!("parent déclaré {:?}, attendu « {} »", e.parent, p.id));
    exiger(type_agent(p, e).is_some(), format!("agent « {} » : « {}/<type de sous-agent> » attendu", e.agent, p.agent));
    exiger(e.profil == p.profil, format!("profil « {} » au lieu de « {} »", e.profil, p.profil));
    exiger(
        Path::new(&e.perimetre.racine).starts_with(&p.perimetre.racine) && !e.perimetre.racine.contains(".."),
        format!("racine {} hors de {}", e.perimetre.racine, p.perimetre.racine),
    );
    for d in &e.perimetre.domaines_autorises {
        exiger(domaine_autorise(d, &p.perimetre.domaines_autorises), format!("domaine {d} non autorisé au parent"));
    }
    for d in &e.perimetre.domaines_modele {
        exiger(p.perimetre.domaines_modele.contains(d), format!("modèle {d} absent du parent"));
    }
    for b in &p.perimetre.branches_protegees {
        exiger(e.perimetre.branches_protegees.contains(b), format!("branche {b} protégée au parent, pas à l'enfant"));
    }
    for s in &e.perimetre.serveurs_mcp {
        match p.perimetre.serveurs_mcp.iter().find(|m| m.nom == s.nom) {
            None => exiger(false, format!("serveur MCP {} absent du parent", s.nom)),
            Some(m) => {
                exiger(m.commande == s.commande, format!("serveur MCP {} : commande différente du parent", s.nom));
                for o in &s.outils {
                    exiger(m.outils.iter().any(|x| x == "*" || x == o), format!("outil MCP {}/{o} non permis au parent", s.nom));
                }
                exiger(m.fiable || !s.fiable, format!("serveur MCP {} fiable pour l'enfant, pas pour le parent", s.nom));
            }
        }
    }
    let (bp, be) = (p.bornes.clone().unwrap_or_default(), e.bornes.clone().unwrap_or_default());
    for (nom, vp, ve) in [
        ("refus", bp.refus, be.refus),
        ("revues", bp.revues, be.revues),
        ("domaines", bp.domaines, be.domaines),
        ("envois", bp.envois, be.envois),
        ("actions", bp.actions, be.actions),
    ] {
        exiger(ve <= vp, format!("borne {nom} : {ve} au-delà du parent ({vp})"));
    }
    if ecarts.is_empty() { Ok(()) } else { Err(ecarts) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mandat::{FichiersPolitique, Perimetre, ServeurMcp};

    fn charge(m: Mandat) -> MandatCharge {
        MandatCharge { mandat: m, regles: String::new(), revue: String::new(), empreinte: String::new() }
    }

    fn parent() -> Mandat {
        Mandat {
            id: "p".into(),
            version: 1,
            profil: "code".into(),
            agent: "claude-code".into(),
            intention: "x".into(),
            parent: None,
            perimetre: Perimetre {
                racine: "/depot".into(),
                domaines_autorises: vec!["python.org".into()],
                branches_protegees: vec!["main".into()],
                domaines_modele: vec!["api.anthropic.com".into()],
                serveurs_mcp: vec![ServeurMcp { nom: "fs".into(), commande: vec!["fs".into()], outils: vec!["lire".into()], fiable: false }],
            },
            politique: FichiersPolitique { regles: "r".into(), revue: "v".into(), regles_sha256: String::new(), revue_sha256: String::new() },
            bornes: None,
            moniteurs: None,
            signature: None,
            signatures: vec![],
        }
    }

    fn enfant() -> Mandat {
        let mut e = parent();
        e.id = "e".into();
        e.parent = Some("p".into());
        e.agent = "claude-code/Explore".into();
        e.perimetre.racine = "/depot/docs".into();
        e.perimetre.domaines_autorises = vec!["docs.python.org".into()];
        e
    }

    #[test]
    fn enfant_inclus() {
        assert_eq!(verifier_inclusion(&charge(parent()), &charge(enfant())), Ok(()));
        assert_eq!(type_agent(&parent(), &enfant()).as_deref(), Some("Explore"));
    }

    #[test]
    fn enfant_qui_deborde_refuse() {
        let mut e = enfant();
        e.perimetre.racine = "/ailleurs".into();
        e.perimetre.domaines_autorises.push("evil.example".into());
        e.perimetre.branches_protegees.clear();
        e.perimetre.serveurs_mcp[0].outils.push("ecrire".into());
        e.perimetre.serveurs_mcp[0].fiable = true;
        e.bornes = Some(crate::bornes::Bornes { refus: 50, ..Default::default() });
        e.parent = Some("autre".into());
        let ecarts = verifier_inclusion(&charge(parent()), &charge(e)).unwrap_err();
        for motif in ["racine", "evil.example", "branche main", "fs/ecrire", "fiable", "borne refus", "parent déclaré"] {
            assert!(ecarts.iter().any(|x| x.contains(motif)), "{motif} absent de {ecarts:?}");
        }
    }
}
