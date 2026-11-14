//! **Modules** (EF-M) : ce qu'on ajoute aux étapes de la chaîne sans toucher au socle.
//!
//! Ce module tient :
//! - le **contrat des moniteurs externes** (étape « moniteurs », EF-E1) : un service local,
//!   écrit dans n'importe quel langage, reçoit l'action et rend un avis. Il est déclaré au
//!   mandat (`moniteurs.externes`), donc couvert par la cosignature ;
//! - l'**agrégation** des avis probabilistes (EF-K2), qui ne produit qu'un plancher ;
//! - le **catalogue** des modules connus d'Aplomb, avec leur étape, leur façon et leurs
//!   capacités : ce que `aplomb modules` et Aplomb Watch affichent.
//!
//! Invariant (EF-M2) : un module du chemin de décision ne fait que durcir. Son avis passe
//! par l'algèbre de décision ; sa panne ou son silence vaut son plancher.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::action::{Action, EvenementOutil};
use crate::decision::{Avis, Niveau};

/// Version du contrat des moniteurs externes, envoyée dans chaque requête.
pub const VERSION_CONTRAT: u32 = 1;

// ---------------------------------------------------------------------------------------
// Moniteurs externes
// ---------------------------------------------------------------------------------------

/// Quand consulter un moniteur externe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Declenchement {
    /// Actions que le profil juge sensibles (comme le juge) ; les autres par échantillon.
    #[default]
    Sensible,
    /// Toutes les actions encore permises.
    Toujours,
}

/// Moniteur externe déclaré au mandat (`moniteurs.externes`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigMoniteurExterne {
    /// Nom court, unique au mandat (journal, Watch, motifs).
    pub id: String,
    /// Adresse du service : `POST <url>` reçoit la requête du contrat v1.
    pub url: String,
    #[serde(default)]
    pub quand: Declenchement,
    /// Part des actions non sensibles soumises au moniteur (0 à 1), avec `quand: sensible`.
    #[serde(default)]
    pub echantillon: f64,
    #[serde(default = "defaut_delai")]
    pub delai_ms: u64,
    /// Avis rendu si le service ne répond pas, se trompe ou dépasse le délai (EF-K3).
    #[serde(default = "defaut_panne")]
    pub panne: Niveau,
    /// Avis le plus sévère qu'il peut rendre (défaut : suspect, soit une revue).
    #[serde(default = "defaut_niveau_max")]
    pub niveau_max: Niveau,
    /// Le moniteur reçoit-il les paramètres de l'action en clair (contenus, EF-M4) ? Sans
    /// cela, il ne reçoit que le verbe, la ressource et les attributs normalisés.
    #[serde(default)]
    pub contenus: bool,
    /// Consultations par session ; au-delà, il n'est plus consulté.
    #[serde(default = "defaut_appels")]
    pub appels_max: u32,
}

fn defaut_delai() -> u64 {
    800
}
fn defaut_panne() -> Niveau {
    Niveau::Suspect
}
fn defaut_niveau_max() -> Niveau {
    Niveau::Suspect
}
fn defaut_appels() -> u32 {
    1000
}

/// Délai le plus long accepté : le hook attend la décision 8 s.
pub const DELAI_MAX_MS: u64 = 3000;

impl ConfigMoniteurExterne {
    /// Vérifie la déclaration ; le message dit quoi corriger.
    pub fn verifier(&self) -> Result<(), String> {
        let ou = format!("moniteurs.externes « {} »", self.id);
        if self.id.is_empty() || !self.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("{ou} : id fait de lettres, chiffres, - ou _ attendu"));
        }
        let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"].iter().any(|p| self.url.starts_with(p));
        if !local && !self.url.starts_with("https://") {
            return Err(format!("{ou} : url en https://, ou en http:// seulement vers la machine (127.0.0.1)"));
        }
        if self.delai_ms == 0 || self.delai_ms > DELAI_MAX_MS {
            return Err(format!("{ou} : delai_ms entre 1 et {DELAI_MAX_MS}"));
        }
        if !(0.0..=1.0).contains(&self.echantillon) {
            return Err(format!("{ou} : echantillon entre 0 et 1"));
        }
        if self.panne == Niveau::Conforme {
            return Err(format!("{ou} : panne « conforme » refusée — un moniteur muet ne peut pas valoir un accord (EF-K3)"));
        }
        Ok(())
    }

    /// Le moniteur sort-il de la machine ? (affiché ; un tel moniteur est déclaré au mandat.)
    pub fn distant(&self) -> bool {
        self.url.starts_with("https://")
    }

    /// Libellé du moniteur dans les avis et le journal.
    pub fn nom(&self) -> String {
        format!("externe:{}", self.id)
    }
}

/// Requête du contrat v1. Le moniteur rend `{"niveau": "conforme|suspect|critique",
/// "score": 0..1, "motif": "…"}`.
pub fn requete(cfg: &ConfigMoniteurExterne, intention: &str, evt: &EvenementOutil, action: &Action, historique: &[Value]) -> Value {
    let mut r = json!({
        "contrat": VERSION_CONTRAT,
        "moniteur": cfg.id,
        "intention": intention.trim(),
        "agent": evt.agent,
        "outil": evt.outil,
        "action": {"verbe": action.verbe, "ressource": action.ressource, "contexte": action.contexte},
        "historique": historique,
    });
    if cfg.contenus {
        r["entree"] = evt.entree.clone();
    }
    r
}

/// Lit la réponse d'un moniteur externe ; son avis est plafonné à `niveau_max`.
pub fn lire_avis(cfg: &ConfigMoniteurExterne, reponse: &Value) -> Result<Avis, String> {
    let niveau: Niveau = serde_json::from_value(reponse.get("niveau").cloned().ok_or("champ « niveau » absent")?)
        .map_err(|_| "niveau attendu : conforme, suspect ou critique".to_string())?;
    let score = reponse.get("score").and_then(Value::as_f64).unwrap_or(match niveau {
        Niveau::Conforme => 0.0,
        Niveau::Suspect => 0.5,
        Niveau::Critique => 1.0,
    }) as f32;
    let motif: String = reponse.get("motif").and_then(Value::as_str).unwrap_or_default().chars().take(300).collect();
    Ok(Avis { moniteur: cfg.nom(), niveau: niveau.min(cfg.niveau_max), score: score.clamp(0.0, 1.0), motif })
}

/// Avis d'un moniteur externe en panne : son plancher déclaré.
pub fn avis_panne(cfg: &ConfigMoniteurExterne, cause: &str) -> Avis {
    Avis { moniteur: cfg.nom(), niveau: cfg.panne, score: 1.0, motif: format!("moniteur indisponible ({cause}) : plancher appliqué") }
}

// ---------------------------------------------------------------------------------------
// Agrégation des avis probabilistes (EF-K2)
// ---------------------------------------------------------------------------------------

/// Règles d'agrégation entre moniteurs probabilistes. Elles ne font que durcir : chaque avis
/// garde son propre plancher, et l'agrégation peut en ajouter un plus sévère.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Agregation {
    /// Nombre de moniteurs distincts qui doivent être au moins « suspect » pour que leur
    /// accord vaille « critique » (gel). Absent : pas d'escalade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalade: Option<u32>,
}

/// Avis d'agrégation : l'accord de plusieurs moniteurs vaut plus que chacun.
pub fn avis_agregation(regles: Option<&Agregation>, avis: &[Avis]) -> Option<Avis> {
    let seuil = regles?.escalade.filter(|n| *n >= 2)?;
    let mut d: Vec<&str> = avis.iter().filter(|a| a.niveau >= Niveau::Suspect).map(|a| a.moniteur.as_str()).collect();
    d.sort_unstable();
    d.dedup();
    (d.len() as u32 >= seuil).then(|| Avis {
        moniteur: "agregation".into(),
        niveau: Niveau::Critique,
        score: 1.0,
        motif: format!("{} moniteurs concordants ({}) : escalade", d.len(), d.join(", ")),
    })
}

// ---------------------------------------------------------------------------------------
// Catalogue des modules (EF-M8)
// ---------------------------------------------------------------------------------------

/// Étapes de la chaîne. Les six premières forment le chemin de décision : leurs modules ne
/// font que durcir (EF-M2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Etape {
    Branchement,
    Normalisation,
    Filtrage,
    Moniteurs,
    Decision,
    Approbation,
    Journal,
    Diffusion,
    Reporting,
    Visualisation,
    Identite,
}

impl Etape {
    pub const TOUTES: [Etape; 11] = [
        Etape::Branchement,
        Etape::Normalisation,
        Etape::Filtrage,
        Etape::Moniteurs,
        Etape::Decision,
        Etape::Approbation,
        Etape::Journal,
        Etape::Diffusion,
        Etape::Reporting,
        Etape::Visualisation,
        Etape::Identite,
    ];

    pub fn libelle(self) -> &'static str {
        match self {
            Etape::Branchement => "branchement",
            Etape::Normalisation => "normalisation (profil)",
            Etape::Filtrage => "filtrage de contenu",
            Etape::Moniteurs => "moniteurs",
            Etape::Decision => "décision",
            Etape::Approbation => "approbation humaine",
            Etape::Journal => "journal",
            Etape::Diffusion => "diffusion",
            Etape::Reporting => "reporting",
            Etape::Visualisation => "visualisation",
            Etape::Identite => "identité et accès",
        }
    }

    /// Étape du chemin de décision ?
    pub fn decision(self) -> bool {
        self <= Etape::Approbation
    }
}

/// Façon dont un module est écrit et exécuté.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Facon {
    /// Fichier interprété par Aplomb (Cedar, YAML, motifs) : aucun code tiers.
    Declaratif,
    /// Livré dans le binaire, activé par configuration.
    Integre,
    /// Service séparé (HTTP), contrat versionné.
    Externe,
}

/// Ce qu'un module reçoit et fait, affiché avant de l'activer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Capacites {
    /// Reçoit des contenus en clair (paramètres d'actions, prompts).
    pub contenus_en_clair: bool,
    /// Envoie des données hors de la machine.
    pub hors_machine: bool,
}

/// Module tel que le montrent `aplomb modules` et Aplomb Watch.
#[derive(Debug, Clone, Serialize)]
pub struct Module {
    pub id: String,
    pub etape: Etape,
    pub facon: Facon,
    pub description: String,
    pub actif: bool,
    pub capacites: Capacites,
    /// Version (modules intégrés) ou contrat (externes).
    pub version: String,
    /// Empreinte de la déclaration ou du fichier (vide pour un module intégré).
    pub empreinte: String,
    /// Comment l'activer, le régler ou le retirer.
    pub reglage: String,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn module(id: &str, etape: Etape, facon: Facon, description: &str, actif: bool, reglage: &str) -> Module {
    Module {
        id: id.into(),
        etape,
        facon,
        description: description.into(),
        actif,
        capacites: Capacites::default(),
        version: if facon == Facon::Integre { VERSION.into() } else { String::new() },
        empreinte: String::new(),
        reglage: reglage.into(),
    }
}

fn empreinte_json<T: Serialize>(v: &T) -> String {
    crate::preuves::sha256_hex(serde_json::to_string(v).unwrap_or_default().as_bytes())
}

/// Modules du chemin de décision et du journal, d'après le mandat : ceux qui sont actifs et
/// ceux qu'on peut ajouter. Les modules propres à l'instance (reporting, diffusion,
/// identité) sont ajoutés par le binaire.
pub fn modules_du_mandat(mandat: &crate::mandat::Mandat) -> Vec<Module> {
    use Etape::*;
    use Facon::*;
    let m = mandat.moniteurs.as_ref();
    let cosigner = "au mandat, puis aplomb cosigner";
    let mut v = vec![
        module("hook-claude-code", Branchement, Integre, "hook PreToolUse de Claude Code (niveau 1)", true, "paramètres gérés de Claude Code (README, « Brancher Claude Code »)"),
        module("proxy-llm", Branchement, Integre, "proxy LLM, API Messages (niveau 2)", !mandat.perimetre.domaines_modele.is_empty(), &format!("perimetre.domaines_modele {cosigner}")),
        module("aplomb-gate", Branchement, Integre, "passerelle sortante HTTP(S) (niveau 2)", true, "HTTPS_PROXY de l'agent"),
        module("passerelle-mcp", Branchement, Integre, "passerelle MCP (niveau 2)", !mandat.perimetre.serveurs_mcp.is_empty(), &format!("perimetre.serveurs_mcp {cosigner}")),
    ];
    for p in crate::profils::PROFILS {
        v.push(module(&format!("profil-{}", p.nom()), Normalisation, Integre, p.description(), p.nom() == mandat.profil, "profil: <nom> au mandat (aplomb profils)"));
    }
    v.push(module("secrets", Filtrage, Integre, "clés et jetons : gel s'ils sortent, masqués au proxy LLM", true, "toujours actif"));
    let filtres = m.map(|m| m.filtres.clone()).unwrap_or_default();
    for (nom, description) in crate::filtres::PACKS {
        let actif = filtres.iter().any(|f| matches!(f, crate::filtres::Filtre::Pack { pack, .. } if pack == nom));
        v.push(module(&format!("filtre-{nom}"), Filtrage, Integre, description, actif, &format!("moniteurs.filtres: [{{pack: {nom}}}] {cosigner}")));
    }
    for f in &filtres {
        if let crate::filtres::Filtre::Fichier { fichier, sha256 } = f {
            let mut x = module(&format!("filtre-fichier:{fichier}"), Filtrage, Declaratif, "pack de motifs de l'organisation", true, &format!("moniteurs.filtres: [{{fichier: …}}] {cosigner}"));
            x.empreinte = sha256.clone();
            v.push(x);
        }
    }
    let juge = m.and_then(|m| m.juge.as_ref());
    let mut j = module("juge", Moniteurs, Externe, "juge LLM (API OpenAI ou Anthropic) : écart à l'intention", juge.is_some(), &format!("moniteurs.juge {cosigner}"));
    if let Some(c) = juge {
        j.description = format!("juge {} ({})", c.modele, c.url);
        j.capacites = Capacites { contenus_en_clair: true, hors_machine: c.url.starts_with("https://") };
        j.empreinte = empreinte_json(c);
    }
    v.push(j);
    let sonde = m.and_then(|m| m.sonde.as_ref());
    let mut s = module("sonde", Moniteurs, Externe, "sonde sur les activations du modèle (déploiement avancé)", sonde.is_some(), &format!("moniteurs.sonde {cosigner} (docs/SONDE.md)"));
    if let Some(c) = sonde {
        s.capacites.contenus_en_clair = true;
        s.empreinte = c.poids_sha256.clone();
    }
    v.push(s);
    v.push(module("raisonnement", Moniteurs, Integre, "lecture du raisonnement explicite du modèle", m.is_none_or(|m| m.raisonnement), "moniteurs.raisonnement: false pour le couper"));
    v.push(module("enchainements", Moniteurs, Integre, "suites d'actions suspectes (télécharger puis exécuter…)", true, "toujours actif"));
    v.push(module("provenance", Moniteurs, Integre, "contenus non fiables : revue des actions qu'ils influencent", true, "toujours actif"));
    for c in m.map(|m| m.externes.as_slice()).unwrap_or_default() {
        let mut x = module(&format!("externe:{}", c.id), Moniteurs, Externe, &format!("moniteur externe {} (contrat v{VERSION_CONTRAT})", c.url), true, &format!("moniteurs.externes {cosigner}"));
        x.capacites = Capacites { contenus_en_clair: c.contenus, hors_machine: c.distant() };
        x.version = format!("contrat v{VERSION_CONTRAT}");
        x.empreinte = empreinte_json(c);
        v.push(x);
    }
    if m.is_none_or(|m| m.externes.is_empty()) {
        v.push(module("externe", Moniteurs, Externe, "votre moniteur (tout langage), contrat HTTP v1 — docs/MODULES.md", false, &format!("moniteurs.externes: [{{id: …, url: http://127.0.0.1:…}}] {cosigner}")));
    }
    let mut r = module("regles-cedar", Decision, Declaratif, &format!("règles {} et revue {}", mandat.politique.regles, mandat.politique.revue), true, "politique.regles / politique.revue, puis aplomb cosigner");
    r.empreinte = mandat.politique.regles_sha256.clone();
    v.push(r);
    v.push(module("bornes", Decision, Integre, "bornes cumulées par session : refus, revues, domaines, envois, actions", true, &format!("bornes: {cosigner}")));
    let escalade = m.and_then(|m| m.agregation.as_ref()).and_then(|a| a.escalade);
    v.push(module("agregation", Decision, Integre, &escalade.map_or("escalade quand plusieurs moniteurs concordent".into(), |n| format!("{n} moniteurs suspects concordants : gel")), escalade.is_some(), &format!("moniteurs.agregation: {{escalade: 2}} {cosigner}")));
    v.push(module("aplomb-watch", Approbation, Integre, "file de revue dans Aplomb Watch", true, "toujours actif"));
    v.push(module("journal-chaine", Journal, Integre, "journal chaîné par session, minimisé, chiffré", true, "toujours actif"));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Phase;
    use serde_json::Map;

    fn cfg() -> ConfigMoniteurExterne {
        serde_yaml::from_str("{id: dlp, url: 'http://127.0.0.1:9100/v1/avis'}").unwrap()
    }

    fn evt() -> EvenementOutil {
        EvenementOutil {
            session: "s".into(),
            agent: "a".into(),
            mode: "hook".into(),
            cwd: "/d".into(),
            outil: "Bash".into(),
            entree: json!({"command": "echo secret"}),
            phase: Phase::Avant,
            chemin_reel: None,
            contenu_execute: None,
            nonce: None,
            appel: None,
            delegation: None,
        }
    }

    #[test]
    fn declaration() {
        let c = cfg();
        assert!(c.verifier().is_ok());
        assert_eq!((c.delai_ms, c.panne, c.niveau_max, c.contenus), (800, Niveau::Suspect, Niveau::Suspect, false));
        let mut d = c.clone();
        d.url = "http://exemple.org/avis".into();
        assert!(d.verifier().unwrap_err().contains("https"));
        let mut d = c.clone();
        d.panne = Niveau::Conforme;
        assert!(d.verifier().unwrap_err().contains("muet"));
        let mut d = c;
        d.id = "a b".into();
        assert!(d.verifier().is_err());
    }

    #[test]
    fn contenus_seulement_si_declares() {
        let a = Action { session: "s".into(), agent: "a".into(), verbe: "executer".into(), ressource: "r".into(), contexte: Map::new() };
        let mut c = cfg();
        assert!(requete(&c, "i", &evt(), &a, &[]).get("entree").is_none());
        c.contenus = true;
        assert_eq!(requete(&c, "i", &evt(), &a, &[])["entree"]["command"], "echo secret");
        assert_eq!(requete(&c, "i", &evt(), &a, &[])["contrat"], VERSION_CONTRAT);
    }

    #[test]
    fn avis_plafonne_et_panne() {
        let c = cfg();
        let a = lire_avis(&c, &json!({"niveau": "critique", "motif": "x"})).unwrap();
        assert_eq!((a.niveau, a.moniteur.as_str()), (Niveau::Suspect, "externe:dlp"));
        assert!(lire_avis(&c, &json!({"niveau": "vert"})).is_err());
        assert!(lire_avis(&c, &json!({})).is_err());
        assert_eq!(avis_panne(&c, "délai").niveau, Niveau::Suspect);
    }

    #[test]
    fn catalogue() {
        let m: crate::mandat::Mandat = serde_yaml::from_str(include_str!("../../../exemples/mandat.yaml")).unwrap();
        let v = modules_du_mandat(&m);
        let ids: Vec<&str> = v.iter().map(|x| x.id.as_str()).collect();
        for id in ["hook-claude-code", "profil-code", "secrets", "filtre-bancaire", "juge", "externe", "regles-cedar", "journal-chaine"] {
            assert!(ids.contains(&id), "{id} absent du catalogue");
        }
        assert!(v.iter().any(|x| x.id == "profil-code" && x.actif) && v.iter().any(|x| x.id == "profil-pentest" && !x.actif));
        assert!(v.iter().all(|x| !x.reglage.is_empty()), "chaque module dit comment le régler");
        assert!(Etape::Approbation.decision() && !Etape::Journal.decision());
    }

    #[test]
    fn escalade() {
        let s = |m: &str| Avis { moniteur: m.into(), niveau: Niveau::Suspect, score: 0.6, motif: String::new() };
        let r = Agregation { escalade: Some(2) };
        assert!(avis_agregation(Some(&r), &[s("juge")]).is_none());
        assert!(avis_agregation(Some(&r), &[s("juge"), s("juge")]).is_none(), "un même moniteur ne compte qu'une fois");
        assert_eq!(avis_agregation(Some(&r), &[s("juge"), s("externe:dlp")]).unwrap().niveau, Niveau::Critique);
        assert!(avis_agregation(None, &[s("juge"), s("sonde")]).is_none());
        assert!(avis_agregation(Some(&Agregation { escalade: Some(1) }), &[s("juge")]).is_none(), "escalade à 1 : sans effet");
    }
}
