//! **Profil M — agent métier régulé** (back-office, banque, assurance, santé).
//!
//! L'agent agit par des outils métier (CRM, messagerie, paiement, GED…), branchés en
//! général par la passerelle MCP d'Aplomb. Le mandat (section `perimetre.metier`) déclare
//! le processus, les outils et leur verbe, les catégories de données accessibles, les
//! destinataires et juridictions autorisés, et des plafonds. Les verbes du profil :
//!
//! | Verbe | Palier par défaut | Réversible | Exemple |
//! |---|---|---|---|
//! | `lire_dossier` | Vert | oui | dossier client du CRM |
//! | `lire_message` | Vert (contenu non fiable) | oui | réclamation, courriel entrant |
//! | `rechercher` | Vert | oui | recherche de dossiers |
//! | `consulter_reference` | Vert | oui | base documentaire, barème |
//! | `ecrire_dossier` | Vert ; Orange pour des coordonnées bancaires | oui | note, statut |
//! | `envoyer` | Vert en interne ; Orange vers l'extérieur | **non** | courriel au client |
//! | `payer` | Orange | **non** | remboursement |
//! | `supprimer` | Orange ; Rouge en masse | **non** | pièce, dossier |
//! | `exporter` | Orange ; Rouge au-delà du plafond | **non** | extraction de lignes |
//! | `approuver` | Rouge, gel | — | l'agent tente de valider lui-même |
//! | `interne` | Vert | oui | outils sans effet |
//! | `autre` | Rouge (refus par défaut, EF-A4) | — | outil non déclaré |
//!
//! **Ressource réelle** (EF-B4) : le destinataire réel est le domaine de chaque adresse
//! (`Nom <a@b>` compris, copies comprises) ; la juridiction d'un paiement est le pays de
//! l'IBAN du bénéficiaire (validé par sa clé), celle d'un envoi est celle que le mandat
//! déclare pour ce destinataire ; un montant est lu en centimes, quel que soit son format.
//!
//! **Invariants du profil** (§9), tenus ici en plus des règles Cedar, pour qu'aucun mandat
//! ne puisse les lever (EF-A5) : aucune action irréversible sans approbation ; aucune donnée
//! sensible vers un destinataire ou une juridiction non autorisés.
//!
//! **Moniteurs du profil** (déterministes, ne font que durcir) : fuite de données,
//! conseil hors cadre réglementaire, cumuls de session (montants payés, dossiers lus), et
//! l'enchaînement « modifier un IBAN puis payer ce même IBAN ».
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::action::{Action, EvenementOutil};
use crate::decision::{Avis, Niveau, Verdict};
use crate::mandat::Mandat;

// ---------------------------------------------------------------------------------------
// Extension du schéma de mandat
// ---------------------------------------------------------------------------------------

/// Section `perimetre.metier` du mandat : l'habilitation de l'agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerimetreMetier {
    /// Processus métier couvert (ex. `traitement-des-reclamations`).
    pub processus: String,
    /// Outils de l'agent et leur verbe. Un outil absent est refusé (EF-A4).
    pub outils: Vec<OutilMetier>,
    /// Catégories de données que l'agent peut lire ou écrire (ex. `identite`, `contrat`).
    #[serde(default)]
    pub donnees: Vec<String>,
    /// Domaines de messagerie de l'organisation : un envoi interne reste un envoi, mais à
    /// un collègue, sans approbation.
    #[serde(default)]
    pub domaines_internes: Vec<String>,
    /// Destinataires externes autorisés ; `*` : tout destinataire (les clients), à qui
    /// seules les catégories listées peuvent être envoyées.
    #[serde(default)]
    pub destinataires: Vec<Destinataire>,
    /// Juridictions autorisées : codes pays ISO (`FR`, `DE`…) ou `UE` (les 27, plus l'EEE).
    pub juridictions: Vec<String>,
    #[serde(default)]
    pub plafonds: Plafonds,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutilMetier {
    /// Nom de l'outil tel que l'agent l'appelle (ex. `mcp__crm__lire_dossier`).
    pub outil: String,
    pub verbe: String,
    /// Catégorie de données que l'outil touche (lecture ou écriture).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categorie: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Destinataire {
    /// Domaine de messagerie (correspondance exacte ou sous-domaine), ou `*`.
    pub domaine: String,
    pub juridiction: String,
    /// Catégories de données sensibles qu'il peut recevoir (`bancaire`, `sante`,
    /// `identifiant_national`). Vide : aucune.
    #[serde(default)]
    pub donnees: Vec<String>,
}

/// Plafonds du mandat. Montants en euros (ou dans la devise du processus).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Plafonds {
    /// Montant maximal d'un paiement.
    pub paiement: f64,
    /// Montant cumulé des paiements d'une session ; au-delà : gel.
    pub paiements_session: f64,
    /// Dossiers distincts lus dans une session ; au-delà : gel (collecte massive).
    pub dossiers_session: u32,
    /// Lignes d'un export.
    pub export_lignes: u64,
}

impl Default for Plafonds {
    fn default() -> Self {
        Self { paiement: 0.0, paiements_session: 0.0, dossiers_session: 30, export_lignes: 0 }
    }
}

/// Verbes du profil : palier par défaut, réversibilité (contrat de profil, §8).
pub const VERBES: &[(&str, &str, bool)] = &[
    ("lire_dossier", "vert", true),
    ("lire_message", "vert", true),
    ("rechercher", "vert", true),
    ("consulter_reference", "vert", true),
    ("ecrire_dossier", "vert", true),
    ("envoyer", "orange", false),
    ("payer", "orange", false),
    ("supprimer", "orange", false),
    ("exporter", "orange", false),
    ("approuver", "rouge", false),
    ("interne", "vert", true),
];

/// Catégories sensibles détectées dans les contenus.
pub const CATEGORIES_SENSIBLES: &[&str] = &["bancaire", "identifiant_national", "sante"];

const UE: &[&str] = &[
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV",
    "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK", "IS", "LI", "NO",
];

/// Vérifie la section métier d'un mandat (au démarrage, à l'évaluation) ; les erreurs disent
/// quoi corriger.
pub fn verifier(mandat: &Mandat) -> Result<(), String> {
    let m = mandat.perimetre.metier.as_ref().ok_or(
        "profil metier : section perimetre.metier absente (processus, outils, juridictions…) — voir exemples/mandat-metier.yaml",
    )?;
    if m.outils.is_empty() {
        return Err("perimetre.metier.outils : déclarer au moins un outil et son verbe".into());
    }
    for o in &m.outils {
        if !VERBES.iter().any(|(v, _, _)| *v == o.verbe) {
            let connus: Vec<&str> = VERBES.iter().map(|(v, _, _)| *v).collect();
            return Err(format!("perimetre.metier.outils : verbe « {} » inconnu pour {} (verbes : {})", o.verbe, o.outil, connus.join(", ")));
        }
    }
    if m.juridictions.is_empty() {
        return Err("perimetre.metier.juridictions : déclarer au moins une juridiction (ex. [FR] ou [UE])".into());
    }
    for d in &m.destinataires {
        if let Some(c) = d.donnees.iter().find(|c| !CATEGORIES_SENSIBLES.contains(&c.as_str())) {
            return Err(format!("perimetre.metier.destinataires {} : catégorie « {c} » inconnue ({})", d.domaine, CATEGORIES_SENSIBLES.join(", ")));
        }
    }
    let p = &m.plafonds;
    if p.paiement < 0.0 || p.paiements_session < 0.0 {
        return Err("perimetre.metier.plafonds : montants positifs attendus".into());
    }
    Ok(())
}

fn juridiction_autorisee(j: &str, autorisees: &[String]) -> bool {
    let j = j.to_ascii_uppercase();
    !j.is_empty()
        && autorisees.iter().any(|a| {
            let a = a.to_ascii_uppercase();
            a == j || ((a == "UE" || a == "EEE") && UE.contains(&j.as_str()))
        })
}

// ---------------------------------------------------------------------------------------
// Lecture des paramètres
// ---------------------------------------------------------------------------------------

const CLES_DOSSIER: &[&str] = &["dossier", "client", "id_dossier", "dossier_id", "reference", "id"];
const CLES_DESTINATAIRE: &[&str] = &["a", "à", "to", "destinataire", "destinataires", "cc", "cci", "bcc", "email", "vers", "destination"];
const CLES_MONTANT: &[&str] = &["montant", "amount", "somme"];
const CLES_BENEFICIAIRE: &[&str] = &["iban", "beneficiaire", "bénéficiaire", "compte"];
const CLES_LIGNES: &[&str] = &["lignes", "limite", "limit", "nombre"];
const CLES_CHAMP: &[&str] = &["champ", "champs", "field", "fields", "modifications"];

fn texte_de(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        autre => autre.to_string(),
    }
}

fn premier(e: &Value, cles: &[&str]) -> String {
    cles.iter().find_map(|c| e.get(*c).filter(|v| !v.is_null()).map(texte_de)).unwrap_or_default()
}

/// Adresses de messagerie : `Nom <a@b>`, listes séparées par virgules, tableaux.
fn adresses(e: &Value) -> Vec<String> {
    static M: OnceLock<Regex> = OnceLock::new();
    let m = M.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})").expect("motif d'adresse"));
    let mut res = Vec::new();
    for c in CLES_DESTINATAIRE {
        if let Some(v) = e.get(*c) {
            let t = texte_de(v);
            for x in m.captures_iter(&t) {
                res.push(x[1].to_ascii_lowercase());
            }
            // Destination qui n'est pas une adresse (domaine, URL) : son hôte.
            if !t.contains('@') && !t.trim().is_empty() {
                let h = t.trim().trim_start_matches("https://").trim_start_matches("http://");
                let h = h.split(['/', ':', '?']).next().unwrap_or("").to_ascii_lowercase();
                if h.contains('.') {
                    res.push(h);
                }
            }
        }
    }
    res.sort();
    res.dedup();
    res
}

/// Montant en centimes : `480`, `480.5`, `"480,50 €"`, `"1 200,00"`.
pub fn montant_centimes(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_f64().map(|x| (x * 100.0).round() as i64),
        Value::String(s) => {
            let t: String = s.chars().filter(|c| c.is_ascii_digit() || *c == ',' || *c == '.' || *c == '-').collect();
            let t = match (t.rfind(','), t.rfind('.')) {
                (Some(v), Some(p)) if v > p => t.replace('.', "").replace(',', "."),
                (Some(_), Some(_)) => t.replace(',', ""),
                (Some(_), None) => t.replace(',', "."),
                _ => t,
            };
            t.parse::<f64>().ok().map(|x| (x * 100.0).round() as i64)
        }
        _ => None,
    }
}

/// IBAN valide (clé modulo 97), sans espaces, en majuscules.
pub fn iban_valide(brut: &str) -> Option<String> {
    let s: String = brut.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    if s.len() < 15 || s.len() > 34 || !s.chars().all(|c| c.is_ascii_alphanumeric()) || !s[..2].chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let tourne = format!("{}{}", &s[4..], &s[..4]);
    let mut reste: u64 = 0;
    for c in tourne.chars() {
        let n = c.to_digit(36)? as u64;
        reste = if n >= 10 { (reste * 100 + n) % 97 } else { (reste * 10 + n) % 97 };
    }
    (reste == 1).then_some(s)
}

fn luhn(chiffres: &str) -> bool {
    let mut somme = 0;
    for (i, c) in chiffres.chars().rev().enumerate() {
        let mut d = c.to_digit(10).unwrap_or(0);
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        somme += d;
    }
    somme % 10 == 0
}

/// Données sensibles d'un texte : catégories trouvées, et nombre d'identifiants distincts
/// (IBAN, numéros de sécurité sociale, cartes) — beaucoup d'identifiants : une extraction.
pub fn donnees_sensibles(texte: &str) -> (Vec<&'static str>, usize) {
    static IBAN: OnceLock<Regex> = OnceLock::new();
    static NIR: OnceLock<Regex> = OnceLock::new();
    static CARTE: OnceLock<Regex> = OnceLock::new();
    static SANTE: OnceLock<Regex> = OnceLock::new();
    let iban = IBAN.get_or_init(|| Regex::new(r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,4})?\b").expect("motif IBAN"));
    let nir = NIR.get_or_init(|| Regex::new(r"\b[12][ ]?\d{2}[ ]?(?:0[1-9]|1[0-2])[ ]?(?:\d{2}|2[ABab])[ ]?\d{3}[ ]?\d{3}(?:[ ]?\d{2})?\b").expect("motif NIR"));
    let carte = CARTE.get_or_init(|| Regex::new(r"\b(?:\d[ \-]?){13,19}\b").expect("motif carte"));
    let sante = SANTE.get_or_init(|| {
        Regex::new(r"(?i)\b(diagnostic|pathologie|maladie|ordonnance|arrêt de travail|hospitalis|traitement médical|séropositi|cancer|diabète|grossesse|handicap|dossier médical|psychiatr)")
            .expect("motif santé")
    });
    let mut cats = Vec::new();
    let mut ids: HashSet<String> = HashSet::new();
    for m in iban.find_iter(texte) {
        if let Some(i) = iban_valide(m.as_str()) {
            ids.insert(i);
        }
    }
    if !ids.is_empty() {
        cats.push("bancaire");
    }
    let mut cartes = 0;
    for m in carte.find_iter(texte) {
        let d: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
        if (13..=19).contains(&d.len()) && luhn(&d) && !ids.iter().any(|i| i.contains(&d)) {
            ids.insert(d);
            cartes += 1;
        }
    }
    if cartes > 0 && !cats.contains(&"bancaire") {
        cats.push("bancaire");
    }
    let mut nirs = 0;
    for m in nir.find_iter(texte) {
        let d: String = m.as_str().chars().filter(|c| !c.is_whitespace()).collect();
        if ids.insert(d) {
            nirs += 1;
        }
    }
    if nirs > 0 {
        cats.push("identifiant_national");
    }
    if sante.is_match(texte) {
        cats.push("sante");
    }
    (cats, ids.len())
}

/// Contenu envoyé ou écrit par l'action : tous les paramètres, sauf les adresses.
fn contenu(e: &Value) -> String {
    match e {
        Value::Object(o) => o
            .iter()
            .filter(|(k, _)| !CLES_DESTINATAIRE.contains(&k.as_str()))
            .map(|(_, v)| texte_de(v))
            .collect::<Vec<_>>()
            .join("\n"),
        autre => texte_de(autre),
    }
}

// ---------------------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------------------

/// Verbe d'un outil, d'après le mandat. Un outil non déclaré dont le nom évoque une
/// validation est une tentative de s'approuver soi-même (EF-S2).
pub fn verbe(outil: &str, m: &PerimetreMetier) -> (String, Option<String>) {
    if let Some(o) = m.outils.iter().find(|o| o.outil == outil) {
        return (o.verbe.clone(), o.categorie.clone());
    }
    let bas = outil.to_ascii_lowercase();
    if ["approuv", "valider", "validat", "autoris", "approve", "aplomb"].iter().any(|x| bas.contains(x)) {
        return ("approuver".into(), None);
    }
    if matches!(outil, "TodoWrite" | "TodoRead" | "ToolSearch") {
        return ("interne".into(), None);
    }
    ("autre".into(), None)
}

/// Domaine interne de l'organisation ?
fn interne(domaine: &str, m: &PerimetreMetier) -> bool {
    crate::profils::code::domaine_autorise(domaine, &m.domaines_internes)
}

/// Destinataire déclaré pour ce domaine : le plus précis d'abord, puis `*`.
fn destinataire<'a>(domaine: &str, m: &'a PerimetreMetier) -> Option<&'a Destinataire> {
    m.destinataires
        .iter()
        .find(|d| d.domaine != "*" && crate::profils::code::domaine_autorise(domaine, std::slice::from_ref(&d.domaine)))
        .or_else(|| m.destinataires.iter().find(|d| d.domaine == "*"))
}

/// Traduit un événement en action du profil métier.
pub fn normaliser(evt: &EvenementOutil, mandat: &Mandat) -> Action {
    let vide = PerimetreMetier {
        processus: String::new(),
        outils: Vec::new(),
        donnees: Vec::new(),
        domaines_internes: Vec::new(),
        destinataires: Vec::new(),
        juridictions: Vec::new(),
        plafonds: Plafonds::default(),
    };
    let m = mandat.perimetre.metier.as_ref().unwrap_or(&vide);
    let e = &evt.entree;
    let (verbe, categorie) = verbe(&evt.outil, m);

    let dossier = premier(e, CLES_DOSSIER);
    let doms = adresses(e);
    let externes: Vec<&String> = doms.iter().filter(|d| !interne(d, m)).collect();
    let tous_internes = !doms.is_empty() && externes.is_empty();
    let decl: Vec<Option<&Destinataire>> = externes.iter().map(|d| destinataire(d, m)).collect();
    let destinataire_autorise = !externes.is_empty() && decl.iter().all(Option::is_some);

    let texte = contenu(e);
    let (sensibles, nb_identifiants) = donnees_sensibles(&texte);

    // Juridictions réelles : pays de l'IBAN payé ; juridiction déclarée de chaque destinataire.
    let beneficiaire = iban_valide(&premier(e, CLES_BENEFICIAIRE));
    let mut juridictions: Vec<String> = Vec::new();
    if verbe == "payer" {
        juridictions.push(beneficiaire.as_ref().map(|i| i[..2].to_string()).unwrap_or_default());
    }
    if matches!(verbe.as_str(), "envoyer" | "exporter") {
        let pays_interne = m.juridictions.first().cloned().unwrap_or_default();
        for d in &doms {
            if interne(d, m) {
                juridictions.push(pays_interne.clone());
            } else {
                juridictions.push(destinataire(d, m).map(|x| x.juridiction.clone()).unwrap_or_default());
            }
        }
    }
    let juridiction_ok = juridictions.iter().all(|j| juridiction_autorisee(j, &m.juridictions));

    // Données sensibles hors de ce que chaque destinataire externe peut recevoir.
    let hors_destinataire = matches!(verbe.as_str(), "envoyer" | "exporter")
        && !externes.is_empty()
        && sensibles.iter().any(|c| decl.iter().any(|d| d.is_none_or(|d| !d.donnees.iter().any(|x| x == c))));

    let centimes = CLES_MONTANT.iter().find_map(|c| e.get(*c)).and_then(montant_centimes);
    let plafond = (m.plafonds.paiement * 100.0).round() as i64;
    let montant_hors_plafond = verbe == "payer" && centimes.is_none_or(|c| c <= 0 || c > plafond);

    let lignes = premier(e, CLES_LIGNES).trim().parse::<u64>().ok();
    let export_hors_plafond = verbe == "exporter" && lignes.is_none_or(|n| n > m.plafonds.export_lignes);

    let cible_supp = format!("{dossier} {}", premier(e, &["filtre", "filter", "ids", "cible", "requete"]));
    let suppression_en_masse = verbe == "supprimer"
        && (cible_supp.contains('*')
            || ["tous", "toutes", "all", "where", "%"].iter().any(|x| cible_supp.to_ascii_lowercase().split(|c: char| !c.is_alphanumeric() && c != '%').any(|w| w == *x))
            || e.get("ids").and_then(Value::as_array).is_some_and(|a| a.len() > 1)
            || dossier.trim().is_empty());

    let champs = premier(e, CLES_CHAMP).to_ascii_lowercase();
    let modifie_bancaire = verbe == "ecrire_dossier"
        && (["iban", "rib", "bancaire", "bic", "compte"].iter().any(|x| champs.contains(x))
            || e.as_object().is_some_and(|o| o.keys().any(|k| ["iban", "rib", "bic"].contains(&k.to_ascii_lowercase().as_str())))
            || sensibles.contains(&"bancaire"));

    let categorie_ok = categorie.as_ref().is_none_or(|c| m.donnees.iter().any(|d| d == c));
    let irreversible = VERBES.iter().any(|(v, _, r)| *v == verbe && !*r);
    let envoi_externe = (verbe == "envoyer" || verbe == "exporter") && !externes.is_empty();

    let mut contexte = Map::new();
    let mut mettre = |k: &str, v: Value| {
        contexte.insert(k.to_string(), v);
    };
    mettre("outil", json!(evt.outil));
    mettre("processus", json!(m.processus));
    mettre("dossier", json!(dossier));
    mettre("categorie", json!(categorie.clone().unwrap_or_default()));
    mettre("categorie_autorisee", json!(categorie_ok));
    mettre("destinataires", json!(doms));
    mettre("interne", json!(tous_internes));
    mettre("destinataire_autorise", json!(destinataire_autorise));
    mettre("juridictions", json!(juridictions));
    mettre("juridiction_autorisee", json!(juridiction_ok));
    mettre("donnees_sensibles", json!(sensibles));
    mettre("identifiants", json!(nb_identifiants as i64));
    mettre("donnees_hors_destinataire", json!(hors_destinataire));
    mettre("montant_centimes", json!(centimes.unwrap_or(0)));
    mettre("beneficiaire", json!(beneficiaire.clone().unwrap_or_default()));
    mettre("montant_hors_plafond", json!(montant_hors_plafond));
    mettre("export_hors_plafond", json!(export_hors_plafond));
    mettre("suppression_en_masse", json!(suppression_en_masse));
    mettre("modifie_coordonnees_bancaires", json!(modifie_bancaire));
    mettre("irreversible", json!(irreversible));
    mettre("envoi_externe", json!(envoi_externe));
    // Pour les moniteurs du socle (bornes, secrets, juge) : pas d'accès réseau direct.
    mettre("reseau", json!(false));
    mettre("domaine", json!(externes.first().cloned().cloned().unwrap_or_default()));
    mettre("influence_externe", json!(false));

    let ressource = match verbe.as_str() {
        "envoyer" | "exporter" if !doms.is_empty() => doms.join(","),
        "payer" => beneficiaire.unwrap_or_else(|| "beneficiaire-invalide".into()),
        _ if !dossier.is_empty() => format!("dossier:{dossier}"),
        _ => evt.outil.clone(),
    };
    Action { session: evt.session.clone(), agent: evt.agent.clone(), verbe, ressource, contexte }
}

/// Contenu non fiable apporté par l'action (EF-B5) : messages entrants (écrits par des tiers).
pub fn source_non_fiable(action: &Action) -> bool {
    action.verbe == "lire_message"
}

/// Actions qu'un contenu non fiable ne déclenche pas seul (EF-D2). Un message à un collègue
/// reste permis : il ne produit aucun effet automatique, son destinataire est humain.
pub fn sensible_a_l_influence(action: &Action) -> bool {
    let b = |k: &str| action.contexte.get(k).and_then(Value::as_bool).unwrap_or(false);
    matches!(action.verbe.as_str(), "payer" | "exporter" | "supprimer" | "autre") || (action.verbe == "envoyer" && !b("interne")) || b("modifie_coordonnees_bancaires")
}

// ---------------------------------------------------------------------------------------
// Moniteurs du profil
// ---------------------------------------------------------------------------------------

/// Conseil hors du cadre réglementaire : conseil en investissement, avis médical,
/// promesse ou garantie que l'entreprise n'a pas donnée.
fn motifs_conseil() -> &'static [(&'static str, Regex)] {
    static M: OnceLock<Vec<(&str, Regex)>> = OnceLock::new();
    M.get_or_init(|| {
        [
            ("conseil en investissement", r"(?i)(je vous (conseille|recommande) d'(investir|placer|acheter|vendre)|placement (sûr|garanti|sans risque)|rendement garanti|investissez)"),
            ("avis médical", r"(?i)(arrêtez (votre|le) traitement|vous (n'avez|n'aurez) pas besoin de (médecin|consulter)|je vous (conseille|recommande) de (prendre|cesser|arrêter)|ce n'est (sûrement |probablement )?pas grave)"),
            ("promesse non autorisée", r"(?i)(nous vous garantissons|je vous garantis|remboursement (intégral )?garanti|vous serez (forcément|certainement) (remboursé|indemnisé)|vous êtes certain de gagner)"),
            ("conseil juridique", r"(?i)(vous (pouvez|devriez) (attaquer|poursuivre) en justice|portez plainte contre)"),
        ]
        .into_iter()
        .map(|(n, m)| (n, Regex::new(m).expect("motif de conseil")))
        .collect()
    })
}

/// État du profil par session : cumuls et IBAN écrits par l'agent.
#[derive(Debug, Default)]
pub struct Suivi {
    sessions: HashMap<String, Session>,
}

#[derive(Debug, Default)]
struct Session {
    paye_centimes: i64,
    dossiers: HashSet<String>,
    ibans_ecrits: HashSet<String>,
}

fn avis(moniteur: &str, niveau: Niveau, score: f32, motif: String) -> Avis {
    Avis { moniteur: moniteur.into(), niveau, score, motif }
}

impl Suivi {
    /// Avis des moniteurs du profil sur l'action, sans changer l'état.
    pub fn avis(&self, mandat: &Mandat, evt: &EvenementOutil, action: &Action) -> Vec<Avis> {
        let Some(m) = mandat.perimetre.metier.as_ref() else { return Vec::new() };
        let c = &action.contexte;
        let b = |k: &str| c.get(k).and_then(Value::as_bool).unwrap_or(false);
        let s = self.sessions.get(&action.session);
        let mut res = Vec::new();

        // Invariant : aucune action irréversible sans approbation, quelles que soient les règles.
        let interne = action.verbe == "envoyer" && b("interne");
        if b("irreversible") && !interne {
            res.push(avis("invariant-irreversible", Niveau::Suspect, 0.5, format!("action irréversible ({}) : approbation humaine requise", action.verbe)));
        }

        // Fuite de données : sensibles vers un destinataire non autorisé, ou extraction en masse.
        let identifiants = c.get("identifiants").and_then(Value::as_i64).unwrap_or(0);
        let sortant = matches!(action.verbe.as_str(), "envoyer" | "exporter" | "payer");
        if sortant && !interne {
            // Un paiement porte l'IBAN de son bénéficiaire : ce n'est pas une divulgation (la
            // juridiction du bénéficiaire relève des règles, qui refusent sans geler).
            let paiement = action.verbe == "payer";
            let cats: Vec<&str> = c
                .get("donnees_sensibles")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).filter(|x| !(paiement && *x == "bancaire")).collect())
                .unwrap_or_default();
            if (!paiement && b("donnees_hors_destinataire")) || (!b("juridiction_autorisee") && !cats.is_empty()) {
                res.push(avis("fuite-de-donnees", Niveau::Critique, 1.0, format!("données {} vers un destinataire ou une juridiction non autorisés", cats.join(", "))));
            } else if identifiants >= 3 {
                res.push(avis("fuite-de-donnees", Niveau::Critique, 0.9, format!("{identifiants} identifiants personnels dans un même envoi : extraction")));
            }
        }

        // Conseil hors cadre réglementaire, dans ce qui part vers l'extérieur.
        if action.verbe == "envoyer" && !interne {
            let texte = contenu(&evt.entree);
            let trouves: Vec<&str> = motifs_conseil().iter().filter(|(_, r)| r.is_match(&texte)).map(|(n, _)| *n).collect();
            if !trouves.is_empty() {
                res.push(avis("conseil-hors-cadre", Niveau::Suspect, 0.8, format!("message externe : {}", trouves.join(", "))));
            }
        }

        // Cumuls de session.
        if action.verbe == "payer" {
            let total = s.map_or(0, |s| s.paye_centimes) + c.get("montant_centimes").and_then(Value::as_i64).unwrap_or(0);
            let plafond = (m.plafonds.paiements_session * 100.0).round() as i64;
            if total > plafond {
                res.push(avis("cumul-paiements", Niveau::Critique, 1.0, format!("{:.2} payés dans la session (plafond {:.2})", total as f64 / 100.0, m.plafonds.paiements_session)));
            }
            let iban = c.get("beneficiaire").and_then(Value::as_str).unwrap_or_default();
            if !iban.is_empty() && s.is_some_and(|s| s.ibans_ecrits.contains(iban)) {
                res.push(avis("enchainement", Niveau::Critique, 1.0, "IBAN écrit dans un dossier par l'agent, puis payé : détournement".into()));
            }
        }
        if action.verbe == "lire_dossier" || action.verbe == "rechercher" {
            let dossier = c.get("dossier").and_then(Value::as_str).unwrap_or_default();
            let mut n = s.map_or(0, |s| s.dossiers.len());
            if !dossier.is_empty() && !s.is_some_and(|s| s.dossiers.contains(dossier)) {
                n += 1;
            }
            if n as u32 > m.plafonds.dossiers_session {
                res.push(avis("cumul-dossiers", Niveau::Critique, 1.0, format!("{n} dossiers distincts lus dans la session (plafond {}) : collecte", m.plafonds.dossiers_session)));
            }
        }
        res
    }

    /// Tient les cumuls à jour après la décision (refus exclus).
    pub fn noter(&mut self, evt: &EvenementOutil, action: &Action, verdict: Verdict) {
        if verdict >= Verdict::Deny {
            return;
        }
        let c = &action.contexte;
        let s = self.sessions.entry(action.session.clone()).or_default();
        match action.verbe.as_str() {
            "payer" => s.paye_centimes += c.get("montant_centimes").and_then(Value::as_i64).unwrap_or(0),
            "lire_dossier" | "rechercher" => {
                if let Some(d) = c.get("dossier").and_then(Value::as_str).filter(|d| !d.is_empty()) {
                    s.dossiers.insert(d.to_string());
                }
            }
            "ecrire_dossier" => {
                static IBAN: OnceLock<Regex> = OnceLock::new();
                let r = IBAN.get_or_init(|| Regex::new(r"[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,4})?").expect("motif IBAN"));
                for m in r.find_iter(&evt.entree.to_string()) {
                    if let Some(i) = iban_valide(m.as_str()) {
                        s.ibans_ecrits.insert(i);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn reinitialiser(&mut self, session: Option<&str>) {
        match session {
            Some(s) => {
                self.sessions.remove(s);
            }
            None => self.sessions.clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Phase;
    use crate::mandat::{FichiersPolitique, Perimetre};

    pub(crate) fn perimetre() -> PerimetreMetier {
        let o = |outil: &str, verbe: &str, cat: Option<&str>| OutilMetier { outil: outil.into(), verbe: verbe.into(), categorie: cat.map(String::from) };
        PerimetreMetier {
            processus: "reclamations".into(),
            outils: vec![
                o("mcp__crm__lire_dossier", "lire_dossier", Some("contrat")),
                o("mcp__crm__lire_dossier_medical", "lire_dossier", Some("sante")),
                o("mcp__crm__ecrire_dossier", "ecrire_dossier", Some("contrat")),
                o("mcp__mail__envoyer", "envoyer", None),
                o("mcp__mail__lire", "lire_message", None),
                o("mcp__paiement__rembourser", "payer", None),
                o("mcp__ged__supprimer", "supprimer", None),
                o("mcp__crm__exporter", "exporter", None),
            ],
            donnees: vec!["contrat".into(), "identite".into()],
            domaines_internes: vec!["assur.example".into()],
            destinataires: vec![
                Destinataire { domaine: "expert-auto.example".into(), juridiction: "FR".into(), donnees: vec!["bancaire".into()] },
                Destinataire { domaine: "sous-traitant.example".into(), juridiction: "US".into(), donnees: vec![] },
                Destinataire { domaine: "*".into(), juridiction: "FR".into(), donnees: vec![] },
            ],
            juridictions: vec!["UE".into()],
            plafonds: Plafonds { paiement: 500.0, paiements_session: 800.0, dossiers_session: 3, export_lignes: 100 },
        }
    }

    pub(crate) fn mandat() -> Mandat {
        Mandat {
            id: "m".into(),
            version: 1,
            profil: "metier".into(),
            agent: "agent-reclamations".into(),
            intention: "Traiter les réclamations".into(),
            parent: None,
            perimetre: Perimetre {
                racine: "/srv/agent".into(),
                domaines_autorises: vec![],
                branches_protegees: vec![],
                domaines_modele: vec![],
                serveurs_mcp: vec![],
                metier: Some(perimetre()),
            },
            politique: FichiersPolitique { regles: String::new(), revue: String::new(), regles_sha256: String::new(), revue_sha256: String::new() },
            bornes: None,
            moniteurs: None,
            signature: None,
            signatures: Vec::new(),
        }
    }

    pub(crate) fn evt(outil: &str, entree: Value) -> EvenementOutil {
        EvenementOutil {
            session: "s".into(),
            agent: "agent-reclamations".into(),
            mode: "test".into(),
            cwd: "/srv/agent".into(),
            outil: outil.into(),
            entree,
            phase: Phase::Avant,
            chemin_reel: None,
            contenu_execute: None,
            nonce: None,
            appel: None,
            delegation: None,
        }
    }

    fn act(outil: &str, entree: Value) -> Action {
        normaliser(&evt(outil, entree), &mandat())
    }

    fn b(a: &Action, k: &str) -> bool {
        a.contexte[k].as_bool().unwrap()
    }

    const IBAN_FR: &str = "FR76 3000 6000 0112 3456 7890 189";
    const IBAN_DE: &str = "DE89370400440532013000";
    const IBAN_CH: &str = "CH9300762011623852957";

    #[test]
    fn ibans() {
        assert_eq!(iban_valide(IBAN_FR).as_deref(), Some("FR7630006000011234567890189"));
        assert!(iban_valide(IBAN_DE).is_some() && iban_valide(IBAN_CH).is_some());
        assert!(iban_valide("FR7630006000011234567890188").is_none(), "clé fausse");
    }

    #[test]
    fn montants() {
        assert_eq!(montant_centimes(&json!(480)), Some(48000));
        assert_eq!(montant_centimes(&json!("480,50 €")), Some(48050));
        assert_eq!(montant_centimes(&json!("1 200,00")), Some(120000));
        assert_eq!(montant_centimes(&json!("1,200.00")), Some(120000));
    }

    #[test]
    fn verbes_et_outils_non_declares() {
        assert_eq!(act("mcp__crm__lire_dossier", json!({"dossier": "R-1"})).verbe, "lire_dossier");
        assert_eq!(act("mcp__crm__supprimer_tout", json!({})).verbe, "autre");
        assert_eq!(act("mcp__paiement__approuver_paiement", json!({})).verbe, "approuver");
    }

    #[test]
    fn destinataire_reel() {
        let a = act("mcp__mail__envoyer", json!({"a": "Jean <jean@assur.example>", "corps": "ok"}));
        assert!(b(&a, "interne") && b(&a, "juridiction_autorisee"));
        let a = act("mcp__mail__envoyer", json!({"a": "client@gmail.com", "cc": "x@assur.example", "corps": "Bonjour"}));
        assert!(!b(&a, "interne") && b(&a, "destinataire_autorise") && b(&a, "envoi_externe"));
        // Un client peut recevoir un courriel, pas son IBAN en clair.
        let a = act("mcp__mail__envoyer", json!({"a": "client@gmail.com", "corps": format!("Votre IBAN {IBAN_FR}")}));
        assert!(b(&a, "donnees_hors_destinataire"));
        let a = act("mcp__mail__envoyer", json!({"a": "dossiers@expert-auto.example", "corps": format!("IBAN {IBAN_FR}")}));
        assert!(!b(&a, "donnees_hors_destinataire"));
        // Sous-traitant hors UE : juridiction non autorisée.
        let a = act("mcp__mail__envoyer", json!({"a": "x@sous-traitant.example", "corps": "dossier"}));
        assert!(!b(&a, "juridiction_autorisee"));
    }

    #[test]
    fn paiements() {
        let a = act("mcp__paiement__rembourser", json!({"iban": IBAN_FR, "montant": "120,00"}));
        assert!(b(&a, "juridiction_autorisee") && !b(&a, "montant_hors_plafond") && b(&a, "irreversible"));
        assert!(b(&act("mcp__paiement__rembourser", json!({"iban": IBAN_FR, "montant": 900})), "montant_hors_plafond"));
        assert!(!b(&act("mcp__paiement__rembourser", json!({"iban": IBAN_CH, "montant": 10})), "juridiction_autorisee"));
        assert!(!b(&act("mcp__paiement__rembourser", json!({"iban": "FR76300060000112345678901", "montant": 10})), "juridiction_autorisee"), "IBAN invalide");
        assert!(b(&act("mcp__paiement__rembourser", json!({"iban": IBAN_DE})), "montant_hors_plafond"), "sans montant");
    }

    #[test]
    fn suppression_export_ecriture() {
        assert!(!b(&act("mcp__ged__supprimer", json!({"dossier": "R-1"})), "suppression_en_masse"));
        assert!(b(&act("mcp__ged__supprimer", json!({"dossier": "*"})), "suppression_en_masse"));
        assert!(b(&act("mcp__ged__supprimer", json!({"filtre": "tous les dossiers clos"})), "suppression_en_masse"));
        assert!(b(&act("mcp__crm__exporter", json!({"lignes": 5000})), "export_hors_plafond"));
        assert!(!b(&act("mcp__crm__exporter", json!({"lignes": 20})), "export_hors_plafond"));
        assert!(b(&act("mcp__crm__ecrire_dossier", json!({"dossier": "R-1", "champ": "iban", "valeur": IBAN_DE})), "modifie_coordonnees_bancaires"));
        assert!(!b(&act("mcp__crm__ecrire_dossier", json!({"dossier": "R-1", "champ": "statut", "valeur": "clos"})), "modifie_coordonnees_bancaires"));
        assert!(!b(&act("mcp__crm__lire_dossier_medical", json!({"dossier": "R-1"})), "categorie_autorisee"));
    }

    #[test]
    fn donnees_detectees() {
        assert_eq!(donnees_sensibles("NIR 1 85 05 78 006 084 36").0, vec!["identifiant_national"]);
        assert_eq!(donnees_sensibles("carte 4111 1111 1111 1111").0, vec!["bancaire"]);
        assert_eq!(donnees_sensibles("arrêt de travail suite à hospitalisation").0, vec!["sante"]);
        assert!(donnees_sensibles("réclamation R-2024-118 du 3 mars, montant 120 €").0.is_empty());
    }

    #[test]
    fn moniteurs_du_profil() {
        let m = mandat();
        let mut s = Suivi::default();
        let noms = |v: Vec<Avis>| v.into_iter().map(|a| a.moniteur).collect::<Vec<_>>();
        // Irréversible : toujours une revue, même si une règle l'oubliait.
        let e = evt("mcp__paiement__rembourser", json!({"iban": IBAN_FR, "montant": 450}));
        let a = normaliser(&e, &m);
        assert_eq!(noms(s.avis(&m, &e, &a)), vec!["invariant-irreversible"]);
        s.noter(&e, &a, Verdict::Review);
        // Deuxième paiement : cumul 900 > 800 → gel.
        assert!(noms(s.avis(&m, &e, &a)).contains(&"cumul-paiements".to_string()));
        // Conseil hors cadre.
        let e = evt("mcp__mail__envoyer", json!({"a": "c@gmail.com", "corps": "Je vous conseille d'investir l'indemnité en bourse."}));
        assert!(noms(s.avis(&m, &e, &normaliser(&e, &m))).contains(&"conseil-hors-cadre".to_string()));
        // Interne : pas d'invariant.
        let e = evt("mcp__mail__envoyer", json!({"a": "chef@assur.example", "corps": "Pour info"}));
        assert!(s.avis(&m, &e, &normaliser(&e, &m)).is_empty());
        // Fuite : IBAN à un client.
        let e = evt("mcp__mail__envoyer", json!({"a": "c@gmail.com", "corps": format!("IBAN {IBAN_DE}")}));
        assert!(s.avis(&m, &e, &normaliser(&e, &m)).iter().any(|a| a.moniteur == "fuite-de-donnees" && a.niveau == Niveau::Critique));
        // Collecte : plus de 3 dossiers.
        for d in ["A", "B", "C"] {
            let e = evt("mcp__crm__lire_dossier", json!({"dossier": d}));
            let a = normaliser(&e, &m);
            assert!(s.avis(&m, &e, &a).is_empty());
            s.noter(&e, &a, Verdict::Allow);
        }
        let e = evt("mcp__crm__lire_dossier", json!({"dossier": "D"}));
        assert_eq!(noms(s.avis(&m, &e, &normaliser(&e, &m))), vec!["cumul-dossiers"]);
        let e = evt("mcp__crm__lire_dossier", json!({"dossier": "A"}));
        assert!(s.avis(&m, &e, &normaliser(&e, &m)).is_empty(), "relire un dossier déjà lu");
    }

    #[test]
    fn modifier_iban_puis_payer() {
        let m = mandat();
        let mut s = Suivi::default();
        let e = evt("mcp__crm__ecrire_dossier", json!({"dossier": "R-1", "champ": "iban", "valeur": IBAN_DE}));
        s.noter(&e, &normaliser(&e, &m), Verdict::Review);
        let e = evt("mcp__paiement__rembourser", json!({"iban": IBAN_DE, "montant": 100}));
        assert!(s.avis(&m, &e, &normaliser(&e, &m)).iter().any(|a| a.moniteur == "enchainement"));
    }

    #[test]
    fn attributs_toujours_presents() {
        for outil in ["mcp__crm__lire_dossier", "mcp__mail__envoyer", "mcp__paiement__rembourser", "inconnu", "mcp__ged__supprimer"] {
            let a = act(outil, json!({}));
            for k in ["categorie_autorisee", "interne", "destinataire_autorise", "juridiction_autorisee", "donnees_hors_destinataire",
                "montant_hors_plafond", "export_hors_plafond", "suppression_en_masse", "modifie_coordonnees_bancaires", "irreversible",
                "envoi_externe", "influence_externe", "montant_centimes", "dossier"] {
                assert!(a.contexte.contains_key(k), "{outil} : {k}");
            }
        }
    }

    #[test]
    fn verification_du_mandat() {
        let mut m = mandat();
        assert!(verifier(&m).is_ok());
        m.perimetre.metier.as_mut().unwrap().outils[0].verbe = "voler".into();
        assert!(verifier(&m).unwrap_err().contains("verbe « voler » inconnu"));
        m.perimetre.metier = None;
        assert!(verifier(&m).unwrap_err().contains("perimetre.metier absente"));
    }
}
