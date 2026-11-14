//! **Rapports réglementaires** (étape 9, reporting) : DORA, ISO/IEC 42001 (annexe A),
//! NIS 2 (art. 20, 21 § 2 et 23). Pour chaque exigence, on indique ce qu'Aplomb apporte, ce
//! qui a été constaté sur l'instance et ce qui reste à l'organisation.
//!
//! Les correspondances sont **indicatives**. Un superviseur d'agents n'est qu'une mesure
//! parmi d'autres ; les statuts portent sur le périmètre de l'agent supervisé, jamais sur
//! l'entité entière.
use serde::{Deserialize, Serialize};

use crate::preuves::{Constats, Statut};

pub const AVERTISSEMENT: &str = "Correspondances indicatives, limitées au périmètre de l'agent supervisé : à faire valider par la \
    fonction conformité avant tout usage réglementaire. Elles ne remplacent ni l'analyse de risques de l'entité ni ses \
    procédures.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Referentiel {
    Dora,
    Iso42001,
    Nis2,
}

impl Referentiel {
    pub fn depuis(nom: &str) -> Result<Self, String> {
        match nom
            .to_lowercase()
            .replace(['-', '_', ' ', '/'], "")
            .as_str()
        {
            "dora" => Ok(Self::Dora),
            "iso42001" | "isoiec42001" | "42001" => Ok(Self::Iso42001),
            "nis2" => Ok(Self::Nis2),
            _ => Err(format!(
                "référentiel inconnu « {nom} » : dora, iso42001 ou nis2"
            )),
        }
    }

    pub fn titre(self) -> &'static str {
        match self {
            Self::Dora => {
                "DORA — règlement (UE) 2022/2554 sur la résilience opérationnelle numérique"
            }
            Self::Iso42001 => "ISO/IEC 42001:2023 — système de management de l'IA, annexe A",
            Self::Nis2 => "NIS 2 — directive (UE) 2022/2555",
        }
    }

    pub fn court(self) -> &'static str {
        match self {
            Self::Dora => "dora",
            Self::Iso42001 => "iso42001",
            Self::Nis2 => "nis2",
        }
    }

    pub const TOUS: [Referentiel; 3] = [Self::Dora, Self::Iso42001, Self::Nis2];
}

/// Une exigence du référentiel et ce que le dossier en montre.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Controle {
    pub reference: String,
    pub objet: String,
    pub statut: Statut,
    pub apport: String,
    pub constat: String,
    pub reste: String,
    pub pieces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rapport {
    pub schema: String,
    pub referentiel: Referentiel,
    pub titre: String,
    pub avertissement: String,
    pub systeme: String,
    pub version_mandat: u32,
    pub instance: String,
    pub genere: u64,
    pub synthese: Synthese,
    pub controles: Vec<Controle>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Synthese {
    pub couvert: usize,
    pub partiel: usize,
    pub hors_perimetre: usize,
}

/// Faits communs aux trois référentiels, déduits des constats.
struct Faits<'a> {
    c: &'a Constats,
    quatre_yeux: bool,
    journal_probant: bool,
    journal: String,
    eval: String,
    acces: String,
    supervision: String,
    alerte: String,
}

fn faits(c: &Constats) -> Faits<'_> {
    let quatre_yeux = c.signataires_mandat.len() >= c.seuil.max(2) && c.comptes_cosignes;
    let journal_probant =
        c.sessions_rompues == 0 && c.sessions_intactes > 0 && c.scelles > 0 && c.scelles_valides;
    let journal = format!(
        "{} session(s) intacte(s), {} rompue(s) ; {} scellé(s){} ; ancre {}",
        c.sessions_intactes,
        c.sessions_rompues,
        c.scelles,
        if c.scelles > 0 && !c.scelles_valides {
            " INVALIDES"
        } else {
            ""
        },
        if c.ancre_verifiee {
            "vérifiée"
        } else {
            "absente ou non vérifiée"
        }
    );
    let eval = match c.evaluation {
        Some((s, u)) => format!(
            "banc rouge/bleu rejoué : sûreté {:.0} %, utilité {:.0} %",
            s * 100.0,
            u * 100.0
        ),
        None => "aucun jeu d'évaluation pour ce profil".into(),
    };
    let oui = |b: bool| if b { "oui" } else { "non" };
    let acces = format!(
        "comptes {} ; {} opérateur(s), {} approbateur(s) ; second facteur : {} ; SSO : {} ; revue des comptes inactifs : {}",
        if c.comptes_cosignes { "cosignés" } else { "NON cosignés" },
        c.operateurs,
        c.approbateurs,
        oui(c.mfa),
        oui(c.sso),
        oui(c.revue_comptes)
    );
    let supervision = format!(
        "{} décision(s), {} revue(s) humaine(s), {} gel(s) sur la période ; délai de revue {} s",
        c.decisions, c.revues, c.gels, c.delai_revue
    );
    let alerte = format!(
        "diffusion SIEM : {} ; canaux d'approbation : {}",
        if c.siem.is_empty() {
            "non configurée".into()
        } else {
            c.siem.join(", ")
        },
        if c.canaux_approbation == 0 {
            "Aplomb Watch seulement".into()
        } else {
            format!("{} canal(aux)", c.canaux_approbation)
        }
    );
    Faits {
        c,
        quatre_yeux,
        journal_probant,
        journal,
        eval,
        acces,
        supervision,
        alerte,
    }
}

fn ctl(
    reference: &str,
    objet: &str,
    statut: Statut,
    apport: &str,
    constat: String,
    reste: &str,
    pieces: &[&str],
) -> Controle {
    Controle {
        reference: reference.into(),
        objet: objet.into(),
        statut,
        apport: apport.into(),
        constat,
        reste: reste.into(),
        pieces: pieces.iter().map(|p| p.to_string()).collect(),
    }
}

fn si(b: bool) -> Statut {
    if b {
        Statut::Couvert
    } else {
        Statut::Partiel
    }
}

/// Exigences du référentiel, statut déduit des constats.
pub fn controles(r: Referentiel, c: &Constats) -> Vec<Controle> {
    let f = faits(c);
    match r {
        Referentiel::Dora => dora(&f),
        Referentiel::Iso42001 => iso42001(&f),
        Referentiel::Nis2 => nis2(&f),
    }
}

fn dora(f: &Faits) -> Vec<Controle> {
    let c = f.c;
    vec![
        ctl("Art. 5", "Gouvernance et organisation (responsabilité de l'organe de direction)", Statut::Partiel,
            "Le mandat de l'agent est cosigné par deux personnes ; tout assouplissement demande quatre yeux.",
            format!("mandat cosigné par {} personne(s), seuil {}", c.signataires_mandat.len(), c.seuil),
            "Approbation du cadre de gestion du risque TIC par l'organe de direction ; rôles et formation.",
            &["mandat/", "gouvernance/confiance.yaml"]),
        ctl("Art. 6", "Cadre de gestion du risque lié aux TIC", Statut::Partiel,
            "Les risques de l'agent sont traduits en invariants et règles déterministes ; le banc rouge/bleu bloque une régression de sûreté.",
            f.eval.clone(), "Cadre documenté pour l'ensemble des systèmes TIC, revu au moins une fois par an.",
            &["mandat/", "evaluation.json"]),
        ctl("Art. 8", "Identification des fonctions, actifs et dépendances", Statut::Partiel,
            "Le mandat déclare le périmètre de l'agent : outils, ressources, chemins d'extension.",
            "périmètre de l'agent déclaré au mandat".into(), "Inventaire des actifs TIC et des fonctions critiques ou importantes.",
            &["mandat/"]),
        ctl("Art. 9 § 4", "Protection et prévention : accès, authentification forte, changements", si(f.quatre_yeux && c.mfa),
            "Chaque action est autorisée avant exécution ; comptes nominatifs à rôles, second facteur pour assouplir, élargissements cosignés.",
            f.acces.clone(), "Politiques de contrôle d'accès et de gestion des changements de l'entité.",
            &["gouvernance/comptes.json", "mandat/"]),
        ctl("Art. 10", "Détection des activités anormales", si(!c.siem.is_empty() && c.decisions > 0),
            "Moniteurs enfichables, juge, contrôle croisé ; chaque refus et chaque gel est journalisé et peut être diffusé au SIEM.",
            format!("{} ; {}", f.supervision, f.alerte), "Surveillance de l'ensemble du SI ; seuils d'alerte et responsables.",
            &["indicateurs.json"]),
        ctl("Art. 11", "Réponse et rétablissement", Statut::Partiel,
            "Gel immédiat par une seule personne (global ou par session), dégel à quatre yeux.",
            format!("{} gel(s) sur la période", c.gels), "Plan de continuité et de réponse TIC, testé.",
            &["indicateurs.json", "journal.json"]),
        ctl("Art. 12", "Sauvegarde, journalisation et restauration", si(f.journal_probant && c.ancre_verifiee),
            "Journal chaîné et scellé, ancré hors de la machine ; archivage sans rompre la vérification.",
            f.journal.clone(), "Politique de sauvegarde et de restauration des systèmes.", &["journal.json"]),
        ctl("Art. 13", "Apprentissage et évolution", Statut::Partiel,
            "Chaque version du mandat rejoue le banc ; les rapports précédents servent de référence de non-régression.",
            format!("référence de non-régression {}", if c.reference_non_regression { "présente" } else { "absente" }),
            "Analyses post-incident et retours d'expérience.", &["evaluation.json"]),
        ctl("Art. 17-19", "Gestion, classification et notification des incidents liés aux TIC", Statut::Partiel,
            "Gels, refus et écarts de contrôle croisé sont des signaux horodatés, avec fuseau, prêts pour le SIEM.",
            f.alerte.clone(), "Classification selon les critères DORA ; notification à l'autorité dans les délais.",
            &["indicateurs.json", "journal.json"]),
        ctl("Art. 24-25", "Tests de résilience opérationnelle numérique", si(c.evaluation.is_some_and(|(s, _)| s >= 0.8)),
            "Banc rouge/bleu rejouable, déterministe, versé au dossier.", f.eval.clone(),
            "Programme de tests de l'entité ; tests de pénétration fondés sur la menace (TLPT) le cas échéant.",
            &["evaluation.json"]),
        ctl("Art. 28", "Risque lié aux prestataires tiers de services TIC", Statut::Partiel,
            "Le modèle et ses fournisseurs restent sous un contrôle externe et déterministe ; aucune donnée ne sort par défaut.",
            format!("profil de déploiement {}", if c.deploiement.is_empty() { "minimal" } else { &c.deploiement }),
            "Registre d'information, clauses contractuelles, stratégie de sortie.", &["mandat/"]),
    ]
}

fn iso42001(f: &Faits) -> Vec<Controle> {
    let c = f.c;
    vec![
        ctl("A.2", "Politiques relatives à l'IA", Statut::Partiel,
            "Le mandat traduit la politique en règles exécutables pour un agent donné.",
            "mandat cosigné".into(), "Politique IA de l'organisme, alignée sur ses autres politiques.", &["mandat/"]),
        ctl("A.3.2", "Rôles et responsabilités", si(f.quatre_yeux && c.approbateurs > 0),
            "Rôles lecteur, opérateur, approbateur ; quatre yeux pour assouplir.", f.acces.clone(),
            "Désignation et formation des personnes.", &["gouvernance/comptes.json"]),
        ctl("A.3.3", "Signalement des préoccupations", Statut::Partiel,
            "Toute personne habilitée peut geler immédiatement.", format!("{} gel(s) sur la période", c.gels),
            "Processus de signalement accessible à tous, y compris de façon confidentielle.", &["indicateurs.json"]),
        ctl("A.5", "Évaluation des impacts des systèmes d'IA", Statut::Partiel,
            "Les invariants et le banc rouge/bleu documentent les effets interdits et leur maîtrise.", f.eval.clone(),
            "Évaluation d'impact sur les personnes et la société.", &["evaluation.json"]),
        ctl("A.6.2.4", "Vérification et validation", si(c.evaluation.is_some()),
            "Banc rouge/bleu rejoué à chaque cosignature et à l'export.", f.eval.clone(),
            "Critères d'acceptation du système complet.", &["evaluation.json"]),
        ctl("A.6.2.6", "Fonctionnement et surveillance", si(c.decisions > 0 && c.approbateurs > 0),
            "Décision avant chaque action, revue humaine priorisée, gel, indicateurs signés.",
            format!("{} ; {}", f.supervision, f.alerte), "Responsables de la surveillance, seuils, revues périodiques.",
            &["indicateurs.json"]),
        ctl("A.6.2.8", "Enregistrement des journaux d'événements", si(f.journal_probant),
            "Journal probatoire chaîné, scellé et ancré.", f.journal.clone(), "Durée de conservation fixée et tenue.",
            &["journal.json"]),
        ctl("A.7", "Données des systèmes d'IA", Statut::HorsPerimetre,
            "Sans objet pour un superviseur : il n'entraîne pas le modèle. Il minimise et chiffre ce qu'il journalise.",
            "—".into(), "Qualité, provenance et préparation des données.", &[]),
        ctl("A.8", "Information des parties intéressées", Statut::Partiel,
            "Intention et périmètre déclarés dans le mandat ; dossier de preuves vérifiable par un tiers.",
            "dossier signé".into(), "Information des utilisateurs et des personnes concernées.", &["LISEZMOI.md", "manifeste.json"]),
        ctl("A.9", "Utilisation des systèmes d'IA (usage responsable, usage prévu)", si(f.quatre_yeux),
            "L'agent ne peut agir hors du mandat ; les actions sensibles passent par un humain.",
            format!("délai de revue {} s, expiration = refus", c.delai_revue),
            "Objectifs d'usage responsable et contrôle de l'usage prévu.", &["mandat/"]),
        ctl("A.10", "Relations avec les tiers et les clients", Statut::Partiel,
            "Contrôle externe du modèle quelle que soit sa provenance.", "—".into(),
            "Répartition des responsabilités avec fournisseurs et clients.", &[]),
    ]
}

fn nis2(f: &Faits) -> Vec<Controle> {
    let c = f.c;
    vec![
        ctl("Art. 20", "Gouvernance (approbation et supervision par les organes de direction)", Statut::Partiel,
            "Mandat cosigné ; gouvernance à quatre yeux.", format!("mandat cosigné par {} personne(s)", c.signataires_mandat.len()),
            "Approbation des mesures par la direction, formation des dirigeants.", &["mandat/"]),
        ctl("Art. 21 § 2 a", "Analyse des risques et sécurité des systèmes d'information", Statut::Partiel,
            "Risques de l'agent traduits en règles et invariants, testés au banc.", f.eval.clone(),
            "Politique d'analyse des risques de l'entité.", &["mandat/", "evaluation.json"]),
        ctl("Art. 21 § 2 b", "Gestion des incidents", si(!c.siem.is_empty()),
            "Refus, gels et écarts journalisés et diffusés au SIEM ; revues notifiées aux réviseurs.", f.alerte.clone(),
            "Procédure de traitement des incidents.", &["indicateurs.json"]),
        ctl("Art. 21 § 2 c", "Continuité, sauvegardes, gestion de crise", Statut::Partiel,
            "Gel immédiat ; journal archivé et vérifiable.", f.journal.clone(), "Plan de continuité et de reprise.",
            &["journal.json"]),
        ctl("Art. 21 § 2 d", "Sécurité de la chaîne d'approvisionnement", Statut::Partiel,
            "Contrôle externe et déterministe des modèles et des outils MCP, quelle que soit leur origine.", "—".into(),
            "Évaluation des fournisseurs et clauses de sécurité.", &[]),
        ctl("Art. 21 § 2 e", "Sécurité de l'acquisition, du développement et de la maintenance", Statut::Partiel,
            "Les élargissements du mandat sont cosignés et rejouent le banc (non-régression).",
            format!("référence de non-régression {}", if c.reference_non_regression { "présente" } else { "absente" }),
            "Gestion des vulnérabilités et divulgation.", &["evaluation.json"]),
        ctl("Art. 21 § 2 f", "Évaluation de l'efficacité des mesures", si(c.evaluation.is_some()),
            "Indicateurs signés et banc rejouable.", format!("{} ; {}", f.eval, f.supervision),
            "Revue périodique des mesures.", &["indicateurs.json", "evaluation.json"]),
        ctl("Art. 21 § 2 h", "Cryptographie et chiffrement", Statut::Couvert,
            "Signatures ed25519 (mandats, réponses, scellés, indicateurs), journal chiffré, TLS vers le SIEM.",
            format!("{} scellé(s) signé(s)", c.scelles), "Politique cryptographique de l'entité.", &["journal.json", "manifeste.json"]),
        ctl("Art. 21 § 2 i", "Sécurité des ressources humaines, contrôle d'accès, gestion des actifs", si(f.quatre_yeux && c.revue_comptes),
            "Comptes nominatifs à rôles, suspension des comptes inactifs, campagnes de revue cosignées.", f.acces.clone(),
            "Gestion des arrivées et départs.", &["gouvernance/comptes.json", "gouvernance/revues/"]),
        ctl("Art. 21 § 2 j", "Authentification à plusieurs facteurs, communications sécurisées", si(c.mfa),
            "Second facteur TOTP ou attesté par le SSO pour assouplir et pour ouvrir la vue.", f.acces.clone(),
            "Généraliser l'authentification forte au reste du SI.", &["gouvernance/comptes.json"]),
        ctl("Art. 23", "Obligations d'information (alerte 24 h, notification 72 h, rapport final)", Statut::Partiel,
            "Événements horodatés avec fuseau, diffusés en continu : de quoi qualifier vite un incident lié à l'agent.",
            f.alerte.clone(), "Qualification de l'incident significatif et notification au CSIRT ou à l'autorité.",
            &["indicateurs.json", "journal.json"]),
    ]
}

/// Rapport complet d'un référentiel.
pub fn rapport(
    r: Referentiel,
    c: &Constats,
    systeme: &str,
    version_mandat: u32,
    instance: &str,
    genere: u64,
) -> Rapport {
    let controles = controles(r, c);
    let n = |s: Statut| controles.iter().filter(|x| x.statut == s).count();
    Rapport {
        schema: "aplomb.rapport/1".into(),
        referentiel: r,
        titre: r.titre().into(),
        avertissement: AVERTISSEMENT.into(),
        systeme: systeme.into(),
        version_mandat,
        instance: instance.into(),
        genere,
        synthese: Synthese {
            couvert: n(Statut::Couvert),
            partiel: n(Statut::Partiel),
            hors_perimetre: n(Statut::HorsPerimetre),
        },
        controles,
    }
}

fn libelle(s: Statut) -> &'static str {
    match s {
        Statut::Couvert => "couvert",
        Statut::Partiel => "partiel",
        Statut::HorsPerimetre => "hors périmètre",
    }
}

fn cellule(s: &str) -> String {
    s.replace(['\n', '\r'], " ").replace('|', "/")
}

/// Lecture humaine (Markdown).
pub fn markdown(r: &Rapport) -> String {
    let mut t = format!(
        "# {}\n\nSystème `{}` v{} — instance `{}`.\n\n> {}\n\n**Synthèse** : {} couvert(s), {} partiel(s), {} hors périmètre.\n\n\
         | Exigence | Objet | Statut | Apport d'Aplomb | Constat | Reste à l'organisation |\n|---|---|---|---|---|---|\n",
        r.titre, r.systeme, r.version_mandat, r.instance, r.avertissement, r.synthese.couvert, r.synthese.partiel, r.synthese.hors_perimetre
    );
    for c in &r.controles {
        t += &format!(
            "| {} | {} | **{}** | {} | {} | {} |\n",
            c.reference,
            cellule(&c.objet),
            libelle(c.statut),
            cellule(&c.apport),
            cellule(&c.constat),
            cellule(&c.reste)
        );
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constats() -> Constats {
        Constats {
            signataires_mandat: vec!["a".into(), "b".into()],
            seuil: 2,
            comptes_cosignes: true,
            approbateurs: 1,
            operateurs: 1,
            evaluation: Some((0.9, 0.95)),
            sessions_intactes: 3,
            scelles: 2,
            scelles_valides: true,
            decisions: 10,
            delai_revue: 120,
            ..Default::default()
        }
    }

    #[test]
    fn noms_des_referentiels() {
        assert_eq!(
            Referentiel::depuis("ISO-42001").unwrap(),
            Referentiel::Iso42001
        );
        assert_eq!(Referentiel::depuis("nis2").unwrap(), Referentiel::Nis2);
        assert!(Referentiel::depuis("sox").unwrap_err().contains("dora"));
    }

    #[test]
    fn les_options_changent_les_statuts() {
        let mut c = constats();
        let statut = |c: &Constats, r, x: &str| {
            controles(r, c)
                .into_iter()
                .find(|k| k.reference == x)
                .unwrap()
                .statut
        };
        assert_eq!(
            statut(&c, Referentiel::Nis2, "Art. 21 § 2 j"),
            Statut::Partiel
        );
        assert_eq!(statut(&c, Referentiel::Dora, "Art. 10"), Statut::Partiel);
        c.mfa = true;
        c.siem = vec!["ecs".into()];
        assert_eq!(
            statut(&c, Referentiel::Nis2, "Art. 21 § 2 j"),
            Statut::Couvert
        );
        assert_eq!(statut(&c, Referentiel::Dora, "Art. 10"), Statut::Couvert);
        assert_eq!(
            statut(&c, Referentiel::Iso42001, "A.6.2.8"),
            Statut::Couvert
        );
    }

    #[test]
    fn rapport_et_markdown() {
        for r in Referentiel::TOUS {
            let x = rapport(r, &constats(), "sys", 1, "inst", 0);
            assert_eq!(
                x.synthese.couvert + x.synthese.partiel + x.synthese.hors_perimetre,
                x.controles.len()
            );
            let md = markdown(&x);
            assert!(md.contains("indicatives") && md.lines().count() > x.controles.len());
        }
    }
}
