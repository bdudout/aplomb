//! **Modules** (EF-M8) : un seul endroit pour voir ce qui est actif à chaque étape, ce que
//! chaque module voit et envoie, et comment l'activer ou le retirer. `aplomb modules` et
//! l'onglet « Modules » d'Aplomb Watch montrent la même liste.
use std::path::Path;

use aplomb_core::modules::{modules_du_mandat, Capacites, Etape, Facon, Module};

/// Modules propres à l'instance (hors mandat) : reporting, preuves, vue gouvernance.
/// Options de l'instance (fichiers à côté des comptes) qui ajoutent des modules.
#[derive(Default)]
pub struct Instance<'a> {
    pub clients_reporting: usize,
    pub diffusion: Option<&'a aplomb_core::diffusion::ConfigDiffusion>,
    pub identite: aplomb_core::identite::ConfigIdentite,
    pub canaux: Option<&'a aplomb_core::approbation::ConfigCanaux>,
    pub panneaux: usize,
    /// Fichier d'état partagé entre instances (`serve --etat-partage`), si actif.
    pub etat_partage: Option<String>,
}

pub fn modules_instance(i: &Instance) -> Vec<Module> {
    let (clients_reporting, diffusion, identite) = (i.clients_reporting, i.diffusion, &i.identite);
    let m = |id: &str, etape, facon, description: &str, actif, reglage: &str| Module {
        id: id.into(),
        etape,
        facon,
        description: description.into(),
        actif,
        capacites: Capacites::default(),
        version: env!("CARGO_PKG_VERSION").into(),
        empreinte: String::new(),
        reglage: reglage.into(),
    };
    let mut v = vec![
        m("scellement", Etape::Journal, Facon::Integre, "scellés Merkle signés et ancrage hors de la machine", true, "serve --scellement <s> ; aplomb ancrer"),
        m("preuves-ai-act", Etape::Reporting, Facon::Integre, "dossier de preuves AI Act signé", true, "aplomb preuves exporter --mandat …"),
        m(
            "reporting-mcp",
            Etape::Reporting,
            Facon::Integre,
            &format!("outils MCP en lecture seule pour un outil de gouvernance ({clients_reporting} client(s))"),
            clients_reporting > 0,
            "aplomb reporting nouveau --id <outil>",
        ),
        m("indicateurs", Etape::Reporting, Facon::Integre, "indicateurs non nominatifs, agrégats signés, fédération", true, "aplomb gouvernance indicateurs"),
        m("rapports-reglementaires", Etape::Reporting, Facon::Integre, "DORA, ISO/IEC 42001, NIS 2 exigence par exigence ; envoi signé à un outil GRC", true, "aplomb rapport --referentiel dora|iso42001|nis2 [--pousser <url>]"),
        m(
            "panneaux",
            Etape::Visualisation,
            Facon::Declaratif,
            &if i.panneaux > 0 { format!("{} panneau(x) déclarés : compteurs, répartitions, séries (indicateurs agrégés)", i.panneaux) } else { "tableaux de bord déclarés en YAML, sur les indicateurs agrégés".into() },
            i.panneaux > 0,
            "panneaux.yaml (docs/APPROBATION.md#panneaux)",
        ),
        m(
            "revue-priorisee",
            Etape::Approbation,
            Facon::Integre,
            "revues triées par priorité, demande enrichie (intention, avis, actions précédentes, conséquences), délai au mandat",
            true,
            "approbation: {delai_s: 300} dans le mandat",
        ),
        m("watch-gouvernance", Etape::Visualisation, Facon::Integre, "onglets Flux, Vue chaînée, Consommation, Gouvernance, Modules", true, "toujours actif"),
        m("comptes-quatre-yeux", Etape::Identite, Facon::Integre, "comptes cosignés, rôles, quatre yeux, Touch ID pour la clé", true, "aplomb compte …"),
    ];
    // État partagé (étape 5) : gels communs à plusieurs instances ; dégel toujours à quatre yeux.
    v.push(m(
        "etat-partage",
        Etape::Decision,
        Facon::Integre,
        &i.etat_partage.as_ref().map(|f| format!("gels, dégels et nonces communs aux instances du mandat ({f})")).unwrap_or_else(|| "gels, dégels et nonces communs à plusieurs instances du mandat (SQLite)".into()),
        i.etat_partage.is_some(),
        "aplomb serve --etat-partage etat.sqlite (docs/ETAT-PARTAGE.md)",
    ));
    // Identité (étape 11) : options cosignées dans comptes.yaml.
    v.push(m("mfa-totp", Etape::Identite, Facon::Integre, "second facteur TOTP : connexion à la vue, dégel, réactivation", identite.mfa_exigee(), "identite: {mfa: {}} dans comptes.yaml, puis aplomb compte mfa --compte <id>"));
    v.push(m(
        "sso-oidc",
        Etape::Identite,
        Facon::Integre,
        &identite.sso.as_ref().map(|s| format!("connexion par OpenID Connect ({}), groupes → rôles", s.emetteur)).unwrap_or_else(|| "connexion par OpenID Connect, groupes de l'annuaire → rôles".into()),
        identite.sso.is_some(),
        "identite.sso dans comptes.yaml (docs/IDENTITE.md)",
    ));
    v.push(m(
        "revue-comptes",
        Etape::Identite,
        Facon::Integre,
        &identite.revue.as_ref().map(|r| format!("suspension après {} j d'inactivité, réactivation à quatre yeux", r.inactivite_jours)).unwrap_or_else(|| "suspension des comptes inactifs, campagnes de revue cosignées".into()),
        identite.revue.is_some(),
        "identite: {revue: {inactivite_jours: 90}} dans comptes.yaml",
    ));
    // Canaux d'approbation (étape 6) : préviennent, ne décident pas.
    let canaux = i.canaux.map(|c| c.canaux.as_slice()).unwrap_or_default();
    if canaux.is_empty() {
        v.push(m("notification-revue", Etape::Approbation, Facon::Integre, "prévenir les réviseurs : Slack, Teams, ticket ITSM, courriel, webhook signé", false, "approbation.yaml (docs/APPROBATION.md)"));
    }
    for k in canaux {
        let mut x = m(&format!("canal:{}", k.id), Etape::Approbation, Facon::Integre, &format!("prévient les réviseurs ({:?}){}", k.type_, if k.details { ", avec le détail" } else { ", sans le détail" }).to_lowercase(), true, "approbation.yaml");
        x.capacites.hors_machine = true;
        x.capacites.contenus_en_clair = k.details;
        v.push(x);
    }
    // Diffusion vers le SIEM (étape 8) : une ligne par destination, ou l'option disponible.
    let destinations = diffusion.map(|c| c.destinations.as_slice()).unwrap_or_default();
    if destinations.is_empty() {
        v.push(m(
            "siem",
            Etape::Diffusion,
            Facon::Integre,
            "journal vers Elastic (ECS), Splunk (HEC), syslog RFC 5424/TLS, CEF, LEEF, OTLP, webhook signé",
            false,
            "aplomb diffusion exemple > diffusion.yaml",
        ));
    }
    for d in destinations {
        let mut x = m(&format!("siem:{}", d.id), Etape::Diffusion, Facon::Integre, &format!("journal au format {}, champs en clair seulement", d.format.nom()), true, "diffusion.yaml");
        x.capacites.hors_machine = d.fichier.is_empty();
        v.push(x);
    }
    v
}

/// Tous les modules, triés par étape.
pub fn tous(mandat: &aplomb_core::mandat::Mandat, i: &Instance) -> Vec<Module> {
    let mut v = modules_du_mandat(mandat);
    v.extend(modules_instance(i));
    v.sort_by_key(|m| m.etape);
    v
}

fn facon(f: Facon) -> &'static str {
    match f {
        Facon::Declaratif => "déclaratif",
        Facon::Integre => "intégré",
        Facon::Externe => "externe",
    }
}

/// `aplomb modules` : la liste lisible.
pub fn afficher(mandat: &Path, reporting: &Path, diffusion: &Path, comptes: &Path, approbation: &Path, panneaux: &Path, tout: bool) -> Result<(), String> {
    let m = aplomb_core::mandat::charger_candidat(mandat).map_err(|e| format!("{} : {e}", mandat.display()))?.mandat;
    let clients = crate::reporting::charger(reporting).map(|c| c.clients.len()).unwrap_or(0);
    let diffusion = crate::diffusion::charger(diffusion)?;
    let identite = std::fs::read_to_string(comptes)
        .ok()
        .and_then(|t| serde_yaml::from_str::<aplomb_core::autorite::FichierComptes>(&t).ok())
        .map(|f| f.identite)
        .unwrap_or_default();
    let canaux = crate::canaux::charger_sans_secrets(approbation)?;
    let panneaux = crate::panneaux::charger(panneaux)?.map_or(0, |p| p.panneaux.len());
    let v = tous(&m, &Instance { clients_reporting: clients, diffusion: diffusion.as_ref(), identite, canaux: canaux.as_ref(), panneaux, etat_partage: None });
    println!("Modules — mandat {} v{} (profil {}), déploiement {}", m.id, m.version, m.profil, aplomb_core::moniteurs::profil_deploiement(m.moniteurs.as_ref()));
    println!("● actif  ○ disponible — sur le chemin de décision (étapes 1 à 6), un module ne peut que durcir.");
    for (i, e) in Etape::TOUTES.iter().enumerate() {
        let de: Vec<&Module> = v.iter().filter(|x| x.etape == *e && (tout || x.actif || !x.id.starts_with("profil-"))).collect();
        if de.is_empty() {
            continue;
        }
        println!();
        println!("{} {}{}", i + 1, e.libelle(), if e.decision() { "" } else { "  (hors décision : données minimisées)" });
        for x in de {
            let mut drapeaux = Vec::new();
            if x.capacites.contenus_en_clair {
                drapeaux.push("lit les contenus");
            }
            if x.capacites.hors_machine {
                drapeaux.push("hors de la machine");
            }
            let d = if drapeaux.is_empty() { String::new() } else { format!(" [{}]", drapeaux.join(", ")) };
            println!("  {} {:<28} {:<10} {}{d}", if x.actif { "●" } else { "○" }, x.id, facon(x.facon), x.description);
            if !x.actif {
                println!("    {:<39} → {}", "", x.reglage);
            }
        }
    }
    println!();
    println!("Écrire votre propre moniteur ou filtre : docs/MODULES.md. Avec les autres profils : aplomb modules --tout");
    Ok(())
}
