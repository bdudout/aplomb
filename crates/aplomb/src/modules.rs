//! **Modules** (EF-M8) : un seul endroit pour voir ce qui est actif à chaque étape, ce que
//! chaque module voit et envoie, et comment l'activer ou le retirer. `aplomb modules` et
//! l'onglet « Modules » d'Aplomb Watch montrent la même liste.
use std::path::Path;

use aplomb_core::modules::{modules_du_mandat, Capacites, Etape, Facon, Module};

/// Modules propres à l'instance (hors mandat) : reporting, preuves, vue gouvernance.
pub fn modules_instance(clients_reporting: usize) -> Vec<Module> {
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
    vec![
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
        m("watch-gouvernance", Etape::Visualisation, Facon::Integre, "onglets Flux, Vue chaînée, Consommation, Gouvernance, Modules", true, "toujours actif"),
        m("comptes-quatre-yeux", Etape::Identite, Facon::Integre, "comptes cosignés, rôles, quatre yeux, Touch ID pour la clé", true, "aplomb compte …"),
    ]
}

/// Tous les modules, triés par étape.
pub fn tous(mandat: &aplomb_core::mandat::Mandat, clients_reporting: usize) -> Vec<Module> {
    let mut v = modules_du_mandat(mandat);
    v.extend(modules_instance(clients_reporting));
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
pub fn afficher(mandat: &Path, reporting: &Path, tout: bool) -> Result<(), String> {
    let m = aplomb_core::mandat::charger_candidat(mandat).map_err(|e| format!("{} : {e}", mandat.display()))?.mandat;
    let clients = crate::reporting::charger(reporting).map(|c| c.clients.len()).unwrap_or(0);
    let v = tous(&m, clients);
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
