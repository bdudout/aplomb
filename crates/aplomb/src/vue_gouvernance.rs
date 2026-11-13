//! `aplomb gouvernance` (J6) : indicateurs agrégés du journal, agrégats signés et
//! fédération entre instances. Le calcul est dans `aplomb_core::indicateurs` ; ici, les
//! fichiers, les clés et l'affichage.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aplomb_core::indicateurs::{self, taux, Agregat, AgregatSigne, Calcul, FichierInstances, Instance, Periode};

pub fn maintenant() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Période des `heures` dernières heures, ou tout le journal.
pub fn periode(heures: Option<u64>) -> Periode {
    let fin = maintenant();
    Periode { debut: heures.map_or(0, |h| fin.saturating_sub(h.saturating_mul(3_600_000))), fin }
}

/// Identifiant d'instance : donné, sinon dérivé de la clé publique des réponses.
pub fn instance(donnee: Option<&str>, cle_pub: &Path) -> String {
    if let Some(i) = donnee {
        return i.to_string();
    }
    std::fs::read_to_string(cle_pub)
        .ok()
        .and_then(|h| aplomb_core::mandat::cle_publique(&h).ok())
        .map_or_else(|| "aplomb-local".to_string(), |c| indicateurs::identifiant_instance(&c))
}

pub struct OptionsIndicateurs {
    pub journal: PathBuf,
    pub heures: Option<u64>,
    pub systeme: Option<String>,
    pub seuil_k: u64,
    pub signer: bool,
    pub cle: PathBuf,
    pub instance: Option<String>,
    pub sortie: Option<PathBuf>,
}

pub fn indicateurs(o: OptionsIndicateurs) -> Result<(), String> {
    let id = instance(o.instance.as_deref(), &o.cle.with_extension("pub"));
    let calcul = Calcul { instance: &id, systeme: o.systeme.as_deref(), periode: periode(o.heures), seuil_k: o.seuil_k };
    let a = indicateurs::calculer(&o.journal, &calcul)?;
    afficher(&a);
    let Some(sortie) = o.sortie else {
        if o.signer {
            return Err("--signer demande --sortie (fichier de l'agrégat signé)".into());
        }
        return Ok(());
    };
    let texte = if o.signer {
        let cle = crate::cle_maitresse::lire_cle_privee(&o.cle, "reponses")?;
        if indicateurs::identifiant_instance(&cle.verifying_key()) != id && o.instance.is_none() {
            return Err("la clé ne correspond pas à sa clé publique".into());
        }
        serde_json::to_string_pretty(&indicateurs::signer(a, &cle))
    } else {
        serde_json::to_string_pretty(&a)
    }
    .map_err(|e| e.to_string())?;
    std::fs::write(&sortie, texte + "\n").map_err(|e| format!("{} : {e}", sortie.display()))?;
    println!("\nagrégat{} écrit : {}", if o.signer { " signé" } else { "" }, sortie.display());
    Ok(())
}

/// Affiche la ligne à déclarer dans le fichier des instances de la fédération.
pub fn declarer_instance(cle_pub: &Path, id: Option<&str>) -> Result<(), String> {
    let hexa = std::fs::read_to_string(cle_pub).map_err(|e| format!("{} : {e} — lancer serve une fois pour la créer", cle_pub.display()))?;
    let cle = aplomb_core::mandat::cle_publique(&hexa).map_err(|e| e.to_string())?;
    let i = Instance { id: id.map_or_else(|| indicateurs::identifiant_instance(&cle), String::from), cle_publique: hexa.trim().into() };
    print!("{}", serde_yaml::to_string(&FichierInstances { instances: vec![i] }).map_err(|e| e.to_string())?);
    Ok(())
}

pub fn federer(fichiers: &[PathBuf], instances: &Path, sortie: Option<&Path>) -> Result<(), String> {
    let inst: FichierInstances = serde_yaml::from_str(&std::fs::read_to_string(instances).map_err(|e| format!("{} : {e}", instances.display()))?)
        .map_err(|e| format!("{} : {e}", instances.display()))?;
    let mut agregats = Vec::new();
    for f in fichiers {
        let a: AgregatSigne = serde_json::from_str(&std::fs::read_to_string(f).map_err(|e| format!("{} : {e}", f.display()))?)
            .map_err(|e| format!("{} : agrégat signé illisible ({e})", f.display()))?;
        agregats.push(a);
    }
    let f = indicateurs::federer(&agregats, &inst)?;
    println!("Fédération : {} agrégat(s) vérifié(s)", f.sources.len());
    for (i, p) in &f.sources {
        println!("  {i} : {} → {}", date(p.debut), date(p.fin));
    }
    println!();
    afficher(&f.total);
    if let Some(s) = sortie {
        std::fs::write(s, serde_json::to_string_pretty(&f).map_err(|e| e.to_string())? + "\n").map_err(|e| format!("{} : {e}", s.display()))?;
        println!("\nvue fédérée écrite : {}", s.display());
    }
    Ok(())
}

/// Date lisible (UTC) d'un horodatage en millisecondes.
pub fn date(ms: u64) -> String {
    if ms == 0 {
        return "origine".into();
    }
    let s = (ms / 1000) as i64;
    let (jours, reste) = (s.div_euclid(86_400), s.rem_euclid(86_400));
    // Algorithme civil de H. Hinnant (jours depuis 1970 → date).
    let z = jours + 719_468;
    let ere = z.div_euclid(146_097);
    let doe = z - ere * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let j = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let a = yoe + ere * 400 + i64::from(m <= 2);
    format!("{a:04}-{m:02}-{j:02} {:02}:{:02} UTC", reste / 3600, reste % 3600 / 60)
}

fn pct(x: f64) -> String {
    format!("{:.1} %", x * 100.0)
}

pub fn afficher(a: &Agregat) {
    let t = taux(a);
    println!("Vue gouvernance — instance {} — système {}", a.instance, a.systeme.as_deref().unwrap_or("tous"));
    println!("  période           : {} → {}", date(a.periode.debut), date(a.periode.fin));
    for m in &a.mandats {
        println!("  mandat            : {} v{} ({})", m.id, m.version, m.empreinte);
    }
    println!("  sessions d'agents : {}", a.sessions);
    for (b, n) in &a.branchements {
        println!("    {b:<26} {n}");
    }
    let d = &a.decisions;
    println!("  décisions         : {} (allow {}, review {}, deny {}, gel {})", d.total(), d.allow, d.review, d.deny, d.gel);
    println!("  taux              : revue {}, refus {}, gel {}, durcies par un moniteur {}", pct(t["revue"]), pct(t["refus"]), pct(t["gel"]), pct(t["durcies"]));
    if !a.regles.is_empty() {
        println!("  règles (hors allow) :");
        for (r, n) in &a.regles {
            println!("    {r:<26} {n}");
        }
    }
    if !a.moniteurs.is_empty() {
        println!("  avis suspects ou critiques :");
        for (m, n) in &a.moniteurs {
            println!("    {m:<26} {n}");
        }
    }
    if a.juge.consultations > 0 {
        println!(
            "  juge              : {} consultations, {} indisponibles ({}), {} ms en moyenne",
            a.juge.consultations,
            a.juge.indisponibles,
            pct(t["juge_indisponible"]),
            a.juge.latence_totale_ms / a.juge.consultations
        );
    }
    let r = &a.revues;
    if r.approuvees + r.refusees + r.expirees > 0 {
        println!("  revues humaines   : {} approuvées, {} refusées, {} expirées", r.approuvees, r.refusees, r.expirees);
    }
    println!("  gels / dégels     : {} / {}", a.administration.gels, a.administration.degels);
    if a.echanges_modele > 0 {
        println!("  modèle            : {} échanges, {} jetons", a.echanges_modele, a.jetons);
    }
    let i = &a.integrite;
    println!(
        "  intégrité         : {} session(s) intacte(s){}",
        i.sessions_intactes,
        if i.sessions_rompues > 0 { format!(", {} ROMPUE(S), non comptée(s)", i.sessions_rompues) } else { String::new() }
    );
    println!("  seuil de publication : catégories vues moins de {} fois regroupées sous « autres »", a.seuil_k);
}
