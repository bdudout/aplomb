//! `aplomb preuves` (J6) : dossier de preuves AI Act d'un système d'IA (un mandat cosigné),
//! signé par l'instance, et sa vérification par un auditeur. La correspondance et le
//! manifeste sont dans `aplomb_core::preuves` ; ici, la collecte des pièces.
//!
//! Le dossier ne contient aucun contenu d'agent ni indicateur nominatif. Il contient le
//! mandat tel que cosigné (périmètre, chemins), les clés publiques de la gouvernance et les
//! identifiants des comptes d'administration avec leurs rôles : ce sont les personnes
//! chargées du contrôle humain (art. 14, 26), qu'un auditeur doit pouvoir connaître.
use std::path::{Path, PathBuf};

use aplomb_core::autorite::{FichierComptes, Role};
use aplomb_core::gouvernance::Confiance;
use aplomb_core::indicateurs::{self, Calcul};
use aplomb_core::preuves::{self, articles, familles, Constats, Manifeste, Statut, MANIFESTE};
use serde_json::{json, Value};

use crate::vue_gouvernance::{date, maintenant, periode};

pub struct OptionsExport {
    pub mandat: PathBuf,
    pub sortie: PathBuf,
    pub journal: PathBuf,
    pub heures: Option<u64>,
    pub confiance: PathBuf,
    pub comptes: PathBuf,
    pub cle: PathBuf,
}

fn lire(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{} : {e}", p.display()))
}

fn ecrire(p: &Path, texte: &str) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{} : {e}", d.display()))?;
    }
    std::fs::write(p, texte).map_err(|e| format!("{} : {e}", p.display()))
}

fn json_joli(v: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(v).map(|s| s + "\n").map_err(|e| e.to_string())
}

fn nom(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "fichier".into())
}

/// Plus ancienne et plus récente entrée du journal (ms), toutes sessions.
fn bornes_journal(dossier: &Path) -> (Option<u64>, Option<u64>) {
    let mut bornes: (Option<u64>, Option<u64>) = (None, None);
    for f in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        if f.path().extension().is_none_or(|x| x != "jsonl") {
            continue;
        }
        let Ok(texte) = std::fs::read_to_string(f.path()) else { continue };
        let h = |l: Option<&str>| l.and_then(|l| serde_json::from_str::<Value>(l).ok()).and_then(|v| v["horodatage"].as_u64());
        let mut lignes = texte.lines().filter(|l| !l.trim().is_empty());
        if let Some(a) = h(lignes.next()) {
            bornes.0 = Some(bornes.0.map_or(a, |x| x.min(a)));
            bornes.1 = Some(bornes.1.map_or(a, |x| x.max(a)));
        }
        if let Some(b) = h(lignes.next_back()) {
            bornes.1 = Some(bornes.1.map_or(b, |x| x.max(b)));
        }
    }
    bornes
}

pub fn exporter(o: OptionsExport) -> Result<(), String> {
    let confiance = Confiance::depuis_yaml(&lire(&o.confiance)?)?;
    let (m, signataires) =
        aplomb_core::mandat::charger_cosigne(&o.mandat, &confiance).map_err(|e| format!("mandat refusé : {e} — un dossier de preuves ne vaut que pour un mandat cosigné"))?;
    if o.sortie.exists() && std::fs::read_dir(&o.sortie).map_err(|e| e.to_string())?.next().is_some() {
        return Err(format!("{} n'est pas vide : choisir un nouveau dossier", o.sortie.display()));
    }
    let cle = crate::cle_maitresse::lire_cle_privee(&o.cle, "reponses")?;
    let instance = indicateurs::identifiant_instance(&cle.verifying_key());
    let s = &o.sortie;
    let mandat = &m.mandat;
    let mut c = Constats { signataires_mandat: signataires, seuil: confiance.seuil(), ..Default::default() };

    // Mandat cosigné et sa politique.
    ecrire(&s.join("mandat").join(nom(&o.mandat)), &lire(&o.mandat)?)?;
    ecrire(&s.join("mandat").join(nom(Path::new(&mandat.politique.regles))), &m.regles)?;
    ecrire(&s.join("mandat").join(nom(Path::new(&mandat.politique.revue))), &m.revue)?;
    if let Some(mo) = &mandat.moniteurs {
        c.juge = mo.juge.is_some();
        c.protocole = mo.protocole.as_ref().map_or("surveillance".into(), |p| format!("{:?}", p.mode).to_lowercase());
    } else {
        c.protocole = "surveillance".into();
    }

    // Gouvernance : clés publiques, comptes et rôles (sans clés).
    ecrire(&s.join("gouvernance/confiance.yaml"), &lire(&o.confiance)?)?;
    let comptes = match lire(&o.comptes) {
        Ok(t) => {
            let f: FichierComptes = serde_yaml::from_str(&t).map_err(|e| format!("{} : {e}", o.comptes.display()))?;
            let cosigne = confiance.verifier(&f.octets_signes(), &f.signatures);
            c.comptes_cosignes = cosigne.is_ok();
            c.operateurs = f.comptes.iter().filter(|x| x.roles.contains(&Role::Operateur)).count();
            c.approbateurs = f.comptes.iter().filter(|x| x.roles.contains(&Role::Approbateur)).count();
            json!({"cosigne": c.comptes_cosignes, "signataires": cosigne.unwrap_or_default(),
                   "comptes": f.comptes.iter().map(|x| json!({"id": x.id, "roles": x.roles})).collect::<Vec<_>>()})
        }
        Err(e) => json!({"absent": e}),
    };
    ecrire(&s.join("gouvernance/comptes.json"), &json_joli(&comptes)?)?;

    // Banc rouge/bleu rejoué sans juge (déterministe), et référence de non-régression.
    if let Some(r) = crate::evaluer::rapport_sans_juge(&o.mandat)? {
        c.evaluation = Some((r.surete, r.utilite));
        ecrire(&s.join("evaluation.json"), &json_joli(&r)?)?;
    }
    c.reference_non_regression = crate::evaluer::chemin_reference(&o.mandat).exists();

    // Indicateurs du système, signés.
    let p = periode(o.heures);
    let calcul = Calcul { instance: &instance, systeme: Some(&mandat.id), periode: p.clone(), seuil_k: indicateurs::SEUIL_K_DEFAUT };
    let a = indicateurs::calculer(&o.journal, &calcul)?;
    c.decisions = a.decisions.total();
    c.gels = a.decisions.gel + a.administration.gels;
    c.revues = a.revues.approuvees + a.revues.refusees + a.revues.expirees;
    c.branchements = a.branchements.keys().cloned().collect();
    c.sessions_intactes = a.integrite.sessions_intactes;
    c.sessions_rompues = a.integrite.sessions_rompues;
    ecrire(&s.join("indicateurs.json"), &json_joli(&indicateurs::signer(a, &cle))?)?;

    // Journal : intégrité, scellés, ancre, conservation.
    let scelles = aplomb_core::scellement::verifier(&o.journal, &cle.verifying_key());
    c.scelles_valides = scelles.is_ok();
    c.scelles = scelles.as_ref().map_or(0, |r| r.scelles);
    let ancre = std::fs::read_to_string(o.journal.join("scelles/derniere-ancre")).ok().map(|x| PathBuf::from(x.trim()));
    let ancre_issue = match &ancre {
        Some(a) if a.exists() => aplomb_core::scellement::verifier_ancre(&o.journal, a).map(|n| format!("{n} scellé(s) retrouvé(s) à l'identique")),
        Some(_) => Err("ancre introuvable (support débranché ?)".into()),
        None => Err("aucune ancre".into()),
    };
    c.ancre_verifiee = ancre_issue.is_ok();
    (c.premiere_entree, c.derniere_entree) = bornes_journal(&o.journal);
    let journal = json!({
        "sessions_intactes": c.sessions_intactes, "sessions_rompues": c.sessions_rompues,
        "scelles": match &scelles {
            Ok(r) => json!({"valides": true, "nombre": r.scelles, "dernier": r.dernier_horodatage, "temoin": r.temoin,
                            "sessions_scellees": r.sessions_scellees, "sessions_nouvelles": r.sessions_nouvelles}),
            Err(e) => json!({"valides": false, "erreur": e}),
        },
        "ancre": match &ancre_issue { Ok(x) => json!({"verifiee": true, "detail": x}), Err(e) => json!({"verifiee": false, "detail": e}) },
        "premiere_entree": c.premiere_entree, "derniere_entree": c.derniere_entree,
        "cle_publique_scelles": hex::encode(cle.verifying_key().to_bytes()),
    });
    // La chaîne de scellés n'est pas jointe : elle nomme les fichiers de session, donc les
    // identifiants de session. Le témoin du dernier scellé suffit pour la confronter à l'ancre.
    ecrire(&s.join("journal.json"), &json_joli(&journal)?)?;

    // Correspondance et lecture humaine.
    let arts = articles(&c);
    let correspondance = json!({"avertissement": preuves::AVERTISSEMENT, "systeme": mandat.id, "version_mandat": mandat.version,
        "periode": p, "constats": c, "ai_act": arts, "familles": familles()});
    ecrire(&s.join("correspondance.json"), &json_joli(&correspondance)?)?;
    ecrire(&s.join("LISEZMOI.md"), &lisezmoi(&m, &instance, &c, &arts, &p))?;

    // Manifeste signé.
    let mut man = Manifeste {
        format: preuves::FORMAT,
        systeme: mandat.id.clone(),
        version_mandat: mandat.version,
        empreinte_mandat: m.empreinte.clone(),
        instance: instance.clone(),
        genere: maintenant(),
        aplomb: env!("CARGO_PKG_VERSION").into(),
        pieces: preuves::inventorier(s)?,
        cle_publique: String::new(),
        signature: String::new(),
    };
    man.signer(&cle);
    ecrire(&s.join(MANIFESTE), &json_joli(&man)?)?;

    println!("Dossier de preuves AI Act — système {} v{} — instance {instance}", mandat.id, mandat.version);
    for a in &arts {
        println!("  {:<22} {:<14} {}", a.article, libelle(a.statut), a.objet);
    }
    println!("  {} pièce(s) signée(s) dans {}", man.pieces.len(), s.display());
    println!("  vérifier : aplomb preuves verifier {}", s.display());
    Ok(())
}

fn libelle(s: Statut) -> &'static str {
    match s {
        Statut::Couvert => "couvert",
        Statut::Partiel => "partiel",
        Statut::HorsPerimetre => "hors périmètre",
    }
}

/// Cellule de tableau Markdown sûre (une ligne, sans barre verticale).
fn cellule(s: &str) -> String {
    s.replace(['\n', '\r'], " ").replace('|', "/")
}

fn lisezmoi(m: &aplomb_core::mandat::MandatCharge, instance: &str, c: &Constats, arts: &[preuves::Article], p: &indicateurs::Periode) -> String {
    let mandat = &m.mandat;
    let mut t = format!(
        "# Dossier de preuves AI Act — {} v{}\n\n\
         Généré le {} par Aplomb {} (instance `{instance}`).\n\n\
         - **Système** : `{}`, profil `{}`, agent `{}`.\n\
         - **Intention déclarée** : {}\n\
         - **Mandat** : empreinte `{}`, cosigné par {} (seuil {}).\n\
         - **Période des indicateurs** : {} → {}.\n\n\
         > {}\n\n\
         ## Articles de l'AI Act\n\n\
         | Article | Objet | Statut | Constat sur l'instance | Reste à l'organisation | Pièces |\n|---|---|---|---|---|---|\n",
        mandat.id,
        mandat.version,
        date(maintenant()),
        env!("CARGO_PKG_VERSION"),
        mandat.id,
        mandat.profil,
        mandat.agent,
        cellule(mandat.intention.trim()),
        &m.empreinte[..m.empreinte.len().min(16)],
        c.signataires_mandat.join(" et "),
        c.seuil,
        date(p.debut),
        date(p.fin),
        preuves::AVERTISSEMENT,
    );
    for a in arts {
        t += &format!(
            "| {} | {} | **{}** | {} | {} | {} |\n",
            a.article,
            cellule(&a.objet),
            libelle(a.statut),
            cellule(&a.constat),
            cellule(&a.reste),
            a.pieces.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(", ")
        );
    }
    t += "\n## Pièces\n\n\
          - `mandat/` : le mandat tel que cosigné, et ses règles.\n\
          - `gouvernance/` : clés publiques et seuil de la gouvernance ; comptes d'administration et leurs rôles (sans clé).\n\
          - `evaluation.json` : banc rouge/bleu rejoué sans juge à l'export (sûreté, utilité, scénarios).\n\
          - `indicateurs.json` : indicateurs agrégés du système, signés, sans rien de nominatif.\n\
          - `journal.json` : intégrité du journal, scellés, ancre, conservation ; le témoin du dernier scellé se confronte \
          à l'ancre conservée hors de la machine (la chaîne de scellés n'est pas jointe : elle nomme les sessions).\n\
          - `correspondance.json` : constats, statut par article, correspondance avec le NIST AI RMF, l'ISO/IEC 42001, l'OWASP, l'ANSSI et le CRA.\n\
          - `manifeste.json` : empreinte SHA-256 de chaque pièce, signé par l'instance.\n\n\
          ## Vérifier ce dossier\n\n\
          `aplomb preuves verifier <dossier> [--cle-pub reponses.pub]` : signature du manifeste, puis chaque pièce \
          (présente, inchangée, aucune en trop). Sans Aplomb, recalculer le SHA-256 de chaque pièce et le comparer au manifeste.\n";
    t
}

pub fn verifier(dossier: &Path, cle_pub: Option<&Path>) -> Result<(), String> {
    let attendue = cle_pub.map(lire).transpose()?;
    let v = preuves::verifier(dossier, attendue.as_deref())?;
    let m: Manifeste = serde_json::from_str(&lire(&dossier.join(MANIFESTE))?).map_err(|e| e.to_string())?;
    println!("dossier intact : système {} v{}, instance {}, {} pièce(s)", m.systeme, m.version_mandat, m.instance, v.pieces);
    println!("généré le {} ; clé de l'instance {}…", date(m.genere), &v.cle_publique[..16]);
    if attendue.is_none() {
        println!("signature vérifiée avec la clé que le manifeste déclare : confronter --cle-pub à la clé connue de l'instance");
    }
    Ok(())
}
