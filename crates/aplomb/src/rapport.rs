//! `aplomb rapport` : rapport réglementaire (DORA, ISO/IEC 42001, NIS 2) d'après l'état
//! mesuré de l'instance ; `--pousser` l'envoie, signé par l'instance, à un outil GRC.
use std::path::PathBuf;

use aplomb_core::rapports::{self, Referentiel};
use ed25519_dalek::Signer;
use serde_json::json;

#[derive(clap::Args)]
pub struct Options {
    /// dora, iso42001 ou nis2.
    #[arg(long)]
    pub referentiel: String,
    /// Mandat du système (défaut : le premier de mandats/).
    #[arg(long)]
    pub mandat: Option<PathBuf>,
    #[arg(long, default_value = "journal")]
    pub journal: PathBuf,
    /// Indicateurs des dernières heures seulement (défaut : tout le journal).
    #[arg(long)]
    pub heures: Option<u64>,
    #[arg(long, default_value = crate::gouverner::CONFIANCE)]
    pub confiance: PathBuf,
    #[arg(long, default_value = "comptes.yaml")]
    pub comptes: PathBuf,
    /// Clé publique de l'instance (rapport non signé).
    #[arg(long, default_value = "cles/reponses.pub")]
    pub cle_pub: PathBuf,
    /// Clé de l'instance (pour signer l'envoi).
    #[arg(long, default_value = "cles/reponses.cle")]
    pub cle: PathBuf,
    /// md (défaut) ou json.
    #[arg(long, default_value = "md")]
    pub format: String,
    /// Écrire dans ce fichier plutôt qu'à l'écran.
    #[arg(long)]
    pub sortie: Option<PathBuf>,
    /// Envoyer le rapport signé à cette adresse (HTTPS, ou HTTP vers la machine locale).
    #[arg(long)]
    pub pousser: Option<String>,
    /// Variable d'environnement qui contient le jeton de l'outil destinataire.
    #[arg(long)]
    pub jeton_env: Option<String>,
}

fn locale(url: &str) -> bool {
    aplomb_core::diffusion::hote_url(url).is_some_and(|(s, h)| {
        s == "https" || (s == "http" && matches!(h, "127.0.0.1" | "localhost" | "::1"))
    })
}

pub fn executer(o: Options) -> Result<(), String> {
    let r = Referentiel::depuis(&o.referentiel)?;
    if !matches!(o.format.as_str(), "md" | "json") {
        return Err("--format md ou json".into());
    }
    let mandat = o
        .mandat
        .clone()
        .ok_or("aucun mandat dans mandats/ : aplomb rapport --mandat <fichier> …")?;
    if let Some(u) = &o.pousser {
        if !locale(u) {
            return Err(format!(
                "{u} : HTTPS requis (HTTP accepté seulement vers 127.0.0.1)"
            ));
        }
    }
    let (cle_priv, cle_pub) = if o.pousser.is_some() {
        let k = crate::cle_maitresse::lire_cle_privee(&o.cle, "reponses")?;
        let p = k.verifying_key();
        (Some(k), p)
    } else {
        let h = std::fs::read_to_string(&o.cle_pub)
            .map_err(|e| format!("{} : {e} (clé publique de l'instance)", o.cle_pub.display()))?;
        (
            None,
            aplomb_core::mandat::cle_publique(&h)
                .map_err(|e| format!("{} : {e}", o.cle_pub.display()))?,
        )
    };
    let instance = aplomb_core::indicateurs::identifiant_instance(&cle_pub);
    let src = crate::preuves::Sources {
        mandat: &mandat,
        journal: &o.journal,
        heures: o.heures,
        confiance: &o.confiance,
        comptes: &o.comptes,
    };
    let col = crate::preuves::collecter(&src, &instance, &cle_pub)?;
    let x = rapports::rapport(
        r,
        &col.constats,
        &col.m.mandat.id,
        col.m.mandat.version,
        &instance,
        crate::identite::maintenant(),
    );

    if let (Some(url), Some(k)) = (&o.pousser, &cle_priv) {
        let octets = serde_json::to_vec(&x).map_err(|e| e.to_string())?;
        let corps = json!({"schema": "aplomb.rapport/1", "rapport": x, "cle_publique": hex::encode(cle_pub.to_bytes()),
                           "signature": hex::encode(k.sign(&octets).to_bytes())});
        let jeton = match &o.jeton_env {
            Some(v) => Some(std::env::var(v).map_err(|_| {
                format!("variable {v} absente : y mettre le jeton de l'outil destinataire")
            })?),
            None => None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let statut = rt.block_on(async {
            let c = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .map_err(|e| e.to_string())?;
            let mut q = c
                .post(url)
                .header("content-type", "application/json")
                .header("x-aplomb-schema", "aplomb.rapport/1");
            if let Some(j) = &jeton {
                q = q.header("authorization", format!("Bearer {j}"));
            }
            q.body(serde_json::to_vec(&corps).map_err(|e| e.to_string())?)
                .send()
                .await
                .map(|r| r.status())
                .map_err(|e| format!("{url} injoignable : {e}"))
        })?;
        if !statut.is_success() {
            return Err(format!(
                "{url} a répondu {} : rapport non accepté",
                statut.as_u16()
            ));
        }
        println!("Rapport {} envoyé, signé par l'instance {instance} : {} couvert(s), {} partiel(s), {} hors périmètre.", r.court(), x.synthese.couvert, x.synthese.partiel, x.synthese.hors_perimetre);
        return Ok(());
    }

    let texte = if o.format == "json" {
        serde_json::to_string_pretty(&x).map_err(|e| e.to_string())? + "\n"
    } else {
        rapports::markdown(&x)
    };
    match &o.sortie {
        Some(f) => {
            std::fs::write(f, texte).map_err(|e| format!("{} : {e}", f.display()))?;
            println!(
                "{} : {} couvert(s), {} partiel(s), {} hors périmètre → {}",
                r.titre(),
                x.synthese.couvert,
                x.synthese.partiel,
                x.synthese.hors_perimetre,
                f.display()
            );
        }
        None => print!("{texte}"),
    }
    Ok(())
}
