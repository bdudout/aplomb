//! Binaire **aplomb** : un seul exécutable pour le service et ses outils.
//!
//! - `aplomb serve`  — API de décision et API d'administration, sur deux ports distincts ;
//! - `aplomb hook`   — adaptateur hook Claude Code (niveau d'assurance 1), fail-closed ;
//! - `aplomb init` — parcours guidé : comptes, confiance, cosignatures (une commande) ;
//! - `aplomb cosigner` — ajoute sa signature à un mandat ou au fichier de comptes (EF-S2) ;
//! - `aplomb evaluer` — banc rouge/bleu : sûreté, utilité et coût d'un mandat (EF-H1, EF-H4) ;
//! - `aplomb verify` — vérifie le journal : chaînes, scellés, ancre (EF-I1, EF-I2) ;
//! - `aplomb ancrer` — copie la chaîne de scellés hors de la machine ;
//! - `aplomb mermaid` — exporte les sessions en diagrammes de séquence Mermaid ;
//! - `aplomb effacer` — efface les contenus d'une session en détruisant sa clé (EF-P2) ;
//! - `aplomb compte` / `aplomb admin` — comptes d'administration et requêtes signées (EF-S2) ;
//! - `aplomb agent` — comptes techniques des agents : consommation et quotas du modèle.
// Pas de code `unsafe`, sauf les appels système des deux modules qui en ont besoin
// (identité du pair d'un socket, Touch ID) ; le cœur `aplomb-core` l'interdit tout à fait.
#![deny(unsafe_code)]

mod admin;
mod agents;
mod cle_maitresse;
mod gouverner;
mod evaluer;
mod hook;
mod juge;
#[allow(unsafe_code)]
mod deverrouillage;
mod mcp;
#[allow(unsafe_code)]
mod presence;
mod modele;
mod passerelle;
mod protocole;
mod serveur;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aplomb", version, about = "Superviseur d'alignement pour agents d'IA")]
struct Cli {
    #[command(subcommand)]
    commande: Commande,
}

#[derive(Subcommand)]
enum Commande {
    /// Lance le service (API décision + API administration).
    Serve(serveur::Options),
    /// Hook Claude Code : lit l'événement sur stdin, répond sur stdout.
    Hook {
        /// Dossiers supervisés (répétable). Sans cette option, tout est supervisé. Utile
        /// quand le hook est installé en paramètres gérés, qui s'appliquent à toute la
        /// machine : hors de ces dossiers, le hook laisse décider Claude Code.
        #[arg(long)]
        perimetre: Vec<PathBuf>,
        /// Clé publique du superviseur : toute réponse non signée par elle est refusée
        /// (protège contre un faux superviseur sur le port de décision).
        #[arg(long)]
        cle_serveur: Option<PathBuf>,
        /// Mode de branchement déclaré au journal : `hook-claude-code` (niveau 1, défaut) ou
        /// `conteneur-isole` (niveau 3, hook installé par l'image du conteneur de l'agent).
        #[arg(long, default_value = "hook-claude-code", value_parser = ["hook-claude-code", "conteneur-isole"])]
        branchement: String,
    },
    /// Prépare tout en une commande : deux comptes, la confiance, les cosignatures.
    Init {
        /// Les deux personnes de la gouvernance (répéter : --membre alice --membre bob).
        #[arg(long = "membre", required = true)]
        membres: Vec<String>,
        /// Mandats à cosigner (défaut : tous ceux de mandats/).
        #[arg(long = "mandat")]
        mandats: Vec<PathBuf>,
        #[arg(long, default_value = "comptes.yaml")]
        comptes: PathBuf,
        #[arg(long, default_value = gouverner::CONFIANCE)]
        confiance: PathBuf,
    },
    /// Phrase de passe une fois pour une durée : ensuite, rien pour serve et admin gel,
    /// Touch ID (ou la phrase) pour les opérations sensibles.
    Deverrouiller {
        #[arg(long, default_value = deverrouillage::DUREE_DEFAUT, value_parser = deverrouillage::lire_duree)]
        duree: std::time::Duration,
    },
    /// Met fin au déverrouillage : la phrase sera redemandée.
    Verrouiller,
    /// Service de déverrouillage (lancé par `deverrouiller`).
    #[command(hide = true)]
    ServiceCle {
        #[arg(long)]
        secondes: u64,
    },
    /// Ajoute sa signature à un mandat ou au fichier de comptes (deux membres requis).
    /// `--compte` se répète quand plusieurs clés sont sur ce poste : une seule phrase.
    Cosigner {
        fichier: PathBuf,
        #[arg(long = "compte", required = true)]
        comptes: Vec<String>,
        #[arg(long)]
        cle: Option<PathBuf>,
        #[arg(long, default_value = gouverner::CONFIANCE)]
        confiance: PathBuf,
        /// Cosigner un mandat même s'il laisse passer des attaques que la version précédente
        /// arrêtait (EF-H4). Décision à assumer : elle est affichée.
        #[arg(long)]
        accepter_regression: bool,
    },
    /// Banc rouge/bleu : joue le jeu d'évaluation du profil avec ce mandat (signé ou non)
    /// et rend sûreté, utilité, budget d'audit et coût du juge (EF-H1, EF-H4).
    Evaluer {
        #[arg(long)]
        mandat: PathBuf,
        /// Jeu d'évaluation (défaut : evaluation.yaml à côté des règles du mandat).
        #[arg(long)]
        jeu: Option<PathBuf>,
        /// Ne pas consulter le juge du mandat (évaluation déterministe).
        #[arg(long)]
        sans_juge: bool,
        /// Part des actions qu'un humain peut revoir.
        #[arg(long, default_value_t = 0.1)]
        budget_audit: f64,
        /// Rapport précédent : échec si une attaque passe moins bien (non-régression).
        #[arg(long)]
        reference: Option<PathBuf>,
        /// Écrit le rapport (JSON), réutilisable comme référence.
        #[arg(long)]
        sortie: Option<PathBuf>,
        /// Mesure ce protocole à la place de celui du mandat : surveillance, report,
        /// reechantillonnage (EF-E2).
        #[arg(long, value_parser = protocole)]
        protocole: Option<aplomb_core::moniteurs::ModeProtocole>,
    },
    /// Vérifie le journal : chaînes, scellés signés, et copie d'ancrage si fournie.
    Verify {
        #[arg(long, default_value = "journal")]
        journal: PathBuf,
        /// Copie d'ancrage à confronter (sinon : dernière ancre connue, si elle existe).
        #[arg(long)]
        ancre: Option<PathBuf>,
        #[arg(long, default_value = "cles/reponses.pub")]
        cle_serveur: PathBuf,
    },
    /// Copie la chaîne de scellés hors de la machine (autre disque, clé USB…).
    Ancrer {
        #[arg(long)]
        vers: PathBuf,
        #[arg(long, default_value = "journal")]
        journal: PathBuf,
    },
    /// Exporte des sessions vérifiées en diagrammes de séquence Mermaid (.mmd).
    Mermaid {
        #[arg(long, default_value = "journal")]
        journal: PathBuf,
        /// Une seule session, écrite sur la sortie standard.
        #[arg(long)]
        session: Option<String>,
        /// Sans --session : dossier où écrire un fichier .mmd par session.
        #[arg(long, default_value = "diagrammes")]
        sortie: PathBuf,
        /// Nombre maximal d'entrées par diagramme (les plus récentes sont gardées).
        #[arg(long, default_value_t = 200)]
        max: usize,
        /// Montre les ressources en clair à l'aide des clés de session (sinon : références).
        #[arg(long)]
        dechiffrer: bool,
        #[arg(long, default_value = "journal-cles")]
        coffre: PathBuf,
    },
    /// Phrase de passe qui protège la clé maîtresse (première installation, changement).
    Phrase {
        #[command(subcommand)]
        commande: CommandePhrase,
    },
    /// Modèle de l'agent : jeton que le proxy LLM injecte à la place de celui de l'agent.
    Modele {
        #[command(subcommand)]
        commande: CommandeModele,
    },
    /// Enveloppe par la clé maîtresse les fichiers de clés encore en clair.
    Cles {
        #[command(subcommand)]
        commande: CommandeCles,
    },
    /// Gère les comptes d'administration.
    Compte {
        #[command(subcommand)]
        commande: CommandeCompte,
    },
    /// Comptes techniques des agents : à qui imputer la consommation du modèle.
    Agent {
        #[command(subcommand)]
        commande: CommandeAgent,
    },
    /// Requête d'administration signée par la clé d'un compte.
    Admin {
        #[arg(long)]
        compte: String,
        /// Clé privée du compte (défaut : ~/.config/aplomb/comptes/<compte>.cle).
        #[arg(long)]
        cle: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:7701")]
        url: String,
        #[command(subcommand)]
        operation: OperationAdmin,
    },
    /// Efface les contenus d'une session : sa clé est détruite, la chaîne reste vérifiable.
    Effacer {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = "journal-cles")]
        coffre: PathBuf,
    },
}

#[derive(Subcommand)]
enum CommandeCompte {
    /// Crée un compte : clé privée dans ~/.config/aplomb/comptes, clé publique dans le fichier.
    Nouveau {
        #[arg(long)]
        id: String,
        /// Rôle (répétable) : lecteur, operateur, approbateur.
        #[arg(long = "role", value_parser = role)]
        roles: Vec<aplomb_core::autorite::Role>,
        #[arg(long, default_value = "comptes.yaml")]
        fichier: PathBuf,
        #[arg(long)]
        dossier: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CommandeAgent {
    /// Crée un compte technique et affiche sa clé, une seule fois.
    Nouveau {
        #[arg(long)]
        id: String,
        /// Personne responsable de l'agent.
        #[arg(long)]
        utilisateur: String,
        /// Quota de jetons (entrée, cache compris, et sortie) par jour UTC.
        #[arg(long)]
        jetons_par_jour: Option<u64>,
        #[arg(long, default_value = agents::FICHIER)]
        fichier: PathBuf,
    },
    /// Liste les comptes techniques.
    Liste {
        #[arg(long, default_value = agents::FICHIER)]
        fichier: PathBuf,
    },
}

#[derive(Subcommand)]
enum CommandePhrase {
    /// Première installation : choisir la phrase de passe (reprend une ancienne clé du trousseau).
    Initialiser,
    /// Changer de phrase de passe.
    Changer,
}

#[derive(Subcommand)]
enum CommandeModele {
    /// Enregistre le jeton du modèle (clé d'API, ou `claude setup-token`), saisi sans affichage.
    Jeton,
}

#[derive(Subcommand)]
enum CommandeCles {
    /// Enveloppe les clés en clair : sessions, comptes, signature des réponses.
    Migrer {
        #[arg(long, default_value = "journal-cles")]
        coffre: PathBuf,
        #[arg(long)]
        comptes: Option<PathBuf>,
        #[arg(long, default_value = "cles")]
        cles: PathBuf,
    },
}

#[derive(Subcommand)]
enum OperationAdmin {
    /// Ouvre la vue technique : affiche un lien de connexion à usage unique.
    Connexion,
    /// Gèle une session, ou toutes (effet immédiat).
    Gel {
        #[arg(long)]
        session: Option<String>,
    },
    /// Demande ou approuve un dégel (deux comptes distincts requis).
    Degel {
        #[arg(long)]
        session: Option<String>,
    },
}

fn protocole(s: &str) -> Result<aplomb_core::moniteurs::ModeProtocole, String> {
    serde_json::from_value(serde_json::Value::String(s.into()))
        .map_err(|_| format!("protocole inconnu « {s} » (surveillance, report, reechantillonnage)"))
}

fn role(s: &str) -> Result<aplomb_core::autorite::Role, String> {
    serde_json::from_value(serde_json::Value::String(s.into()))
        .map_err(|_| format!("rôle inconnu « {s} » (lecteur, operateur, approbateur)"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.commande {
        Commande::Serve(opts) => serveur::lancer(opts),
        Commande::Hook { perimetre, cle_serveur, branchement } => {
            return hook::executer(&perimetre, cle_serveur.as_deref(), &branchement)
        }
        Commande::Init { membres, mandats, comptes, confiance } => {
            let mandats = if mandats.is_empty() { mandats_par_defaut() } else { mandats };
            gouverner::init(&membres, &comptes, &mandats, &confiance)
        }
        Commande::Cosigner { fichier, comptes, cle, confiance, accepter_regression } => {
            if cle.is_some() && comptes.len() > 1 {
                Err("--cle ne vaut que pour un seul --compte".into())
            } else {
                comptes.iter().try_for_each(|c| gouverner::cosigner(&fichier, c, cle.as_deref(), &confiance, accepter_regression))
            }
        }
        Commande::Evaluer { mandat, jeu, sans_juge, budget_audit, reference, sortie, protocole } => {
            evaluer::lancer(evaluer::Options { mandat, jeu, sans_juge, budget_audit, reference, sortie, protocole })
        }
        Commande::Verify { journal, ancre, cle_serveur } => verifier(&journal, ancre.as_deref(), &cle_serveur),
        Commande::Ancrer { vers, journal } => ancrer(&journal, &vers),
        Commande::Mermaid { journal, session, sortie, max, dechiffrer, coffre } => {
            let coffre = if dechiffrer { Some(coffre) } else { None };
            mermaid(&journal, session.as_deref(), &sortie, max, coffre.as_deref())
        }
        Commande::Effacer { session, coffre } => effacer(&session, &coffre),
        Commande::Phrase { commande: CommandePhrase::Initialiser } => cle_maitresse::initialiser(),
        Commande::Phrase { commande: CommandePhrase::Changer } => cle_maitresse::changer(),
        Commande::Deverrouiller { duree } => deverrouillage::deverrouiller(duree),
        Commande::Verrouiller => deverrouillage::verrouiller(),
        Commande::ServiceCle { secondes } => deverrouillage::servir(std::time::Duration::from_secs(secondes)),
        Commande::Modele { commande: CommandeModele::Jeton } => cle_maitresse::enregistrer_jeton_modele(),
        Commande::Cles { commande: CommandeCles::Migrer { coffre, comptes, cles } } => {
            migrer(&coffre, &comptes.unwrap_or_else(admin::dossier_cles), &cles)
        }
        Commande::Compte { commande: CommandeCompte::Nouveau { id, roles, fichier, dossier } } => {
            admin::nouveau_compte(&id, &roles, &dossier.unwrap_or_else(admin::dossier_cles), &fichier)
        }
        Commande::Agent { commande: CommandeAgent::Nouveau { id, utilisateur, jetons_par_jour, fichier } } => {
            agents::nouveau(&fichier, &id, &utilisateur, jetons_par_jour)
        }
        Commande::Agent { commande: CommandeAgent::Liste { fichier } } => agents::liste(&fichier),
        Commande::Admin { compte, cle, url, operation } => {
            use aplomb_core::autorite::Operation;
            let (op, session) = match operation {
                OperationAdmin::Connexion => (Operation::Connexion, None),
                OperationAdmin::Gel { session } => (Operation::Gel, session),
                OperationAdmin::Degel { session } => (Operation::Degel, session),
            };
            admin::envoyer(&compte, cle.as_deref(), &url, op, session)
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aplomb : {e}");
            ExitCode::FAILURE
        }
    }
}

fn mandats_par_defaut() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir("mandats")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    v.sort();
    v
}

/// Dernière ancre utilisée, retenue pour que `aplomb verify` la confronte sans option.
const ANCRE_CONNUE: &str = "scelles/derniere-ancre";

fn verifier(journal: &std::path::Path, ancre: Option<&std::path::Path>, cle_serveur: &std::path::Path) -> Result<(), String> {
    use aplomb_core::scellement;
    let j = aplomb_core::journal::Journal::ouvrir(journal).map_err(|e| e.to_string())?;
    let sessions = j.verifier_tout().map_err(|(f, e)| format!("ÉCHEC {f} : {e}"))?;
    println!("chaînes : {} session(s) intactes", sessions.len());
    let cle = aplomb_core::mandat::cle_publique(
        &std::fs::read_to_string(cle_serveur).map_err(|e| format!("{} : {e}", cle_serveur.display()))?,
    )
    .map_err(|e| e.to_string())?;
    let r = scellement::verifier(journal, &cle).map_err(|e| format!("ÉCHEC des scellés : {e}"))?;
    if r.scelles == 0 {
        println!("scellés : aucun encore (le superviseur scelle toutes les minutes)");
    } else {
        println!(
            "scellés : {} signés et chaînés ; {} session(s) conforme(s) au dernier, {} nouvelle(s) depuis",
            r.scelles, r.sessions_scellees, r.sessions_nouvelles
        );
        println!("témoin du dernier scellé : {}", r.temoin.unwrap_or_default());
    }
    let ancre = ancre
        .map(std::path::Path::to_path_buf)
        .or_else(|| std::fs::read_to_string(journal.join(ANCRE_CONNUE)).ok().map(|s| PathBuf::from(s.trim())));
    match ancre {
        Some(a) if a.exists() => {
            let n = scellement::verifier_ancre(journal, &a).map_err(|e| format!("ÉCHEC de l'ancre {} : {e}", a.display()))?;
            println!("ancre {} : {n} scellé(s) retrouvés à l'identique", a.display());
        }
        Some(a) => println!("ancre {} introuvable (support débranché ?) : non vérifiée", a.display()),
        None => println!("aucune ancre : aplomb ancrer --vers <autre disque> pour en créer une"),
    }
    Ok(())
}

fn ancrer(journal: &std::path::Path, vers: &std::path::Path) -> Result<(), String> {
    let cible = aplomb_core::scellement::ancrer(journal, vers)?;
    let _ = std::fs::write(journal.join(ANCRE_CONNUE), cible.display().to_string());
    let (seq, temoin) = aplomb_core::scellement::temoin(journal)?.unwrap_or_default();
    println!("chaîne de scellés copiée vers {}", cible.display());
    println!("témoin à noter ailleurs (papier, courriel à soi-même) : scellé {seq}, {temoin}");
    Ok(())
}

/// Enveloppe chaque fichier de clé encore en clair, en place (écriture atomique, 0600).
fn migrer(coffre: &std::path::Path, comptes: &std::path::Path, cles: &std::path::Path) -> Result<(), String> {
    use aplomb_core::confidentiel::{envelopper, est_enveloppe, Coffre};
    let maitre = cle_maitresse::cle_maitresse()?;
    let mut a_traiter: Vec<(PathBuf, String)> = Vec::new();
    let mut lister = |dossier: &std::path::Path, etiquette: &dyn Fn(&str) -> String| {
        for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
            let nom = e.file_name().to_string_lossy().to_string();
            if nom.ends_with(".cle") {
                a_traiter.push((e.path(), etiquette(&nom)));
            }
        }
    };
    lister(coffre, &|n| Coffre::etiquette_fichier(n));
    lister(comptes, &|n| format!("compte:{}", n.trim_end_matches(".cle")));
    a_traiter.push((cles.join("reponses.cle"), "reponses".into()));
    let (mut faits, mut deja) = (0, 0);
    for (chemin, etiquette) in a_traiter {
        let Ok(texte) = std::fs::read_to_string(&chemin) else { continue };
        if est_enveloppe(&texte) {
            deja += 1;
            continue;
        }
        let secret = hex::decode(texte.trim()).map_err(|e| format!("{} : {e}", chemin.display()))?;
        let temporaire = chemin.with_extension("cle.tmp");
        {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut f = options.open(&temporaire).map_err(|e| format!("{} : {e}", temporaire.display()))?;
            f.write_all(envelopper(&maitre, &etiquette, &secret).as_bytes()).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        std::fs::rename(&temporaire, &chemin).map_err(|e| e.to_string())?;
        faits += 1;
    }
    println!("{faits} clé(s) enveloppée(s), {deja} déjà enveloppée(s)");
    println!("l'ancien contenu en clair a été remplacé ; sur SSD, des traces peuvent subsister");
    Ok(())
}

fn effacer(session: &str, coffre: &std::path::Path) -> Result<(), String> {
    let c = aplomb_core::confidentiel::Coffre::ouvrir(coffre).map_err(|e| e.to_string())?;
    if c.effacer(session).map_err(|e| e.to_string())? {
        println!("session {session} : clé détruite, contenus effacés (la chaîne reste vérifiable)");
        Ok(())
    } else {
        Err(format!("aucune clé pour la session {session} (déjà effacée, ou journal en clair)"))
    }
}

fn mermaid(
    journal: &std::path::Path,
    session: Option<&str>,
    sortie: &std::path::Path,
    max: usize,
    coffre: Option<&std::path::Path>,
) -> Result<(), String> {
    use aplomb_core::mermaid::{lire_session, ouvrir_contenus, sequence};
    let coffre = match coffre {
        Some(d) => Some(
            aplomb_core::confidentiel::Coffre::ouvrir(d)
                .map_err(|e| e.to_string())?
                .avec_maitre(cle_maitresse::cle_maitresse()?),
        ),
        None => None,
    };
    let lire = |chemin: &std::path::Path| {
        lire_session(chemin)
            .map(|e| ouvrir_contenus(e, coffre.as_ref()))
            .map_err(|e| format!("ÉCHEC {} : {e}", chemin.display()))
    };
    if let Some(s) = session {
        let j = aplomb_core::journal::Journal::ouvrir(journal).map_err(|e| e.to_string())?;
        let chemin = j.chemin(s);
        if !chemin.exists() {
            return Err(format!("session {s} absente du journal"));
        }
        let entrees = lire(&chemin)?;
        print!("{}", sequence(&entrees, max));
        return Ok(());
    }
    std::fs::create_dir_all(sortie).map_err(|e| e.to_string())?;
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(journal)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    fichiers.sort();
    for f in &fichiers {
        // Une chaîne altérée arrête l'export : aucun diagramme d'un journal douteux.
        let entrees = lire(f)?;
        let cible = sortie.join(f.with_extension("mmd").file_name().unwrap_or_default());
        std::fs::write(&cible, sequence(&entrees, max)).map_err(|e| e.to_string())?;
    }
    println!("{} diagramme(s) écrits dans {}", fichiers.len(), sortie.display());
    Ok(())
}
