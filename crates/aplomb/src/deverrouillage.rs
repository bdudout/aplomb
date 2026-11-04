//! **Déverrouillage** : la phrase de passe une fois, pour une durée choisie (8 h par défaut).
//!
//! `aplomb deverrouiller` ouvre la clé maîtresse et la confie à un petit service local,
//! joignable par un socket réservé à l'utilisateur (`~/.config/aplomb/agent.sock`, 0600).
//! Les commandes suivantes lui demandent la clé au lieu de redemander la phrase :
//!
//! - sans rien demander pour ce qui ne peut pas relâcher la supervision : `serve`,
//!   `admin … gel` ;
//! - avec une **preuve de présence** pour tout le reste (cosigner, dégeler, se connecter à
//!   Aplomb Watch, déchiffrer…) : Touch ID sur macOS ; ailleurs, la phrase de passe.
//!
//! L'agent tourne sous le même utilisateur (niveau 1) et peut donc joindre le socket. Le
//! service ne remet la clé qu'au binaire `aplomb` lui-même (chemin vérifié par le système,
//! pas déclaré par le client), et la fenêtre de présence montre la ligne de commande réelle
//! du demandeur, lue par le service : un agent ne peut ni se faire passer pour `serve`, ni
//! déguiser un `cosigner`. Le service refuse d'être inspecté par un autre processus
//! (`PT_DENY_ATTACH` sur macOS, `PR_SET_DUMPABLE` sur Linux). Au niveau 3, l'agent confiné
//! n'a aucun accès au socket.
use std::path::PathBuf;
use std::time::Duration;

/// Durée par défaut et durée maximale du déverrouillage.
pub const DUREE_DEFAUT: &str = "8h";
const DUREE_MAX: Duration = Duration::from_secs(24 * 3600);

pub fn chemin_socket() -> PathBuf {
    crate::cle_maitresse::dossier_config().join("agent.sock")
}

/// Durée lisible : `8h`, `30m`, `90s`.
pub fn lire_duree(texte: &str) -> Result<Duration, String> {
    let t = texte.trim();
    let (nombre, unite) = t.split_at(t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len()));
    let n: u64 = nombre.parse().map_err(|_| format!("durée « {texte} » : ex. 8h, 30m"))?;
    let secondes = match unite {
        "h" => n * 3600,
        "m" | "min" => n * 60,
        "s" | "" => n,
        _ => return Err(format!("durée « {texte} » : unité h, m ou s")),
    };
    let d = Duration::from_secs(secondes);
    if d.is_zero() || d > DUREE_MAX {
        return Err("durée entre 1 s et 24 h".into());
    }
    Ok(d)
}

/// La commande (arguments après `aplomb`) exige-t-elle une preuve de présence ? Seules
/// `serve` et `admin … gel` s'en passent : elles ne peuvent que superviser ou durcir.
pub fn exige_presence(args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("serve") => false,
        Some("admin") => {
            // Toutes les options d'`admin` prennent une valeur : la première position libre
            // est l'opération.
            let mut i = 1;
            while i < args.len() && args[i].starts_with("--") {
                i += if args[i].contains('=') { 1 } else { 2 };
            }
            args.get(i).map(String::as_str) != Some("gel")
        }
        _ => true,
    }
}

#[cfg(not(unix))]
pub fn deverrouiller(_duree: Duration) -> Result<(), String> {
    Err("déverrouillage pas encore disponible sur ce système : la phrase est demandée à chaque commande".into())
}

#[cfg(not(unix))]
pub fn verrouiller() -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
pub fn servir(_duree: Duration) -> Result<(), String> {
    Err("non disponible sur ce système".into())
}

#[cfg(not(unix))]
pub fn demander_cle() -> Option<Result<aplomb_core::confidentiel::Cle, String>> {
    None
}

#[cfg(unix)]
pub use unix::{demander_cle, deverrouiller, servir, verrouiller};

#[cfg(unix)]
mod unix {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};

    use aplomb_core::confidentiel::Cle;
    use serde_json::{json, Value};

    use super::{chemin_socket, exige_presence};
    use crate::presence::{confirmer, Presence};

    fn requete(op: &str) -> Option<Value> {
        let mut flux = UnixStream::connect(chemin_socket()).ok()?;
        // La preuve de présence peut prendre le temps d'un geste.
        flux.set_read_timeout(Some(Duration::from_secs(130))).ok()?;
        writeln!(flux, "{}", json!({"op": op})).ok()?;
        let mut ligne = String::new();
        BufReader::new(flux).read_line(&mut ligne).ok()?;
        serde_json::from_str(&ligne).ok()
    }

    fn decoder(hex_cle: &str) -> Option<Cle> {
        hex::decode(hex_cle).ok()?.try_into().ok()
    }

    /// Clé maîtresse par le service, s'il tourne. `None` : pas de service, ou pas de preuve
    /// de présence possible ici — l'appelant demande la phrase de passe.
    pub fn demander_cle() -> Option<Result<Cle, String>> {
        let r = requete("cle")?;
        if let Some(c) = r.get("cle").and_then(Value::as_str) {
            return Some(decoder(c).ok_or_else(|| "réponse du service illisible".to_string()));
        }
        match r.get("erreur").and_then(Value::as_str) {
            Some(e) => Some(Err(format!("service de déverrouillage : {e}"))),
            None => None,
        }
    }

    pub fn deverrouiller(duree: Duration) -> Result<(), String> {
        if let Some(r) = requete("etat") {
            let reste = r.get("reste").and_then(Value::as_u64).unwrap_or(0);
            println!("déjà déverrouillé (encore {} min) ; aplomb verrouiller pour finir", reste / 60);
            return Ok(());
        }
        let cle = crate::cle_maitresse::cle_maitresse_par_phrase()?;
        let mut service = std::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
        use std::os::unix::process::CommandExt;
        service
            .args(["service-cle", "--secondes", &duree.as_secs().to_string()])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            // Hors du groupe du terminal : un Ctrl-C ne l'arrête pas.
            .process_group(0);
        let mut enfant = service.spawn().map_err(|e| format!("lancement du service : {e}"))?;
        let mut entree = enfant.stdin.take().ok_or("entrée du service")?;
        writeln!(entree, "{}", hex::encode(cle)).map_err(|e| e.to_string())?;
        drop(entree);
        let mut ligne = String::new();
        BufReader::new(enfant.stdout.take().ok_or("sortie du service")?).read_line(&mut ligne).map_err(|e| e.to_string())?;
        if ligne.trim() != "pret" {
            return Err(format!("le service n'a pas démarré : {}", ligne.trim()));
        }
        let s = duree.as_secs();
        let lisible = if s >= 3600 { format!("{} h {:02} min", s / 3600, s % 3600 / 60) } else { format!("{} min", s.div_ceil(60)) };
        println!("Aplomb déverrouillé pour {lisible}.");
        println!("  serve et admin gel : sans rien demander ;");
        println!(
            "  opérations sensibles (cosigner, dégeler, se connecter, déchiffrer) : {}.",
            if cfg!(target_os = "macos") { "Touch ID" } else { "phrase de passe" }
        );
        println!("Pour finir avant : aplomb verrouiller");
        Ok(())
    }

    pub fn verrouiller() -> Result<(), String> {
        match requete("arreter") {
            Some(_) => println!("Aplomb verrouillé : la phrase sera redemandée."),
            None => println!("Aplomb n'était pas déverrouillé."),
        }
        Ok(())
    }

    /// Interdit l'inspection de la mémoire du service par un autre processus.
    fn durcir() {
        // SAFETY : appels système sans pointeur.
        unsafe {
            #[cfg(target_os = "macos")]
            libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }

    /// Service (sous-commande cachée `service-cle`) : lit la clé sur son entrée, puis sert.
    pub fn servir(duree: Duration) -> Result<(), String> {
        durcir();
        let mut ligne = String::new();
        std::io::stdin().read_line(&mut ligne).map_err(|e| e.to_string())?;
        let cle = decoder(ligne.trim()).ok_or("clé illisible")?;
        let chemin = chemin_socket();
        let _ = std::fs::remove_file(&chemin);
        // Socket créé en 0600 d'emblée, dans le dossier 0700 de la configuration.
        // SAFETY : umask n'a pas de précondition.
        let ancien = unsafe { libc::umask(0o177) };
        let ecoute = UnixListener::bind(&chemin).map_err(|e| format!("{} : {e}", chemin.display()));
        unsafe { libc::umask(ancien) };
        let ecoute = ecoute?;
        let moi = std::env::current_exe().and_then(|p| p.canonicalize()).map_err(|e| e.to_string())?;
        let fin = Instant::now() + duree;
        let chemin_fin = chemin.clone();
        std::thread::spawn(move || {
            std::thread::sleep(duree);
            let _ = std::fs::remove_file(&chemin_fin);
            std::process::exit(0);
        });
        println!("pret");
        let _ = std::io::stdout().flush();
        // Une demande à la fois : une seule fenêtre de présence à l'écran.
        for flux in ecoute.incoming().flatten() {
            if traiter(flux, &cle, &moi, fin) {
                let _ = std::fs::remove_file(&chemin);
                return Ok(());
            }
        }
        Ok(())
    }

    /// Rend vrai pour arrêter le service.
    fn traiter(mut flux: UnixStream, cle: &Cle, moi: &std::path::Path, fin: Instant) -> bool {
        let _ = flux.set_read_timeout(Some(Duration::from_secs(5)));
        let mut ligne = String::new();
        if BufReader::new(&flux).read_line(&mut ligne).is_err() {
            return false;
        }
        let op = serde_json::from_str::<Value>(&ligne).ok().and_then(|v| v.get("op").and_then(Value::as_str).map(String::from));
        let pair = pair::lire(&flux);
        // Une seule écriture : la réponse arrive d'un bloc.
        let mut repondre = |v: Value| {
            let _ = flux.write_all(format!("{v}\n").as_bytes());
        };
        let Some(pair) = pair else {
            repondre(json!({"erreur": "demandeur inconnu"}));
            return false;
        };
        // SAFETY : getuid n'a pas de précondition.
        if pair.uid != unsafe { libc::getuid() } {
            repondre(json!({"erreur": "autre utilisateur"}));
            return false;
        }
        match op.as_deref() {
            Some("etat") => repondre(json!({"reste": fin.saturating_duration_since(Instant::now()).as_secs()})),
            Some("arreter") => {
                repondre(json!({"ok": true}));
                return true;
            }
            Some("cle") => {
                if pair.exe.as_deref() != Some(moi) {
                    repondre(json!({"erreur": "seul le binaire aplomb reçoit la clé"}));
                    return false;
                }
                let args = pair.args.get(1..).unwrap_or_default().to_vec();
                if exige_presence(&args) {
                    let raison = format!("autoriser « aplomb {} »", args.join(" "));
                    match confirmer(&raison) {
                        Presence::Confirmee => {}
                        Presence::Indisponible => {
                            repondre(json!({"presence": "indisponible"}));
                            return false;
                        }
                        Presence::Refusee(m) => {
                            repondre(json!({"erreur": format!("présence non confirmée ({m})")}));
                            return false;
                        }
                    }
                }
                repondre(json!({"cle": hex::encode(cle)}));
            }
            _ => repondre(json!({"erreur": "opération inconnue"})),
        }
        false
    }

    /// Identité du processus à l'autre bout du socket, lue auprès du système.
    mod pair {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::path::PathBuf;

        pub struct Pair {
            pub uid: libc::uid_t,
            pub exe: Option<PathBuf>,
            pub args: Vec<String>,
        }

        #[cfg(target_os = "linux")]
        pub fn lire(flux: &UnixStream) -> Option<Pair> {
            let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
            let mut taille = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            // SAFETY : tampon et taille cohérents.
            let r = unsafe {
                libc::getsockopt(flux.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut _, &mut taille)
            };
            if r != 0 {
                return None;
            }
            let exe = std::fs::read_link(format!("/proc/{}/exe", cred.pid)).ok();
            let args = std::fs::read(format!("/proc/{}/cmdline", cred.pid))
                .ok()?
                .split(|o| *o == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect();
            Some(Pair { uid: cred.uid, exe, args })
        }

        #[cfg(target_os = "macos")]
        pub fn lire(flux: &UnixStream) -> Option<Pair> {
            const SOL_LOCAL: libc::c_int = 0;
            const LOCAL_PEERPID: libc::c_int = 2;
            let fd = flux.as_raw_fd();
            let (mut uid, mut gid) = (0, 0);
            let mut pid: libc::pid_t = 0;
            let mut taille = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
            // SAFETY : tampons et tailles cohérents.
            unsafe {
                if libc::getpeereid(fd, &mut uid, &mut gid) != 0
                    || libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &mut pid as *mut _ as *mut _, &mut taille) != 0
                {
                    return None;
                }
            }
            let mut tampon = vec![0u8; 4096];
            // SAFETY : tampon de la taille annoncée.
            let n = unsafe { libc::proc_pidpath(pid, tampon.as_mut_ptr() as *mut _, tampon.len() as u32) };
            let exe = (n > 0).then(|| PathBuf::from(String::from_utf8_lossy(&tampon[..n as usize]).to_string()));
            let exe = exe.and_then(|p| p.canonicalize().ok());
            Some(Pair { uid, exe, args: arguments(pid).unwrap_or_default() })
        }

        /// Arguments d'un processus (`KERN_PROCARGS2` : argc, chemin, puis argv).
        #[cfg(target_os = "macos")]
        fn arguments(pid: libc::pid_t) -> Option<Vec<String>> {
            let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
            let mut taille: libc::size_t = 0;
            // SAFETY : première requête pour la taille, seconde avec un tampon de cette taille.
            unsafe {
                if libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut taille, std::ptr::null_mut(), 0) != 0 {
                    return None;
                }
                let mut tampon = vec![0u8; taille];
                if libc::sysctl(mib.as_mut_ptr(), 3, tampon.as_mut_ptr() as *mut _, &mut taille, std::ptr::null_mut(), 0) != 0 {
                    return None;
                }
                tampon.truncate(taille);
                let argc = i32::from_ne_bytes(tampon.get(..4)?.try_into().ok()?) as usize;
                let mut reste = tampon[4..].split(|o| *o == 0).filter(|a| !a.is_empty());
                reste.next()?; // chemin de l'exécutable
                Some(reste.take(argc).map(|a| String::from_utf8_lossy(a).to_string()).collect())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn seules_les_commandes_sans_risque_s_en_passent() {
        assert!(!exige_presence(&a("serve --mandat m.yaml")));
        assert!(!exige_presence(&a("admin --compte alice gel")));
        assert!(!exige_presence(&a("admin --compte=alice gel --session s")));
        assert!(!exige_presence(&a("admin --compte alice --url http://x gel")));
        assert!(exige_presence(&a("admin --compte alice degel")));
        assert!(exige_presence(&a("admin --compte alice connexion")));
        assert!(exige_presence(&a("admin --compte gel degel")), "la valeur d'une option n'est pas l'opération");
        assert!(exige_presence(&a("cosigner m.yaml --compte alice")));
        assert!(exige_presence(&a("mermaid --dechiffrer")));
        assert!(exige_presence(&[]));
    }

    #[test]
    fn durees() {
        assert_eq!(lire_duree("8h").unwrap(), Duration::from_secs(8 * 3600));
        assert_eq!(lire_duree("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(lire_duree("90").unwrap(), Duration::from_secs(90));
        assert!(lire_duree("25h").is_err());
        assert!(lire_duree("0s").is_err());
        assert!(lire_duree("8j").is_err());
    }
}
