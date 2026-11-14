//! Publication (J12, CRA) : nomenclature logicielle, signature et vérification des livrables.
//!
//! - `aplomb publication sbom` — nomenclature CycloneDX 1.6 du binaire en cours, tirée du
//!   `Cargo.lock` compilé dedans : elle décrit exactement ce qui a été construit, sans
//!   cargo ni réseau.
//! - `aplomb publication signer <fichier> --compte <id>` — signature ed25519 de l'empreinte
//!   SHA-256 du fichier, par la clé d'un membre (`<fichier>.sig.json`).
//! - `aplomb publication verifier <fichier>` — contrôle l'empreinte et la signature, contre
//!   une clé publique donnée ou contre les membres du fichier de confiance.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const VERROU: &str = include_str!("../../../Cargo.lock");
pub const SCHEMA_SIGNATURE: &str = "aplomb.signature-publication/1";

#[derive(Debug, Default, PartialEq)]
struct Paquet {
    nom: String,
    version: String,
    source: Option<String>,
    empreinte: Option<String>,
    dependances: Vec<String>,
}

/// Lecture minimale du format `Cargo.lock` (blocs `[[package]]`).
fn paquets(verrou: &str) -> Vec<Paquet> {
    let mut v: Vec<Paquet> = Vec::new();
    let mut dans_deps = false;
    for ligne in verrou.lines() {
        let l = ligne.trim();
        if l == "[[package]]" {
            v.push(Paquet::default());
            dans_deps = false;
            continue;
        }
        let Some(p) = v.last_mut() else { continue };
        if dans_deps {
            if l == "]" {
                dans_deps = false;
            } else if let Some(d) = l.trim_end_matches(',').strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                p.dependances.push(d.to_string());
            }
            continue;
        }
        let Some((cle, val)) = l.split_once(" = ") else { continue };
        let texte = val.trim_matches('"').to_string();
        match cle {
            "name" => p.nom = texte,
            "version" => p.version = texte,
            "source" => p.source = Some(texte),
            "checksum" => p.empreinte = Some(texte),
            "dependencies" => dans_deps = val.trim() == "[",
            _ => {}
        }
    }
    v
}

fn reference(p: &Paquet) -> String {
    format!("pkg:cargo/{}@{}", p.nom, p.version)
}

/// Nomenclature CycloneDX 1.6 (JSON). `horodatage` : RFC 3339.
pub fn sbom(horodatage: &str) -> Value {
    let tous = paquets(VERROU);
    let resoudre = |d: &str| -> Option<String> {
        // « nom » ou « nom version » (plusieurs versions du même paquet).
        let mut it = d.split(' ');
        let nom = it.next()?;
        let version = it.next();
        tous.iter().find(|p| p.nom == nom && version.map_or(true, |v| v == p.version)).map(reference)
    };
    let mut composants = Vec::new();
    let mut dependances = Vec::new();
    for p in &tous {
        let interne = p.source.is_none();
        let mut c = json!({
            "type": if interne { "application" } else { "library" },
            "bom-ref": reference(p),
            "name": p.nom,
            "version": p.version,
            "purl": reference(p),
        });
        if let Some(e) = &p.empreinte {
            c["hashes"] = json!([{"alg": "SHA-256", "content": e}]);
        }
        if interne {
            c["licenses"] = json!([{"expression": if p.nom == "aplomb-core" { "Apache-2.0" } else { "EUPL-1.2" }}]);
        }
        // Le binaire lui-même est décrit dans metadata.component (bom-ref unique).
        if p.nom != "aplomb" {
            composants.push(c);
        }
        dependances.push(json!({"ref": reference(p), "dependsOn": p.dependances.iter().filter_map(|d| resoudre(d)).collect::<Vec<_>>()}));
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": horodatage,
            "tools": {"components": [{"type": "application", "name": "aplomb", "version": env!("CARGO_PKG_VERSION")}]},
            "component": {"type": "application", "bom-ref": format!("pkg:cargo/aplomb@{}", env!("CARGO_PKG_VERSION")),
                "name": "aplomb", "version": env!("CARGO_PKG_VERSION"), "licenses": [{"expression": "EUPL-1.2"}]},
        },
        "components": composants,
        "dependencies": dependances,
    })
}

pub fn ecrire_sbom(sortie: Option<&Path>) -> Result<(), String> {
    // Construction reproductible : SOURCE_DATE_EPOCH fixe l'horodatage.
    let instant = std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|s| s.parse::<i64>().ok())
        .and_then(|s| jiff::Timestamp::from_second(s).ok()).unwrap_or_else(jiff::Timestamp::now);
    let maintenant = instant.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    let texte = serde_json::to_string_pretty(&sbom(&maintenant)).map_err(|e| e.to_string())?;
    match sortie {
        Some(p) => {
            std::fs::write(p, texte + "\n").map_err(|e| format!("{} : {e}", p.display()))?;
            println!("Nomenclature CycloneDX écrite : {} ({} composants)", p.display(), paquets(VERROU).len());
        }
        None => println!("{texte}"),
    }
    Ok(())
}

fn empreinte(fichier: &Path) -> Result<String, String> {
    let octets = std::fs::read(fichier).map_err(|e| format!("{} : {e}", fichier.display()))?;
    Ok(hex::encode(Sha256::digest(&octets)))
}

fn message(nom: &str, sha256: &str) -> Vec<u8> {
    format!("{SCHEMA_SIGNATURE}\n{nom}\n{sha256}").into_bytes()
}

fn chemin_signature(fichier: &Path) -> PathBuf {
    let mut s = fichier.as_os_str().to_owned();
    s.push(".sig.json");
    PathBuf::from(s)
}

fn nom_de(fichier: &Path) -> String {
    fichier.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn signer(fichier: &Path, compte: &str, cle: Option<&Path>) -> Result<(), String> {
    let chemin_cle = cle.map(Path::to_path_buf).unwrap_or_else(|| crate::admin::dossier_cles().join(format!("{compte}.cle")));
    let privee = crate::cle_maitresse::lire_cle_privee(&chemin_cle, &format!("compte:{compte}"))?;
    let sha = empreinte(fichier)?;
    let nom = nom_de(fichier);
    let sig = privee.sign(&message(&nom, &sha));
    let sortie = chemin_signature(fichier);
    // Plusieurs membres signent le même livrable : on ajoute à la liste, tant que
    // l'empreinte n'a pas changé (sinon on repart d'une liste vide).
    let mut signatures: Vec<Value> = std::fs::read_to_string(&sortie).ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(|d| d["sha256"].as_str() == Some(sha.as_str()))
        .and_then(|d| d["signatures"].as_array().cloned())
        .unwrap_or_default();
    signatures.retain(|s| s["signataire"] != compte);
    signatures.push(json!({
        "signataire": compte,
        "cle_publique": hex::encode(privee.verifying_key().to_bytes()),
        "signature": hex::encode(sig.to_bytes()),
    }));
    let doc = json!({"schema": SCHEMA_SIGNATURE, "fichier": nom, "sha256": sha, "signatures": signatures});
    std::fs::write(&sortie, serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n").map_err(|e| format!("{} : {e}", sortie.display()))?;
    println!("Signé par {compte} : {} (SHA-256 {sha}, {} signature(s))", sortie.display(), doc["signatures"].as_array().map_or(0, Vec::len));
    Ok(())
}

fn cle_hex(h: &str) -> Result<VerifyingKey, String> {
    let o: [u8; 32] = hex::decode(h.trim()).ok().and_then(|v| v.try_into().ok()).ok_or("clé publique : 32 octets hex attendus")?;
    VerifyingKey::from_bytes(&o).map_err(|e| format!("clé publique : {e}"))
}

/// Vérifie un livrable. Clés admises : `--cle-publique` (hex ou fichier qui la contient),
/// sinon les membres du fichier de confiance. La clé portée par la signature elle-même
/// n'est jamais crue sur parole. `seuil` : nombre de signataires de confiance distincts.
pub fn verifier(fichier: &Path, signature: Option<&Path>, cle_publique: Option<&str>, confiance: &Path, seuil: usize) -> Result<(), String> {
    let chemin = signature.map(Path::to_path_buf).unwrap_or_else(|| chemin_signature(fichier));
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&chemin).map_err(|e| format!("{} : {e}", chemin.display()))?)
        .map_err(|e| format!("{} : {e}", chemin.display()))?;
    if doc["schema"] != SCHEMA_SIGNATURE {
        return Err(format!("{} : schéma inconnu", chemin.display()));
    }
    let sha = empreinte(fichier)?;
    if doc["sha256"].as_str() != Some(sha.as_str()) {
        return Err(format!("REFUSÉ : {} ne correspond pas à l'empreinte signée (fichier modifié)", fichier.display()));
    }
    let confiance_cles: Vec<(String, VerifyingKey)> = match cle_publique {
        Some(c) => {
            let texte = if Path::new(c).is_file() { std::fs::read_to_string(c).map_err(|e| format!("{c} : {e}"))? } else { c.to_string() };
            vec![("clé fournie".into(), cle_hex(&texte)?)]
        }
        None => {
            let conf: Value = serde_yaml::from_str(&std::fs::read_to_string(confiance).map_err(|e| format!("{} : {e} (ou --cle-publique)", confiance.display()))?)
                .map_err(|e| format!("{} : {e}", confiance.display()))?;
            conf["membres"].as_array().into_iter().flatten()
                .filter_map(|m| Some((m["id"].as_str()?.to_string(), cle_hex(m["cle_publique"].as_str()?).ok()?)))
                .collect()
        }
    };
    let m = message(doc["fichier"].as_str().unwrap_or_default(), &sha);
    let mut reconnus: Vec<String> = Vec::new();
    for s in doc["signatures"].as_array().into_iter().flatten() {
        let Some(sig) = s["signature"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|v| <[u8; 64]>::try_from(v).ok()).map(|o| Signature::from_bytes(&o)) else { continue };
        if let Some((id, _)) = confiance_cles.iter().find(|(_, k)| k.verify(&m, &sig).is_ok()) {
            if !reconnus.contains(id) {
                reconnus.push(id.clone());
            }
        }
    }
    if reconnus.len() >= seuil.max(1) {
        println!("OK : {} signé par {} (SHA-256 {sha})", fichier.display(), reconnus.join(", "));
        Ok(())
    } else {
        Err(format!("REFUSÉ : {} signature(s) de confiance pour {}, {} exigée(s)", reconnus.len(), fichier.display(), seuil.max(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lit_le_verrou_et_produit_une_nomenclature() {
        let p = paquets(VERROU);
        assert!(p.iter().any(|x| x.nom == "aplomb-core" && x.source.is_none()));
        assert!(p.iter().any(|x| x.nom == "serde" && x.empreinte.is_some()));
        let b = sbom("2026-11-14T00:00:00Z");
        assert_eq!(b["specVersion"], "1.6");
        assert_eq!(b["components"].as_array().unwrap().len(), p.len() - 1);
        let core = b["dependencies"].as_array().unwrap().iter().find(|d| d["ref"].as_str().unwrap().starts_with("pkg:cargo/aplomb-core@")).unwrap();
        assert!(core["dependsOn"].as_array().unwrap().iter().any(|r| r.as_str().unwrap().starts_with("pkg:cargo/serde@")));
    }
}
