//! Panneaux d'Aplomb Watch (option) : lecture de `panneaux.yaml`.
use std::path::Path;

use aplomb_core::panneaux::ConfigPanneaux;

pub fn charger(chemin: &Path) -> Result<Option<ConfigPanneaux>, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => ConfigPanneaux::depuis_yaml(&t).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} : {e}", chemin.display())),
    }
}
