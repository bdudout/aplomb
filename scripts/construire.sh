#!/bin/sh
# Compile aplomb. (Plus de certificat ni de trousseau : la clé maîtresse est protégée par
# une phrase de passe, voir src/cle_maitresse.rs.)
set -eu
cd "$(dirname "$0")/.."
cargo build "$@"
echo "aplomb compilé : target/debug/aplomb"
