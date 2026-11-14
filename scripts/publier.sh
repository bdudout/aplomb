#!/bin/sh
# Construction de publication reproductible, nomenclature et signature (docs/CRA.md).
#   scripts/publier.sh --compte alice [--compte bob]
# Deux constructions depuis le même commit, sur la même chaîne d'outils, donnent le même
# binaire : chemins absolus effacés, horodatage fixé au commit, dépendances verrouillées.
# Construction optimisée : plusieurs minutes, à ne pas lancer dans le banc.
set -eu
cd "$(dirname "$0")/.."
comptes=""
while [ $# -gt 0 ]; do
  case "$1" in
    --compte) comptes="$comptes $2"; shift 2 ;;
    *) echo "usage : scripts/publier.sh --compte <id> [--compte <id>]" >&2; exit 2 ;;
  esac
done
[ -n "$comptes" ] || { echo "au moins un --compte signataire" >&2; exit 2; }
if [ -n "$(git status --porcelain)" ]; then
  echo "arbre de travail modifié : publier depuis un commit propre" >&2; exit 1
fi
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$(pwd)=/aplomb --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo -C codegen-units=1"
cargo build --release --locked -p aplomb
cible=$(rustc -vV | sed -n 's/^host: //p')
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
sortie="publication/aplomb-$version-$cible"
mkdir -p publication
cp target/release/aplomb "$sortie"
./target/release/aplomb publication sbom --sortie "$sortie.cdx.json"
( cd publication && shasum -a 256 "$(basename "$sortie")" "$(basename "$sortie").cdx.json" > "$(basename "$sortie").sha256" )
for c in $comptes; do
  ./target/release/aplomb publication signer "$sortie" --compte "$c"
  ./target/release/aplomb publication signer "$sortie.cdx.json" --compte "$c"
done
n=$(echo $comptes | wc -w | tr -d " ")
./target/release/aplomb publication verifier "$sortie" --seuil "$n"
echo "Publication prête dans publication/ (binaire, nomenclature, empreintes, signatures)."
