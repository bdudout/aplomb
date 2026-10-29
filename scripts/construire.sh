#!/bin/sh
# Compile sal puis le signe avec le certificat local « SAL dev local » : macOS garde alors
# l'autorisation d'accès au trousseau d'une compilation à l'autre (voir certificat-dev.sh).
set -eu
cd "$(dirname "$0")/.."
cargo build "$@"
NOM="SAL dev local"
if security find-identity -v -p codesigning | grep -q "$NOM"; then
  codesign -f -s "$NOM" -i fr.sal.cli target/debug/sal 2>/dev/null
  echo "sal compilé et signé (« $NOM »)"
else
  echo "sal compilé SANS signature : macOS redemandera l'accès au trousseau." >&2
  echo "Pour l'éviter, une fois : scripts/certificat-dev.sh" >&2
fi
