#!/bin/sh
# À lancer UNE FOIS : crée le certificat local « SAL dev local » qui signe le binaire sal.
#
# Pourquoi : sans signature, macOS reconnaît sal à son empreinte exacte, qui change à
# chaque compilation, et redemande alors l'accès au trousseau (mot de passe). Signé par ce
# certificat, sal est reconnu par « identifiant fr.sal.cli + certificat » : l'autorisation
# « Toujours autoriser » survit aux recompilations.
#
# Ce que macOS te demandera (une fois) : ton mot de passe pour faire confiance au
# certificat. Ensuite, au premier lancement du sal signé, « Toujours autoriser ».
set -eu
NOM="SAL dev local"
TROUSSEAU="$HOME/Library/Keychains/login.keychain-db"

if security find-identity -v -p codesigning | grep -q "$NOM"; then
  echo "le certificat « $NOM » existe déjà : rien à faire"
  exit 0
fi

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cat > "$T/ext.cnf" <<EOF
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=$NOM
[ext]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout "$T/cle.pem" -out "$T/cert.pem" -config "$T/ext.cnf" 2>/dev/null
MDP=$(openssl rand -hex 16)
openssl pkcs12 -export -inkey "$T/cle.pem" -in "$T/cert.pem" -name "$NOM" -out "$T/id.p12" -passout "pass:$MDP" 2>/dev/null
# Seul codesign peut utiliser la clé privée sans demander.
security import "$T/id.p12" -k "$TROUSSEAU" -P "$MDP" -T /usr/bin/codesign >/dev/null
echo "macOS va demander ton mot de passe pour faire confiance au certificat de signature (une seule fois)."
security add-trusted-cert -r trustRoot -p codeSign -k "$TROUSSEAU" "$T/cert.pem"
echo "certificat « $NOM » prêt. Compiler désormais avec : scripts/construire.sh"
