#!/bin/sh
# Vérifie le confinement du niveau 3 depuis l'intérieur du conteneur de l'agent.
# Prérequis : `aplomb serve` lancé sur l'hôte, images construites.
# Usage : conteneur/verifier.sh [fichier .env]   (défaut : conteneur/.env)
set -u
cd "$(dirname "$0")"
ENV="${1:-.env}"

docker compose --env-file "$ENV" up -d aplomb-decision aplomb-gate >/dev/null 2>&1 || {
  echo "relais non démarrés (docker compose up)"; exit 1; }

docker compose --env-file "$ENV" run --rm --no-deps -T --entrypoint sh agent -s <<'EOF'
ok=0; ko=0
attendu() { # attendu <description> <oui|non> <commande…>
  d="$1"; a="$2"; shift 2
  if "$@" >/dev/null 2>&1; then r=oui; else r=non; fi
  if [ "$r" = "$a" ]; then ok=$((ok+1)); m="ok  "; else ko=$((ko+1)); m="ÉCHEC"; fi
  printf '%s %-62s (%s)\n' "$m" "$d" "$r"
}
c() { curl -sS -o /dev/null --max-time 8 -f "$@"; }
# Le hook installé par l'image, sur un événement Claude Code ; succès si la décision contient $1.
hook() {
  printf '{"session_id":"verif-conteneur","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"%s"},"cwd":"%s"}' "$2" "$PWD" \
    | /usr/local/bin/aplomb hook --branchement conteneur-isole --cle-serveur /etc/aplomb/reponses.pub | grep -q "$1"
}

attendu "Hook : lecture d'un secret refusée (réponse signée)"      oui hook '"deny"' /home/agent/.ssh/id_rsa
attendu "Hook : lecture dans le dépôt laissée à Claude Code"       oui hook '^{}$' "$PWD/calcul.py"

attendu "API de décision joignable"                                oui c http://aplomb-decision:7700/v1/health
attendu "PyPI par Aplomb Gate (domaine du mandat)"                 oui c https://pypi.org/simple/
attendu "Domaine hors mandat par Aplomb Gate"                      non c https://example.com/
# Canal modèle : toute réponse HTTP prouve que la connexion a abouti (un GET y reçoit 405).
attendu "Canal modèle (api.anthropic.com) par Aplomb Gate"          oui sh -c 'curl -s -o /dev/null --max-time 8 -w "%{http_code}" https://api.anthropic.com/v1/messages | grep -qv "^000$"'
attendu "Domaine voisin du canal modèle (anthropic.com)"            non c https://anthropic.com/
attendu "Sortie directe, sans proxy"                               non c --noproxy '*' https://pypi.org/simple/
attendu "Sortie directe par adresse IP"                            non c --noproxy '*' http://1.1.1.1/
attendu "Hôte : API d'administration (7701)"                       non c --noproxy '*' http://host.docker.internal:7701/
attendu "API d'administration via le relais de décision"           non c http://aplomb-decision:7701/
attendu "API d'administration via Aplomb Gate (adresse interne)"   non c -x http://aplomb-gate:7702 http://127.0.0.1:7701/
attendu "Résolution DNS d'un nom externe"                          non getent hosts example.com
attendu "Écriture dans les paramètres gérés"                       non sh -c 'echo {} > /etc/claude-code/managed-settings.json'
attendu "Remplacement du binaire du hook"                          non sh -c 'cp /bin/true /usr/local/bin/aplomb'
attendu "Écriture hors du dépôt (système en lecture seule)"        non touch /opt/x
attendu "Écriture dans le dépôt"                                   oui sh -c 'touch .aplomb-essai && rm .aplomb-essai'
echo
echo "$ok vérification(s) conformes, $ko échec(s)"
[ "$ko" -eq 0 ]
EOF
