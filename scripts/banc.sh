#!/bin/sh
# Banc d'essai autonome : une instance d'Aplomb jetable (phrase, comptes, mandat, jeton et
# journal à elle, dans un dossier temporaire), un faux modèle, puis le parcours complet
# d'un agent confiné rejoué : appel au modèle par le proxy, hook avec identifiant d'appel,
# vue chaînée lue par l'API d'Aplomb Watch ; passerelle MCP, provenance, délégation. Ne touche ni à ~/.config/aplomb ni au journal réel.
# Usage : scripts/banc.sh [--garder]   (--garder : laisse le dossier pour inspection)
set -eu
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
APLOMB="$RACINE/target/debug/aplomb"
# Chemin réel (macOS : /var est un lien vers /private/var), comme le calcule le hook.
B="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/aplomb-banc.XXXXXX")" && pwd -P)"
P=178   # ports 17800 (décision) à 17803 (proxy LLM), 17804 (faux modèle), 17805 (MCP)
PIDS=""
fin() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
  if [ "${1:-}" = "--garder" ]; then echo "dossier gardé : $B"; else rm -rf "$B"; fi
}
trap 'fin "${GARDER:-}"' EXIT
[ "${1:-}" = "--garder" ] && GARDER=--garder

# Secrets jetables : variables réservées aux tests, jamais en usage réel.
export HOME="$B/maison" APLOMB_PHRASE="phrase-jetable-du-banc" APLOMB_JETON_MODELE="faux-jeton-du-banc-0123456789"
export APLOMB_URL="http://127.0.0.1:${P}00"
mkdir -p "$HOME" "$B/depot" "$B/mandats"
cp -R "$RACINE/profils" "$B/"
cat > "$B/mandats/banc.yaml" <<EOF
id: banc
version: 1
profil: code
agent: claude-code
intention: Banc d'essai d'Aplomb.
perimetre:
  racine: $B/depot
  domaines_autorises: [docs.python.org]
  branches_protegees: [main]
  domaines_modele: ["http://127.0.0.1:${P}04"]
  serveurs_mcp:
  - {nom: notes, commande: [python3, "$RACINE/scripts/faux-mcp.py"], outils: [chercher]}
politique:
  regles: ../profils/code/regles.cedar
  revue: ../profils/code/revue.cedar
bornes: {refus: 5, revues: 20, domaines: 10, envois: 3, actions: 2000}
EOF
# Mandats de sous-agents : « Explore » cantonné à docs/ ; « Large » déborde du parent.
enfant() {  # id, type, racine, domaines
  cat > "$B/mandats/$1.yaml" <<EOF
id: $1
version: 1
profil: code
agent: claude-code/$2
parent: banc
intention: Sous-agent du banc.
perimetre:
  racine: $3
  domaines_autorises: [$4]
  branches_protegees: [main]
politique:
  regles: ../profils/code/regles.cedar
  revue: ../profils/code/revue.cedar
bornes: {refus: 5, revues: 20, domaines: 10, envois: 3, actions: 2000}
EOF
}
enfant explorer Explore "$B/depot/docs" docs.python.org
enfant large Large "$B/depot" "docs.python.org, evil.example"
mkdir -p "$B/depot/docs"

ok=0; ko=0
verifier() {  # libellé, condition (code shell)
  if eval "$2"; then ok=$((ok + 1)); printf '  ok   %s\n' "$1"; else ko=$((ko + 1)); printf '  ÉCHEC %s\n' "$1"; fi
}

cd "$B"
"$APLOMB" init --membre alice --membre bob --mandat mandats/banc.yaml --mandat mandats/explorer.yaml \
  --mandat mandats/large.yaml > init.log 2>&1
"$APLOMB" modele jeton > jeton.log 2>&1
python3 "$RACINE/scripts/faux-modele.py" "${P}04" requetes.jsonl & PIDS="$PIDS $!"
"$APLOMB" serve --mandat mandats/banc.yaml --ecoute-decision "127.0.0.1:${P}00" --ecoute-admin "127.0.0.1:${P}01" \
  --ecoute-passerelle "127.0.0.1:${P}02" --ecoute-llm "127.0.0.1:${P}03" --ecoute-mcp "127.0.0.1:${P}05" \
  --mandat-enfant mandats/explorer.yaml > serve.log 2>&1 & PIDS="$PIDS $!"
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:${P}01/" && break; sleep 0.1; done

S="agent-banc-$$"
echo "--- Proxy LLM"
appel_modele() {
  curl -s -X POST "http://127.0.0.1:${P}03/v1/messages" -H "x-api-key: sk-ant-api03-cle-de-l-agent" \
    -H "x-claude-code-session-id: $S" -H "content-type: application/json" \
    -d '{"model":"faux-modele","messages":[{"role":"user","content":"ls"}]}'
}
R1="$(appel_modele)"
verifier "réponse du modèle relayée (outil demandé)" 'printf %s "$R1" | grep -q toolu_banc_1'
verifier "clé de l'agent retirée" '! grep -q cle-de-l-agent requetes.jsonl'
verifier "jeton d'Aplomb injecté en Bearer" 'grep -q "Bearer faux-jeton-du-banc" requetes.jsonl'
verifier "chemin hors conversation refusé" \
  '[ "$(curl -s -o /dev/null -w %{http_code} -X POST http://127.0.0.1:${P}03/v1/files)" = 403 ]'

echo "--- Hook en conteneur, contrôle croisé"
hook() {  # événement, identifiant d'appel, commande
  printf '{"session_id":"%s","cwd":"%s","hook_event_name":"%s","tool_name":"Bash","tool_use_id":"%s","tool_input":{"command":"%s"}}' \
    "$S" "$B/depot" "$1" "$2" "$3" | "$APLOMB" hook --branchement conteneur-isole --cle-serveur cles/reponses.pub
}
# Allow : le hook ne dit rien et laisse faire Claude Code ; un refus s'afficherait.
D1="$(hook PreToolUse toolu_banc_1 ls)"; hook PostToolUse toolu_banc_1 ls > /dev/null
verifier "action demandée par le modèle permise" '! printf %s "$D1" | grep -q deny'
hook PreToolUse toolu_jamais_vu "echo x" > /dev/null
R2="$(appel_modele)"
verifier "second échange relayé (texte)" 'printf %s "$R2" | grep -q fini'

echo "--- Aplomb Watch"
LIEN="$("$APLOMB" admin --compte alice --url "http://127.0.0.1:${P}01" connexion | grep -o 'http://[^ ]*ticket=[^ ]*')"
curl -s -o /dev/null -c biscuits "$LIEN"
curl -s -b biscuits "http://127.0.0.1:${P}01/admin/sessions" > sessions.json
curl -s -b biscuits "http://127.0.0.1:${P}01/admin/chaine?session=$S" > chaine.json
verifier "API protégée sans connexion" \
  '[ "$(curl -s -o /dev/null -w %{http_code} "http://127.0.0.1:${P}01/admin/chaine?session=$S")" = 401 ]'
verifier "session listée" 'grep -q "\"$S\"" sessions.json'
lire() { python3 -c "import json,sys; c=json.load(open('chaine.json')); print($1)"; }
verifier "verdict allow dans la vue chaînée" '[ "$(lire "c[\"tours\"][0][\"actions\"][0][\"verdict\"]")" = allow ]'
verifier "rattachement par identifiant de session" '[ "$(lire "c[\"rattachement\"]")" = session ]'
verifier "deux échanges chaînés" '[ "$(lire "len(c[\"tours\"])")" = 2 ]'
verifier "action liée à l'outil demandé, exécutée" \
  '[ "$(lire "[(a[\"appel\"], a[\"execute\"]) for a in c[\"tours\"][0][\"actions\"]]")" = "[('"'"'toolu_banc_1'"'"', True)]" ]'
verifier "jetons d'entrée, cache compris" '[ "$(lire "c[\"tours\"][0][\"echange\"][\"jetons_entree\"]")" = 120 ]'
verifier "action sans demande du modèle en écart" \
  '[ "$(lire "[a[\"appel\"] for a in c[\"hors_demande\"]]")" = "['"'"'toolu_jamais_vu'"'"']" ]'
verifier "contrôle croisé au journal : demande reconnue" 'grep -q "demandée par le modèle (échange 1)" journal/agent-banc-*.jsonl'
verifier "contrôle croisé au journal : écart" 'grep -q "ÉCART : action sans demande du modèle" journal/agent-banc-*.jsonl'
verifier "journal intact" '"$APLOMB" verify --journal journal > verify.log 2>&1'

echo "--- Passerelle MCP"
MCP="http://127.0.0.1:${P}05/mcp/notes"
rpc() {  # session, corps JSON
  curl -s -X POST "$MCP" -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
    ${1:+-H "mcp-session-id: $1"} -d "$2"
}
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"banc","version":"1"}}}'
ouvrir_mcp() {
  curl -s -D - -o /dev/null -X POST "$MCP" -H "content-type: application/json" -d "$INIT" | tr -d '\r' | sed -n 's/^mcp-session-id: //p'
}
appel_mcp() {  # session, outil
  rpc "$1" "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{\"q\":\"x\"},\"_meta\":{\"claudecode/toolUseId\":\"toolu_mcp_1\"}}}"
}
LISTE='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
SID="$(ouvrir_mcp)"
verifier "session MCP ouverte par la passerelle" '[ -n "$SID" ]'
rpc "$SID" '{"jsonrpc":"2.0","method":"notifications/initialized"}' > /dev/null
verifier "outils listés" 'rpc "$SID" "$LISTE" | grep -q chercher'
verifier "outil déclaré transmis" 'appel_mcp "$SID" chercher | grep -q "résultat de chercher"'
verifier "outil non déclaré refusé (revue = refus)" 'appel_mcp "$SID" effacer | grep -q "\"isError\":true"'
verifier "serveur absent du mandat : 404" \
  '[ "$(curl -s -o /dev/null -w %{http_code} -X POST http://127.0.0.1:${P}05/mcp/autre -H content-type:application/json -d "$INIT")" = 404 ]'
verifier "session MCP inconnue refusée" \
  '[ "$(curl -s -o /dev/null -w %{http_code} -X POST "$MCP" -H content-type:application/json -H "mcp-session-id: faux" -d "$INIT")" = 404 ]'
touch "$B/depot/.bascule"
SID2="$(ouvrir_mcp)"
rpc "$SID2" "$LISTE" > /dev/null
verifier "définition d'outil modifiée : outil refusé" 'appel_mcp "$SID2" chercher | grep -q "définition a changé"'
verifier "appel MCP journalisé avec son identifiant d'appel" 'grep -q toolu_mcp_1 journal/mcp-*.jsonl'

echo "--- Provenance (contenu non fiable)"
S2="provenance-$$"
hook_s() {  # session, événement, outil, entrée JSON
  printf '{"session_id":"%s","cwd":"%s","hook_event_name":"%s","tool_name":"%s","tool_use_id":"toolu_x","tool_input":%s}' \
    "$1" "$B/depot" "$2" "$3" "$4" | "$APLOMB" hook --cle-serveur cles/reponses.pub
}
LS='{"command":"ls"}'
verifier "avant : commande permise" '! hook_s "$S2" PreToolUse Bash "$LS" | grep -q "\"ask\""'
hook_s "$S2" PostToolUse WebFetch '{"url":"https://docs.python.org/3/"}' > /dev/null
verifier "après une page web : commande en revue" 'hook_s "$S2" PreToolUse Bash "$LS" | grep -q "\"ask\""'
ECRIT="{\"file_path\":\"$B/depot/a.txt\",\"content\":\"x\"}"
verifier "écriture dans le dépôt toujours permise" '! hook_s "$S2" PreToolUse Write "$ECRIT" | grep -q "ask\|deny"'
verifier "provenance au journal" 'grep -q "\"provenance\"" journal/provenance-*.jsonl'

echo "--- Délégation (sous-agents)"
S3="delegation-$$"
hook_d() {  # type de sous-agent, chemin écrit
  printf '{"session_id":"%s","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Write","agent_type":"%s","agent_id":"agent-1","tool_input":{"file_path":"%s","content":"x"}}' \
    "$S3" "$B/depot" "$1" "$2" | "$APLOMB" hook --cle-serveur cles/reponses.pub
}
verifier "sous-agent dans son mandat : permis" '! hook_d Explore "$B/depot/docs/a.md" | grep -q deny'
verifier "sous-agent hors de son mandat : refusé" 'hook_d Explore "$B/depot/src.py" | grep -q deny'
verifier "sous-agent sans mandat enfant : mandat parent" '! hook_d Plan "$B/depot/src.py" | grep -q deny'
verifier "chaîne de délégation au journal" 'grep -q "explorer v1" journal/delegation-*.jsonl'
verifier "mandat enfant plus large refusé au démarrage" \
  '! "$APLOMB" serve --mandat mandats/banc.yaml --mandat-enfant mandats/large.yaml --ecoute-decision 127.0.0.1:${P}10 \
     --ecoute-admin 127.0.0.1:${P}11 --ecoute-passerelle 127.0.0.1:${P}12 --ecoute-llm 127.0.0.1:${P}13 \
     --ecoute-mcp 127.0.0.1:${P}15 > large.log 2>&1 && grep -q "evil.example" large.log'
verifier "journal intact (fin)" '"$APLOMB" verify --journal journal > verify.log 2>&1'

echo
echo "$ok vérification(s) réussie(s), $ko échec(s)"
[ "$ko" = 0 ] || { echo "journaux : serve.log, init.log dans $B (relancer avec --garder)"; exit 1; }
