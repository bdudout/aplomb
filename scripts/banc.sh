#!/bin/sh
# Banc d'essai autonome : une instance d'Aplomb jetable (phrase, comptes, mandat, jeton et
# journal à elle, dans un dossier temporaire), un faux modèle, puis le parcours complet
# d'un agent confiné rejoué : appel au modèle par le proxy, hook avec identifiant d'appel,
# vue chaînée lue par l'API d'Aplomb Watch. Ne touche ni à ~/.config/aplomb ni au journal réel.
# Usage : scripts/banc.sh [--garder]   (--garder : laisse le dossier pour inspection)
set -eu
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
APLOMB="$RACINE/target/debug/aplomb"
B="$(mktemp -d "${TMPDIR:-/tmp}/aplomb-banc.XXXXXX")"
P=178   # ports 17800 (décision) à 17804 (faux modèle)
PIDS=""
fin() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
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
politique:
  regles: ../profils/code/regles.cedar
  revue: ../profils/code/revue.cedar
bornes: {refus: 5, revues: 20, domaines: 10, envois: 3, actions: 2000}
EOF

ok=0; ko=0
verifier() {  # libellé, condition (code shell)
  if eval "$2"; then ok=$((ok + 1)); printf '  ok   %s\n' "$1"; else ko=$((ko + 1)); printf '  ÉCHEC %s\n' "$1"; fi
}

cd "$B"
"$APLOMB" init --membre alice --membre bob --mandat mandats/banc.yaml > init.log 2>&1
"$APLOMB" modele jeton > jeton.log 2>&1
python3 "$RACINE/scripts/faux-modele.py" "${P}04" requetes.jsonl & PIDS="$PIDS $!"
"$APLOMB" serve --mandat mandats/banc.yaml --ecoute-decision "127.0.0.1:${P}00" --ecoute-admin "127.0.0.1:${P}01" \
  --ecoute-passerelle "127.0.0.1:${P}02" --ecoute-llm "127.0.0.1:${P}03" > serve.log 2>&1 & PIDS="$PIDS $!"
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

echo
echo "$ok vérification(s) réussie(s), $ko échec(s)"
[ "$ko" = 0 ] || { echo "journaux : serve.log, init.log dans $B (relancer avec --garder)"; exit 1; }
