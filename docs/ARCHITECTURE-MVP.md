# Aplomb — Architecture du MVP (jalon J1)

> Jalon **J1 —
> MVP « agent de code »** : profil C, déploiement Minimal, niveau d'assurance 1 (coopératif).
> Décision structurante : [`adr/0001-coeur-reseau-et-modes-de-branchement.md`](adr/0001-coeur-reseau-et-modes-de-branchement.md).

## Critère d'acceptation de J1

Chaque action de Claude Code dans le dépôt bac à sable est **décidée avant exécution** et
**journalisée** ; les propriétés de l'algèbre de décision sont prouvées par tests.

## Vue d'ensemble

```
Claude Code (dépôt bac-a-sable)
   │ hook PreToolUse / PostToolUse  (JSON sur stdin)
   ▼
aplomb hook ──HTTP──▶ aplomb serve ── API décision :7700 ─┐
 (fail-closed)       │                                │  POST /v1/decide   → Allow / Review / Deny / Gel
                     │                                │  POST /v1/observe  → journal du résultat
                     │                                │  GET  /v1/health
                     │                                │
                     ├─ API administration :7701 ─────┤  GET  /           → vue technique
                     │  (jamais exposée à l'agent)    │  GET  /admin/events (SSE), POST /admin/gel, /admin/degel
                     │                                │  GET  /admin/verify (vérifie la chaîne du journal)
                     ▼
              aplomb-core (bibliothèque, sans I/O réseau)
                normaliser (profil C) → politique Cedar → combiner → journal chaîné
```

## Flux d'une action

1. Claude Code s'apprête à appeler un outil (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`…).
2. Le hook `aplomb hook` lit l'événement sur stdin et l'envoie à `POST /v1/decide`.
3. **Profil C** (`aplomb_core::profils::code`) : traduit l'appel d'outil en **action normalisée**
   (verbe, ressource réelle, contexte calculé : chemin canonique, dans le dépôt ?, fichier
   sensible ?, domaine réseau autorisé ?, push vers une branche protégée ?…).
4. **Politique Cedar** (`aplomb_core::politique`) : deux ensembles de règles issus du mandat :
   - `regles` — `permit` / `forbid`, refus par défaut ; un `forbid` l'emporte toujours ;
   - `revue` — `permit` dont la correspondance impose une **revue humaine** (palier Orange).
   Toute erreur d'évaluation ⇒ **Deny** (une erreur ne doit jamais faire sauter un `forbid`).
5. **Algèbre de décision** (`aplomb_core::decision`) : `final = max(politique, planchers des
   moniteurs, gel)` dans `Allow < Review < Deny < Gel`. En J1, aucun moniteur probabiliste.
6. **Journal** (`aplomb_core::journal`) : une chaîne de hachage SHA-256 **par session**, en JSONL.
7. Le hook traduit : Allow → `allow`, Review → `ask` (confirmation dans Claude Code),
   Deny / Gel → `deny`. Serveur injoignable ou réponse invalide ⇒ `deny` (fail-closed).

## Où vit quoi

| Chemin | Rôle |
|---|---|
| `crates/aplomb-core/src/decision.rs` | Verdict, avis, combinaison (invariant « ne peut que durcir ») |
| `crates/aplomb-core/src/action.rs` | Action normalisée et événement d'outil |
| `crates/aplomb-core/src/mandat.rs` | Mandat YAML, signature et vérification ed25519 |
| `crates/aplomb-core/src/politique.rs` | Évaluation Cedar (règles + revue), fail-closed |
| `crates/aplomb-core/src/profils/code.rs` | Profil C : normalisation des outils Claude Code |
| `crates/aplomb-core/src/journal.rs` | Journal chaîné par session, vérification |
| `crates/aplomb/src/main.rs` | Binaire `aplomb` : `serve`, `hook`, `init`, `cosigner`, `verify`, `ancrer`, `admin`, `compte`, `mermaid`, `effacer`, `trousseau` |
| `crates/aplomb/src/serveur.rs` | API décision (7700) et API administration (7701) séparées |
| `crates/aplomb/src/mcp.rs`, `crates/aplomb-core/src/mcp.rs` | Passerelle MCP (7704) : serveurs du mandat lancés par Aplomb, appels jugés, définitions épinglées |
| `crates/aplomb-core/src/delegation.rs` | Inclusion d'un mandat de sous-agent dans son parent (EF-B6) |
| `crates/aplomb/src/ui.html` | Vue technique minimale (flux temps réel) |
| `profils/code/` | Règles Cedar et mandat type du profil C |
| `exemples/mandat.yaml` | Modèle de mandat (l'instance — mandats, comptes, confiance — n'est pas versionnée) |

## Ce que J1 ne fait pas (jalons suivants)

- ~~Niveau 1 seulement~~ : niveau 3 fait (J3, lot 2). L'agent confiné dans un conteneur sans route vers l'extérieur ne sort que par Aplomb Gate ; le hook et ses paramètres appartiennent à root dans l'image ; l'API d'administration est injoignable (voir `conteneur/`). Le modèle se joint par le proxy LLM (J3, lot 3, niveau 2), qui détient le jeton.
- ~~Pas d'authentification sur l'API d'administration~~ : fait (J2, lot 3). Comptes nominatifs à clé ed25519, rôles, requêtes signées sans rejeu, dégel à quatre yeux, sessions de navigateur par ticket à usage unique. Quatre yeux pour modifier un mandat ou le fichier de comptes : fait (J2, lot 5).
- ~~Clés hors trousseau, composants non authentifiés~~ : fait (J2, lot 4). Clé maîtresse protégée par phrase de passe (Argon2id), tous les fichiers de clés enveloppés ; le trousseau macOS a été abandonné, il redemandait le mot de passe à chaque recompilation ; réponses du superviseur signées sur un nonce du hook (anti-usurpation, anti-rejeu). Le chiffrement du trafic (mTLS) est reporté au jalon J3 : sur la boucle locale, au niveau 1, l'agent partage l'utilisateur du hook et un certificat client ne prouverait rien.
- ~~Journal ni signé ni ancré~~ : fait (J2, lot 5). Scellés périodiques signés (racine de Merkle des sessions), ancrage hors ligne par `aplomb ancrer`. Les entrées sont signées à travers le scellé, donc avec un décalage d'au plus une période (60 s par défaut).
- ~~Minimisation du journal~~ : fait (J2, lot 2). Contenus venant de l'agent chiffrés par session (ChaCha20-Poly1305), effacement par destruction de la clé. Les clés sont encore des fichiers 0600, pas dans le trousseau (lot 4).
- ~~Ni passerelle MCP, ni provenance, ni délégation~~ : fait (J3, lot 4).
  - **Passerelle MCP** (niveau 2) : les serveurs MCP du mandat (`perimetre.serveurs_mcp`) sont
    lancés par Aplomb sur l'hôte, un processus par session ; l'agent les joint en HTTP par
    `http://127.0.0.1:7704/mcp/<nom>`. Chaque `tools/call` est jugé et journalisé avant
    transmission ; une revue attend la réponse d'un humain dans Aplomb Watch (file de revue, 2 min, puis refus). La définition de chaque outil
    est épinglée à sa première présentation : si elle change ensuite, l'outil est refusé.
    Seuls les outils listés au mandat passent sans revue (règle `revue-outil-mcp`).
  - **Provenance** (EF-B5, EF-D2) : une page web, un fichier hors du dépôt, la sortie réseau
    d'une commande, le résultat d'un serveur MCP non déclaré fiable ou la sortie d'un
    sous-agent marquent la session. Le contenu reste dans le contexte du modèle : les
    actions sensibles qui suivent (commande, réseau, outil MCP, délégation, envoi) passent
    au moins en revue (moniteur déterministe « provenance »). Lire et écrire dans le dépôt
    restent permis. La marque vaut pour toute la session : approximation prudente, faute de
    suivre la provenance valeur par valeur comme CaMeL.
  - **Délégation** (EF-B6) : un mandat de sous-agent (`agent: claude-code/<type>`,
    `parent: <id>`) est chargé par `serve --mandat-enfant` s'il est cosigné et inclus dans
    le parent (racine, domaines, modèles, serveurs MCP, branches protégées, bornes) ; ses
    actions sont jugées par les deux mandats, le plus sévère l'emporte. Un sous-agent sans
    mandat enfant suit le mandat parent. Le journal garde la chaîne (type et identifiant
    du sous-agent, mandat enfant appliqué).
  - Reste : serveurs MCP distants (HTTP) et secrets des serveurs MCP détenus par Aplomb.
- ~~Pas de moniteur probabiliste~~ : J5, lot 1 fait. Moniteur « secrets » déterministe
  (`aplomb-core/src/moniteurs.rs`) et juge enfichable (`crates/aplomb/src/juge.rs`) en
  cascade, saisine enveloppée, budget et mesure. Lot 2 fait : banc rouge/bleu
  (`aplomb-core/src/evaluation.rs`, `profils/code/evaluation.yaml`, `aplomb evaluer`),
  non-régression à la cosignature, injections visant le juge dans le jeu. Lot 3 fait :
  raisonnement lu au proxy LLM (EF-E3) et protocoles `report` et `reechantillonnage`
  (EF-E2, `crates/aplomb/src/protocole.rs`). Lot 4 fait : moniteur d'enchaînements
  (EF-E4, `moniteurs::avis_enchainement`), protocoles et raisonnement mesurés par
  `aplomb evaluer --protocole` (étapes avec `raisonnement` et `alternatives`), propositions
  écartées comptées comme refus. J5 est terminé, sauf l'essai avec de vrais modèles locaux
  (juge et modèle de confiance) : seuls le faux modèle et le faux juge du banc ont servi.
