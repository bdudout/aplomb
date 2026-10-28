# SAL — Architecture du MVP (jalon J1)

> Cadrage : [`../../docs/EXPRESSION-DE-BESOIN.md`](../../docs/EXPRESSION-DE-BESOIN.md), jalon **J1 —
> MVP « agent de code »** : profil C, déploiement Minimal, niveau d'assurance 1 (coopératif).
> Décision structurante : [`adr/0001-coeur-reseau-et-modes-de-branchement.md`](adr/0001-coeur-reseau-et-modes-de-branchement.md).
> Projet **local** : aucun remote, aucune publication.

## Critère d'acceptation de J1

Chaque action de Claude Code dans le dépôt bac à sable est **décidée avant exécution** et
**journalisée** ; les propriétés de l'algèbre de décision sont prouvées par tests.

## Vue d'ensemble

```
Claude Code (dépôt bac-a-sable)
   │ hook PreToolUse / PostToolUse  (JSON sur stdin)
   ▼
sal hook ──HTTP──▶ sal serve ── API décision :7700 ─┐
 (fail-closed)       │                                │  POST /v1/decide   → Allow / Review / Deny / Gel
                     │                                │  POST /v1/observe  → journal du résultat
                     │                                │  GET  /v1/health
                     │                                │
                     ├─ API administration :7701 ─────┤  GET  /           → vue technique
                     │  (jamais exposée à l'agent)    │  GET  /admin/events (SSE), POST /admin/gel, /admin/degel
                     │                                │  GET  /admin/verify (vérifie la chaîne du journal)
                     ▼
              sal-core (bibliothèque, sans I/O réseau)
                normaliser (profil C) → politique Cedar → combiner → journal chaîné
```

## Flux d'une action

1. Claude Code s'apprête à appeler un outil (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`…).
2. Le hook `sal hook` lit l'événement sur stdin et l'envoie à `POST /v1/decide`.
3. **Profil C** (`sal_core::profils::code`) : traduit l'appel d'outil en **action normalisée**
   (verbe, ressource réelle, contexte calculé : chemin canonique, dans le dépôt ?, fichier
   sensible ?, domaine réseau autorisé ?, push vers une branche protégée ?…).
4. **Politique Cedar** (`sal_core::politique`) : deux ensembles de règles issus du mandat :
   - `regles` — `permit` / `forbid`, refus par défaut ; un `forbid` l'emporte toujours ;
   - `revue` — `permit` dont la correspondance impose une **revue humaine** (palier Orange).
   Toute erreur d'évaluation ⇒ **Deny** (une erreur ne doit jamais faire sauter un `forbid`).
5. **Algèbre de décision** (`sal_core::decision`) : `final = max(politique, planchers des
   moniteurs, gel)` dans `Allow < Review < Deny < Gel`. En J1, aucun moniteur probabiliste.
6. **Journal** (`sal_core::journal`) : une chaîne de hachage SHA-256 **par session**, en JSONL.
7. Le hook traduit : Allow → `allow`, Review → `ask` (confirmation dans Claude Code),
   Deny / Gel → `deny`. Serveur injoignable ou réponse invalide ⇒ `deny` (fail-closed).

## Où vit quoi

| Chemin | Rôle |
|---|---|
| `crates/sal-core/src/decision.rs` | Verdict, avis, combinaison (invariant « ne peut que durcir ») |
| `crates/sal-core/src/action.rs` | Action normalisée et événement d'outil |
| `crates/sal-core/src/mandat.rs` | Mandat YAML, signature et vérification ed25519 |
| `crates/sal-core/src/politique.rs` | Évaluation Cedar (règles + revue), fail-closed |
| `crates/sal-core/src/profils/code.rs` | Profil C : normalisation des outils Claude Code |
| `crates/sal-core/src/journal.rs` | Journal chaîné par session, vérification |
| `crates/sal/src/main.rs` | Binaire `sal` : `serve`, `hook`, `keygen`, `sign`, `verify` |
| `crates/sal/src/serveur.rs` | API décision (7700) et API administration (7701) séparées |
| `crates/sal/src/ui.html` | Vue technique minimale (flux temps réel) |
| `profils/code/` | Règles Cedar et mandat type du profil C |
| `bac-a-sable/` | Dépôt de test où le hook est activé |

## Ce que J1 ne fait pas (jalons suivants)

- Niveau 1 seulement : une action faite hors hook n'est pas vue (niveau 3 au jalon J3).
- ~~Pas d'authentification sur l'API d'administration~~ : fait (J2, lot 3). Comptes nominatifs à clé ed25519, rôles, requêtes signées sans rejeu, dégel à quatre yeux, sessions de navigateur par ticket à usage unique. Restent : mTLS et clés dans le trousseau (lot 4), quatre yeux pour modifier un mandat ou le fichier de comptes, HTTP en clair sur la boucle locale.
- Entrées du journal chaînées mais pas encore signées ni ancrées hors machine : J2.
- ~~Minimisation du journal~~ : fait (J2, lot 2). Contenus venant de l'agent chiffrés par session (ChaCha20-Poly1305), effacement par destruction de la clé. Les clés sont encore des fichiers 0600, pas dans le trousseau (lot 4).
- Pas de moniteur probabiliste (juge, guard model) : J5.
