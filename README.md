<p align="center"><img src="docs/logo/aplomb-logotype.svg" alt="Aplomb" width="420"></p>

# Aplomb — superviseur d'alignement pour agents d'IA (MVP)

Superviseur générique d'agents d'IA : chaque action est décidée **avant** exécution
(Allow / Review / Deny / Gel) selon un **mandat signé**, puis **journalisée** dans une
chaîne de hachage. Premier cas : **Claude Code** (profil C « agent de code »), branché
par hook (niveau d'assurance 1, coopératif).

| Module | Rôle | État |
|---|---|---|
| **Aplomb** | Cœur de décision (`aplomb-core`), service `aplomb serve`, hook Claude Code | MVP |
| **Aplomb Gate** | Passerelles : réseau sortant (`127.0.0.1:7702`), proxy LLM (`127.0.0.1:7703`), passerelle MCP (`127.0.0.1:7704`) | faites, avec le confinement |
| **Aplomb Watch** | Journal scellé, vue technique, export Mermaid, puis indicateurs pour le management | journal, flux en direct et vue chaînée faits |
| **Aplomb Pentest** | Profil dédié aux tests d'intrusion supervisés | à venir |

- Architecture du MVP : [`docs/ARCHITECTURE-MVP.md`](docs/ARCHITECTURE-MVP.md)
- Décision : [`docs/adr/0001-coeur-reseau-et-modes-de-branchement.md`](docs/adr/0001-coeur-reseau-et-modes-de-branchement.md)

## Licence

- `crates/aplomb-core` (bibliothèque) : [Apache-2.0](crates/aplomb-core/LICENSE).
- Tout le reste (binaire `aplomb`, profils, scripts, documentation) : [EUPL-1.2](LICENSE),
  licence de l'Union européenne, valable en français comme dans les autres langues de l'UE.

Les contributions sont les bienvenues : voir [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Démarrage

```sh
cargo build
./target/debug/aplomb init --membre alice --membre bob     # une fois : phrase de passe, comptes, confiance, cosignatures
./target/debug/aplomb serve --mandat mandats/bac-a-sable.yaml
```

Toutes les clés d'Aplomb sont chiffrées par une clé maîtresse, elle-même protégée par ta
**phrase de passe** (Argon2id, `~/.config/aplomb/cle-maitresse.yaml`). La phrase est demandée,
sans affichage, une fois par commande qui en a besoin (`serve`, `admin`, `cosigner`…).
Changer de phrase : `aplomb phrase changer`. Sans la phrase, les clés sont perdues.

Pour ne pas la retaper : `aplomb deverrouiller` (8 h par défaut, `--duree 2h`). La phrase est
demandée une fois, puis `serve` et `admin … gel` ne demandent plus rien ; les opérations
sensibles (cosigner, dégeler, se connecter à Aplomb Watch, déchiffrer) demandent Touch ID sur
macOS, la phrase ailleurs. La fenêtre de Touch ID montre la commande exacte, lue par Aplomb
auprès du système : un agent ne peut pas la déguiser. `aplomb verrouiller` met fin au
déverrouillage. macOS et Linux ; Windows : phrase à chaque commande pour l'instant.

- Confier le jeton du modèle au proxy LLM : `./target/debug/aplomb modele jeton` (saisi sans
  affichage, chiffré), puis redémarrer `aplomb serve`. L'agent confiné n'a ainsi aucun jeton.
- Vue technique (Aplomb Watch) : `./target/debug/aplomb admin --compte alice connexion` affiche un lien de
  connexion à usage unique (2 minutes), qui ouvre une session de navigateur de 8 heures.
  Onglet « Vue chaînée » : pour une session d'agent, chaque appel au modèle, les outils qu'il
  demande (identifiant `toolu_…`), la décision d'Aplomb sur chacun, puis le trafic d'Aplomb Gate ;
  les écarts du contrôle croisé (action sans demande du modèle, outil demandé jamais présenté)
  sont en rouge.
- Administration signée : `aplomb admin --compte alice gel [--session <id>]` (effet immédiat) ;
  `aplomb admin --compte alice degel` puis `aplomb admin --compte bob degel` (quatre yeux : deux
  comptes distincts, dans les 10 minutes). Les clés privées sont dans `~/.config/aplomb/comptes/`.
- Dépôt de test supervisé : `../bac-a-sable` (hook dans `.claude/settings.json`)
- Rejouer des scénarios sans Claude Code : `scripts/scenarios.sh`
- Banc d'essai autonome : `scripts/banc.sh` monte une instance jetable (phrase, comptes,
  mandat, jeton et journal à elle, dans un dossier temporaire) et un faux modèle, puis rejoue
  le parcours d'un agent confiné : proxy LLM, hook avec identifiant d'appel, contrôle croisé,
  vue chaînée, passerelle MCP, provenance, délégation, file de revue, déverrouillage (43 vérifications). Rien n'est
  demandé, rien du réel n'est touché.
- Modèle local (Ollama, vLLM, llama.cpp) : `domaines_modele: ["http://127.0.0.1:11434"]` ;
  HTTP en clair n'est accepté que vers la machine elle-même.
- Vérifier le journal : `./target/debug/aplomb verify --journal journal`
- Effacer les contenus d'une session (la chaîne reste vérifiable) : `./target/debug/aplomb effacer --session <id>`
- Suivre les requêtes d'un agent en diagramme de séquence Mermaid (rendu par Pele ou tout outil Mermaid) :
  `./target/debug/aplomb mermaid --session <id>` (sortie standard), ou
  `./target/debug/aplomb mermaid --sortie diagrammes` pour un fichier `.mmd` par session.
  Seule une chaîne vérifiée est exportée. Par défaut, les ressources n'apparaissent que
  par leur référence ; `--dechiffrer` les montre en clair à l'aide des clés de session.

Serveurs MCP et sous-agents se déclarent au mandat :

```yaml
perimetre:
  serveurs_mcp:
  - {nom: notes, commande: [npx, -y, "@exemple/serveur-notes"], outils: [chercher]}
```

puis `claude mcp add --transport http notes http://127.0.0.1:7704/mcp/notes`. Un mandat de
sous-agent porte `agent: claude-code/<type de sous-agent>` et `parent: <id du mandat>` ; on le
charge par `aplomb serve --mandat <parent> --mandat-enfant <enfant>`.

Toute modification d'un mandat, de ses règles `profils/code/*.cedar` ou de `comptes.yaml`
impose deux signatures : `aplomb cosigner <fichier> --compte alice --compte bob` quand les
deux clés sont sur ce poste ; sinon chacun signe chez soi avec son `--compte`.
Sinon `aplomb serve` refuse de démarrer et dit qui doit signer.

- Ancrer le journal hors de la machine : `./target/debug/aplomb ancrer --vers /Volumes/<clé USB>`
  (copie des scellés, et témoin à noter ailleurs). `aplomb verify` confronte ensuite le
  journal à cette copie.

En conteneur : `docker compose up --build` (image non encore construite ni testée sur ce
poste).

## État (J1)

| | |
|---|---|
| Tests | 99 (algèbre par tests de propriété, mandat, Cedar, profil C par effet, journal, export Mermaid, bornes, chiffrement et effacement, comptes et quatre yeux, enveloppes et réponses signées, gouvernance, scellement et ancrage, passerelle) |
| Scénarios hook | 26 joués, dont 11 de l'annexe A (« Assume misalignment ») : points protégés gelés quel que soit le chemin, envoi vers un domaine autorisé en revue, script exécuté jugé sur son contenu |
| Bornes cumulées | Refus, revues, domaines, envois et actions comptés par session ; dépassement = gel (EF-A6, EF-J5) |
| Agent confiné (niveau 3) | `conteneur/` : Claude Code dans un réseau Docker interne, seuls la décision et Aplomb Gate sont relayés ; hook géré par root ; 20 vérifications d'isolement rejouables (`conteneur/verifier.sh`) |
| Hook hors de portée | Paramètres gérés prêts (`deploiement/`), non installés : droits administrateur requis |
| Journal minimisé | Métadonnées en clair ; ressource, commande, chemin et domaine chiffrés par session (EF-P1) ; `aplomb effacer` détruit la clé (EF-P2) |
| Administration | Comptes nominatifs à clé ed25519, rôles lecteur / opérateur / approbateur ; requêtes signées, horodatées, sans rejeu ; geler seul, dégeler à quatre yeux ; toutes les API d'administration authentifiées (EF-S1, EF-S2) |
| Clés | Clé maîtresse protégée par phrase de passe (Argon2id) ; clés de session, de comptes et de signature enveloppées (`aplomb cles migrer` pour l'existant) (EF-S4) ; déverrouillage pour une durée, Touch ID pour les opérations sensibles |
| Réponses signées | Le hook n'accepte que les réponses signées sur son nonce par la clé du superviseur (`--cle-serveur cles/reponses.pub`) : faux superviseur et rejeu refusés (EF-S3) |
| Gouvernance | Mandat et comptes cosignés par deux membres distincts au moins (fichier de confiance, seuil 2) ; `aplomb init` prépare tout en une commande (EF-S2) |
| Scellement | Toutes les 60 s (`--scellement`) et à l'arrêt : racine de Merkle des sessions, signée et chaînée ; troncature, suppression et réécriture détectées ; ancrage hors ligne (EF-I1, EF-I2) |
| Aplomb Gate (passerelle sortante) | `127.0.0.1:7702` pour `HTTPS_PROXY` : domaines du mandat, adresses internes refusées (ressource réelle), envoi plafonné à 1 Mio par connexion, une revue attend la réponse d'un humain dans Aplomb Watch ; tout est journalisé (EF-C1, EF-C4, EF-B4) |
| Proxy LLM (niveau 2) | `127.0.0.1:7703` pour `ANTHROPIC_BASE_URL` : amont = `domaines_modele` du mandat ; seuls les appels de conversation passent ; clé de l'agent retirée, jeton d'Aplomb injecté (`aplomb modele jeton`, chiffré) ; appels, jetons et outils demandés journalisés ; coupé par le gel |
| Passerelle MCP (niveau 2) | `127.0.0.1:7704/mcp/<nom>` : serveurs du mandat (`serveurs_mcp`) lancés par Aplomb ; chaque appel d'outil jugé et journalisé ; définitions d'outils épinglées (une description qui change = outil refusé) |
| File de revue | Une action des passerelles (Gate, MCP) en revue attend 2 min la réponse d'un opérateur ou d'un approbateur dans Aplomb Watch (Approuver / Refuser) ; sans réponse, refus ; l'issue et le compte sont journalisés |
| Provenance (EF-B5) | Après un contenu non fiable (page web, résultat MCP, fichier hors du dépôt, sortie de sous-agent), les actions sensibles de la session passent en revue |
| Délégation (EF-B6) | Mandats de sous-agents (`serve --mandat-enfant`) cosignés et inclus dans le parent ; actions jugées par les deux ; chaîne au journal |
| Contrôle croisé (niveaux 2 et 3) | En conteneur, chaque action présentée au superviseur doit porter l'identifiant d'un appel d'outil demandé par le modèle au proxy : sinon, écart au journal et dans la vue chaînée |
| Fail-closed | Superviseur injoignable ⇒ refus vérifié |
| Journal | Altération d'une décision détectée à la ligne exacte |
| Latence | ≈ 10 ms par action, lancement du processus hook compris |

Limites connues : voir « Ce que J1 ne fait pas » dans l'architecture.
