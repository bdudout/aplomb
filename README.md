<p align="center"><img src="docs/logo/aplomb-logotype.svg" alt="Aplomb" width="420"></p>

# Aplomb — superviseur d'alignement pour agents d'IA (MVP)

Superviseur générique d'agents d'IA : chaque action est décidée **avant** exécution
(Allow / Review / Deny / Gel) selon un **mandat signé**, puis **journalisée** dans une
chaîne de hachage. Premier cas : **Claude Code** (profil C « agent de code »), branché
par hook (niveau d'assurance 1, coopératif).

| Module | Rôle | État |
|---|---|---|
| **Aplomb** | Cœur de décision (`aplomb-core`), service `aplomb serve`, hook Claude Code | MVP |
| **Aplomb Gate** | Passerelles : réseau sortant (`127.0.0.1:7702`) et canal modèle, puis proxy LLM et passerelle MCP | réseau sortant et confinement faits |
| **Aplomb Watch** | Journal scellé, vue technique, export Mermaid, puis indicateurs pour le management | journal et vue faits |
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

- Vue technique (Aplomb Watch) : `./target/debug/aplomb admin --compte alice connexion` affiche un lien de
  connexion à usage unique (2 minutes), qui ouvre une session de navigateur de 8 heures.
- Administration signée : `aplomb admin --compte alice gel [--session <id>]` (effet immédiat) ;
  `aplomb admin --compte alice degel` puis `aplomb admin --compte bob degel` (quatre yeux : deux
  comptes distincts, dans les 10 minutes). Les clés privées sont dans `~/.config/aplomb/comptes/`.
- Dépôt de test supervisé : `../bac-a-sable` (hook dans `.claude/settings.json`)
- Rejouer des scénarios sans Claude Code : `scripts/scenarios.sh`
- Vérifier le journal : `./target/debug/aplomb verify --journal journal`
- Effacer les contenus d'une session (la chaîne reste vérifiable) : `./target/debug/aplomb effacer --session <id>`
- Suivre les requêtes d'un agent en diagramme de séquence Mermaid (rendu par Pele ou tout outil Mermaid) :
  `./target/debug/aplomb mermaid --session <id>` (sortie standard), ou
  `./target/debug/aplomb mermaid --sortie diagrammes` pour un fichier `.mmd` par session.
  Seule une chaîne vérifiée est exportée. Par défaut, les ressources n'apparaissent que
  par leur référence ; `--dechiffrer` les montre en clair à l'aide des clés de session.

Toute modification d'un mandat, de ses règles `profils/code/*.cedar` ou de `comptes.yaml`
impose deux signatures : `aplomb cosigner <fichier> --compte alice`, puis `--compte bob`.
Sinon `aplomb serve` refuse de démarrer et dit qui doit signer.

- Ancrer le journal hors de la machine : `./target/debug/aplomb ancrer --vers /Volumes/<clé USB>`
  (copie des scellés, et témoin à noter ailleurs). `aplomb verify` confronte ensuite le
  journal à cette copie.

En conteneur : `docker compose up --build` (image non encore construite ni testée sur ce
poste).

## État (J1)

| | |
|---|---|
| Tests | 80 (algèbre par tests de propriété, mandat, Cedar, profil C par effet, journal, export Mermaid, bornes, chiffrement et effacement, comptes et quatre yeux, enveloppes et réponses signées, gouvernance, scellement et ancrage, passerelle) |
| Scénarios hook | 26 joués, dont 11 de l'annexe A (« Assume misalignment ») : points protégés gelés quel que soit le chemin, envoi vers un domaine autorisé en revue, script exécuté jugé sur son contenu |
| Bornes cumulées | Refus, revues, domaines, envois et actions comptés par session ; dépassement = gel (EF-A6, EF-J5) |
| Agent confiné (niveau 3) | `conteneur/` : Claude Code dans un réseau Docker interne, seuls la décision et Aplomb Gate sont relayés ; hook géré par root ; 17 vérifications d'isolement rejouables (`conteneur/verifier.sh`) |
| Hook hors de portée | Paramètres gérés prêts (`deploiement/`), non installés : droits administrateur requis |
| Journal minimisé | Métadonnées en clair ; ressource, commande, chemin et domaine chiffrés par session (EF-P1) ; `aplomb effacer` détruit la clé (EF-P2) |
| Administration | Comptes nominatifs à clé ed25519, rôles lecteur / opérateur / approbateur ; requêtes signées, horodatées, sans rejeu ; geler seul, dégeler à quatre yeux ; toutes les API d'administration authentifiées (EF-S1, EF-S2) |
| Clés | Clé maîtresse protégée par phrase de passe (Argon2id) ; clés de session, de comptes et de signature enveloppées (`aplomb cles migrer` pour l'existant) (EF-S4) |
| Réponses signées | Le hook n'accepte que les réponses signées sur son nonce par la clé du superviseur (`--cle-serveur cles/reponses.pub`) : faux superviseur et rejeu refusés (EF-S3) |
| Gouvernance | Mandat et comptes cosignés par deux membres distincts au moins (fichier de confiance, seuil 2) ; `aplomb init` prépare tout en une commande (EF-S2) |
| Scellement | Toutes les 60 s (`--scellement`) et à l'arrêt : racine de Merkle des sessions, signée et chaînée ; troncature, suppression et réécriture détectées ; ancrage hors ligne (EF-I1, EF-I2) |
| Aplomb Gate (passerelle sortante) | `127.0.0.1:7702` pour `HTTPS_PROXY` : domaines du mandat, adresses internes refusées (ressource réelle), envoi plafonné à 1 Mio par connexion, revue = refus ; canal modèle (`domaines_modele` du mandat) ouvert hors politique mais fermé par le gel ; tout est journalisé (EF-C1, EF-C4, EF-B4) |
| Fail-closed | Superviseur injoignable ⇒ refus vérifié |
| Journal | Altération d'une décision détectée à la ligne exacte |
| Latence | ≈ 10 ms par action, lancement du processus hook compris |

Limites connues : voir « Ce que J1 ne fait pas » dans l'architecture.
