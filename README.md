# SAL — Superviseur d'Alignement Local (MVP, jalon J1)

Superviseur générique d'agents d'IA : chaque action est décidée **avant** exécution
(Allow / Review / Deny / Gel) selon un **mandat signé**, puis **journalisée** dans une
chaîne de hachage. Premier cas : **Claude Code** (profil C « agent de code »), branché
par hook (niveau d'assurance 1, coopératif).

- Cadrage : [`../docs/EXPRESSION-DE-BESOIN.md`](../docs/EXPRESSION-DE-BESOIN.md)
- Architecture du MVP : [`docs/ARCHITECTURE-MVP.md`](docs/ARCHITECTURE-MVP.md)
- Décision : [`docs/adr/0001-coeur-reseau-et-modes-de-branchement.md`](docs/adr/0001-coeur-reseau-et-modes-de-branchement.md)

> Projet **local** : aucun remote, aucune publication.

## Démarrage

```sh
cargo build
./target/debug/sal keygen --dossier cles                        # une fois
./target/debug/sal sign mandats/bac-a-sable.yaml --cle cles/sal.cle
./target/debug/sal compte nouveau --id alice --role operateur        # une fois par personne
./target/debug/sal compte nouveau --id bob --role approbateur
./target/debug/sal serve --mandat mandats/bac-a-sable.yaml --cle-publique cles/sal.pub
```

- Vue technique : `./target/debug/sal admin --compte alice connexion` affiche un lien de
  connexion à usage unique (2 minutes), qui ouvre une session de navigateur de 8 heures.
- Administration signée : `sal admin --compte alice gel [--session <id>]` (effet immédiat) ;
  `sal admin --compte alice degel` puis `sal admin --compte bob degel` (quatre yeux : deux
  comptes distincts, dans les 10 minutes). Les clés privées sont dans `~/.config/sal/comptes/`.
- Dépôt de test supervisé : `../bac-a-sable` (hook dans `.claude/settings.json`)
- Rejouer des scénarios sans Claude Code : `scripts/scenarios.sh`
- Vérifier le journal : `./target/debug/sal verify --journal journal`
- Effacer les contenus d'une session (la chaîne reste vérifiable) : `./target/debug/sal effacer --session <id>`
- Suivre les requêtes d'un agent en diagramme de séquence Mermaid (rendu par Pele ou tout outil Mermaid) :
  `./target/debug/sal mermaid --session <id>` (sortie standard), ou
  `./target/debug/sal mermaid --sortie diagrammes` pour un fichier `.mmd` par session.
  Seule une chaîne vérifiée est exportée. Par défaut, les ressources n'apparaissent que
  par leur référence ; `--dechiffrer` les montre en clair à l'aide des clés de session.

Toute modification des règles `profils/code/*.cedar` ou du mandat impose de le
re-signer ; sinon `sal serve` refuse de démarrer.

En conteneur : `docker compose up --build` (image non encore construite ni testée sur ce
poste).

## État (J1)

| | |
|---|---|
| Tests | 67 (algèbre par tests de propriété, mandat, Cedar, profil C par effet, journal, export Mermaid, bornes, chiffrement et effacement, comptes et quatre yeux, enveloppes et réponses signées) |
| Scénarios hook | 26 joués, dont 11 de l'annexe A (« Assume misalignment ») : points protégés gelés quel que soit le chemin, envoi vers un domaine autorisé en revue, script exécuté jugé sur son contenu |
| Bornes cumulées | Refus, revues, domaines, envois et actions comptés par session ; dépassement = gel (EF-A6, EF-J5) |
| Hook hors de portée | Paramètres gérés prêts (`deploiement/`), non installés : droits administrateur requis |
| Journal minimisé | Métadonnées en clair ; ressource, commande, chemin et domaine chiffrés par session (EF-P1) ; `sal effacer` détruit la clé (EF-P2) |
| Administration | Comptes nominatifs à clé ed25519, rôles lecteur / opérateur / approbateur ; requêtes signées, horodatées, sans rejeu ; geler seul, dégeler à quatre yeux ; toutes les API d'administration authentifiées (EF-S1, EF-S2) |
| Clés | Clé maîtresse dans le trousseau macOS ; clés de session, de comptes et de signature enveloppées (`sal trousseau migrer` pour l'existant) (EF-S4) |
| Réponses signées | Le hook n'accepte que les réponses signées sur son nonce par la clé du superviseur (`--cle-serveur cles/reponses.pub`) : faux superviseur et rejeu refusés (EF-S3) |
| Fail-closed | Superviseur injoignable ⇒ refus vérifié |
| Journal | Altération d'une décision détectée à la ligne exacte |
| Latence | ≈ 10 ms par action, lancement du processus hook compris |

Limites connues : voir « Ce que J1 ne fait pas » dans l'architecture.
