# Approbation, rapports réglementaires et panneaux

Sans réglage, Aplomb envoie les demandes de revue humaine à Aplomb Watch. Une revue sans
réponse au bout de 120 s vaut refus. Tout le reste de cette page est optionnel :

| Option | Fichier | Activée par |
|---|---|---|
| Délai de revue | le mandat (`approbation:`) | la cosignature du mandat |
| Prévenir les réviseurs (Slack, Teams, ITSM, courriel, webhook) | `approbation.yaml` | sa présence au démarrage de `serve` |
| Panneaux d'Aplomb Watch | `panneaux.yaml` | sa présence au démarrage de `serve` |
| Rapports DORA, ISO/IEC 42001, NIS 2 | aucun | `aplomb rapport` (toujours disponible) |

`aplomb modules` montre ce qui est actif à l'étape 6 (approbation), 9 (reporting) et
10 (visualisation).

## Revues priorisées et enrichies

Chaque demande de revue arrive avec :

- une **priorité** (normale, haute, critique) et ses raisons, par exemple « effet
  irréversible », « sort de la machine » ou « moniteur suspect : … ». Les revues
  critiques passent en tête de la file ;
- l'**intention** du mandat, les avis des moniteurs et les contenus non fiables lus
  avant l'action ;
- les **5 actions précédentes** de la session ;
- ce qui se passe si l'on approuve, si l'on refuse ou si personne ne répond.

La priorité est calculée de façon déterministe à partir du verbe, des signaux du profil et
des avis des moniteurs. Elle ne change jamais la décision : elle ne fait qu'ordonner la file.

### Délai de revue

Le délai se règle dans le mandat. Il est donc cosigné, et personne ne peut l'allonger seul :

```yaml
approbation: {delai_s: 300}   # de 15 à 3600 s ; défaut 120
```

## Prévenir les réviseurs (`approbation.yaml`)

Les canaux **préviennent**, ils ne décident pas. La décision se prend toujours dans Aplomb
Watch, par un compte habilité, et elle est journalisée. Un lien reçu par messagerie ne
peut donc pas approuver une action.

```yaml
lien: https://aplomb.exemple.fr/         # adresse d'Aplomb Watch pour les réviseurs
canaux:
- {id: secops, type: slack, url_env: APLOMB_SLACK_WEBHOOK}
- {id: astreinte, type: teams, url_env: APLOMB_TEAMS_WEBHOOK, priorite_min: haute}
- {id: servicenow, type: itsm, url: https://exemple.service-now.com/api/now/table/incident, jeton_env: APLOMB_ITSM_JETON}
- {id: soar, type: webhook, url: https://soar.exemple.fr/aplomb, jeton_env: APLOMB_SOAR_SECRET}
- {id: rssi, type: courriel, a: [rssi@exemple.fr], de: aplomb@exemple.fr, priorite_min: critique}
```

| Type | Envoi |
|---|---|
| `slack` | webhook entrant (`text`) ; l'URL est un secret, donc lue dans `url_env` |
| `teams` | webhook de flux de travail, carte adaptative |
| `itsm` | ticket, champs ServiceNow (`short_description`, `urgency`, `impact`, `correlation_id`) ; jeton en `Authorization: Bearer` |
| `webhook` | JSON `aplomb.revue/1`, signé comme la diffusion : `X-Aplomb-Signature: sha256=HMAC(secret, horodatage + "." + corps)` |
| `courriel` | `sendmail -t` (Postfix, msmtp…), sujet encodé en UTF-8 ; `sendmail:` pour un autre chemin |

- **Secrets** : ils sont lus seulement dans des variables d'environnement. Si une variable
  manque, `serve` refuse de démarrer et la nomme.
- **HTTPS obligatoire**, sauf vers la machine elle-même.
- **`priorite_min`** : le canal ne reçoit que les demandes de cette priorité ou plus.
  Exemple : le courriel du RSSI pour les seules revues critiques.
- **Peu de contenu** : par défaut, le message dit quoi (outil, système, priorité, raisons,
  délai) mais ne dit pas sur quoi. `details: true` ajoute le résumé et le motif, qui
  peuvent nommer la ressource visée ; `aplomb modules` le signale alors.
- **Traçabilité** : chaque envoi est journalisé avec son issue (`notification-revue`,
  canal, revue, « envoyée » ou la cause de l'échec). Un canal en panne ne retarde ni
  ne change la décision.

## Rapports réglementaires

```bash
aplomb rapport --referentiel dora                 # Markdown à l'écran
aplomb rapport --referentiel iso42001 --format json --sortie iso42001.json
aplomb rapport --referentiel nis2 --pousser https://acra.exemple.fr/api/aplomb --jeton-env ACRA_JETON
```

| Référentiel | Exigences couvertes par le rapport |
|---|---|
| DORA, règlement (UE) 2022/2554 | art. 5, 6, 8, 9 § 4, 10, 11, 12, 13, 17-19, 24-25, 28 |
| ISO/IEC 42001:2023, annexe A | A.2, A.3.2, A.3.3, A.5, A.6.2.4, A.6.2.6, A.6.2.8, A.7, A.8, A.9, A.10 |
| NIS 2, directive (UE) 2022/2555 | art. 20, 21 § 2 a à j, 23 |

Pour chaque exigence, le rapport donne :

- son statut : couvert, partiel ou hors périmètre ;
- ce qu'Aplomb apporte ;
- ce qui a été **mesuré sur l'instance** : cosignatures, banc rouge/bleu, intégrité du
  journal, second facteur, SSO, revue des comptes, diffusion SIEM, canaux d'approbation,
  délai de revue ;
- ce qui reste à l'organisation.

Les statuts suivent les options actives. Par exemple, l'art. 21 § 2 j de NIS 2 passe à
« couvert » quand le second facteur est exigé.

> Ces correspondances sont **indicatives**. Elles sont limitées au périmètre de l'agent
> supervisé et doivent être validées par la fonction conformité. Un superviseur d'agents
> ne rend pas, à lui seul, une entité conforme à DORA ou NIS 2.

- **Envoi à un outil GRC** (ACRA ou autre) : `--pousser` envoie
  `{schema: "aplomb.rapport/1", rapport, cle_publique, signature}` par POST. La signature
  ed25519 est faite par la clé de l'instance, sur les octets JSON du rapport ; le jeton
  est passé en Bearer. HTTPS est obligatoire, sauf vers 127.0.0.1.
- **Dossier de preuves** : `aplomb preuves exporter` joint les trois rapports
  (`rapports/*.json` et `*.md`). Ils sont couverts par le manifeste signé.
- **Reporting MCP** : l'outil `rapport_reglementaire` donne le même rapport, avec les
  cosignataires anonymisés.

## Reporting MCP : outils ajoutés

| Outil | Rend |
|---|---|
| `rapport_reglementaire` | rapport DORA, ISO/IEC 42001 ou NIS 2 (`referentiel`, `heures`) |
| `modules` | modules actifs et disponibles, étape par étape |
| `revues_en_attente` | nombre de revues en attente par priorité, âge de la plus ancienne, délai |

Comme les autres outils, ils sont en lecture seule et ne rendent rien de nominatif.

## Panneaux

L'onglet « Tableaux » d'Aplomb Watch affiche les panneaux déclarés dans `panneaux.yaml` :

```yaml
panneaux:
- {titre: Refus sur 24 h, type: compteur, mesure: decisions.deny, heures: 24}
- {titre: Taux de revue, type: compteur, mesure: taux.revue, heures: 168}
- {titre: Règles déclenchées, type: repartition, mesure: regles, heures: 168, lignes: 5}
- {titre: Revues par jour, type: serie, mesure: decisions.review, heures: 168, points: 7}
```

- **Types** :
  - `compteur` : une valeur ;
  - `repartition` : une table triée, parmi `regles`, `moniteurs`, `outils`,
    `branchements`, `decisions`, `revues`, `administration` ;
  - `serie` : de 2 à 48 intervalles.
- **Mesures** : tout chemin numérique des indicateurs agrégés (`decisions.allow`,
  `revues.expirees`, `juge.indisponibles`, `jetons`…) ou des taux (`taux.refus`,
  `taux.revues_expirees`…). Une mesure inconnue est refusée au démarrage.
- **Rien de nominatif** : un panneau ne lit que les indicateurs agrégés. Il ne peut
  montrer ni une session, ni un compte, ni un contenu.
- **Coût** : chaque panneau relit le journal à l'ouverture de l'onglet, et une série le
  relit une fois par intervalle. Sur un gros journal, préférer peu de points.

## Pas encore fait

- Répondre à une revue depuis Slack ou Teams. C'est un choix : la décision reste dans
  Aplomb Watch, sous un compte signé.
- PagerDuty et Opsgenie (possibles dès aujourd'hui par le canal `webhook`).
- Un format d'import propre à ACRA, au-delà de `aplomb.rapport/1`.
