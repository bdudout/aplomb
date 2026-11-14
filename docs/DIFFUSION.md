# Diffusion du journal vers le SIEM, et conservation

Option désactivée par défaut. Sans fichier `diffusion.yaml`, Aplomb ne contacte aucun
service externe.

## Activer en trois commandes

```bash
aplomb diffusion exemple > diffusion.yaml     # modèle commenté : Elastic, Splunk, syslog, OTLP…
aplomb diffusion verifier                     # fichier, variables des jetons, ce qui partira
aplomb diffusion tester --destination elastic # un événement de test
```

Puis redémarrer `aplomb serve`. La ligne `diffusion (SIEM)` du démarrage donne les
destinations et le fuseau horaire. L'état de chaque destination (envoyés, retard, dernière
erreur) est servi par `GET /admin/diffusion`. Les destinations apparaissent aussi dans
`aplomb modules`, à l'étape 8.

## Formats

| `format` | Pour | Transport |
|---|---|---|
| `ecs` | Elastic, OpenSearch | `url` vers l'API `_bulk`, en-tête `ApiKey` ; `_id` = identifiant de l'événement |
| `splunk-hec` | Splunk | `url` du HTTP Event Collector, en-tête `Splunk <jeton>`, `sourcetype` `aplomb:journal` |
| `syslog` | rsyslog, syslog-ng, Sentinel (AMA), QRadar… | `adresse: hôte:port`, RFC 5424 sur TLS (RFC 5425), ou `fichier` |
| `cef` | ArcSight, Sentinel | idem syslog |
| `leef` | QRadar | idem syslog |
| `otlp` | collecteur OpenTelemetry | `url` OTLP/HTTP JSON (`/v1/logs`) |
| `webhook` | outil interne, SOAR, chat | `url` ; lot JSON signé |
| `json` | Filebeat, Splunk UF, Fluent Bit | `fichier` : une ligne par événement |

Un jeton ou un secret n'est jamais écrit dans le fichier : `jeton_env` donne le nom de la
variable d'environnement qui le porte. Si la variable manque, `serve` refuse de démarrer et
dit laquelle définir.

En clair (`http://`, `tls: false`), seulement vers la machine elle-même. `ca:` ajoute
l'autorité de certification d'un SIEM interne.

`types` choisit ce qui part : `session`, `decision`, `administration` par défaut ; aussi
`observation` et `modele`.

## L'événement pivot `aplomb/1`

Chaque entrée du journal devient un événement pivot, puis il est mis au format de la
destination :

```json
{
  "schema": "aplomb/1",
  "id": "empreinte de l'entrée (identifiant unique)",
  "horodatage": "2026-11-14T11:23:07.592+01:00",
  "horodatage_utc": "2026-11-14T10:23:07.592Z",
  "fuseau": "Europe/Paris",
  "epoch_ms": 1794651787592,
  "instance": "aplomb-prod", "systeme": "assistant-code", "agent": "claude-code", "profil": "code",
  "session": "…", "seq": 2, "type": "decision", "gravite": 5,
  "verdict": "review", "regle": "…", "outil": "Bash", "verbe": "executer", "motif": "…",
  "moniteurs": [{"moniteur": "filtre:bancaire", "niveau": "critique"}],
  "empreinte": "…", "precedent": "…"
}
```

- **Ce qui ne sort jamais** : les contenus chiffrés par session (commande, chemin, domaine,
  paramètres d'outils). Ils restent dans le journal local et s'effacent avec la clé de la
  session. Les motifs détaillés des moniteurs non plus.
- **Horodatage** (EF-N2) : RFC 3339 à la milliseconde, avec le décalage du fuseau IANA
  choisi (`fuseau:`, sinon celui du système), heure d'été comprise. L'heure UTC est toujours
  jointe. En syslog, l'horodatage est en heure locale avec décalage ; en ECS, `@timestamp`
  est en UTC et `event.timezone` donne le fuseau.
- **Gravité** de 0 à 10 : 10 pour un gel, 7 pour un refus, 5 pour une revue, 8 pour un gel
  ou un dégel décidé par un humain. Elle donne la sévérité syslog, CEF et OpenTelemetry.
- **Dérive d'horloge** : si l'horloge du système saute de plus de 2 s par rapport au temps
  écoulé, une entrée `derive-horloge` est journalisée (et diffusée).

## Ni perte ni doublon

Le journal sert lui-même de file d'attente. Chaque destination garde, par session, l'endroit
jusqu'où elle a reçu (`<journal>/diffusion/<id>.json`), et ce curseur n'avance qu'après un
envoi réussi.

- SIEM coupé : les événements attendent dans le journal. Les nouveaux essais s'espacent
  jusqu'à 30 s. Après 5 échecs de suite, une entrée `diffusion-en-echec` est journalisée,
  puis `diffusion-retablie` au retour du SIEM.
- Aplomb redémarré : chaque destination reprend à son curseur.
- Arrêt brutal entre l'envoi et l'écriture du curseur : le dernier lot peut repartir, avec
  les mêmes identifiants. Elastic l'écarte de lui-même (`_id`) ; ailleurs, dédoublonner sur
  `event.id`, `aplomb.event_id` ou `externalId`.

## Webhook signé

En-têtes `X-Aplomb-Schema`, `X-Aplomb-Horodatage` (secondes Unix) et
`X-Aplomb-Signature: sha256=<hex>`. La signature est le HMAC-SHA256, avec le secret, de
`<horodatage>.<corps>`. Le destinataire la recalcule, et refuse un horodatage trop ancien.

## Conservation du journal (EF-I5)

```bash
aplomb journal archiver --jours 180 --vers /mnt/archive/aplomb
```

- Seules partent les sessions sans activité depuis N jours **et** déjà couvertes par un
  scellé.
- Chaque session est copiée, la copie est vérifiée, puis l'archivage est inscrit au
  registre de rétention (session `_retention`, chaînée et scellée comme les autres), et
  enfin la session est retirée du journal actif.
- `aplomb verify` accepte une session absente seulement si le registre dit qu'elle a été
  archivée dans l'état scellé. Une suppression hors registre reste détectée.
- L'archive se vérifie à part (`aplomb verify --journal /mnt/archive/aplomb`). À la fin de
  la durée de conservation, on peut la détruire : les scellés et le registre restent, et
  le journal actif reste vérifiable.
