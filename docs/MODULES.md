# Modules d'Aplomb

Aplomb est fait d'un socle (mandat, combinaison des avis, journal) et de **modules** branchés
à chaque étape du traitement d'une action. Une PME démarre avec le minimum. Une banque ou un
hôpital ajoute ses filtres, ses moniteurs et ses sorties, sans toucher au socle.

```bash
aplomb modules                 # modules actifs du premier mandat de mandats/
aplomb modules --mandat mandats/mon-agent.yaml --tout   # avec tout ce qui est disponible
```

Les modules actifs sont aussi visibles dans l'onglet **Modules** d'Aplomb Watch
(`GET /admin/modules`, réservé aux comptes connectés). Chaque session du journal porte, dans
son en-tête, la liste des modules actifs sur la décision, avec leur version et leur empreinte.

## Les étapes

| # | Étape | Exemples de modules |
|---|---|---|
| 1 | branchement | hook Claude Code, proxy LLM, Aplomb Gate, passerelle MCP |
| 2 | normalisation | profils `code`, `pentest`, `metier` (traduisent un outil en effet) |
| 3 | filtrage de contenu | secrets, packs `bancaire`, `identifiant_national`, `sante`, `coordonnees`, packs de l'organisation |
| 4 | moniteurs | juge, sonde, raisonnement, enchaînements, provenance, moniteurs externes |
| 5 | décision | règles Cedar, bornes, agrégation |
| 6 | approbation | file de revue priorisée et enrichie, délai au mandat, canaux Slack, Teams, ITSM, courriel, webhook (voir [APPROBATION.md](APPROBATION.md)) |
| 7 | journal | chaîne de hachage, scellement |
| 8 | diffusion | export SIEM : ECS, Splunk HEC, syslog, CEF, LEEF, OTLP, webhook (voir [DIFFUSION.md](DIFFUSION.md)) |
| 9 | reporting | reporting MCP, dossier de preuves AI Act, rapports DORA, ISO/IEC 42001, NIS 2, envoi signé à un outil GRC, indicateurs |
| 10 | visualisation | Aplomb Watch, vue gouvernance, panneaux déclarés (`panneaux.yaml`) |
| 11 | identité | comptes à quatre yeux, MFA TOTP, SSO OpenID Connect, revue des comptes (voir [IDENTITE.md](IDENTITE.md)) |

## La règle d'or

Sur le chemin de décision (étapes 1 à 6), **un module ne peut que durcir** une décision
(Allow < Review < Deny < Gel). Aucun module n'autorise ce que les règles refusent. Un module
en panne vaut son plancher : la revue par défaut, jamais « conforme ».

Les modules lourds (SIEM, SSO, MFA…) sont désactivés par défaut. La découverte de l'outil
reste en une commande.

## Filtres de contenu

```yaml
moniteurs:
  filtres:
  - pack: bancaire                  # IBAN (clé vérifiée), cartes (Luhn)
  - pack: sante
    local: suspect                  # aussi en revue quand la donnée ne sort pas
  - fichier: ../filtres/contrats.yaml
```

- `sortant` : palier quand la donnée est dans une action qui sort de la machine (défaut :
  `critique`, la session gèle).
- `local` : palier dans les autres cas (défaut : `conforme`, sans effet).
- Ce qui sort de la machine est décidé par le profil (réseau, `git push`, envoi externe,
  paiement, export…).
- Le journal nomme ce qui a été trouvé, jamais la valeur.

Un pack de l'organisation est un fichier YAML :

```yaml
nom: contrats
motifs:
- {nom: numéro de contrat, motif: 'CT-[0-9]{8}'}
sortant: critique
local: suspect
```

La cosignature du mandat (`aplomb cosigner`) pose l'empreinte sha256 du fichier dans le
mandat. Si le fichier change ensuite, `aplomb serve` refuse de démarrer : il faut faire
recosigner le mandat.

## Moniteurs externes (contrat v1)

Un moniteur externe est un service HTTP de l'organisation : un classifieur maison, un outil
DLP, un modèle spécialisé. Il est déclaré au mandat :

```yaml
moniteurs:
  externes:
  - id: dlp
    url: http://127.0.0.1:9000/v1/avis   # en clair : seulement vers la machine elle-même
    quand: sensible        # ou « toujours » ; sensible = actions que le juge verrait
    echantillon: 0.05      # part des autres actions soumises
    delai_ms: 800          # 3000 au plus
    panne: suspect         # palier si le service ne répond pas (jamais « conforme »)
    niveau_max: suspect    # « critique » l'autorise à geler
    contenus: false        # true : il reçoit aussi l'entrée brute de l'outil
    appels_max: 1000       # par session
  agregation:
    escalade: 2            # 2 moniteurs probabilistes suspects ou pire ⇒ gel
```

Aplomb envoie un `POST` en JSON :

```json
{
  "contrat": 1,
  "moniteur": "dlp",
  "intention": "intention du mandat signé",
  "agent": "claude-code",
  "outil": "Bash",
  "action": {"verbe": "reseau", "ressource": "docs.python.org", "contexte": "…"},
  "historique": ["lire src/a.py", "…"],
  "entree": {"command": "…"}
}
```

`entree` n'est envoyée que si le moniteur déclare `contenus: true`. `aplomb modules`
l'affiche (« lit les contenus »), pour qu'on sache ce que chaque module voit.

Il répond :

```json
{"niveau": "conforme", "score": 0.1, "motif": "rien à signaler"}
```

`niveau` vaut `conforme`, `suspect` ou `critique`. Il est plafonné par `niveau_max`. Une
réponse illisible, une erreur HTTP ou un délai dépassé valent `panne`. Les moniteurs
externes sont consultés en parallèle ; leur niveau, leur latence et leurs pannes sont au
journal.

Exemple minimal : [`scripts/faux-moniteur.py`](../scripts/faux-moniteur.py), utilisé par le
banc d'essai.

## Écrire un module

| Façon | Quand | Exemple |
|---|---|---|
| Déclaratif | des motifs, des règles, sans code | pack de filtres en YAML, règles Cedar |
| Intégré | un module livré avec Aplomb, activé au mandat | `pack: bancaire`, juge, sonde |
| Externe | un service à vous, dans votre langage | moniteur externe (contrat v1) |

Un nouveau profil (normalisation) s'ajoute par le registre de profils de `aplomb-core`
(`profils/mod.rs`). Il fournit ses **signaux** : ce qui mérite le juge, ce qui sort de la
machine, ce qui lit une donnée sensible. Le socle ne lit aucun verbe propre à un profil.
