# État partagé : plusieurs instances, un même mandat

Par défaut, une instance d'Aplomb garde son état en mémoire : gels, demandes de dégel,
nonces des requêtes signées. C'est le bon choix pour un poste ou une petite équipe.

Quand un même système supervisé passe par plusieurs instances, par exemple plusieurs
processus derrière un répartiteur ou une instance de secours, elles partagent cet état
dans un fichier SQLite :

```bash
aplomb serve --mandat mandats/prod.yaml --etat-partage /srv/aplomb/etat.sqlite
```

L'option est désactivée par défaut. Sans elle, rien ne change.

## Ce qui est partagé

| État | Effet |
|---|---|
| **Gels**, globaux et par session | Un gel posé sur une instance, par un opérateur, une borne ou un verdict de gel, s'applique à toutes **avant leur décision suivante**. Chaque décision relit les gels. |
| **Dégels** | Un dégel approuvé sur une instance est propagé aux autres. Chacune remet ses compteurs de la session à zéro et le note au journal (`degel-propage`). |
| **Demandes en attente** (dégel, réactivation) | Alice demande le dégel sur l'instance A, Bob l'approuve sur l'instance B. Les quatre yeux valent entre instances : Alice ne peut pas approuver sa demande sur B. |
| **Nonces** des requêtes signées | Une requête d'administration ne se rejoue pas sur une autre instance. |

Les opérations d'administration passent dans une transaction exclusive : deux
approbations simultanées sur deux instances ne dégèlent pas deux fois.

## En cas de doute, on refuse

| Situation | Effet |
|---|---|
| Fichier illisible, table absente, verrou tenu plus de 2 s | Pas de décision, donc l'action est refusée. Le hook répond `deny` (superviseur injoignable). |
| Gel qui n'a pas pu être écrit | La décision suivante réessaie l'écriture et refuse tant qu'elle échoue |
| Passerelle qui ne peut pas lire les gels | La session est tenue pour gelée |
| Opération d'administration pendant une panne | Refusée (`503`, « opération refusée »). Rien n'est appliqué à moitié. |

## Garde-fous au démarrage

- **Un fichier par mandat.** `serve` refuse un fichier qui sert un autre mandat.
- **Une version du mandat à la fois.** Si des instances actives servent une autre version
  du mandat, `serve` refuse de démarrer. On les arrête, puis on les redémarre toutes sur le
  nouveau mandat. Une instance est active si elle s'est manifestée dans la dernière minute.
- `serve` annonce le fichier et le nombre d'autres instances actives. L'onglet Modules et
  l'état de la vue (`etat_partage`) les montrent aussi.

## Ce qui reste propre à chaque instance

- **Journal, coffre, clés de session** : chaque instance a les siens (`--journal`,
  `--coffre`). Le dossier de preuves s'exporte instance par instance.
- **Compteurs des bornes** (refus, envois, domaines…) : ils comptent par instance.
  Routez une session vers une même instance (affinité de session au répartiteur). Un gel
  posé par une borne, lui, s'applique partout.
- **Revues en attente** : la passerelle attend la réponse sur l'instance qui tient la
  connexion. Le réviseur répond depuis la vue de cette instance.
- **Sessions de la vue, suspensions pour inactivité** : on se connecte à chaque instance.
  L'activité d'un compte est relevée par instance (`--activite`).

## Limites

- SQLite suffit pour plusieurs processus **sur une même machine**, ou sur un disque local
  partagé. Il ne convient pas à un partage réseau (NFS, SMB) : les verrous n'y sont pas
  fiables. Pour plusieurs machines, il faudra PostgreSQL, qui n'est pas encore fait.
- Une instance sert un mandat. Plusieurs systèmes supervisés demandent plusieurs
  instances, chacune avec son propre fichier d'état partagé.
- Le fichier ne contient ni contenu d'action ni secret, seulement des identifiants de
  session, de compte et des nonces. Il reste à protéger comme le reste de l'instance
  (droits du compte de service) : qui peut l'écrire peut dégeler.
