# État partagé : plusieurs instances, un même mandat

Par défaut, une instance d'Aplomb garde son état en mémoire : gels, compteurs des bornes,
demandes de dégel, nonces des requêtes signées. C'est le bon choix pour un essai.

Avec l'option `--etat-partage`, cet état vit dans un stockage commun. Deux moteurs, même
contrat :

| Moteur | Quand | Option |
|---|---|---|
| **SQLite** | Une machine : un poste, un serveur, plusieurs processus. Rien à installer : le moteur est compilé avec le binaire. | `--etat-partage /srv/aplomb/etat.sqlite` |
| **PostgreSQL** | Plusieurs machines : instances derrière un répartiteur, en centre de données. Base en haute disponibilité. | `--etat-partage "postgres://aplomb@pg1,pg2,pg3/aplomb?sslmode=require&target_session_attrs=read-write"` |

```bash
aplomb serve --mandat mandats/prod.yaml --etat-partage /srv/aplomb/etat.sqlite
```

L'option est désactivée par défaut. Sans elle, rien ne change. Les deux architectures de
référence, poste unique et centre de données, sont décrites dans
[ARCHITECTURES.md](ARCHITECTURES.md).

Même avec une seule instance, l'option SQLite a un intérêt : les gels et les compteurs
des bornes **survivent au redémarrage** de l'instance.

## Ce qui est partagé

| État | Effet |
|---|---|
| **Gels**, globaux et par session | Un gel posé sur une instance, par un opérateur, une borne ou un verdict de gel, s'applique à toutes **avant leur décision suivante**. Chaque décision relit les gels. |
| **Compteurs des bornes** (refus, revues, envois, domaines, actions) | Une session répartie sur plusieurs instances est bornée comme si elle n'en voyait qu'une : 3 refus sur A et 3 sur B font 6 refus. L'affinité de session n'est plus nécessaire. |
| **Dégels** | Un dégel approuvé sur une instance est propagé aux autres. Les compteurs de la session repartent de zéro partout. Chaque instance le note à son journal (`degel-propage`). |
| **Demandes en attente** (dégel, réactivation) | Alice demande le dégel sur l'instance A, Bob l'approuve sur l'instance B. Les quatre yeux valent entre instances : Alice ne peut pas approuver sa demande sur B. |
| **Nonces** des requêtes signées | Une requête d'administration ne se rejoue pas sur une autre instance. |

Chaque décision et chaque opération d'administration passent dans une **transaction
exclusive** entre instances : `BEGIN IMMEDIATE` en SQLite, verrou consultatif propre au
mandat en PostgreSQL. Deux décisions simultanées sur deux instances ne perdent pas de
compteur. Deux approbations simultanées ne dégèlent pas deux fois.

## En cas de doute, on refuse

| Situation | Effet |
|---|---|
| Stockage illisible, table absente, verrou tenu plus de 2 s, base injoignable | Pas de décision, donc l'action est refusée. Le hook répond `deny` (superviseur injoignable). |
| Connexion PostgreSQL perdue pendant une transaction | La transaction échoue jusqu'au bout. Rien n'est appliqué à moitié. La requête suivante se reconnecte. |
| Gel ou compteur qui n'a pas pu être écrit | La décision n'est pas rendue (refus). La suivante réécrit d'abord les gels. |
| Passerelle qui ne peut pas lire l'état | La session est tenue pour gelée. |
| Opération d'administration pendant une panne | Refusée (`503`, « opération refusée »). |

Pendant une bascule PostgreSQL (quelques secondes à quelques dizaines de secondes selon
la grappe), les agents sont donc **bloqués, pas libres**.

## PostgreSQL

- **Adresse** : `postgres://compte@hôte[:port][,hôte2…]/base?options`. Plusieurs hôtes et
  `target_session_attrs=read-write` : Aplomb suit le primaire après une bascule.
- **TLS obligatoire hors de la machine** : un hôte qui n'est ni la boucle locale ni un
  socket Unix exige `sslmode=require`. Le certificat du serveur et son nom sont toujours
  vérifiés : racines publiques, plus l'autorité interne passée par
  `--etat-partage-ca ca-interne.pem`.
- **Mot de passe** : jamais dans l'adresse, car elle est visible dans la liste des
  processus. `serve` le lit dans `PGPASSWORD`.
- **Base** : une base, ou un schéma par `options=-csearch_path%3Daplomb_prod`, par mandat.
  Aplomb crée ses tables au premier démarrage. Le compte n'a besoin que des droits sur
  ces tables.
- **Démarrage** : une base injoignable empêche `serve` de démarrer.
- **Binaire** : PostgreSQL est compilé par défaut. `cargo build --no-default-features`
  donne un binaire SQLite seul, plus petit.

## Garde-fous au démarrage

- **Un stockage par mandat.** `serve` refuse un stockage qui sert un autre mandat.
- **Une version du mandat à la fois.** Si des instances actives servent une autre version
  du mandat, `serve` refuse de démarrer. On les arrête, puis on les redémarre toutes sur le
  nouveau mandat. Une instance est active si elle s'est manifestée dans la dernière minute.
- `serve` annonce le stockage, son moteur et le nombre d'autres instances actives.
  L'onglet Modules et l'état de la vue (`etat_partage`) les montrent aussi.

## Ce qui reste propre à chaque instance

- **Journal, coffre, clés de session** : chaque instance a les siens (`--journal`,
  `--coffre`). Le dossier de preuves s'exporte instance par instance ; la diffusion SIEM
  part de chaque instance et le SIEM les réunit.
- **Budgets des moniteurs** (appels au juge, à la sonde, aux moniteurs externes) et
  cumuls propres au profil : ils comptent par instance. Une session répartie peut donc
  consulter le juge un peu plus souvent que son budget. C'est un coût, pas une
  ouverture : les bornes, elles, sont communes.
- **Revues en attente** : la passerelle attend la réponse sur l'instance qui tient la
  connexion. Le réviseur répond depuis la vue de cette instance.
- **Sessions de la vue, suspensions pour inactivité** : on se connecte à chaque instance.
  L'activité d'un compte est relevée par instance (`--activite`).

## Limites

- SQLite ne convient pas à un partage réseau (NFS, SMB) : les verrous n'y sont pas
  fiables. Entre machines, prendre PostgreSQL.
- Les décisions d'un mandat passent l'une après l'autre : une transaction courte par
  décision, quelques millisecondes sur un réseau local. C'est largement assez pour des
  agents dont chaque action prend des secondes. Le débit n'a pas été mesuré.
- Une instance sert un mandat. Plusieurs systèmes supervisés demandent plusieurs
  instances, chacune avec son propre stockage (ou schéma).
- Le stockage ne contient ni contenu d'action ni secret. On y trouve des identifiants de
  session et de compte, des noms de domaine contactés (compteurs des bornes) et des
  nonces. **Qui peut l'écrire peut dégeler** : le fichier SQLite se protège par les droits
  du compte de service ; la base PostgreSQL par un compte dédié, TLS et le pare-feu.
- Le scénario PostgreSQL du banc ne se joue que si PostgreSQL est installé sur la machine
  du banc (`initdb`). Sans lui, le banc ne vérifie que les adresses refusées et la base
  injoignable.
