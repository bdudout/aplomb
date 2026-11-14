# Politique de sécurité

## Signaler une vulnérabilité

Ne publiez pas de ticket public. Utilisez le **signalement privé de GitHub**. Sur le dépôt :
onglet *Security*, puis *Report a vulnerability*.

Indiquez :
- la version, ou le commit ;
- le mode de branchement (hook, passerelle, mandataire du modèle, conteneur) ;
- les étapes pour reproduire le problème ;
- l'effet observé, par exemple une action laissée passer alors que le mandat la refuse.

Nous accusons réception sous **5 jours ouvrés**. Ensuite :
- un premier diagnostic sous **15 jours** ;
- une date de correctif convenue avec vous ;
- une divulgation coordonnée, et un crédit si vous le souhaitez.

## Ce qui est une vulnérabilité

- Une action que le mandat refuse ou soumet à revue, et qui est pourtant exécutée.
- Un contournement du journal probatoire : entrée modifiée ou supprimée sans être détectée.
- Une signature de mandat, de compte ou de livrable acceptée alors qu'elle est invalide.
- Une fuite de secret : clé, jeton, contenu chiffré du coffre.

Le refus d'une action légitime est un **défaut**, pas une vulnérabilité : Aplomb refuse
par principe en cas de doute.

## Vulnérabilités activement exploitées

Ce cas relève du règlement (UE) 2024/2847, art. 14, à partir du 11 septembre 2026. Les
délais comptent à partir du moment où nous en avons connaissance :
- **24 h** : alerte précoce ;
- **72 h** : notification ;
- **14 jours** après la mise à disposition du correctif : rapport final.

Le signalement passe par la plateforme unique de l'ENISA. Voir [docs/CRA.md](docs/CRA.md).

## Versions prises en charge

Chaque version mineure reçoit des correctifs de sécurité pendant 5 ans. Les correctifs
sont publiés en version corrective signée. Vérifier un livrable :

```bash
aplomb publication verifier <binaire> --seuil 2
```
