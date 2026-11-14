# Profils déclaratifs : un métier sans recompiler

Les profils intégrés couvrent trois cas : code, pentest, agent métier. Un autre métier,
comme les RH, la relation client ou les achats, se décrit dans **un fichier YAML**. Ses
décisions s'écrivent en Cedar. Il n'y a pas de Rust à écrire, ni de nouvelle version
d'Aplomb à attendre.

Exemple complet : [`exemples/profil-rh/`](../exemples/profil-rh/) et
[`exemples/mandat-rh.yaml`](../exemples/mandat-rh.yaml).

## Le fichier de profil

```yaml
nom: rh
description: Agent RH — dossiers du personnel (SIRH), courriers, exports vers la paie
referentiels: ["RGPD, art. 9 et 88"]
outils:
- {outil: mcp__sirh__lire_dossier, verbe: lire_dossier, ressource: matricule, sensible: true}
- {outil: mcp__sirh__exporter, verbe: exporter, ressource: destinataire, envoi: true, domaine: destinataire}
- {outil: "mcp__web__*", verbe: lire_web, source_non_fiable: true}
attributs: [champ, montant]
sensibles_a_l_influence: [exporter, envoyer, modifier_dossier]
```

| Champ | Rôle |
|---|---|
| `outils[].outil` | Nom exact de l'outil, ou préfixe terminé par `*` |
| `verbe` | Action Cedar (`Action::"<verbe>"`). `autre` est réservé. |
| `ressource` | Champ de l'entrée qui désigne la ressource (journal, règles) |
| `sensible` | Donnée sensible : la lire puis l'envoyer est un enchaînement surveillé |
| `envoi` + `domaine` | L'action fait sortir des données ; `domaine` désigne le champ du destinataire, compté dans les bornes et lu par `context.domaine` |
| `source_non_fiable` | Le résultat est un contenu non fiable : ensuite, les verbes de `sensibles_a_l_influence` passent en revue |
| `attributs` | Champs de l'entrée copiés dans le contexte Cedar (`context.champ`…). Ils sont toujours présents, vides par défaut, pour que les règles n'échouent pas sur un champ absent. |

**Refus par défaut** : un outil que le profil ne déclare pas reçoit le verbe `autre`.
Aucune règle ne le permet, et le juge l'examine toujours. Le nom d'un profil intégré
(`code`, `pentest`, `metier`) ne peut pas être repris.

## Le lier au mandat

```yaml
profil: rh
profil_declaratif: {fichier: profil-rh/profil.yaml}
politique: {regles: profil-rh/regles.cedar, revue: profil-rh/revue.cedar}
```

À la cosignature, `aplomb cosigner` pose l'empreinte SHA-256 du fichier, comme pour les
règles Cedar et les filtres. Si quelqu'un modifie le profil sans faire recosigner le
mandat, `aplomb serve` refuse de démarrer.

## Ce que le profil ne fait pas

Le profil ne décide rien. Il nomme des verbes et des attributs ; les règles Cedar,
cosignées, décident. Les invariants du socle s'appliquent comme pour un profil intégré :
algèbre de décision, bornes, gel, provenance, journal, juge. Les moniteurs propres à un
domaine, en revanche, restent dans les profils intégrés ou dans des moniteurs externes
(voir [MODULES.md](MODULES.md)).
