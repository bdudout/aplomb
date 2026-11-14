# Aplomb et le Cyber Resilience Act — dossier de conformité (indicatif)

> **Statut : document de travail, indicatif.** Ce dossier rassemble ce qu'Aplomb fournit
> déjà pour le règlement (UE) 2024/2847 (« CRA »). Il ne remplace pas un avis juridique.
> La qualification (EF-L1) reste à faire valider avant toute mise sur le marché commerciale.

## Calendrier

| Date | Ce qui s'applique |
|---|---|
| 10 décembre 2024 | Entrée en vigueur du règlement |
| 11 juin 2026 | Dispositions sur les organismes d'évaluation de la conformité |
| **11 septembre 2026** | **Obligations de signalement** (art. 14) : vulnérabilités activement exploitées et incidents graves, à l'ENISA et au CSIRT coordinateur |
| **11 décembre 2027** | Toutes les autres obligations : exigences essentielles (Annexe I), dossier technique, déclaration UE de conformité, marquage CE |

## L1 — Qualification du produit

**Aplomb est aujourd'hui un logiciel libre** (aplomb-core sous Apache-2.0, le binaire sous
EUPL-1.2), publié sans contrepartie financière et sans service payant associé. Le CRA ne
vise pas les logiciels libres fournis **en dehors d'une activité commerciale** (considérants
18 et 19). Tant que cela reste vrai, le dépôt public n'est pas une « mise sur le marché ».

La qualification redevient nécessaire dès qu'il y a une activité commerciale : version
vendue, support payant, monétisation de données, intégration dans un produit commercial.
Deux lectures sont possibles pour Aplomb :

| Lecture | Argument | Conséquence |
|---|---|---|
| Produit « par défaut » | Aplomb contrôle les actions d'un agent d'IA. Ce n'est ni un pare-feu, ni un IDS, ni un SIEM au sens de l'Annexe III. | Auto-évaluation (module A, Annexe VIII) |
| Produit « important », classe I (Annexe III) | Il décide de l'accès d'un logiciel à des ressources (logique de **contrôle d'accès**). Il gère aussi des comptes, la MFA et le SSO (logique de **gestion des identités**). | Norme harmonisée appliquée intégralement, sinon tierce partie (module B+C ou H) |

**Position de travail : produit important de classe I, par prudence.** C'est la lecture la
plus exigeante des deux plausibles. Le dossier se construit pour elle. Si un avis
juridique retient « par défaut », rien n'est perdu. L'éditeur commercial, s'il y en a un,
devra trancher. Un **intendant du logiciel libre** (art. 24) n'aurait, lui, que des
obligations allégées : politique de cybersécurité, coopération avec les autorités,
signalement.

## L2 — Gestion des vulnérabilités

| Exigence (Annexe I partie II, art. 14) | Ce qu'Aplomb fournit |
|---|---|
| Contact sécurité publié, divulgation coordonnée | [SECURITY.md](../SECURITY.md) : signalement privé par GitHub (*Private vulnerability reporting*), accusé de réception sous 5 jours ouvrés |
| Inventaire des composants | `aplomb publication sbom` : nomenclature CycloneDX 1.6, tirée du `Cargo.lock` compilé dans le binaire |
| Correction sans délai, mise à jour gratuite | Correctifs publiés sur `main` et dans une version corrective signée (L3) |
| Signalement d'une vulnérabilité activement exploitée : alerte précoce sous **24 h**, notification sous **72 h**, rapport final sous **14 jours** après le correctif | Procédure décrite dans SECURITY.md. **Reste à faire** : un exercice à blanc (critère d'acceptation EF-L2). Le signalement passera par la plateforme unique de l'ENISA. |
| Avis de sécurité publics | GitHub Security Advisories du dépôt |

## L3 — Période de support et mises à jour

- **Période de support annoncée** : chaque version mineure reçoit des correctifs de
  sécurité pendant **5 ans** à partir de sa publication. C'est la durée minimale par défaut
  du CRA (art. 13 §8), sauf durée d'usage plus courte justifiée.
- **Correctifs séparés des évolutions** : une version corrective `x.y.z+1` ne contient que
  des correctifs de sécurité et de défauts, sans nouvelle fonction.
- **Livrables signés** : `scripts/publier.sh --compte <id>` produit le binaire, sa
  nomenclature, leurs empreintes, et les signatures ed25519 des membres de confiance.
  N'importe qui vérifie avec :

  ```bash
  aplomb publication verifier aplomb-0.1.0-aarch64-apple-darwin --seuil 2
  ```

  La vérification n'utilise que les clés de `cles/confiance.yaml` ou celle passée par
  `--cle-publique`. Elle ne fait jamais confiance à la clé jointe à la signature.
- **Construction reproductible** : même commit et même chaîne d'outils donnent le même
  binaire. Pour cela, `scripts/publier.sh` :
  - verrouille les dépendances (`--locked`) ;
  - fixe l'horodatage à celui du commit (`SOURCE_DATE_EPOCH`), y compris dans la
    nomenclature ;
  - efface les chemins absolus (`--remap-path-prefix`) ;
  - utilise une seule unité de génération de code.

  Pour contrôler la reproductibilité, construire deux fois et comparer les empreintes.

## L4 — Dossier technique (Annexe VII)

| Pièce | Où | État |
|---|---|---|
| Description générale, usage prévu | README, [ARCHITECTURE-MVP.md](ARCHITECTURE-MVP.md) ; usage prévu : superviser des agents d'IA, **pas** évaluer des personnes (EF-L5) | Fait |
| Conception, architecture, modes de branchement | [ARCHITECTURE-MVP.md](ARCHITECTURE-MVP.md), [adr/](adr/), [MODULES.md](MODULES.md) | Fait |
| Analyse de risque cybersécurité | Expression de besoin (risques R1 à R10), [AUDIT-2026-11.md](AUDIT-2026-11.md) | À consolider en une analyse dédiée au produit |
| Configuration sûre par défaut | Défauts : refus en cas de doute (*fail-closed*), options lourdes désactivées, HTTP en clair seulement vers la boucle locale, secrets lus dans l'environnement | Fait |
| Nomenclature logicielle | `aplomb publication sbom` | Fait |
| Gestion des vulnérabilités | SECURITY.md, § L2 | Fait, exercice à blanc à faire |
| Résultats d'essais | `cargo test`, banc `scripts/banc.sh` (377 vérifications avec PostgreSQL, 368 sans) | Fait |
| Normes appliquées | Aucune norme harmonisée CRA publiée à ce jour. Suivre les travaux du CEN-CENELEC (JTC 13) | À suivre |
| Déclaration UE de conformité, marquage CE | — | Seulement en cas de mise sur le marché |

## Ce qui reste

- **Avis juridique** sur la qualification (L1). Il est indispensable avant toute offre
  commerciale.
- **Exercice à blanc** de signalement à 24 h, 72 h et 14 jours (L2).
- **Analyse de risque** propre au produit, distincte de celle des systèmes supervisés.
- **Signature des versions par une infrastructure publique**, en plus des clés des
  membres : Sigstore ou attestation de provenance SLSA dans une intégration continue.
  Le dépôt n'a pas encore d'intégration continue de publication.
