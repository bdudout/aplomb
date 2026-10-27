# ADR 0001 — Cœur réseau et modes de branchement

- **Statut** : accepté (brouillon)
- **Date** : 2026-10-27

## Contexte
SAL doit superviser des IA locales et web, quel que soit le domaine (expression de
besoin §1, §8). Les agents se branchent de manières très différentes : hooks (Claude
Code), API LLM compatibles OpenAI ou Anthropic, outils MCP, conteneurs. Le superviseur
doit pouvoir tourner sur la même machine que l'agent (conteneurisé) ou sur un autre
hôte, et ne jamais être administrable par l'agent (EF-S1).

## Décision
1. Le **cœur** (`sal-core`) est une bibliothèque Rust **pure** : normalisation, politique,
   combinaison, journal. Aucun réseau, aucune connaissance du mode de branchement.
2. Il est exposé par un **service réseau** (`sal serve`) avec **deux API sur deux ports** :
   décision (joignable par l'agent) et administration (jamais joignable par l'agent).
   Le même binaire tourne en local ou dans un conteneur.
3. Chaque **mode de branchement** est un adaptateur mince qui traduit son trafic en
   événement d'outil puis appelle l'API de décision. Il déclare son **niveau
   d'assurance** (§11). Premier adaptateur : le hook Claude Code (niveau 1).
4. **Fail-closed** partout : superviseur injoignable, réponse invalide ou erreur
   d'évaluation ⇒ refus.
5. Politique exprimée en **Cedar** (refus par défaut, `forbid` prioritaire, analysable),
   le contexte étant calculé par le profil. Le palier « revue » est un second ensemble
   de règles Cedar.

## Alternatives écartées
- **Bibliothèque embarquée dans l'agent** : impossible pour un agent tiers ou web, et
  l'agent aurait la main sur son propre superviseur.
- **Un seul port** : mélange décision et administration ; un agent pourrait s'approuver.
- **OPA/Rego** : écosystème Go, langage moins analysable ; Cedar s'impose dans les
  passerelles d'agents (état de l'art §3-A/B).
- **Moteur de règles maison (comme CLUSA)** : adapté à un domaine fermé, pas à des
  profils écrits par des tiers.

## Conséquences
- (+) Un seul cœur pour tous les modes et tous les domaines ; ajout d'un mode = un adaptateur.
- (+) Séparation décision / administration dès J1.
- (−) Un saut réseau local par action (< 1 ms visé) ; refus total si le service tombe (assumé, ENF-11).
- (−) Le mode hook reste coopératif : il ne garantit pas H5 (niveau 1).
