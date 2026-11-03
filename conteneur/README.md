# Aplomb, niveau 3 : l'agent confiné

Au niveau 1, Aplomb ne voit que ce qui passe par le hook de Claude Code : un script lancé
par l'agent peut ouvrir une connexion sans être vu. Au niveau 3, l'agent tourne dans un
conteneur **sans route vers l'extérieur**. Tout ce qu'il fait, outil ou sous-processus,
ne peut sortir que par Aplomb Gate.

```
hôte (macOS)                                  Docker
──────────────                                ─────────────────────────────────────────
aplomb serve (phrase de passe)                réseau « isole » (internal : aucune route)
  :7700 décision   ◀── relais aplomb-decision ──┐
  :7701 admin      ✗ (relayée nulle part)       ├── agent : Claude Code, utilisateur agent,
  :7702 Aplomb Gate ◀── relais aplomb-gate ─────┘   système de fichiers en lecture seule,
       │                                            seul le dépôt est monté
       ▼
   internet (domaines du mandat, canal modèle)
```

- Le **superviseur reste sur l'hôte** : ni ses clés, ni son journal, ni sa phrase de passe
  ne sont dans le conteneur.
- Le **hook** et ses paramètres gérés appartiennent à root dans l'image ; l'agent ne peut
  ni les modifier ni ajouter les siens (`allowManagedHooksOnly`). Il se déclare au journal
  en mode `conteneur-isole` (niveau 3).
- Le **dépôt** est monté au même chemin que sur l'hôte : la racine du mandat signé reste
  juste, sans recosignature.
- **Canal modèle** : Claude Code doit joindre son modèle. Les domaines listés dans
  `perimetre.domaines_modele` du mandat passent par Aplomb Gate sans la politique (mais pas
  pendant un gel), en TLS de bout en bout, et chaque connexion est journalisée.

## Utilisation

Prérequis : Docker Desktop, et `aplomb serve` lancé sur l'hôte.

```sh
cd conteneur
cp .env.exemple .env          # renseigner APLOMB_DEPOT et le jeton
docker compose run --rm agent # première fois : construit les images (quelques minutes)
```

Le jeton se crée sur l'hôte avec `claude setup-token`. Il reste dans `conteneur/.env`,
qui n'est jamais versionné ni envoyé dans les images.

Arrêter les relais : `docker compose down`.

## Limites connues

- **Canal modèle** : le trafic vers le fournisseur du modèle est chiffré de bout en bout,
  Aplomb n'en voit que le volume. Un script de l'agent pourrait s'en servir avec une autre
  clé d'API. Le proxy LLM (J3, lot 3) fermera ce point en terminant ce canal lui-même.
- **mTLS entre hook et superviseur** : non fait, volontairement. Le hook tourne sous le
  même utilisateur que l'agent : un certificat client lisible par le hook l'est aussi par
  l'agent, et ne prouverait donc rien. L'usurpation du superviseur est déjà empêchée par
  les réponses signées. L'agent peut appeler l'API de décision directement, mais elle ne
  fait que juger : il n'obtient rien de plus qu'en passant par le hook.
- Le niveau déclaré (`conteneur-isole`) est informatif : il figure au journal mais ne
  change pas les décisions.
