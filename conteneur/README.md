# Aplomb, niveau 3 : l'agent confiné

Au niveau 1, Aplomb ne voit que ce qui passe par le hook de Claude Code : un script lancé
par l'agent peut ouvrir une connexion sans être vu. Au niveau 3, l'agent tourne dans un
conteneur **sans route vers l'extérieur**. Tout ce qu'il fait, outil ou sous-processus,
ne peut sortir que par Aplomb Gate ; il ne parle à son modèle que par le proxy LLM
d'Aplomb (niveau 2), qui détient le jeton.

```
hôte (macOS)                                  Docker
──────────────                                ─────────────────────────────────────────
aplomb serve (phrase de passe)                réseau « isole » (internal : aucune route)
  :7700 décision   ◀── relais aplomb-decision ──┐
  :7701 admin      ✗ (relayée nulle part)       ├── agent : Claude Code, utilisateur agent,
  :7702 Aplomb Gate ◀── relais aplomb-gate ─────┤   système de fichiers en lecture seule,
  :7703 proxy LLM  ◀── relais aplomb-llm ──────┘   seul le dépôt est monté, aucun jeton
       │
       ▼
   internet : domaines du mandat (Gate) ; modèle, avec le jeton d'Aplomb (proxy LLM)
```

- Le **superviseur reste sur l'hôte** : ni ses clés, ni son journal, ni sa phrase de passe
  ne sont dans le conteneur.
- Le **hook** et ses paramètres gérés appartiennent à root dans l'image ; l'agent ne peut
  ni les modifier ni ajouter les siens (`allowManagedHooksOnly`). Il se déclare au journal
  en mode `conteneur-isole` (niveau 3).
- Le **dépôt** est monté au même chemin que sur l'hôte : la racine du mandat signé reste
  juste, sans recosignature.
- **Proxy LLM** : Claude Code joint son modèle par `ANTHROPIC_BASE_URL=http://aplomb-llm:7703`.
  Aplomb relaie vers le premier domaine de `perimetre.domaines_modele` du mandat, ne laisse
  passer que les appels de conversation (`POST /v1/messages`), retire toute clé fournie par
  l'agent et injecte la sienne, journalise chaque appel (modèle, volumes, jetons, outils
  demandés par le modèle) et coupe tout pendant un gel. Le modèle n'est plus joignable
  directement par Aplomb Gate.

- **Contrôle croisé** : le hook transmet l'identifiant d'appel (`tool_use_id`) que le modèle
  a donné à l'outil ; le superviseur vérifie qu'il l'a vu passer dans une réponse du proxy.
  Une action sans demande du modèle (script, injection hors conversation) est signalée comme
  écart au journal et dans la vue chaînée d'Aplomb Watch.

## Utilisation

Prérequis : Docker Desktop, et `aplomb serve` lancé sur l'hôte.

```sh
claude setup-token            # sur l'hôte : crée un jeton (ou utiliser une clé d'API)
aplomb modele jeton           # le confie à Aplomb, chiffré ; puis redémarrer aplomb serve
cd conteneur
cp .env.exemple .env          # renseigner APLOMB_DEPOT
docker compose run --rm agent # première fois : construit les images (quelques minutes)
```

`conteneur/verifier.sh` rejoue les vérifications d'isolement. Chaque refus d'Aplomb Gate
compte dans la borne de refus de la session `passerelle` (5, puis gel) : le script en
consomme trois par passage ; redémarrer le superviseur, ou dégeler, remet à zéro.

Arrêter les relais : `docker compose down`.

## Limites connues

- **Contenu des échanges avec le modèle** : le proxy relève les outils demandés, mais ne
  juge pas encore le contenu des requêtes (ce que l'agent envoie au modèle) ; c'est le rôle
  des moniteurs (J5). Un script de l'agent peut appeler le proxy : il paie avec le compte
  d'Aplomb et tout est journalisé, mais ne peut rien envoyer ailleurs.
- **mTLS entre hook et superviseur** : non fait, volontairement. Le hook tourne sous le
  même utilisateur que l'agent : un certificat client lisible par le hook l'est aussi par
  l'agent, et ne prouverait donc rien. L'usurpation du superviseur est déjà empêchée par
  les réponses signées. L'agent peut appeler l'API de décision directement, mais elle ne
  fait que juger : il n'obtient rien de plus qu'en passant par le hook.
- Le niveau déclaré (`conteneur-isole`) est informatif : il figure au journal mais ne
  change pas les décisions.
