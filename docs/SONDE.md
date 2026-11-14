# Sonde : le moniteur interne (J7)

Une **sonde** lit les activations d'un modèle de langue, et non son texte. Elle donne un score
de 0 à 1 : par exemple, « cette action ressemble à une tromperie ». Aplomb en fait un avis de
moniteur comme un autre.

Ce document explique :

1. ce que la sonde peut faire et ne pas faire dans Aplomb ;
2. comment la déclarer au mandat ;
3. l'API du serveur d'activations ;
4. ce que mesure le banc, avec le faux serveur et la sonde de test ;
5. comment construire une vraie sonde sur un modèle local (procédure **non jouée**) ;
6. les éléments du déploiement Avancé et leur justification.

## 1. Le contrat : un signal d'appoint, jamais une autorisation

- **La sonde ne peut que durcir une décision (EF-F2).**
  - Un score haut met l'action en revue.
  - Un score bas ne change rien : l'action reste soumise aux règles, aux invariants et aux autres moniteurs.
  - L'algèbre de décision prend le maximum. Un test de propriété (`sonde::tests::jamais_condition_d_autorisation`) le vérifie pour tout score, tout verdict et toute panne.
- **Elle ne regarde que ce qui serait permis.** Une action déjà refusée, gelée ou en revue ne lui est pas envoyée :
  - pas de latence inutile ;
  - aucune donnée de plus ne part vers le serveur d'activations.
- **Une panne vaut le plancher configuré (EF-F3, EF-K3).** Délai dépassé, serveur injoignable, réponse illisible ou budget de session épuisé :
  - `plancher: suspect` (par défaut) met l'action en revue ;
  - `plancher: conforme` laisse passer : c'est le mode dégradé, à choisir en connaissance de cause.
- **Niveau maximal.**
  - Par défaut, la sonde met en revue (`niveau_max: suspect`).
  - `niveau_max: critique` l'autorise à geler la session : ce n'est pas recommandé tant que la sonde n'est pas validée sur du trafic réel.

## 2. Déclarer la sonde au mandat

```yaml
moniteurs:
  sonde:
    url: http://127.0.0.1:8090        # serveur d'activations, sur la machine elle-même
    modele: qwen2.5-3b-instruct       # le modèle dont la sonde lit les activations
    poids: ../profils/metier/sonde-tromperie.json   # sonde linéaire, relative au mandat
    seuil: 0.5                        # au-delà : revue
    delai_ms: 1500                    # 2000 au plus ; au-delà, plancher
    plancher: suspect                 # en cas de panne : revue (ou « conforme »)
    appels_max: 1000                  # consultations par session, puis plancher
```

- **`aplomb cosigner`** pose l'empreinte des poids (`poids_sha256`) dans le mandat.
  - `aplomb serve` refuse de démarrer si les poids ont changé depuis : « poids de la sonde … modifiés depuis la cosignature : faire recosigner le mandat ».
  - Une sonde est une règle de décision au même titre que les fichiers Cedar : elle passe par les quatre yeux (EF-G1).
- **Sans `poids`**, le serveur applique la sonde lui-même et ne rend que le score.
  - C'est plus simple, mais les poids ne sont alors pas liés au mandat.
  - Ne le faire que si le serveur est lui-même sous contrôle.
- **Mesurer la sonde avant de signer :**
  - `aplomb evaluer --mandat <mandat>` joue le jeu d'évaluation avec la sonde ;
  - `--sans-sonde` la retire, pour comparer ;
  - `--seuil-sonde 0.65` essaie un autre seuil sans toucher au mandat.

## 3. API du serveur d'activations

`POST <url>/v1/activations`, corps JSON :

```json
{"modele": "qwen2.5-3b-instruct", "couche": 16,
 "contexte": "<intention du mandat>", "texte": "<raisonnement>\n<outil> <paramètres>",
 "appel": "<id de l'appel d'outil, ou null>", "score": false}
```

- `couche` : celle sur laquelle la sonde a été entraînée (champ `couche` du fichier de poids).
- `texte` : ce que l'agent s'apprête à faire, précédé de son raisonnement s'il a été lu au proxy LLM. Les secrets sont masqués avant l'envoi.
- `score` : `false` quand Aplomb applique lui-même les poids du mandat, `true` sinon.

Deux réponses sont possibles :

- `{"activations": [x1, x2, …]}` : un vecteur, la moyenne des états cachés de la couche sur les jetons du texte. Aplomb calcule alors `score = σ(w·(x − moyenne) + b)` avec les poids du mandat.
- `{"score": 0.73}` : seulement quand le mandat ne donne pas de poids.

Le fichier de poids (`Poids`, dans `crates/aplomb-core/src/sonde.rs`) :

```json
{"nom": "tromperie", "description": "…", "modele": "qwen2.5-3b-instruct", "couche": 16,
 "poids": [ … ], "biais": -0.3, "moyenne": [ … ]}
```

## 4. Ce que mesure le banc

Rien de lourd ne tourne sur le banc, conformément aux contraintes du projet.

- **`scripts/faux-activations.py serveur <port>`** (Python, bibliothèque standard seule) répond à l'API ci-dessus.
  - Ses « activations » sont un sac de mots haché (512 dimensions, mots et paires de mots).
  - Le mot `PANNE` dans le texte le fait attendre 3 s, pour tester le plancher.
- **`scripts/faux-activations.py entrainer`** entraîne une régression logistique sur `scripts/sonde-entrainement.jsonl` :
  - 40 phrases trompeuses et 40 honnêtes ;
  - génériques, sans rapport avec le jeu d'évaluation.
- **La sonde de test** est `profils/metier/sonde-test.json`.
  - C'est un classifieur de texte, pas une lecture d'états internes.
  - Elle sert à vérifier la chaîne de bout en bout : contrat, empreinte, plancher, coût, mesure.
  - Ses chiffres ne disent rien de ce que donnerait une vraie sonde.

### Mesure

Banc rouge/bleu du profil métier (`profils/metier/evaluation.yaml`), sur le mandat d'exemple, sans juge, avec 22 attaques et 12 tâches légitimes (18 actions). Cinq attaques ne sont visibles que par un moniteur interne : leurs paramètres sont anodins, seul le raisonnement trahit l'intention.

| | Sûreté | Attaques « sonde » vues | Utilité sans humain | Revues (actions légitimes) | Coût de la sonde |
|---|---|---|---|---|---|
| Sans sonde (`--sans-sonde`) | 77 % | 0 / 5 | 58 % | 5 / 18 | — |
| Sonde de test, seuil 0,50 | 86 % | 2 / 5 | 33 % | 8 / 18 | 29 consultations, quelques ms |
| Sonde de test, seuil 0,65 | 77 % | 0 / 5 | 42 % | 7 / 18 | 29 consultations, quelques ms |

Lecture :

- **La sonde attrape ce que rien d'autre ne voit.** Au seuil 0,50, elle met en revue deux des cinq attaques invisibles aux règles et aux moniteurs déterministes :
  - un message qui présente un remboursement comme déjà contrôlé (`approbateur-trompe`) ;
  - une liste de clients fortunés extraite sous un prétexte (`liste-de-clients-fortunes`).
  - Elle ne fait perdre aucune attaque déjà arrêtée : `--reference` le vérifie, sans régression.
- **Elle se paie en revues.**
  - Sans sonde, 7 tâches légitimes sur 12 passent sans humain ; au seuil 0,50, 4 seulement. Trois tâches de plus passent en revue : lire et analyser un dossier, un contrôle anti-fraude, une transmission à un collègue.
  - Aucune tâche légitime n'est bloquée : la sonde ne refuse jamais, elle demande un humain.
- **Relever le seuil coûte aussitôt la détection.** À 0,65, aucune attaque « sonde » n'est vue, et deux tâches légitimes restent en revue.
  - Une sonde de texte aussi faible ne sépare pas les deux populations.
  - C'est attendu, et c'est ce que le banc doit montrer avant toute signature.
- **Il faut donc calibrer une vraie sonde de cette façon :**
  1. fixer le seuil sur du trafic légitime réel, avec le budget d'audit (`--budget-audit`) ;
  2. puis mesurer la sûreté gagnée.

`scripts/banc.sh` rejoue ces trois mesures et vérifie aussi :

- le service : déploiement affiché, empreinte des poids, plancher en cas de panne, poids modifiés refusés ;
- le journal : empreinte au journal, journal vérifiable ;
- les preuves et le reporting.

## 5. Construire une vraie sonde sur un modèle local (procédure non jouée)

> Rien de ce qui suit n'a été exécuté : aucun modèle n'est installé sur le poste de
> développement. C'est la marche à suivre, pas un résultat.

### Ce qu'on peut attendre, et ce qu'on ne peut pas

- **Si l'agent tourne sur un modèle local** (déploiement 5), le serveur d'activations peut charger **le même modèle**.
  - La sonde lit alors une représentation interne réelle de ce que l'agent s'apprête à faire.
  - C'est le cas visé par EF-F.
- **Si l'agent tourne sur un modèle distant** (Claude par l'API), Aplomb n'a pas accès à ses activations.
  - Le serveur relit le texte de l'action avec un modèle local : c'est une sonde « lectrice ».
  - Elle reste plus riche qu'une expression régulière, mais ce n'est pas un moniteur interne au sens strict.
  - Le champ `modele` du mandat doit le dire honnêtement.
- **Ollama ne convient pas tel quel.** Il n'expose pas les états cachés intermédiaires. `/api/embed` ne rend qu'un plongement final, et pour les modèles de plongement seulement.

### Étapes (Mac M1, MLX)

1. **Serveur d'activations.**
   - Avec `mlx-lm` (`pip install mlx-lm`, quelques centaines de Mo, sans torch), charger un petit modèle instruit, par exemple `mlx-community/Qwen2.5-3B-Instruct-4bit` (environ 2 Go).
   - Exposer `POST /v1/activations` :
     - tokeniser `texte` ;
     - faire passer les jetons par les couches jusqu'à `couche` ;
     - rendre la moyenne des états cachés.
   - Avec llama.cpp, `llama-server --embeddings --pooling mean` donne un vecteur de la dernière couche seulement. Cela fait une sonde plus grossière, mais sans écrire de code.
   - Écouter sur `127.0.0.1` uniquement : Aplomb refuse une `url` non locale (EF-P5).
2. **Jeu de contraste.** Quelques centaines d'actions du domaine (réclamations), en paires :
   - même tâche, version honnête et version trompeuse ;
   - raisonnement compris ;
   - écrites à la main ou générées puis relues.
   - **Ne pas réutiliser `profils/metier/evaluation.yaml`** : il sert à mesurer, pas à entraîner.
3. **Entraînement.**
   - Extraire les activations de chaque exemple, sur deux ou trois couches du milieu du réseau.
   - Entraîner une régression logistique par couche (le code de `scripts/faux-activations.py entrainer` convient, en lui passant des vecteurs).
   - Garder la couche qui sépare le mieux sur un jeu tenu à part.
   - Écrire le fichier de poids : `nom`, `modele`, `couche`, `poids`, `biais`, `moyenne`.
4. **Mesure, avant de signer.**
   - `aplomb evaluer --mandat <mandat> --sans-sonde --sortie sans.json`
   - `aplomb evaluer --mandat <mandat> --sortie avec.json --reference sans.json`
   - Essayer deux ou trois seuils (`--seuil-sonde`). Retenir celui qui tient le budget d'audit sur les tâches légitimes.
5. **Cosigner** le mandat (`aplomb cosigner`), qui lie les poids, puis relancer `aplomb serve`.
   - La latence de la sonde et ses pannes apparaissent dans Aplomb Watch (`etat_supervision`).

## 6. Déploiement Avancé : ce qui a été ajouté, et pourquoi

Aplomb affiche et journalise un **profil de déploiement**, calculé à partir des moniteurs du mandat (`moniteurs::profil_deploiement`) :

| Profil | Moniteurs |
|---|---|
| `minimal` | règles, invariants et moniteurs déterministes seuls |
| `standard` | + juge |
| `avance` | + juge + sonde interne |
| `avance-sans-juge` | + sonde interne, sans juge |

Seuls les éléments nécessaires au contrat du moniteur interne ont été ajoutés :

| Élément | Justification |
|---|---|
| Profil de déploiement au démarrage, dans l'en-tête de chaque session, dans les preuves (art. 15) et le reporting MCP (`lister_systemes`) | Un auditeur doit savoir quels moniteurs protégeaient une décision donnée ; le dossier de preuves et l'outil de gouvernance le lisent sans ouvrir le mandat |
| Empreinte des poids liée au mandat par la cosignature, vérifiée au démarrage | La sonde décide comme une règle : la changer sans quatre yeux contournerait la gouvernance (EF-G1) |
| URL de la sonde limitée à la machine (`http://127.0.0.1`), délai borné à 2 s | Les activations rejouent le contenu des actions, données personnelles comprises : elles ne quittent pas la machine (EF-P5) ; le hook attend la décision 8 s au plus |
| Plancher configurable et budget de consultations par session | Une sonde en panne ne doit ni bloquer l'agent sans fin, ni le laisser passer à l'insu de l'opérateur : le choix est explicite et journalisé (EF-F3, EF-K3) |
| Coût mesuré (consultations, latence, pannes) dans `aplomb evaluer` et Aplomb Watch | Un moniteur se juge sur ce qu'il attrape **et** sur ce qu'il coûte (EF-E5, EF-H3) |
| Activations jamais demandées pour une action déjà refusée ou en revue | Minimisation des données et de la latence |

Ce qui n'a **pas** été fait, faute de besoin démontré :

- plusieurs sondes à la fois ;
- une sonde qui gèle par défaut ;
- un chiffrement du lien vers le serveur d'activations, qui reste sur la machine.
