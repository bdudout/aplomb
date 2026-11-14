# Brancher d'autres agents de code : Codex, Cursor

`aplomb hook` sait lire le format d'événement et répondre dans le format de trois agents :

| Agent | Option | Branchement journalisé | « Demander à l'humain » |
|---|---|---|---|
| Claude Code | `--agent claude-code` (défaut) | `hook-claude-code` | Oui : Claude Code fait confirmer l'action |
| Codex CLI | `--agent codex` | `hook-codex` | Non : une revue devient un **refus** motivé (« revue humaine requise ») |
| Cursor | `--agent cursor` | `hook-cursor` | Non : une revue devient un **refus** motivé. La réponse `ask` de Cursor n'est pas fiable d'une version à l'autre. |

Le mandat nomme l'agent : `agent: codex` ou `agent: cursor`. Un hook qui se présente
sous un autre agent que celui du mandat est refusé. Le reste ne change pas : réponses
signées sur le nonce, refus si le superviseur est injoignable, journal, bornes, gel.

Une action en revue est refusée, pas perdue : l'agent reçoit le motif, et l'humain peut
élargir le mandat (à quatre yeux) si l'action était légitime. Pour une vraie file de
revue avec ces agents, faire passer leurs outils MCP par la passerelle MCP : la revue y
attend la réponse d'un humain dans Aplomb Watch.

## Codex CLI

`~/.codex/hooks.json`, ou `.codex/hooks.json` dans le projet :

```json
{
  "hooks": {
    "PreToolUse": [{"hooks": [{"type": "command",
      "command": "/Users/moi/.cargo/bin/aplomb hook --agent codex --cle-serveur /Users/moi/aplomb-instance/cles/reponses.pub"}]}],
    "PostToolUse": [{"hooks": [{"type": "command",
      "command": "/Users/moi/.cargo/bin/aplomb hook --agent codex --cle-serveur /Users/moi/aplomb-instance/cles/reponses.pub"}]}]
  }
}
```

Le format suit la documentation des hooks de Codex à la date de J12 (novembre 2026). Il
peut aussi se déclarer dans `config.toml` : vérifiez la syntaxe de votre version.

Ce qu'Aplomb comprend :
- **Commandes** : `shell`, `exec_command` et `local_shell` sont jugées comme une commande
  `Bash`. Une commande donnée en tableau (`["bash", "-lc", "…"]`) est jugée sur son
  dernier élément.
- **`apply_patch`** devient une écriture par fichier touché (`*** Update File:`,
  `*** Add File:`, `*** Delete File:`, `*** Move to:`). Le patch est refusé dès qu'un seul
  de ces fichiers est refusé.
- Les autres outils (MCP compris) sont jugés sous leur nom.

## Cursor

`.cursor/hooks.json` dans le projet :

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{"command": "aplomb hook --agent cursor --cle-serveur cles/reponses.pub"}],
    "beforeMCPExecution":   [{"command": "aplomb hook --agent cursor --cle-serveur cles/reponses.pub"}],
    "beforeReadFile":       [{"command": "aplomb hook --agent cursor --cle-serveur cles/reponses.pub"}],
    "preToolUse":           [{"command": "aplomb hook --agent cursor --cle-serveur cles/reponses.pub"}],
    "afterFileEdit":        [{"command": "aplomb hook --agent cursor --cle-serveur cles/reponses.pub"}]
  }
}
```

Correspondances :
- `beforeShellExecution` devient `Bash`.
- `beforeReadFile` devient `Read`.
- `beforeMCPExecution` devient `mcp__<serveur>__<outil>`.
- `preToolUse` est jugé sous le nom de l'outil (`Shell` devient `Bash`, `Delete` devient
  `Write`).
- `afterFileEdit` et `postToolUse` sont journalisés après coup, sans réponse.

La session est le `conversation_id` de Cursor.

## Ce qui n'est pas couvert

- **Gemini CLI** : remplacé par Antigravity CLI le 18 juin 2026. Pas d'adaptateur tant
  que le format des hooks d'Antigravity n'est pas stabilisé.
- **Contrôle croisé** (identifiant d'appel d'outil vu au proxy du modèle) : il suppose
  que l'agent passe par le proxy LLM. Codex et Cursor peuvent y passer par l'API
  compatible OpenAI (`/v1/chat/completions`, voir le README). Cursor, qui appelle ses
  propres serveurs, n'y passe pas.
- Un hook reste un branchement de **niveau 1** : l'agent tourne avec les droits de
  l'utilisateur. Pour le niveau 3, le confiner (voir `conteneur/`).
