# Installer le hook hors de portée de l'agent (niveau 1 renforcé)

Dans le dépôt, le hook est déclaré dans `bac-a-sable/.claude/settings.json`, un fichier
que l'agent peut modifier. SAL gèle déjà toute tentative (règle `point-protege`), mais
la configuration reste à portée de main. Les **paramètres gérés** de Claude Code
corrigent cela (EF-C5, principe 9 de l'expression de besoin) :

- ils passent avant tous les autres fichiers de paramètres ;
- avec `allowManagedHooksOnly`, seuls les hooks de l'administrateur s'exécutent ;
- le fichier et le binaire appartiennent à root : l'agent, qui tourne sous ton compte,
  ne peut ni les modifier ni les remplacer.

## Installation (droits administrateur, à faire toi-même)

```sh
sudo install -d -o root -g wheel -m 755 /usr/local/libexec/sal
sudo install -o root -g wheel -m 755 target/debug/sal /usr/local/libexec/sal/sal
sudo install -o root -g wheel -m 644 cles/reponses.pub /usr/local/libexec/sal/reponses.pub
sudo install -d -o root -g wheel -m 755 "/Library/Application Support/ClaudeCode"
sudo install -o root -g wheel -m 644 deploiement/managed-settings.json "/Library/Application Support/ClaudeCode/managed-settings.json"
```

Ensuite, retire le hook du dépôt (`bac-a-sable/.claude/settings.json`), sinon il
s'exécute deux fois. Dans une session Claude Code, `/status` doit afficher les
paramètres gérés dans la ligne `Setting sources`.

## À savoir avant d'installer

- **Toute la machine est concernée** : les paramètres gérés s'appliquent à toutes les
  sessions Claude Code, dans tous les dossiers. L'option `--perimetre` limite la
  supervision aux dossiers listés ; ailleurs, le hook laisse décider Claude Code.
- **`allowManagedHooksOnly` désactive tes autres hooks**, ceux de tes projets et de
  `~/.claude/settings.json`. Vérifie que tu n'en dépends pas.
- **Le superviseur doit tourner** (`sal serve`) : sinon, toute action dans le
  périmètre est refusée (fail-closed). Hors périmètre, rien ne change.
- **Un administrateur local peut tout défaire** : la protection vaut contre l'agent, qui
  n'a pas les droits root, pas contre un humain administrateur de la machine.
- **À vérifier** : la documentation ne dit pas clairement si un `disableAllHooks` posé
  dans un fichier de projet désactive aussi les hooks gérés. SAL gèle de toute façon
  une commande qui le contient ou qui écrit dans un dossier `.claude`.
- **Mise à jour** : après chaque `cargo build`, recopier le binaire avec la deuxième
  commande ci-dessus.

## Désinstallation

```sh
sudo rm "/Library/Application Support/ClaudeCode/managed-settings.json"
sudo rm -r /usr/local/libexec/sal
```
