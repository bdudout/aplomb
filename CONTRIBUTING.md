# Contribuer à Aplomb

Merci de ton intérêt. Aplomb est publié sous deux licences : `crates/aplomb-core` sous
Apache-2.0, le reste sous EUPL-1.2 (voir [`README.md`](README.md#licence)).

## Accord de contribution

Pour garder la possibilité de faire évoluer la licence du projet (par exemple proposer
une licence commerciale en plus de l'EUPL), chaque contribution doit être accompagnée de
l'accord suivant, à recopier dans la description de la demande de fusion :

> Je suis l'auteur de cette contribution, ou j'ai le droit de la proposer. Je la publie
> sous la licence du fichier concerné (Apache-2.0 ou EUPL-1.2) et j'accorde en outre à
> Brice Dudout, à titre gratuit, mondial, non exclusif et irrévocable, le droit de
> l'utiliser, de la modifier et de la distribuer sous toute autre licence, libre ou non.

Sans cet accord, la contribution ne peut pas être fusionnée.

## En pratique

- `cargo test` doit passer, et `scripts/scenarios.sh` si la contribution touche aux décisions.
- Toute modification d'un mandat, des règles `profils/code/*.cedar` ou de `comptes.yaml`
  doit être recosignée (`aplomb cosigner`) : le superviseur refuse sinon de démarrer.
- Une faille de sécurité se signale en privé, pas dans un ticket public.
