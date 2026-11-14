# Identité : MFA, SSO, revue des comptes

Par défaut, Aplomb n'a besoin ni d'annuaire ni de second facteur. Chaque compte a sa clé
ed25519, protégée par la phrase de passe. Assouplir (dégeler, cosigner) demande toujours
deux personnes.

Les trois options ci-dessous se déclarent dans `comptes.yaml`, sous `identite:`. Elles
sont donc **cosignées** avec la liste des comptes : personne ne peut retirer seul le second
facteur ou la revue. Elles apparaissent dans `aplomb modules`, à l'étape 11.

```yaml
comptes:
- {id: alice, roles: [operateur], cle_publique: …}
- {id: bob, roles: [approbateur], cle_publique: …}
identite:
  mfa: {}                          # second facteur obligatoire
  revue: {inactivite_jours: 90}    # suspension des comptes inactifs
  sso:                             # connexion par l'annuaire (OpenID Connect)
    emetteur: https://login.microsoftonline.com/<tenant>/v2.0
    client_id: 3f2a…
    secret_env: APLOMB_SSO_SECRET
    autorisation: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
    jeton: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
    redirection: https://aplomb.exemple.fr/sso/retour
    roles: {SecOps: [operateur], DSI-Risques: [approbateur], Audit: [lecteur]}
```

Après modification : `aplomb cosigner comptes.yaml --compte alice --compte bob`, puis
redémarrer `aplomb serve`. La ligne `identité` du démarrage résume ce qui est actif.

## Second facteur (TOTP)

```bash
aplomb compte mfa --compte alice              # adresse otpauth:// et clé à saisir
aplomb compte mfa --compte alice --code 123456  # confirme et active
```

Toute application TOTP convient : Aegis, FreeOTP, Google ou Microsoft Authenticator,
1Password. Le secret est enveloppé par la clé maîtresse, dans
`~/.config/aplomb/mfa/<compte>.totp`.

Une fois `mfa` déclaré, le second facteur est exigé :

| Action | Comment |
|---|---|
| Ouvrir Aplomb Watch | le lien de `aplomb admin connexion` demande le code ; un mauvais code consomme le lien |
| Dégeler (demande et approbation) | `aplomb admin --compte alice degel --code 123456` |
| Réactiver un compte suspendu | `aplomb admin --compte alice reactiver --cible bob --code 123456` |
| Geler | jamais : durcir reste immédiat, sans second facteur |

- Un code ne sert qu'une fois.
- Le téléphone peut avoir 30 s d'avance ou de retard.
- Les refus sont journalisés.

La cosignature d'un mandat ou des comptes se fait hors ligne. Elle demande déjà la clé du
compte et la phrase de passe, ou Touch ID.

## SSO (OpenID Connect)

- Le lien de connexion est `https://<aplomb>/sso/debut`. Aplomb utilise le flux « code
  d'autorisation » avec PKCE (S256), un état et un nonce à usage unique.
- Le jeton d'identité est reçu directement du point `jeton`, sur TLS (OIDC Core,
  § 3.1.3.7). Aplomb en vérifie l'émetteur, l'audience, les dates et le nonce.
- **Les rôles viennent des groupes** (`roles:`). Une personne dont aucun groupe n'a de
  rôle est refusée.
- **Le SSO authentifie, il ne décide pas.**
  - Une identité SSO n'a de rôles que le temps de sa session.
  - Elle ne peut pas cosigner : les mandats et les comptes restent signés par des clés.
  - Elle ne peut pas approuver sa propre demande : les quatre yeux s'appliquent comme
    pour les autres comptes.
- **Avec `mfa`**, le fournisseur doit attester un second facteur (`amr` : `mfa`, `otp`,
  `hwk`, etc.). Sinon, la connexion est refusée. C'est au fournisseur d'imposer la MFA à
  ces groupes (accès conditionnel).
- Le secret du client est lu dans la variable nommée par `secret_env`. Si elle manque,
  `serve` refuse de démarrer.

Fournisseurs testés au banc : un faux fournisseur local (`scripts/faux-idp.py`). Entra ID,
Okta, Keycloak et Google Workspace suivent le même flux, mais n'ont pas encore été
essayés.

## Revue des comptes

- Avec `revue`, un compte sans activité depuis N jours est suspendu, au démarrage puis
  toutes les heures. L'activité, ce sont les requêtes signées, les connexions et les
  réponses aux revues ; elle est suivie dans `activite-comptes.json`.
- La suspension est journalisée et diffusée au SIEM si l'option est active.
- La réactivation demande deux comptes, dont aucun n'est le compte visé :

```bash
aplomb admin --compte alice reactiver --cible bob --code …
aplomb admin --compte carole reactiver --cible bob --code …
```

**Campagne de revue**, par exemple chaque trimestre :

```bash
aplomb compte revue --attestation revues/revue-2026-T4.yaml
# compléter le constat dans le fichier, puis :
aplomb cosigner revues/revue-2026-T4.yaml --compte alice --compte bob
```

La campagne liste les comptes, leurs rôles (les cumuls sont signalés), leur dernière
activité et le second facteur. Une fois cosignée, `aplomb preuves exporter` la joint au
dossier de preuves (`gouvernance/revues/`).

## Pas encore fait

- WebAuthn (clés de sécurité, passkeys).
- SAML.
- Provisionnement SCIM.
- Revue des comptes techniques des agents (`agents.yaml`).
