// Profil C — agent de code. Règles permit / forbid.
// Refus par défaut : tout ce qui n'est pas permis est refusé ; un forbid l'emporte toujours.
// Les attributs de `context` sont calculés par sal_core::profils::code (toujours présents).

// --- Autorisations ---------------------------------------------------------

@id("lire")
permit (principal, action == Action::"lire", resource);

@id("ecrire-dans-le-depot")
permit (principal, action == Action::"ecrire", resource)
when { context.dans_depot };

@id("executer-dans-le-depot")
permit (principal, action == Action::"executer", resource)
when { context.cwd_dans_depot };

@id("reseau-autorise")
permit (principal, action == Action::"reseau", resource)
when { context.domaine_autorise };

@id("outils-internes")
permit (principal, action == Action::"interne", resource);

// Délégation, outils MCP et outils inconnus : permis ici, mais soumis à revue (revue.cedar).
@id("deleguer")
permit (principal, action == Action::"deleguer", resource);

@id("outil-mcp")
permit (principal, action == Action::"outil_mcp", resource);

@id("autre-outil")
permit (principal, action == Action::"autre", resource);

// --- Interdits (prioritaires) ------------------------------------------------

@id("secrets")
forbid (principal, action, resource)
when { context.chemin_sensible || context.commande_lit_secret };

@id("ecriture-hors-depot")
forbid (principal, action == Action::"ecrire", resource)
unless { context.dans_depot };

@id("push-branche-protegee")
forbid (principal, action, resource)
when { context.pousse_branche_protegee };

@id("suppression-hors-depot")
forbid (principal, action, resource)
when { context.suppression_hors_depot };

@id("contournement-des-controles")
forbid (principal, action, resource)
when { context.contourne_controles };

@id("reseau-non-autorise")
forbid (principal, action, resource)
when { context.reseau && !context.domaine_autorise };

// L'agent qui agit sur sa propre supervision est traité comme désaligné : gel (EF-C2).
@id("atteinte-a-la-supervision")
@verdict("gel")
forbid (principal, action, resource)
when { context.touche_supervision };
