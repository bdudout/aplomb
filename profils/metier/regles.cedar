// Profil M — agent métier régulé. Règles permit / forbid.
// Refus par défaut : un outil non déclaré au mandat (verbe « autre ») est refusé (EF-A4).
// Les attributs de `context` sont calculés par aplomb_core::profils::metier (toujours présents).
// Les invariants du profil (rien d'irréversible sans approbation, pas de fuite de données)
// sont aussi tenus par ses moniteurs : retirer une règle ici ne les lève pas (EF-A5).

// --- Autorisations ---------------------------------------------------------

@id("lire-un-dossier-habilite")
permit (principal, action == Action::"lire_dossier", resource)
when { context.categorie_autorisee };

@id("lire-un-message-entrant")
permit (principal, action == Action::"lire_message", resource);

@id("rechercher")
permit (principal, action == Action::"rechercher", resource)
when { context.categorie_autorisee };

@id("consulter-la-reference")
permit (principal, action == Action::"consulter_reference", resource);

@id("mettre-a-jour-un-dossier")
permit (principal, action == Action::"ecrire_dossier", resource)
when { context.categorie_autorisee };

@id("envoyer-a-un-destinataire-autorise")
permit (principal, action == Action::"envoyer", resource)
when { context.interne || context.destinataire_autorise };

// Irréversibles : permis ici, toujours soumis à approbation (revue.cedar et moniteurs).
@id("payer")
permit (principal, action == Action::"payer", resource);

@id("supprimer")
permit (principal, action == Action::"supprimer", resource);

// Un export reste dans l'organisation : vers l'extérieur, refus par défaut.
@id("exporter-en-interne")
permit (principal, action == Action::"exporter", resource)
unless { context.envoi_externe };

@id("outils-internes")
permit (principal, action == Action::"interne", resource);

// --- Interdits (prioritaires) ------------------------------------------------

@id("donnees-hors-habilitation")
forbid (principal, action, resource)
unless { context.categorie_autorisee };

@id("destinataire-non-autorise")
forbid (principal, action == Action::"envoyer", resource)
unless { context.interne || context.destinataire_autorise };

@id("juridiction-non-autorisee")
forbid (principal, action, resource)
unless { context.juridiction_autorisee };

@id("donnees-sensibles-vers-un-destinataire-non-autorise")
forbid (principal, action, resource)
when { context.donnees_hors_destinataire };

@id("paiement-hors-plafond")
forbid (principal, action == Action::"payer", resource)
when { context.montant_hors_plafond };

@id("export-hors-plafond")
forbid (principal, action == Action::"exporter", resource)
when { context.export_hors_plafond };

@id("suppression-en-masse")
forbid (principal, action == Action::"supprimer", resource)
when { context.suppression_en_masse };

// L'agent qui tente de valider lui-même ce qu'un humain doit approuver est désaligné : gel.
@id("auto-approbation")
@verdict("gel")
forbid (principal, action == Action::"approuver", resource);
