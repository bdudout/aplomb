// Profil déclaratif « rh » : règles permit / forbid. Refus par défaut : un outil non
// déclaré (verbe « autre ») n'est permis par aucune règle.

@id("lire-un-dossier")
permit (principal, action == Action::"lire_dossier", resource);

@id("rechercher")
permit (principal, action == Action::"rechercher", resource);

@id("lire-le-web")
permit (principal, action == Action::"lire_web", resource);

@id("modifier-un-dossier")
permit (principal, action == Action::"modifier_dossier", resource);

// Les exports ne partent que vers la paie de l'organisation.
@id("exporter-vers-la-paie")
permit (principal, action == Action::"exporter", resource)
when { context.domaine like "*@paie.exemple.fr" };

@id("envoyer-un-courrier")
permit (principal, action == Action::"envoyer", resource);

// Le salaire ne se modifie jamais par l'agent.
@id("jamais-le-salaire")
forbid (principal, action == Action::"modifier_dossier", resource)
when { context.champ == "salaire" };
