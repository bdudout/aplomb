// Profil C — agent de code. Règles de revue humaine (palier Orange).
// Évaluées seulement si regles.cedar autorise ; une correspondance ⇒ Review
// (Claude Code demande alors confirmation à l'utilisateur).

@id("revue-lecture-hors-depot")
permit (principal, action == Action::"lire", resource)
unless { context.dans_depot };

@id("revue-git-push")
permit (principal, action == Action::"executer", resource)
when { context.commande like "*git push*" };

@id("revue-suppression-recursive")
permit (principal, action == Action::"executer", resource)
when { context.suppression_recursive };

@id("revue-installation-de-dependance")
permit (principal, action == Action::"executer", resource)
when { context.installe_dependance };

@id("revue-desactivation-de-tests")
permit (principal, action == Action::"ecrire", resource)
when { context.desactive_tests };

// Sens des flux (EF-C4) : un domaine autorisé en lecture ne l'est pas en écriture.
@id("revue-envoi-externe")
permit (principal, action, resource)
when { context.envoi_externe };

@id("revue-delegation")
permit (principal, action == Action::"deleguer", resource);

// Outil MCP : sans revue seulement s'il est déclaré au mandat (serveur et outil).
@id("revue-outil-mcp")
permit (principal, action == Action::"outil_mcp", resource)
unless { context.mcp_declare };

@id("revue-outil-inconnu")
permit (principal, action == Action::"autre", resource);
