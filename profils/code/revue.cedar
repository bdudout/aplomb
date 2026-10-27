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

@id("revue-delegation")
permit (principal, action == Action::"deleguer", resource);

@id("revue-outil-mcp")
permit (principal, action == Action::"outil_mcp", resource);

@id("revue-outil-inconnu")
permit (principal, action == Action::"autre", resource);
