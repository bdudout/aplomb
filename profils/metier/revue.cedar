// Profil M — agent métier régulé. Règles de revue humaine (palier Orange).
// Évaluées seulement si regles.cedar autorise ; une correspondance ⇒ Review.
// Invariant du profil : aucune action irréversible sans approbation.

@id("revue-paiement")
permit (principal, action == Action::"payer", resource);

@id("revue-suppression")
permit (principal, action == Action::"supprimer", resource);

@id("revue-export")
permit (principal, action == Action::"exporter", resource);

@id("revue-envoi-externe")
permit (principal, action == Action::"envoyer", resource)
unless { context.interne };

@id("revue-coordonnees-bancaires")
permit (principal, action == Action::"ecrire_dossier", resource)
when { context.modifie_coordonnees_bancaires };
