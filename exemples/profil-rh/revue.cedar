// Profil déclaratif « rh » : une correspondance impose une revue humaine.

@id("revue-envoi")
permit (principal, action == Action::"envoyer", resource);

@id("revue-modification")
permit (principal, action == Action::"modifier_dossier", resource);
