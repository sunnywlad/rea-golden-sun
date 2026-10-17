# Étape 21, premier essai non promu (2026-10-16)

État validé conservé : étape 20, `ghidra_thumb_literal_pilot`, 2 330 fonctions. La copie d'essai **`ghidra_thumb_literal_medium` n'est pas promue**.

Les 148 fonctions prévues ont été créées, pour 3 839 instructions et 8 134 octets. L'analyse ARM a ensuite laissé des annotations de données hors du périmètre approuvé :

- 294 nouvelles unités sur les mots de pool prévus ;
- 12 nouvelles unités hors pools : `0x02001078`, `0x0200107a`, `0x0200107c`, `0x0200107e`, `0x02001080`, `0x02001082`, `0x02001084`, `0x03001e9c`, `0x03001ec0`, `0x03001ed8`, `0x08084a8c`, `0x08084a8d` ;
- trois anciennes unités modifiées ou supprimées : `0x02000438`, `0x0200043a`, `0x04000014`.

Les octets/permissions mémoire, anciens noms/corps et anciennes instructions restent identiques. Les 148 C terminent sans avertissement. Ces succès ne suffisent pas : les invariants sur les données échouent.

Cause vérifiée dans la source installée : `ArmAnalyzer.evaluateReference` appelle `createData` sur les lectures/écritures référencées. `ConstantPropagationAnalyzer.createData` est `public final`, et peut effacer une petite unité Undefined pour en créer une plus large. Le ciblage des corps n'interdit pas ces changements dans les données référencées.

Preuves conservées : `thumb_literal_medium_before/`, `thumb_literal_medium_recovery/`, `thumb_literal_medium_after/`, `thumb_literal_medium.log`. Cette variante n'est pas promue.

Correction en préparation : exporter les seuls retours RETURN reconnus automatiquement dans cette copie d'analyse, puis repartir d'une nouvelle copie de l'étape 20. Y récupérer les fonctions sans relancer ArmAnalyzer, appliquer seulement les retours dont les octets/P-code brut et le motif source concordent, et déclarer uniquement les mots de pool prouvés, sans effacer aucune donnée existante. Ne pas utiliser de rollback imbriqué, piège déjà établi dans ce projet. Vérifier à nouveau tous les invariants et la persistance avant promotion.
