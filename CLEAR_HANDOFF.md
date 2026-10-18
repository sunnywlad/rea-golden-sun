# Reprise après l’étape 34 terminée

L’étape 34 est terminée : les 30 entrées ROM restantes ont été récupérées et vérifiées, soit 2 253/2 253 entrées reconnues. Le candidat cumulatif compte 2 623 fonctions, contre 2 593 dans la baseline.

## État Ghidra

- Candidat prêt, fermé puis rouvert et comparé : `work/ghidra_step34_runtime_arm_scoped/step9.gpr`.
- Baseline retenue, intacte : `work/ghidra_thumb_special_pair_scoped/step9.gpr`.
- Le candidat n’est pas promu. Toute promotion attend l’ordre explicite de Wladimir.
- Aucun nouveau lot n’est autorisé.

La récupération des entrées de stockage ROM ne couvre pas les fonctions copiées en DMA vers des buffers runtime. Restent notamment `Func_9bb8`, `Func_55d8` (copie `Func_20f4` vers la pile) et `Func_d304` (copie `Func_a494` vers un bloc alloué). Ne pas les traiter sans autorisation.

## Lectures de reprise

1. `work/step34.md`, résultat, lots et limites.
2. Section « Étape 34 » de `RUN_STATE.md`, état Ghidra et références aux preuves.
3. `work/step34_aggregate_verification.json`, preuve cumulative.

L’étape 34 a été menée avec GPT-6 Luna en effort High. Le coût réel par rapport à Sol Medium n’a pas été mesuré ; aucun gain chiffré ne doit être attribué à cette tâche.

Les fichiers du projet font foi. Mémoire et Notion restent sous la responsabilité de Claude.
