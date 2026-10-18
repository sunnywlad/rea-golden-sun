# Étape 34 : récupération du reliquat ROM (terminée)

## État au 18 octobre 2026

Les 30 entrées absentes au départ ont été récupérées et contrôlées dans la copie cumulative `work/ghidra_step34_runtime_arm_scoped/step9.gpr`. La baseline retenue `work/ghidra_thumb_special_pair_scoped/step9.gpr` reste intacte ; le candidat n'a pas été promu. Le candidat a été fermé puis rouvert avant comparaison.

Lots validés :

- Cinq `.call_via` : `Func_94544`, `Func_b81c8`, `Func_1cbd4`, `Func_4ab0`, `Func_4e54`.
- Cinq dispatchs Thumb par tables locales : `Func_949a8`, `Func_a4924`, `Func_26080`, `Func_a414c`, `Func_f3078`.
- `Func_f95f0`, avec un appel à l'étiquette de retour partagée `0x080f9a12` et un transfert final vérifié vers la routine Thumb IWRAM `0x03007000`.
- `Func_404` et `Func_20f4`, récupérées avec `TMode=0` et désassemblage générique Ghidra.
- Huit entrées ARM simples du bloc ROM `rom_770` : `Func_888`, `Func_89c`, `Func_8d4`, `Func_948`, `Func_984`, `Func_b50`, `Func_b60`, `Func_d30`.
- Trois entrées ARM `rom_770` : `Func_770` (corps limité au code avant ses îlots de données), `Func_8d8` et `Func_1af8` (dispatchs PC calculés, corps bornés et vérifiés sur source).
- Quatre chevauchements code/donnée : `Func_6abc`, `Func_6b84`, `Func_6c24`, `Func_6f48`. Les quatre unités `undefined2` aux entrées ont été remplacées par du code confirmé par la source ; les îlots de littéraux restent hors des corps.
- Deux fonctions à modes mêlés, `Func_f9674` et `Func_dc8`, récupérées avec des plages Thumb/ARM explicitement séparées et vérifiées sur les octets ROM.

Preuve cumulative : `work/step34_aggregate_verification.json`. Résultat : 2 593 à 2 623 fonctions, 5 239 instructions ajoutées, 142 unités de données définies ajoutées, quatre `undefined2` source-confirmées remplacées, octets et permissions mémoire conservés, fonctions/instructions précédentes intactes, snapshot sauvegardé identique après réouverture.

Preuves par lot : `step34_callvia_verification.json`, `step34_cumulative_switch_verification.json`, `step34_f95f0_verification.json`, `step34_arm_verification.json`, `step34_runtime_arm_verification.json`, `step34_manual_arm_verification.json`, `step34_overlap_verification.json`, `step34_f9674_verification.json`, `step34_dc8_verification.json`. Les audits `after` et `reopened` sont sous `work/step34_*`. Les décompilations sont des représentations d'analyse ; l'équivalence sémantique C n'est pas démontrée. La comparaison confirme l'intégrité de la ROM, des permissions mémoire et des instructions préexistantes.

## Changements de scripts

`scripts/plan_thumb_inline.py` reconnaît maintenant l'expansion exacte de `.call_via`, les remplissages d'alignement exécutés, les dispatchs vérifiés par table et le transfert IWRAM final de `Func_f95f0`. `RecoverThumb.java` sait désassembler les instructions planifiées individuellement et créer le corps de code source exact pour les dispatchs calculés. `ExportApprovedReturns.java` émet les preuves P-code de retour depuis la paire source `pop`/`bx` et les octets Thumb, sans exiger une passe globale de l'analyseur. `ApplyApprovedAnalysis.java` n'applique que les overrides et littéraux ainsi approuvés. `RecoverArm.java` ajoute le mode ARM avec contexte explicite et désassemblage générique. `verify_thumb_recovery.py` contrôle aussi la preuve du transfert IWRAM.

## Limites

La récupération concerne les entrées de stockage ROM. Les fonctions copiées en DMA vers des buffers runtime restent à reconstruire séparément, notamment `Func_9bb8`, `Func_55d8` (copie `Func_20f4` vers la pile) et `Func_d304` (copie `Func_a494` vers un bloc alloué). Les décompilations ne démontrent pas l'équivalence sémantique C.

La commande `python3 -m py_compile scripts/plan_thumb_inline.py scripts/verify_thumb_recovery.py` passe. `RecoverArm.java`, `RecoverMixed.java` et `RecoverOverlapThumb.java` traitent les plages source-bornées des lots ARM, mixtes et code/donnée.
