# Étape 17 : reconnaissance automatique des retours Thumb (2026-10-16)

Projet courant validé : **`archive:ghidra_thumb_analyzed/step9.gpr`**, `gs_us_map.elf`, copie de l'étape 16. **2 261 fonctions**, **1 891/2 253 entrées ROM (83,93 %)**. Aucun changement d'inventaire ; baseline REA inchangée.

## Diagnostic et comparaison contrôlée

Les quatre wrappers de l'étape 15 ont été comparés sur deux copies indépendantes du même état (2 174 fonctions) :

- `ghidra_thumb_return_probe` : annotation guidée `FlowOverride.RETURN` sur les quatre BX finaux, script `ThumbWrapperReturn.java`. Le script vérifie les octets et les cinq instructions exactes avant de modifier quoi que ce soit.
- `ghidra_thumb_arm_probe` : appel à **l'analyseur ARM installé dans Ghidra**, ciblé sur les quatre corps, script `ArmReturnAnalyze.java`. Aucun override imposé par le script.

Les deux expériences donnent le même C. L'analyseur ARM reconnaît de lui-même les quatre retours par registre et installe l'override RETURN. La variante automatique a été fermée/rouverte : C, exports, P-code et signatures identiques après réouverture.

La comparaison globale ne trouve que les quatre changements d'instruction attendus. Le P-code brut est identique ; dans le P-code effectif, seul le dernier opérateur passe de BRANCHIND à RETURN, avec le même opérande. Les signatures persistées des quatre fonctions restent `DEFAULT undefined(void)`, convention inconnue et purge inconnue. Aucune signature source n'est imposée.

Preuves : `thumb_arm_before/`, `thumb_arm_after/`, `thumb_arm_reopened/`, fichiers `return_evidence.json`, `thumb_arm_verification.json`. Les audits manuels sont dans `thumb_return_before/after/`. La copie manuelle n'est pas promue.

**Interprétation corrigée :** les faux appels indirects des étapes 15–16 apparaissent dans notre pipeline sans analyse automatique. SLEIGH représente un BX de registre générique comme BRANCHIND ; `ArmAnalyzer.flowConstants`, callback `evaluateContext`, reconnaît ensuite un registre de lien propagé et applique RETURN. Les résultats sans ce passage ne démontrent pas une incapacité de Ghidra avec analyse ARM activée. Ils restent les observations exactes de la configuration auparavant testée.

Sources locales : `ARMTHUMBinstructions.sinc:1587-1598`, classe `ArmAnalyzer.java` contenue dans `Ghidra/Processors/ARM/lib/ARM-src.zip`, et `PcodeEmit.dumpReturnOverride` dans `SoftwareModeling-src.zip`.

## Application aux 97 fonctions récupérées

Une nouvelle copie de l'étape 16 reçoit l'analyse ARM ciblée sur les **97 corps** créés aux étapes 15 et 16, liste `thumb_all97.tsv`.

- **36 changements de flux**, tous `COMPUTED_JUMP → TERMINATOR`, aux retours par registre attendus.
- Aucune instruction créée ou supprimée ; aucun autre champ des instructions cibles modifié dans les exports détaillés.
- Tous les autres hashes d'instruction, les noms/corps des fonctions, les données définies et les octets/permissions mémoire sont identiques.
- Les **97 C terminent sans avertissement**, contre 72 avertissements au total avant cette analyse.
- Après fermeture/réouverture : snapshots, cibles et C identiques.

L'analyseur peut, en général, créer données, références et désassemblage. La sélection d'un AddressSet ne garantit pas à elle seule que seuls les retours changent ; c'est l'audit de ce lot qui démontre ici l'absence d'effets annexes.

Preuves : `thumb_analyzed_before/`, `thumb_analyzed_after/`, `thumb_analyzed_reopened/`, **`thumb_analyzed_verification.json`**. Revue indépendante Sol/high des deltas globaux, de la persistance et des quatre sondes à résultat r0.

## Limite de type qui reste visible sans avertissement

La correction du flux ne prouve pas le prototype C. Les quatre sondes `Func_5ac0`, `Func_a3ce4`, `Func_f3898`, `Func_f95c8` retrouvent leur calcul bas dans r0, mais Ghidra construit un retour **64 bits** avec LR restauré comme mot haut, via `CONCAT44(unaff_lr, résultat_r0)`. La source assembleur ne justifie pas cette largeur.

Onze fonctions du lot présentent ce motif de largeur suspecte : `Func_5ac0`, `Func_78a8c`, `Func_8e990`, `Func_a3ce4`, `Func_a413c`, `Func_bf65c`, `Func_c0edc`, `Func_f3898`, `Func_f38ac`, `Func_f40b4`, `Func_f95c8`. `Func_bf65c` l'exprime par `(ulonglong)unaff_lr << 0x20` plutôt que CONCAT44. Le cas est analogue à `Func_f4008` observé à l'étape 13.

Les quatre wrappers initiaux ont un retour C `unaff_lr` sur 32 bits. Il reflète la valeur physique de r0 après `pop {r0}` ; cela ne prouve pas que le source retourne intentionnellement cette valeur. Aucun prototype n'a été forcé pour obtenir un C plus présentable.

## Reproduction et suite

```sh
# Sur une copie de l'étape 16, entre audits avant/après :
# analyzeHeadless ... -noanalysis -postScript ArmReturnAnalyze.java work/thumb_all97.tsv
python3 -I scripts/verify_arm_analysis.py work/thumb_analyzed_before work/thumb_analyzed_after work/thumb_analyzed_reopened work/thumb_analyzed_verification.json
```

Le protocole retenu pour les prochains lots ajoute cette analyse ciblée entre création et audit final. Toute donnée/référence/instruction ajoutée hors du plan nécessite une revue avant promotion du projet.

La famille suivante, `thumb_long_plan/`, contient **27 fonctions sans données inline ni alias non résolu**, 1 684 octets et 788 instructions, taille maximale 114 octets. Revue source : branches internes résolues, toutes les instructions atteignables, bornes du TSV respectées, piles équilibrées sur les chemins examinés. Récupération lancée sur copie `ghidra_thumb_long` ; cet état n'est courant qu'après vérification et réouverture.

362 entrées de référence restent absentes avant ce prochain lot. Notion en attente, aucun outil connecté disponible ; mémoire non modifiée.
