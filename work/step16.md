# Étape 16 : 87 petites entrées Thumb supplémentaires (2026-10-16)

Projet courant : `archive:ghidra_thumb_small/step9.gpr`, programme `gs_us_map.elf`, copie de l'étape 15.

- **87 fonctions créées**, exactement le lot prévu ; **2 261 fonctions** au total.
- **1 891/2 253 entrées de stockage ROM (83,93 %)**, contre 1 804 à l'étape 15. Baseline REA inchangée ; récupération guidée.
- **323 instructions, 694 octets** nouveaux. Adresses, longueurs, octets, corps et destinations directes concordent avec le plan dérivé du source.
- Les 191 286 anciennes instructions, les noms/corps des fonctions préexistantes, les 23 047 unités de données définies et les octets/permissions mémoire sont conservés.
- Réouverture en lecture seule et second passage : 87 fonctions préexistantes, aucun ajout ; snapshots globaux, cibles et C identiques.

## Sélection et preuves

Le plan `thumb_small_plan/plan.json` sélectionne, parmi les 431 Thumb ROM non définies restantes après le pilote, les fonctions de taille ≤32 octets sans directives/pools internes ni pseudo-littéraux. Les cibles directes doivent être des labels locaux ou des `Func_<hex>` dont l'adresse est explicite. Les retours indirects admis sont `bx lr` ou `bx rN` précédé du `pop {rN}` correspondant. Cette dernière sélection établit un motif source, pas une reconnaissance automatique du retour par Ghidra.

Les alias `_Func_*` et `Func_af0_from_thumb` sont exclus : leur adresse de stub doit être résolue, sans supprimer naïvement leur préfixe.

```sh
python3 -I scripts/plan_thumb_recovery.py work/thumb_pilot_after/snapshot.json work/thumb_small_plan --max-code-bytes 32 --resolved-branches-and-returns
python3 -I scripts/verify_thumb_recovery.py work/thumb_small_plan/plan.json work/thumb_small_before work/thumb_small_after work/thumb_small_reopened work/thumb_small_verification.json
```

Audits : `thumb_small_before/`, `thumb_small_after/`, `thumb_small_reopened/`. Résultats de création et listings : `thumb_small_recovery/`. Second passage : `thumb_small_repeat/`. Vérification automatique passée : `thumb_small_verification.json`.

## Qualité observée du C

Les 87 décompilations terminent. La répartition est **55 sans avertissement, 32 avec deux avertissements**. Dix-sept fonctions contiennent un appel BL, pour 24 BL cumulés.

- 55 épilogues `bx lr` : 45 retours sur une seule instruction, dix fonctions de deux instructions au plus.
- 32 épilogues `pop {rN}; bx rN` : pour chacune, les deux avertissements visent exactement le BX final, table de sauts non récupérée et indirect traité comme appel. Le C ajoute un appel indirect fictif.

L'absence d'avertissement ne prouve pas l'équivalence du C. Dix sondes non triviales ont été confrontées au source : copie de mots en boucle (`Func_412c`), conditions/calcul booléen (`Func_5ac0`), gardes et écritures (`Func_c3ec`, `Func_ea54`, `Func_1edcc`), parcours de liens (`Func_1656c`), intervalle (`Func_a3ce4`), boucle de quatre pointeurs (`Func_b7e04`), borne [0,31] (`Func_f3898`) et sélection 2/3 (`Func_f95c8`). Les opérations précédant l'épilogue concordent sur ces sondes. Quatre valeurs de retour r0 sont masquées par les prototypes C `void` et le faux appel indirect : `Func_5ac0`, `Func_a3ce4`, `Func_f3898`, `Func_f95c8`.

Les rapports de qualité doivent conserver ces défauts de la configuration testée. Le plan et son vérificateur contrôlent la structure et les octets, pas l'encodage des opérandes du source par un assembleur indépendant ni l'équivalence dynamique du C.

## Effet de la configuration d'analyse

Toutes les récupérations de ces lots utilisent `-noanalysis` et désactivent l'analyse automatique du désassemblage pour conserver le périmètre des modifications. Cela explique une limite possible des retours : SLEIGH encode `bx lr` comme RETURN, mais un BX de registre générique comme BRANCHIND. L'analyseur ARM de propagation de constantes contient une reconnaissance supplémentaire du registre de lien et applique un override RETURN.

Source locale : `Ghidra/Processors/ARM/data/languages/ARMTHUMBinstructions.sinc:1587-1598` et `ghidra/app/plugin/core/analysis/ArmAnalyzer.java` dans `Ghidra/Processors/ARM/lib/ARM-src.zip`, méthode `flowConstants`, callback `evaluateContext`.

Les faux appels observés avec analyse désactivée ne démontrent donc pas que Ghidra configuré avec cette analyse serait incapable de reconnaître ces retours. Une comparaison séparée, sur copie du pilote de l'étape 15, teste l'override guidé et l'analyse ARM ciblée. Ces copies expérimentales ne remplacent pas le projet courant.

## Suite et état

**362 entrées restent absentes** : 346 ROM non définies (344 Thumb +2 ARM), douze entrées de stockage du bloc rom_770 chargé en IWRAM et quatre cas code/donnée. Les prochaines familles sont les Thumb plus longues, les stubs/alias à résoudre et les cas avec données inline. Avant extension, terminer l'expérience sur les retours pour fixer le protocole d'analyse et distinguer les défauts de configuration des limites de l'outil.

Notion non synchronisé, aucun outil connecté disponible. Mémoire non modifiée.
