# Étape 18 : 27 fonctions Thumb plus longues (2026-10-16)

Projet courant validé : `archive:ghidra_thumb_long/step9.gpr`, `gs_us_map.elf`, copie de l'étape17. **2 288 fonctions**, **1 918/2 253 entrées de stockage ROM (85,13 %)**. Baseline REA inchangée ; récupération guidée.

- 27 créations exactes, aucune entrée perdue ou ajoutée hors lot.
- 788 instructions et 1 684 octets créés. Code exact du plan source, modes et destinations directes vérifiés.
- Anciens noms/corps, instructions, données définies et octets/permissions mémoire conservés.
- Analyse ARM ciblée incluse avant export final : 27 C terminés sans avertissement.
- Réouverture et second passage en lecture seule : mêmes snapshots, cibles et C ; 27 fonctions préexistantes.

Preuves : `thumb_long_plan/`, `thumb_long_before/`, `thumb_long_recovery/`, `thumb_long_after/`, `thumb_long_repeat/`, `thumb_long_reopened/`, **`thumb_long_verification.json`**. Réexécuter `scripts/verify_thumb_recovery.py` avec ces dossiers pour vérifier les artefacts.

## Revue de qualité

Les fonctions font 36 à 114 octets, sans pools ou directives internes. Les branches sont internes et résolues. La revue source vérifie l'atteignabilité des instructions, les bornes du TSV et l'équilibrage des piles, en supposant les appels conformes à leur convention de pile.

Quatre sondes confrontées au C :

| Fonction | Opérations retrouvées | Limite |
|---|---|---|
| Func_20b64 | Copie d'une chaîne, suffixes, padding, appel avec argument -2 | Buffer local de 20 octets, contrat de longueur d'entrée non établi depuis la source |
| Func_c388 | Dispatch sur valeurs 1/2, traitement de quatre entrées | Prototype de retour inféré |
| Func_e73a0 | Recherche parmi 32 slots de 28 octets | État d'entrée r9 implicite dans la signature C |
| Func_da24c | Recherche d'index puis émission d'indices bornés | Largeur de retour 64 bits suspecte |

Neuf C infèrent un retour 64 bits incorporant LR : `Func_45a4`, `Func_bacc`, `Func_1ec24`, `Func_21af0`, `Func_28db4`, `Func_28ea8`, `Func_78550`, `Func_7a550`, `Func_da24c`. Aucun prototype source n'est établi et aucune signature n'a été imposée. L'absence d'avertissement ne valide pas ces signatures.

Revue indépendante Sol/high : deltas globaux, persistance, code du plan et quatre sondes. Luna/low : source des27, tailles, limites et atteignabilité.

## Suite

335 entrées de référence restent absentes : 319 ROM non définies (317 Thumb +2 ARM), douze du bloc rom_770 chargé en IWRAM et quatre code/donnée.

La prochaine famille contient 27 fonctions sans données inline mais appelant des alias. `scripts/resolve_thumb_aliases.py` résout 709 stubs depuis les macros/déclarations du dépôt et vérifie tous leurs octets dans la ROM. Les BL doivent viser l'adresse du stub ; le littéral de ce stub doit viser le vrai symbole avec son mode et son éventuel remappage RAM. Les modes des symboles `_noalign` sont lus depuis leur déclaration source, car l'ancien `repo_funcs.txt` ne les indexe pas tous.

Ce lot utilise 21 alias et 48 appels alias, dont deux appels vers `Func_af0_from_thumb` : stub `0x080022ec`, registre r3, cible ARM IWRAM `0x03000380`, stockage ROM Func_af0 à `0x08000af0`. Il n'établira pas le corps runtime de cette cible RAM. Les 20 autres alias sont des exports r4 vers Thumb ROM ; ne pas confondre `rom_77000` avec `rom_770`.

Sources : `include/macros.inc`, `stage1.ld`, `goldensun.ld`, `rom_c0/src/rom_1b70.s:553`, `rom_c0/src/rom_770.s:265`. Plan `thumb_alias_plan/` et preuves `thumb_aliases.json`. Copie de récupération en cours `ghidra_thumb_alias`, à promouvoir seulement après vérification et réouverture.

Notion en attente, mémoire non modifiée.
