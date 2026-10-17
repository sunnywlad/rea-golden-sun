# Étape 19 : 27 fonctions appelant des stubs (2026-10-16)

Projet courant validé : **`archive:ghidra_thumb_alias/step9.gpr`**, programme `gs_us_map.elf`. **2 315 fonctions**, **1 945/2 253 entrées de stockage ROM (86,33 %)**. Baseline REA inchangée ; récupération guidée.

- 27 créations exactes, aucune entrée hors lot ni perte.
- **501 instructions, 1 134 octets** ajoutés, conformes au plan source.
- Anciens noms/corps/instructions, données définies et octets/permissions mémoire conservés.
- Analyse ARM ciblée incluse. 27 C terminés sans avertissement.
- Réouverture et second passage vérifiés ; snapshots, cibles et C identiques.

Preuves : `thumb_alias_plan/`, `thumb_alias_before/`, `thumb_alias_recovery/`, `thumb_alias_after/`, `thumb_alias_repeat/`, `thumb_alias_reopened/`, **`thumb_alias_verification.json`**.

## Résolution des alias

`scripts/resolve_thumb_aliases.py` lit les déclarations et les macros du dépôt, puis vérifie dans la ROM épinglée **709 stubs** : 705 exports r4 vers Thumb ROM et quatre stubs explicites r3 vers ARM IWRAM. Les modes viennent des déclarations `.arm_func_start`, `.thumb_func_start` et `_noalign`. Ces dernières ne sont pas toutes incluses dans l'ancien index `repo_funcs.txt`.

Les exports sont placés en tête de leurs sections selon `stage1.ld` et `goldensun.ld`. Leurs adresses sont base de bloc +8×index. Chacun contient un LDR Thumb de 2 octets, un BX de 2 octets et son littéral de 4 octets, vérifiés octet par octet. Pour les stubs explicites, les huit octets exacts doivent avoir une occurrence alignée unique dans la ROM. Les pointeurs de fonction Thumb ont leur bit bas ; les cibles ARM et les adresses de données ne le reçoivent pas.

Le lot de 27 utilise **21 noms d'alias et 48 appels alias**, ainsi que 18 BL directs ordinaires : **66 BL au total**. Le plan conserve l'adresse du stub et les preuves de sa destination. Le vérificateur compare le BL à l'adresse du stub, puis la preuve de stub à son véritable symbole cible. Il ne supprime pas un préfixe `_` pour confondre ces deux adresses.

Les six cibles `77394`, `78414`, `7842c`, `78b9c`, `7961c`, `79ef8` appartiennent à `rom_77000`, qui reste en ROM. Le bloc remappé en IWRAM est `rom_770`, distinct.

### Deux appels vers ARM IWRAM

`Func_f40d0` et `Func_f40e8` appellent `Func_af0_from_thumb`. Les BL à `0x080f40da` et `0x080f40f4` ciblent le stub **`0x080022ec`**, octets `004b184780030003` : LDR dans r3, BX r3, pointeur **`0x03000380`**. Cette dernière adresse est celle de `Func_af0` ARM dans le bloc copié, stocké à `0x08000af0`.

Sources : `rom_f4000/src/rom_f4008.s:97-122`, `rom_c0/src/rom_1b70.s:553`, `rom_c0/src/rom_770.s:265`, `stage1.ld:26-28`, `goldensun.ld:28-32`, `include/macros.inc`.

Le C appelle `FUN_080022ec`, signe les arguments et le résultat 16 bits comme dans la source. La récupération des appelants ne reconstruit pas le corps exécuté en IWRAM ; aucune sémantique métier de la cible n'est déduite du seul stub.

## Revue C et limites

Quatre sondes : `Func_b868`, `Func_25180`, `Func_f40d0`, `Func_f40e8`. Les décisions, accès mémoire, appels et valeurs basses observés concordent avec leurs sources.

- `Func_b868` : le C décompose un store 32 bits nul en deux stores 16 bits nuls, même effet pour la mémoire ordinaire concernée ; retour `unaff_lr` inféré.
- `Func_25180` : choix des codes 0/1/2 retrouvé, mais prototype 64 bits inféré avec LR comme mot haut.
- `Func_f40d0/e8` : arguments et extension signée 16 bits retrouvés ; même limite de largeur64 incluant LR, cible runtime non reconstruite.

Les prototypes source restent inconnus ; zéro avertissement ne démontre pas leur fidélité. Revue préalable Sol/high des 709 stubs et 66 BL indépendamment des tables attendues ; revue Luna/low des deltas et quatre sondes après récupération.

## Suite

**308 entrées de référence restent absentes** : 292 ROM non définies (290 Thumb +2 ARM), douze du bloc rom_770 copié en IWRAM et quatre cas code/donnée.

La famille des 290 Thumb est étudiée séparément : 241 ont des pseudo-LDR et un pool final sans directive interne ; 48 comportent aussi des données/directives internes ; une routine utilise des LDR explicites vers des labels, sans pseudo-LDR (`Func_f95f0`, qui est bien du code, pas des données seules). Un planificateur conservateur résout les valeurs de constantes et exclut toute expression inconnue ou pool interne. Premier pilote lancé : quinze petites fonctions, **200 octets/100 instructions**, **21 mots de pool** vérifiés depuis la ROM.

Notion en attente, mémoire non modifiée.
