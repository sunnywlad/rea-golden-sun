# Étape 12 : inventaire des 482 entrées restantes

## Résultat en lecture seule

Projet inspecté : `archive:ghidra_shared_split/step9.gpr`, programme `gs_us_map.elf`, langage `ARM:LE:32:v8`. Les 2 141 entrées de fonctions sont exactement celles du projet sauvegardé à l'étape 11. Aucune fonction ni annotation créée.

| État à l'adresse de stockage ROM | Thumb | ARM | Total |
|---|---:|---:|---:|
| Instruction décodée, sans fonction propriétaire | 3 | 21 | 24 |
| Aucun code ni donnée défini à l'entrée | 442 | 12 | 454 |
| Demi-mot défini comme donnée undefined2 | 4 | 0 | 4 |
| Total | 449 | 33 | 482 |

- Aucune des 482 entrées ne se trouve au milieu d'une instruction.
- Aucun propriétaire de fonction à ces 482 adresses d'entrée. Un corps calculé ultérieurement peut toutefois rejoindre une autre fonction.
- 30 cibles ont des références à l'adresse paire (36 références), aucune à l'adresse impaire.
- Les 442 entrées Thumb non décodées ont TMode=0 dans l'état courant. Cela indique l'absence du contexte Thumb attendu à ces adresses, pas 442 instructions ARM déjà décodées.
- Les 24 instructions existantes ont le mode attendu : 21 ARM avec TMode=0, trois Thumb avec TMode=1.
- Les quatre données ont TMode=0 et leurs deux premiers octets sont des opcodes Thumb confirmés par le dépôt.

Preuves : `work/remaining_inventory.json`, `work/remaining_reference.json`, `work/remaining_summary.json`.

## Stockage ROM et exécution IWRAM

Douze des entrées restantes appartiennent au bloc rom_770 : 11 ARM et un Thumb (Func_dc8). Elles sont stockées en ROM mais liées pour être exécutées en IWRAM.

- Plage de stockage : 0x08000770–0x08001b6f.
- Plage de destination : 0x03000000–0x030013ff.
- Adresse d'exécution : 0x03000000 + (offset ROM - 0x770).
- Func_dc8 : stockage 0x08000dc8, exécution 0x03000658.
- Func_948 : stockage 0x08000948, exécution 0x030001d8.

Les scripts de linkage placent rom_770 en IWRAM avec chargement ROM (`stage1.ld:26`, `goldensun.ld:28`). `rom_c0/src/rom_2e00.s:243` charge l'adresse de stockage et prépare la copie DMA vers iwram_0. Le symbole iwram_0 vaut 0x03000000 (`wram.sym:134`).

L'inventaire aux douze adresses d'exécution confirme la limite de l'ELF actuel :
- Le segment IWRAM est initialisé à zéro et marqué non exécutable.
- Onze adresses n'ont pas de fonction.
- Func_948 a un placeholder de fonction à 0x030001d8, d'un octet, sans instruction. Cela ne prouve pas une analyse du code runtime.
- Les octets réellement copiés au démarrage ne sont pas présents dans cette image IWRAM.

Le rappel 1 771/2 253 = 78,61 % mesure donc les débuts de code **stockés en ROM**, pas toutes les fonctions à leur adresse d'exécution. Ce taux reste inchangé pendant l'inventaire.

| Rôle de l'adresse | Déjà décodées | Non définies | Code lu comme donnée | Total |
|---|---:|---:|---:|---:|
| Entrées directement liées en ROM | 23 | 443 | 4 | 470 |
| Stockage ROM du bloc copié en IWRAM | 1 | 11 | 0 | 12 |

Preuve runtime : `work/remaining_runtime_inventory.json`. Le remappage n'est pas appliqué aux autres entrées ARM.

## Les quatre données sont aussi du code

Dans `work/repo/rom_c0/src/rom_6878.s` :

| Entrée | Première instruction | Octets ROM | Routine de copie |
|---|---|---|---|
| Func_6abc | ldrb r0, [r0] | 00 78 | Func_6ac0 |
| Func_6b84 | push {r4, lr} | 10 b5 | Func_6ba8 |
| Func_6c24 | push {r4, r5, lr} | 30 b5 | Func_6c68 |
| Func_6f48 | mov r2, r0 | 02 1c | Func_6e24 |

Ces routines enlèvent le bit Thumb du pointeur avant de lire les instructions par demi-mots et de les recopier. Certaines copies sont placées sur la pile puis appelées indirectement :
- Func_6abc : définition ligne 254 ; copie et lecture ligne 276.
- Func_6b84 : définition ligne 359 ; lecture ligne 409, appel de la copie via r3 ligne 431.
- Func_6c24 : définition ligne 438 ; lecture ligne 502, appel de la copie via r3 ligne 523.
- Func_6f48 : définition ligne 813 ; lecture ligne 706 ; copie sur la pile transmise à Func_6f6c ligne 734, appel indirect via r1 ligne 838.

Ghidra produit des références READ aux adresses paires, puis définit les premiers demi-mots comme undefined2. Cette donnée n'est pas simplement un faux marquage : le programme lit vraiment du code comme des données. Une future récupération doit préserver les octets et ces références, même si l'affichage principal devient une instruction.

Exemple Func_6abc : deux mots ROM contiennent le pointeur impair 0x08006abd, mais aucune référence analysée n'est enregistrée vers cette adresse impaire. La référence READ part de l'instruction ldrh à 0x08006ae4 vers l'adresse paire 0x08006abc. Un mot pointeur brut ne garantit donc pas un xref au même bit bas.

## Reproduire

```sh
~/ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless ~/rea-golden-sun/archive:ghidra_shared_split step9 -process gs_us_map.elf -noanalysis -readOnly -scriptPath ~/rea-golden-sun/scripts -postScript InventoryMissing.java ~/rea-golden-sun/work/remaining_targets.tsv ~/rea-golden-sun/work/remaining_inventory.json
# Même commande avec remaining_runtime_targets.tsv et remaining_runtime_inventory.json pour les douze VMAs.
python3 -I scripts/remaining_reference.py work/repo_funcs.txt work/remaining_inventory.json work/repo work/remaining_reference.json --runtime-inventory work/remaining_runtime_inventory.json
```

Construire remaining_targets.tsv par différence entre les 2 253 noms Func_* du dépôt et les entrées de fonctions sauvegardées ; format mode, adresse de stockage hexadécimale, nom, séparés par tabulations. Les adresses runtime viennent de remaining_reference.json.

Scripts durables : `scripts/InventoryMissing.java`, `scripts/remaining_reference.py`. L'export Java a été corrigé puis intégralement relu par le parseur JSON sur les 482 enregistrements. L'audit Python a été vérifié avec et sans inventaire runtime optionnel.

## Prochaine étape

Récupérer d'abord les **23 entrées déjà décodées et directement liées en ROM** (20 ARM et trois Thumb), sans changer leur mode ni leurs octets. Lot prêt : `work/recover_decoded_rom.tsv`.

Les douze entrées copiées en IWRAM restent séparées ; leur analyse runtime demande de représenter les octets chargés en RAM. Les 443 entrées ROM non définies et les quatre cas code/donnée peuvent être traités ensuite avec le mode explicite et les preuves de source.
