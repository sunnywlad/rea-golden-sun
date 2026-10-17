# Étape 9 : récupération Ghidra assistée par la référence

## Résultat vérifié après sauvegarde et réouverture

- Projet séparé : `archive:ghidra_step9_saved/step9.gpr`, programme `gs_us_map.elf`.
- Baseline : 1 914 procédures, exactement les mêmes adresses que REA.
- Après récupération : 2 140 procédures ; 226 des 227 cibles créées, toutes en Thumb (TMode=1), toutes décompilées.
- Adresses communes avec les 2 253 fonctions du dépôt : 1 544 avant (68,53 %), 1 770 après (78,56 %).
- Thumb : 1 751/2 201 après ; ARM inchangé : 19/52.
- Aucune adresse de procédure baseline perdue, aucun ajout hors de la liste cible.
- Réouverture : 2 140 procédures, ensemble d'adresses identique au relevé après récupération.
- Second passage en lecture seule : 226 entrées préexistantes, le même conflit unique, aucun changement d'adresses.
- ELF SHA256 inchangé : `e3dbcc1d87bd85ebb90199b267dcb965143bbcd2c2692651166b3b34cd8f885f`.

La récupération utilise les noms et limites de fonctions du dépôt. Ce résultat est une récupération Ghidra guidée par la référence, pas une amélioration autonome de REA. La session REA reste sur sa baseline de 1 914 procédures.

## Comparaison avec le dépôt

- `Func_3008` : corps de 2 octets, `bx lr`, correspond exactement ; C : simple retour.
- `Func_3810` : test d'un demi-mot à ewram_2000, puis écriture de 0xc3ff (demi-mot) dans REG_KEYCNT et de 1 (octet) à iwram_1cb8 ; correspond.
- `Func_e220` : trois voies, écriture, addition de paramètre multiplié par 4, puis comparaison booléenne à l'offset 0x57 ; correspond.
- `Func_cacc` : dispatch initial et appel via table concordent ; revue partielle, listing limité à 160 instructions et sept avertissements du décompilateur.
- 20 des 226 fichiers C portent au moins un WARNING. Le succès de décompilation n'établit pas l'exactitude complète du C.
- Des signatures restent approximatives, notamment des retours artificiels `unaff_lr`.

Références : `work/repo/rom_c0/src/rom_2e00.s:232`, `rom_3650.s:174`, `work/repo/rom_9000/src/rom_e220.s:3`, `rom_ca6c.s:59`. Revue : `work/recovery_saved/probe_review.md`.

## Le conflit de code partagé

`Func_f9ac0` (0x080f9ac0) ne peut pas être créée comme corps distinct sans remanier un corps existant :
- Le dépôt place son corps sur 0x080f9ac0–0x080f9adf.
- `Func_f9b10` saute à la queue partagée `.Lf9ac2` (0x080f9ac2).
- La baseline Ghidra attribue à FUN_080f9b10 deux plages : 0x080f9ac2–0x080f9adf et 0x080f9b10–0x080f9b3d.
- Il s'agit d'un partage réel de code, confirmé par `work/repo/rom_f9000/src/rom_f95e0.s:575` et `:625`.
- Le script conserve ce corps et signale le conflit. Il ne crée pas une fonction partielle pour gonfler le compteur.

Autre cas traité : `Func_f9ae0` termine par des sauts directs vers des entrées connues du dépôt. Son corps est borné à sa propre plage, avec vérification des destinations ; aucun corps voisin n'est absorbé.

## Scripts et pièges observés

- `scripts/RecoverThumb.java` prend cibles TSV, toutes les limites de fonctions TSV, dossier de résultats.
- Il réutilise les instructions Thumb déjà décodées ; 223 créations réutilisent explicitement l'instruction d'entrée. Les trois autres passent par le désassembleur.
- Il ne réécrit TMode que si nécessaire, refuse les unités de code incompatibles et les chevauchements, borne les corps par le flux Ghidra et les entrées connues du dépôt.
- Il ne relance pas l'analyse automatique et exporte avant/après, statuts, C et listings assembleur.
- `scripts/recovery_report.py` compare les adresses et modes ; une fonction non créée n'est pas comptée comme échec de décompilation.
- Ghidra refuse de réécrire le contexte sur des instructions déjà décodées, même si TMode vaut déjà 1.
- `AddressSet.intersect` retourne un nouvel ensemble, il ne modifie pas l'ancien.
- Les transactions imbriquées partagent la transaction du script : un rollback local annulait toutes les créations à la sauvegarde. Le script n'ouvre plus de transaction par cible. La persistance est contrôlée par une réouverture, pas par le message Save succeeded seul.
- En cas d'échec après changement de contexte/désassemblage, ces annotations sont conservées et signalées ; aucun effacement aveugle.

Ces frictions restent dans les fichiers du projet. La mémoire sera examinée en fin de session.

## Reproduire

Ghidra 12.1.4, JDK 21. Importer le même ELF mappé dans un projet séparé avec le chargeur ELF par défaut et l'analyse par défaut. Sauvegarder une copie de la baseline. Construire `work/recovery_targets.tsv` depuis `work/missed_thumb_xrefs.json` et `work/repo_function_boundaries.tsv` depuis les 2 253 noms Func_* (adresse = 0x08000000 + offset).

```sh
~/ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless ~/rea-golden-sun/archive:ghidra_step9_saved step9 -process gs_us_map.elf -noanalysis -scriptPath ~/rea-golden-sun/scripts -postScript RecoverThumb.java ~/rea-golden-sun/work/recovery_targets.tsv ~/rea-golden-sun/work/repo_function_boundaries.tsv ~/rea-golden-sun/work/recovery_saved
python3 -I scripts/recovery_report.py work/repo_funcs.txt work/recovery_saved/before.json work/recovery_saved/after.json work/recovery_saved/targets.json work/procs_current.json work/recovery_saved/report
```

Refaire le traitement en lecture seule vers un autre dossier après réouverture ; vérifier que les 226 entrées sont préexistantes et que les ensembles d'adresses restent identiques. Preuve actuelle : `work/recovery_saved/persistence_check.json`. Le rapport généré et les 226 fichiers C sont dans `work/recovery_saved/`. Les dossiers `recovery`, `recovery_final` et `recovery_repeat` correspondent aux essais intermédiaires et ne sont pas l'état sauvegardé de référence.

## Suite

Examiner les 50 cibles encore indéterminées à l'étape 8, puis la représentation des fonctions à queue partagée. Les 483 entrées du dépôt encore absentes après récupération comprennent 450 Thumb (dont le conflit partagé) et 33 ARM.
