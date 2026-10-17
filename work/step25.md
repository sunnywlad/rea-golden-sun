# Étape 25 : les 35 autres fonctions à pools internes

**Étape terminée et travail mis en pause à la demande de Wladimir.** Aucun lot suivant n'est lancé.

Projet validé : `archive:ghidra_thumb_inline_remaining_scoped/step9.gpr`, programme `gs_us_map.elf`. **2 591 fonctions**, dont **2 221/2 253 entrées ROM de référence (98,58 %)**. Il reste 32 entrées de référence. La baseline REA reste 1 914 procédures et 1 544 entrées reconnues ; tous les gains de cette récupération sont guidés par le désassemblage de référence.

Les 35 fonctions ajoutent **10 323 instructions et 21 884 octets de code**. Le plan décrit **589 mots de pool**, dont douze unités préexistantes conservées et exactement 577 nouvelles unités undefined4. Les corps comportent plusieurs plages ; les pools et le remplissage sont exclus du code. La plus grande fonction du lot occupe 1 988 octets de code.

Le pipeline reprend celui du pilote : copie d'analyse séparée, reconnaissance ARM puis export de 35 RETURN liés au SHA256 du plan, et récupération sur copie propre avec application des seuls retours et pools approuvés. Aucun ArmAnalyzer général ni effacement de donnée dans le projet retenu. La copie d'analyse `ghidra_thumb_inline_remaining_probe` reste un témoin et ne doit pas être promue.

Les audits globaux passent : anciennes fonctions, instructions et données définies conservées ; octets et permissions de tous les blocs mémoire inchangés. Après fermeture/réouverture, snapshots, preuves littérales et C identiques. Le second passage ne crée rien et conserve les 35 RETURN et les 589 slots. Vérification : `thumb_inline_remaining_scoped_verification.json`.

Les 35 décompilations terminent. Une seule porte un avertissement : Func_d5e54, « Restarted to delay deadcode elimination for space: stack ». Il est conservé dans les preuves ; le contrôle de corps exact ne démontre pas l'équivalence de son C. Quatorze C présentent encore une largeur de retour avec LR suspecte, aucun prototype imposé.

Deux sondes ont été confrontées au source. Func_5d10 conserve les sauvegardes et écritures halfword de registres, les appels d'initialisation, les écritures DMA et la boucle de construction des pointeurs. Func_1f77c conserve le chemin initial retournant -9, le parcours de trois enregistrements espacés de 0x40, les écritures halfword conditionnelles, le masque 0x120 et l'ajout de 100 quand les comptes concordent. Son CONCAT44(LR,résultat) reste un artefact de retour inféré. Le lot complet n'a pas fait l'objet d'une preuve d'équivalence C.

Preuves : `thumb_inline_remaining_plan/`, `thumb_inline_remaining_approved_returns.json`, `thumb_inline_remaining_scoped_before/`, `thumb_inline_remaining_scoped_recovery/`, `thumb_inline_remaining_scoped_after/`, `thumb_inline_remaining_scoped_repeat/`, `thumb_inline_remaining_scoped_reopened/`, `thumb_inline_remaining_scoped_verification.json`, `thumb_inline_remaining_c_review.json` et journaux correspondants. Inventaire des 32 restantes : `step25_remaining.json`.

Répartition restante :

- 14 Thumb ROM ordinaires : cinq macros `.call_via`, cinq opérations explicites sur PC, un cas Thumb/ARM mixte, un appel vers un label dans un autre corps, une feuille SWI et une base de table d'exports.
- 2 ARM ROM ordinaires : Func_404 et Func_20f4.
- 12 entrées de stockage du bloc rom_770 exécuté en IWRAM.
- 4 cas où les octets sont à la fois lus comme données et exécutés comme code.

Préparation de la suite, sans mutation Ghidra : `thumb_special_pair_final_plan/` sélectionne Func_12518 et Func_fa674, 674 instructions, 1 420 octets et vingt mots de pool. `Symbols` démontre Exports_185000 comme adresse paire 0x08185000 depuis le label source et le premier stub déjà vérifié ; ce pointeur de table ne doit pas être confondu avec le pointeur Thumb 0x08185001. Le planificateur vérifie aussi exactement l'opcode et l'immédiat de `swi 0x2a`. Les 45 anciens layouts restent identiques ; trois cas invalides sont rejetés dans `thumb_special_planner_checks.json`. Aucun projet de récupération de cette paire n'a été créé. La sémantique BIOS et les instances de code copiées en RAM restent hors de cette preuve de disposition.

Les sous-agents ont atteint leur limite d'utilisation ; la revue finale et les contrôles sont ceux du principal. Notion reste en attente depuis l'étape 13, sans outil connecté disponible. Mémoire Claude inchangée. Tous les processus Ghidra lancés pour cette étape sont terminés et le projet est fermé.
