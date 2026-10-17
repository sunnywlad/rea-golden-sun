# Golden Sun x REA : étape 27 terminée (2026-10-16)

Lire d'abord `CLEAR_HANDOFF.md` pour les lectures minimales, l'audit des références et le prochain lot sémantique. Reprise par prompt collé manuellement, aucun routage intersession requis.

**État de reprise prioritaire : étape 27, audit comparatif terminé.** Alchemy explique déjà Func_12518 (`Ui_RunIconMonitor`), le getter et les structures ; 512 métadonnées et 2 062 slots de scripts concordent avec notre ROM. L'éditeur vise la même table via le littéral pointeur 0x185020. Priorité de composition des couches identifiée ; paramètre 0..15 transmis au décodeur. Rapport `work/step27.md`, preuve `work/step27_reference_verification.json`. Suite : SPR_000, animation 0, jusqu'au décodeur et au tampon de pixels. Projet Ghidra de l'étape 26 conservé sans lancement dans ce lot, `work/ghidra_thumb_special_pair_scoped/step9.gpr`, 2 593 fonctions et 2 223/2 253 entrées ROM (98,67 %), trente absentes. Aucun nom/type importé, aucun nouveau lot de récupération lancé. Voir `RUN_STATE.md`.

## Objectif et état
Analyser la ROM Golden Sun USA (SHA1 `5c4695205413df7db52b9a184815a07783999971`) avec REA/Ghidra 12.1.4 et comparer au désassemblage gsret/goldensun. REA utilise l'ELF mappé `work/gs_us_map.elf`. Les 1 914 adresses de procédures de cette session sont identiques à celles du précédent `work/procs.json`.

## Résultat de l'étape 8
- Les 676 fonctions Thumb manquées ont toutes été interrogées par `xrefs(addr|1)` : 227 positives (33,6 %).
- Parmi les 444 avec pointeur impair aligné, 227 positives et 217 négatives ; parmi les 232 sans pointeur, aucune positive. Aucune erreur.
- Scan indépendant : 8 463 cibles impaires dans la ROM, 3 540 avec xrefs. 409 sont des débuts de fonctions Thumb du dépôt, dont 182 déjà reconnues par REA.
- Après exclusion des fonctions déjà connues : 3 358 cibles, dont 227 fonctions confirmées, 3 081 adresses de données déclarées du dépôt et 50 indéterminées. Précision brute pour de nouvelles fonctions : 6,8 % à 8,3 %.
- Exclure les données du dépôt laisse 277 cibles, au moins 81,9 % confirmées. Ce filtre dépend de la référence.
- 186 des 227 fonctions ont une source xref exactement à l'emplacement d'un mot pointeur. Les 41 autres ont des références depuis d'autres sources, notamment des instructions.
- Aucune fonction créée. Rappel global actuel : 1 544/2 253 = 68,5 %. Rappel potentiel après récupération réussie des 227 : 1 771/2 253 = 78,6 %.

## Étape 9 : état sauvegardé
- 226 des 227 cibles sont créées dans le projet Ghidra séparé `archive:ghidra_step9_saved/step9.gpr`, programme `gs_us_map.elf`. 2 140 procédures, 1 770/2 253 entrées de référence (78,56 %, contre 68,53 % avant), aucune entrée initiale perdue.
- Toutes les 226 créations ont TMode=1 et une décompilation terminée. Trois sondes concordent avec les instructions du dépôt ; 20 fichiers C portent des avertissements, la qualité complète n'est pas établie.
- Le cas restant, Func_f9ac0, partage du code avec Func_f9b10 ; le corps existant est conservé. Le dépôt confirme les branches vers la queue partagée à 0x080f9ac2.
- Persistance vérifiée après fermeture/réouverture : 2 140 procédures identiques. Second passage en lecture seule : 226 préexistantes, même conflit unique, aucune modification d'adresses.
- REA reste sur sa baseline. La récupération utilise les noms et limites du dépôt, ce n'est pas une détection autonome.
- Résultats de référence : `work/recovery_saved/`, rapport `work/step9.md`, `work/recovery_saved/persistence_check.json`. Les autres dossiers de récupération sont des essais intermédiaires.
- Scripts durables : `scripts/RecoverThumb.java` (cibles TSV, toutes les limites TSV, dossier de sortie) et `scripts/recovery_report.py`.
- Pièges : réécrire TMode=1 sur des instructions existantes provoque une erreur ; AddressSet.intersect ne modifie pas l'ensemble initial ; un rollback imbriqué peut annuler tout le lot du script à la sauvegarde. Le script n'ouvre plus de transaction par cible.

## Étape 10 : les 50 indéterminées sont des données générées
- 50/50 classées : les adresses impaires interrogées sont 25 adresses de payloads compressés et 25 adresses de tableaux de longueurs. Il ne faut pas effacer le bit bas d'un pointeur de données.
- `strings.s` est généré lors du build du dépôt et absent de l'archive source. Les 42 paires de StringPointers à 0x080736b8 et leurs longueurs reconstruisent les plages de ces données.
- Décompression/recompression avec les outils C du dépôt : 10 722 textes, 42/42 payloads et 42/42 tableaux de longueurs identiques à la ROM.
- Sept cibles paires sont déjà désassemblées par Ghidra bien qu'elles soient des données. Aucune nouvelle fonction créée ; le projet sauvegardé de l'étape 9 reste inchangé.
- Précision de la piste brute pour de nouvelles entrées : 227/3 358 = 6,76 %. Les 3 131 autres cibles sont des données ; aucune inconnue restante. Le filtrage par la référence laisse les 227 entrées, dont 226 créées à l'étape 9.
- Scripts durables : `scripts/unknown_reference.py`, `scripts/strings_roundtrip.py`. Rapport : `work/step10.md`. Preuves : `work/unknown50.json`, `work/string_roundtrip/roundtrip.json`, `work/unknown50_rea_inspection.json`. Ne pas publier les textes/blocs extraits.

## Étape 11 : queue partagée résolue pour l'inventaire
- Projet de travail actuel : `archive:ghidra_shared_split/step9.gpr`, programme `gs_us_map.elf`. 2 141 fonctions, dont 1 771/2 253 entrées du dépôt (78,61 %). Les 227 cibles sont toutes des fonctions, aucune entrée précédente perdue.
- CreateFunctionCmd réattribue la queue 0x080f9ac2–0x080f9adf à Func_f9ac0 et réduit le corps attribué à Func_f9b10 à sa plage 0x080f9b10–0x080f9b3d. La création directe du script refusait ce chevauchement.
- Aucun octet ni branche modifié ; C de Func_f9b10 identique octet pour octet avant/après. Les deux décompilations terminent sans avertissement. Labels/commentaires conservent l'invariant LR déjà empilé à l'entrée de la queue.
- Sauvegarde et réouverture vérifiées, corps et annotations persistants. Script durable : `scripts/SharedTailProbe.java` (inspect/split/annotate).
- Limite : l'appel à Func_f9a98 dans la queue est attribué à Func_f9ac0. getCalledFunctions(Func_f9b10) l'omet après transfert, malgré le chemin inchangé et sa présence dans le C. Un graphe fondé seulement sur les corps manque les appels atteints par code partagé.
- Rapport : `work/step11.md`. Preuves : `work/shared_split/`, `work/shared_selected/verification.json`, `work/shared_verified/`. La variante label seul dans `archive:ghidra_shared_annotated` est un témoin, pas le projet de travail retenu.

## Étape 12 : inventaire des 482 restantes
- Lecture seule, 2 141 fonctions inchangées. 449 Thumb +33 ARM aux adresses de stockage ROM : 24 déjà décodées sans fonction, 454 entrées non définies, quatre données undefined2. Aucun propriétaire à l'entrée, aucune cible au milieu d'une instruction.
- 454 non définies =442 Thumb (TMode0 au lieu du Thumb attendu) +12 ARM. Les 24 décodées =21 ARM (TMode0) +3 Thumb (TMode1). Trente cibles ont des xrefs paires, aucune impaire.
- Les quatre undefined2 sont des instructions que le jeu lit pour copier du code : Func_6abc/6b84/6c24/6f48. Premiers octets et routines de copie confirmés. Conserver code/data semantics, ne pas déclarer ces données arbitrairement fausses.
- Douze entrées restantes (11 ARM +Func_dc8 Thumb) sont du code stocké dans rom_770 puis copié en IWRAM. Runtime =0x03000000+(offset ROM-0x770). RAM ELF actuellement remplie de zéros et non exécutable ; placeholder Func_948 à 0x030001d8 sans instruction. Le rappel actuel mesure le stockage ROM, pas toutes les adresses d'exécution.
- Répartition hors code copié : 23 déjà décodées, 443 non définies, quatre code/donnée ; les douze du bloc copié sont traitées à part.
- Rapport `work/step12.md`, inventaires `work/remaining_inventory.json`, `remaining_reference.json`, `remaining_runtime_inventory.json`, résumé `remaining_summary.json`. Scripts durables : `scripts/InventoryMissing.java`, `scripts/remaining_reference.py`.

## Étape 13 : les 23 entrées créées et sauvegardées
- Projet à l'étape 13 : `archive:ghidra_decoded23/step9.gpr`, programme `gs_us_map.elf`. 2 164 fonctions, 1 794/2 253 entrées de stockage ROM (79,63 %). 20 ARM +3 Thumb ajoutées ; noms et corps préexistants, modes, octets et références aux entrées conservés.
- Réouverture vérifiée ; second passage en lecture seule : 23 préexistantes. Aucune nouvelle entrée hors du lot ni perte de baseline. Empreintes de tous les blocs mémoire initialisés inchangées.
- Les 23 décompilations terminent, mais une fonction a un corps incomplet : Func_9bb8, 220 octets et deux avertissements, second dispatch/handlers manquants. Func_f4008 a une signature de retour 64 bits suspecte sans avertissement (r0 nul, r1 utilisé pour LR ; aucun prototype source 64 bits établi). Deux autres sondes concordent sur les opérations examinées.
- Script durable `scripts/RecoverDecoded.java` (lot mode<TAB>adresse<TAB>nom, dossier résultat). Rapport `work/step13.md`, résultats `work/decoded_recovery/`, `work/decoded_verified/`, preuve `work/decoded_recovery/verification.json` et revue `probe_review.md`.
- Le champ global all_function_names_and_bodies_unchanged est faux au premier passage à cause des créations ; la comparaison des seuls corps/noms préexistants est vraie.

## Étape 14 : contrôle de flux de Func_9bb8 récupéré
- Projet à l'étape 14 : `archive:ghidra_func9bb8/step9.gpr`, programme `gs_us_map.elf`, copie du projet de l'étape 13. 2 164 fonctions, rappel ROM inchangé à 1 794/2 253 (79,63 %).
- Corps de Func_9bb8 : 432 octets, 108 instructions, contre 220 octets. 53 instructions ajoutées. Les deux dispatchs sont restitués : quatre cas d'alignement et seize cas à 0x08009cd8. Table signée à 0x08009cdc–0x08009cfb ; cibles = 0x08009ce0 + offset.
- Sept références COMPUTED_JUMP et override manuel selon le mécanisme du SwitchOverride.java fourni avec Ghidra. Données inline, NOP hors corps, modes, octets, permissions et autres fonctions conservés. Fermeture/réouverture et second passage vérifiés ; annotations et C final persistants.
- Limite : le default du C ne justifie aucune équivalence pour les indices hors 0..15, non bornés par l'assembleur. Deux avertissements restent : override manuel et globaux chevauchants.
- Trois copies DMA confirmées après allocation 0x2c4, slot 0x34 : Func_aa0c copie 0x1e4 octets, Func_c880 et Func_c62c copient 0x2c4. Base runtime variable, en IWRAM ou EWRAM. Ce projet décrit le stockage ROM ; l'instance RAM et son chemin d'appel indirect restent à reconstruire.
- Scripts durables : `scripts/Func9bb8Flow.java`, `scripts/verify_func9bb8.py`. Rapport `work/step14.md`, exports `work/func9bb8_repair/`, `work/func9bb8_repeat/`, `work/func9bb8_final/verification.json`. Ne pas écraser les preuves du premier passage avec une nouvelle exécution.

## Étape 15 : pilote de dix entrées Thumb
- Projet à l'étape 15 : `archive:ghidra_thumb_pilot/step9.gpr`, programme `gs_us_map.elf`. 2 174 fonctions ; rappel ROM 1 804/2 253 (80,07 %).
- Dix entrées, 27 instructions et 62 octets de code créés. Audits globaux : octets/permissions, autres fonctions, 191 259 anciennes instructions et 23 047 données définies conservés. Réouverture et second passage vérifiés.
- Six feuilles C conformes. Quatre wrappers (Func_c9c9c, Func_d5274, Func_d8988, Func_d9adc) ont leur corps exact mais le C ajoute un faux appel indirect à leur retour `pop {r0}; bx r0` : qualité C partielle, deux avertissements chacun.
- RecoverThumb.java contrôle désormais les sorties même si la destination undefined n'a pas produit de corps extérieur. Les sauts calculés sans flows et les pools inline demandent toujours une preuve source séparée. Ne pas promouvoir une copie dont la vérification échoue.
- Rapport `work/step15.md`, plan `work/thumb_pilot_plan/`, audits `work/thumb_pilot_before/`, `thumb_pilot_after/`, `thumb_pilot_reopened/`, preuve `thumb_pilot_verification.json`. Scripts nouveaux : `RecoveryAudit.java`, `plan_thumb_recovery.py`, `verify_thumb_recovery.py`.

## Étape 16 : 87 petites fonctions supplémentaires
- Projet à l'étape 16 : `archive:ghidra_thumb_small/step9.gpr`, programme `gs_us_map.elf`. 2 261 fonctions ; rappel ROM 1 891/2 253 (83,93 %).
- 87 créations exactes, 323 instructions et 694 octets. Données définies, 191 286 anciennes instructions, corps/noms et mémoire conservés. Réouverture et second passage vérifiés ; preuve `work/thumb_small_verification.json`.
- 55 C sans avertissement, 32 avec faux appel indirect à l'épilogue pop-reg/BX-reg ; dix sondes non triviales examinées. Ne pas assimiler les 87 corps récupérés à 87 C validés.
- Sélection source ≤32 octets, sans données inline ou alias de cible non résolu : `work/thumb_small_plan/`. Audits `thumb_small_before/`, `thumb_small_after/`, `thumb_small_reopened/`. Rapport `work/step16.md`.
- Analyse automatique désactivée pendant ces récupérations. L'analyseur ARM de Ghidra contient précisément une reconnaissance des retours par registre ; expérience séparée en cours pour distinguer effet de configuration et limite de l'outil. Copies de test `archive:ghidra_thumb_return_probe` (override guidé sur quatre wrappers) et `archive:ghidra_thumb_arm_probe` (analyse ARM ciblée), toutes deux issues de l'étape 15, donc seulement 2 174 fonctions : ne pas les confondre avec le projet courant.

## Étape 17 : analyse ARM ciblée, retours reconnus
- Projet à l'étape 17 : `archive:ghidra_thumb_analyzed/step9.gpr`, programme `gs_us_map.elf`. Toujours 2 261 fonctions, rappel ROM 1 891/2 253 (83,93 %).
- Comparaison contrôlée sur les quatre wrappers initiaux : l'analyseur ARM reconnaît automatiquement les retours, C identique à l'override guidé. Cause révisée : les faux appels étaient liés à notre configuration sans analyse ARM ; aucune incapacité de Ghidra complet n'est démontrée.
- Analyse ciblée aux 97 fonctions nouvelles : 36 retours corrigés, 97 C sans avertissement. Aucun autre changement d'instruction, de corps, de données ou de mémoire. Réouverture vérifiée ; preuve `work/thumb_analyzed_verification.json`.
- Onze largeurs de retour 64 bits suspectes, LR comme mot haut ; quatre sondes r0 vérifiées mais prototypes source non établis. Les wrappers initiaux retournent unaff_lr en C. Aucune signature forcée.
- Rapport `work/step17.md`, audits `thumb_analyzed_before/after/reopened`, liste `thumb_all97.tsv`. Scripts `ArmReturnAnalyze.java`, `ReturnEvidence.java`, `verify_arm_analysis.py` ; l'override manuel `ThumbWrapperReturn.java` reste une expérience séparée.

## Étape 18 : 27 fonctions plus longues
- Projet à l'étape 18 : `archive:ghidra_thumb_long/step9.gpr`, programme `gs_us_map.elf`. 2 288 fonctions ; rappel ROM 1 918/2 253 (85,13 %).
- 27 créations exactes, 788 instructions, 1684 octets. Analyse ARM ciblée, anciens corps/instructions/données/mémoire conservés, réouverture et second passage vérifiés. Preuve `work/thumb_long_verification.json`, rapport `work/step18.md`.
- 27 C sans avertissement ; quatre sondes confrontées au source. Neuf largeurs de retour64 suspectes, r9 implicite dans Func_e73a0 et contrat de longueur du buffer de Func_20b64 non établi. Pas de prototype imposé.
- Prochaine famille d'alias vérifiée : `work/thumb_alias_plan/`,27fonctions1134octets. 709stubs vérifiés dans `work/thumb_aliases.json`, dont21 utilisésparlot (48BLalias+18BLdirects). Stubaf0_from_thumb080022ec→ARM-IWRAM03000380 à distinguer des exportsr4 versThumbROM.

## Étape 19 : fonctions appelant des stubs
- Projet à l'étape19 : `archive:ghidra_thumb_alias/step9.gpr`, programme `gs_us_map.elf`. 2 315 fonctions ; rappel ROM 1 945/2 253 (86,33 %).
- 27 créations exactes, 501 instructions,1134 octets. Anciennes fonctions/instructions/données/mémoire conservées. Analyse ARM ciblée,27C sans avertissement, réouverture et second passage vérifiés. Preuve `work/thumb_alias_verification.json`, rapport `work/step19.md`.
- Résolution de709stubs depuis macros/source et octetsROM ;48BLvers21alias +18BLdirects vérifiés. Les deux appelsaf0_from_thumb visent080022ec puis ARM-IWRAM03000380, corps runtime non reconstruit. Ne jamais confondre adresse de stub et cible réelle ni rom_77000 et rom_770.
- Quatre sondesC relues, opérations basses concordantes mais retoursLR/largeurs64 inférés encore non validés.

## Étape20 : pilote de quinze fonctions à pools finaux
- Projet courant : `archive:ghidra_thumb_literal_pilot/step9.gpr`, `gs_us_map.elf`.2330fonctions ; rappelROM1960/2253(87,00%).
- Quinzecréations exactes,100instructions/200octetscode ;21mots littéraux/84octetsdata +24alignement/interstice. Les21nouvellesunitésundefined4 sont exactement sur les slots approuvés ; toutesanciennesdonnées/instructions/fonctions et mémoire conservées.
- QuinzeC sans avertissement, opérationssource vérifiées ; type de retour unaff_lr deFunc_5e70 encoreinféré. Réouverture et secondpassage vérifiés, preuve`work/thumb_literal_pilot_verification.json`, rapport`work/step20.md`.
- Script`plan_thumb_literals.py` : LDR/branches décodésROM, expressions AST résoluesdepuis sources, pools seulementfinaux. `LiteralAudit.java` vérifieslots horscode. Vérificateur n'autorise nouvellesdataque surslots4octetsapprouvés, anciennesdataconservées.

## Étape 21 : 148 fonctions à pools finaux

- Projet validé : `archive:ghidra_thumb_literal_medium_scoped/step9.gpr`, 2 478 fonctions, rappel ROM 2 108/2 253 (93,56 %).
- 148 fonctions, 3 839 instructions et 8 134 octets créés. Exactement 294 nouvelles données sur les slots approuvés ; anciennes fonctions/instructions/données et mémoire conservées. Réouverture et second passage idempotent vérifiés.
- Premier essai `ghidra_thumb_literal_medium` rejeté pour données hors périmètre et trois anciennes unités supprimées. Préserver `work/step21_attempt.md` et ses audits.
- Correction : exporter 129 RETURN depuis la copie d'analyse, contrôler plan/octets/TMode/P-code/source, puis appliquer seulement ces retours et les pools sur une copie propre sans ArmAnalyzer. Scripts `ExportApprovedReturns.java` et `ApplyApprovedAnalysis.java`.
- 148 C sans avertissement, tous identiques à ceux de la copie analysée. 28 retours larges avec LR suspects, 99 retours directs LR ; prototypes non établis. Quatre sondes relues, pas de preuve d'équivalence générale.
- Rapport `work/step21.md`, preuve `work/thumb_literal_medium_scoped_verification.json`. Sous-agents limités en usage, revue finale faite par le principal.

## Étape 22 : 58 fonctions longues à pools finaux

- Projet validé : `archive:ghidra_thumb_literal_large_scoped/step9.gpr`, 2 536 fonctions, rappel ROM 2 166/2 253 (96,14 %).
- 58 fonctions, 6 625 instructions, 14 420 octets de code. 306 mots de pool : 302 nouvelles unités undefined4 et quatre pointeurs préexistants conservés.
- 55 retours reconnus sur copie d'analyse, exportés et appliqués après contrôle sur copie propre sans ArmAnalyzer. Toutes les anciennes annotations/mémoire conservées. Réouverture et second passage idempotent vérifiés.
- 58 C sans avertissement, seize largeurs avec LR suspectes. Deux sondes source relues, pas de preuve d'équivalence C générale.
- Rapport `work/step22.md`, preuve `work/thumb_literal_large_scoped_verification.json`.

## Étape 23 : dix fonctions appelant call_via

- Projet validé : `archive:ghidra_thumb_call_via_scoped/step9.gpr`, 2 546 fonctions, rappel ROM 2 176/2 253 (96,58 %).
- Quinze trampolines BX/NOP démontrés par source/macros/linker et une séquence ROM unique à 0x080072e4 ; `resolve_call_via.py` et `thumb_aliases_with_call_via.json`.
- Dix fonctions, 1 285 instructions, 2 788 octets. 67 mots de pool : 59 nouvelles unités et huit données préservées. Dix RETURN appliqués sur copie propre. Conservation globale, réouverture et idempotence vérifiées.
- Dix C sans avertissement, quatre retours larges avec LR suspects. Func_55d8 copie Func_20f4 vers la pile par DMA avant appel via sp ; Func_d304 copie Func_a494 vers un bloc alloué puis appelle via r6. Corps dans les buffers runtime non instanciés.
- Rapport `work/step23.md`, preuve `work/thumb_call_via_scoped_verification.json`.

## Étape 24 : pilote de dix fonctions à pools internes

- Projet validé : `archive:ghidra_thumb_inline_pilot_scoped/step9.gpr`, 2 556 fonctions, rappel ROM 2 186/2 253 (97,03 %).
- Nouveau `plan_thumb_inline.py` : disposition source/ROM vérifiée, chaque mot lu par un LDR, toutes les instructions atteignables, aucun fallthrough dans les pools. Corps non contigus comparés par body_ranges, layout thumb-inline-v1.
- Dix fonctions, 222 instructions, 470 octets. 39 mots : 33 nouvelles données et six préservées. Sept RETURN appliqués sur copie propre. Conservation globale, réouverture et idempotence vérifiées.
- Dix C sans avertissement, trois sondes source relues. Retours inférés toujours non validés.
- Rapport `work/step24.md`, preuve `work/thumb_inline_pilot_scoped_verification.json`.

## Étape 25 : les 35 autres fonctions à pools internes

- Projet validé : `archive:ghidra_thumb_inline_remaining_scoped/step9.gpr`, 2 591 fonctions, rappel ROM 2 221/2 253 (98,58 %).
- 35 fonctions, 10 323 instructions, 21 884 octets. 589 mots de pool : 577 nouvelles unités undefined4 et douze unités préservées. Corps non contigus exacts, anciennes annotations et mémoire conservées.
- 35 RETURN exportés depuis la copie d'analyse puis appliqués sur copie propre. Réouverture et second passage idempotent vérifiés, snapshots et C identiques.
- 35 C terminés ; un avertissement sur la pile dans Func_d5e54. Quatorze retours larges avec LR suspects. Deux sondes source relues, aucune preuve d'équivalence C générale.
- Rapport `work/step25.md`, preuve `work/thumb_inline_remaining_scoped_verification.json`, inventaire `work/step25_remaining.json`.

## Étape 26 : Func_12518 et Func_fa674

- Pause levée explicitement par Wladimir. Projet validé : `work/ghidra_thumb_special_pair_scoped/step9.gpr`, 2 593 fonctions, rappel ROM 2 223/2 253 (98,67 %).
- Plan `work/thumb_special_pair_final_plan/` régénéré et provenance contrôlée. Deux fonctions, 674 instructions, 1 420 octets. Vingt mots de pool : seize nouvelles unités undefined4 et quatre pointeurs préexistants conservés.
- Zéro override RETURN nécessaire. Copie d'analyse `ghidra_thumb_special_pair_probe` à ne pas promouvoir : ArmAnalyzer y crée une donnée hors pools à 0x03001c90. La copie propre retenue ne reçoit que les modifications approuvées, sans ArmAnalyzer.
- Anciens noms/corps de fonctions, instructions, données définies et mémoire conservés. Après fermeture/réouverture puis second passage : snapshots, cibles, pools et C identiques. Aucun processus Ghidra restant.
- Deux C terminés sans avertissement. Func_12518 conserve quatre plages de code, quatre entrées initialisées, dix entrées de rendu et la base d'exports paire 0x08185000. Func_fa674 conserve SWI 0x2a puis BX LR. Équivalence sémantique complète, prototypes et effets BIOS non établis.
- Relevés Luna/low et revue indépendante Sol/high disponibles et terminés. Avis final favorable. Principal seul aux commandes Ghidra.
- Rapport `work/step26.md`, preuve `work/thumb_special_pair_scoped_verification.json`, revue `work/thumb_special_pair_independent_review.md`, inventaire `work/step26_remaining.json`.

## Étape 27 : audit comparatif des références

Alchemy correspond à Func_12518 (`Ui_RunIconMonitor`), son getter et ses helpers. Les structures IconColumn, AnimationEntry et AnimationObject étaient déjà documentées. La priorité 0..3 ordonne les couches avant composition ; le paramètre 0..15 atteint le décodeur Func_9bb8. Le template GS1 de Game Tools Collection décrit la même table via l'indirection 0x185020 vers 0x08185024. La comparaison de 512 métadonnées, 512 comptes et 2 062 slots de scripts ne trouve aucun écart. Rapport `work/step27.md`, preuve `work/step27_reference_verification.json`, revue `work/step27_independent_review.md`.

Aucun Ghidra lancé, aucun nom/type appliqué, aucune récupération supplémentaire. Les clones restent propres aux révisions initiales ; le sparse-checkout a été élargi pour lire données et parseur. Mémoire Claude inchangée. La qualification debug reste une hypothèse étayée, l'accessibilité runtime inconnue et la reconstruction complète Alchemy non vérifiée. Son commentaire de rechargement par Select ne s'applique pas au stub Func_2f0c de notre ROM.

## Suite non exécutée

Prochain lot sémantique retenu : suivre SPR_000, animation 0, jusqu'à Func_9bb8 et au tampon de pixels. Détailler les seize modes du paramètre de dessin à partir des sources déjà présentes, puis vérifier dispatch, tables de conversion et exemple reproductible. L'accès à l'interface en jeu est un lot distinct. Clones partiels à historique court, révisions dans `work/external_references.json`, périmètre dans `external/README.md`. Aucune dépendance installée et aucun build externe vérifié.

30 entrées restent absentes : 12 Thumb ROM ordinaires, 2 ARM ROM (Func_404 et Func_20f4), 12 entrées de stockage rom_770 et 4 code/donnée. Aucun prochain lot de récupération choisi ou lancé. La pause précédente est levée ; l'autorisation de récupération portait sur la paire maintenant terminée. Wladimir a ensuite demandé la poursuite du déchiffrement sémantique, décrite en tête de ce fichier. Voir `RUN_STATE.md` pour les limites et la procédure des prochaines copies.

Les contrôles du planificateur de l'étape 25 restent conservés : trois cas invalides rejetés et 45 layouts antérieurs identiques dans `work/thumb_special_planner_checks.json`. Ne pas transformer Exports_185000 en pointeur Thumb. La reconstruction des buffers runtime du code copié reste distincte du rappel des entrées de stockage ROM.

## Fichiers et reproduction
Les scripts sont durables. `work/` contient aussi les projets sauvegardés et les preuves à préserver. Rapport détaillé : `work/step8.md`. Liste nominative : `work/missed_thumb_xrefs.json`. Validation avec sources et plages de données : `work/pointer_validation.json`. Preuves REA : `work/pointer_xrefs.json`, `work/missed_no_pointer_xrefs.json`, profil dans `work/pointer_run_metadata.json`.

```sh
python3 -I scripts/pointer_candidates.py scan 'work/rom/Golden Sun (USA, Europe).gba' work/repo_funcs.txt work/procs.json work/pointer_candidates.json
python3 -I scripts/pointer_candidates.py summarize work/pointer_candidates.json work/pointer_xrefs.json work/pointer_summary.md
python3 -I scripts/validate_pointer_xrefs.py work/pointer_candidates.json work/pointer_xrefs.json 'work/rom/Golden Sun (USA, Europe).gba' work/repo work/pointer_validation.json --extra-xrefs work/missed_no_pointer_xrefs.json
```

Pour refaire les requêtes REA : ouvrir l'ELF mappé, attendre `binary_overview`, interroger les 8 463 valeurs `pointer_value` de l'inventaire puis les 232 fonctions Thumb manquées absentes de cet inventaire à `addr|1`. Sauvegarder les enveloppes `{address, result}` avec `structuredContent.normalized_result` et l'identifiant de preuve. `list_procedures` permet de vérifier la stabilité de la baseline.

## Conventions
Réponses courtes, mode développeur. Déléguer à Luna quand cela économise le contexte (autorisation de Wladimir). Après chaque étape, actualiser les deux pages Notion et le fichier de reprise. Mémoire en lecture seule pour Codex ; bilan des ajouts éventuels en fin de session seulement, selon Wladimir. Ne jamais publier de ROM ni d'ELF.

Pages actualisées jusqu'à l'étape 13 ; étapes 14 à 27 en attente. Aucun outil Notion utilisé dans ce lot ; les fichiers locaux font foi :
- [Golden Sun : reprise](https://app.notion.com/p/3f7e8064f32181b18c3de21b11da95d0)
- [Golden Sun : sommaire](https://app.notion.com/p/3f7e8064f321817f9aecd11fff53057f)

Le précédent `HANDOFF.md`, lu au début de la session, n'était plus présent lors de la mise à jour. Ce fichier conserve la reprise de l'étape terminée.
