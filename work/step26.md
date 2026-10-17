# Étape 26 : Func_12518 et Func_fa674

**Étape terminée après levée de la pause par Wladimir. Le lot autorisé est récupéré et validé. Aucun autre lot lancé.**

Projet retenu : `work/ghidra_thumb_special_pair_scoped/step9.gpr`, programme `gs_us_map.elf`. **2 593 fonctions**, dont **2 223/2 253 entrées ROM de référence, soit 98,67 %**. Il reste trente entrées. La baseline REA reste 1 914 procédures et 1 544 entrées reconnues ; cette récupération est guidée par la référence.

Le plan autorisé `thumb_special_pair_final_plan/` a été régénéré dans un dossier distinct. Les deux plans sont identiques après normalisation des seuls chemins de provenance relatifs/absolus ; toutes les empreintes des sources correspondent. Le lancement direct avec `python3 -I scripts/plan_thumb_inline.py` échoue sur l'import voisin `plan_thumb_literals`. La relance avec chemin de scripts explicite résout cet import, sans modifier les scripts. Deux copies neuves du projet fermé de l'étape 25 ont ensuite été créées.

Func_12518 : **672 instructions, 1 416 octets**, quatre plages de code séparées par les pools et le remplissage. Func_fa674 : **deux instructions, quatre octets**, `swi 0x2a` puis `bx lr`, octets `2adf 7047`. Total : **674 instructions et 1 420 octets**. Vingt adresses de mots de pool, lues par vingt-deux références littérales : seize unités undefined4 créées et quatre pointeurs préexistants à 0x08012944, 0x08012948, 0x0801294c et 0x08012950 conservés.

La copie `ghidra_thumb_special_pair_probe` a reçu RecoverThumb et ArmAnalyzer. L'export confirme **zéro override RETURN** : Func_12518 boucle sans épilogue de retour, Func_fa674 possède déjà un BX LR terminal. La sonde a ajouté dix-sept données, dont une hors pools à 0x03001c90. Elle n'est pas promue. La copie propre `ghidra_thumb_special_pair_scoped`, créée directement depuis l'étape 25, a reçu RecoverThumb et ApplyApprovedAnalysis, sans ArmAnalyzer. Elle n'a ajouté que les seize unités de pool autorisées. Les deux C sont identiques à ceux de la sonde.

Les audits globaux passent. Le snapshot initial correspond exactement à celui de l'étape 25. Les 2 591 anciens noms/corps de fonctions, les 215 292 anciennes instructions et les 24 333 anciennes données définies sont conservés. Les octets et permissions de tous les blocs mémoire sont inchangés. Les seules additions sont les deux fonctions, leurs 674 instructions et les seize unités de pool. État final : 215 966 instructions et 24 349 données définies.

Après sauvegarde et fermeture, un nouveau processus a rouvert le projet. Snapshots, cibles, pools et C sont identiques à l'état final. Puis le second RecoverThumb reconnaît les deux fonctions préexistantes ; ApplyApprovedAnalysis ne crée aucun RETURN ni aucune donnée et conserve les vingt slots. Un audit après ce second passage donne encore les mêmes snapshots et C. Le projet est sauvegardé et fermé ; tous les processus Ghidra de cette reprise sont terminés.

Les deux décompilations terminent sans avertissement. Le contrôle ciblé de Func_12518 retrouve les triples d'écritures DMA3, l'initialisation de quatre entrées, les écritures halfword à 0x05000000 et 0x04000000, la boucle de dix entrées de rendu et les branches des états 0..3. L'assembleur passe à Func_2f0c l'indice 0x11 ou 0x12 et la base paire Exports_185000 = 0x08185000, stockée dans le pool à 0x08012af4. Le C conserve cet appel sous noms et types inférés. Les BL vers le premier stub à 0x08185000 correspondent aussi au plan ; l'adresse de code directe et la base de table paire ont ici la même valeur, sans justifier de changer la donnée en 0x08185001.

Le C de Func_fa674 conserve `software_interrupt(0x2a)` et le retour. Cela ne démontre ni les effets BIOS du service, ni son ABI. Les descriptions de pile et les prototypes de Func_12518 restent inférés. Aucun prototype n'a été imposé, aucune équivalence sémantique complète des C n'est revendiquée.

Luna/low a effectué les relevés source en lecture seule. Sol/high a relu indépendamment le plan, les scripts, les ajouts et les trois états après/réouvert/répété, y compris les empreintes des deux C. Avis final favorable sans réserve bloquante, avec les limites sémantiques ci-dessus. Le principal seul a exécuté et modifié Ghidra. Compte rendu : `thumb_special_pair_independent_review.md`.

Preuves : `thumb_special_pair_preflight.json`, `thumb_special_pair_revalidated_plan/`, `thumb_special_pair_probe_before/`, `probe_recovery/`, `probe_after/`, `probe_differences.json`, `approved_returns.json`, `scoped_before/`, `scoped_recovery/`, `scoped_after/`, `scoped_reopened/`, `scoped_repeat/`, `scoped_repeated/`, `scoped_verification.json`, `c_review.json`, tous sous `work/` avec le préfixe `thumb_special_pair_`. Journaux `thumb_special_pair_probe`, `thumb_special_pair_scoped` et `thumb_special_pair_scoped_reopen`, extensions `.log` et `.console.log`. Les preuves de l'étape 25 sont conservées.

Inventaire `step26_remaining.json` : douze Thumb ROM ordinaires, deux ARM ROM (Func_404 et Func_20f4), douze entrées de stockage rom_770 et quatre cas code/donnée. Aucun lot suivant n'a été lancé. Les instances du code copié dans leurs buffers runtime restent à reconstruire. Le rappel mesure les entrées de stockage ROM.

`RUN_STATE.md` et `STEP8_HANDOFF.md` actualisés. Notion reste en attente depuis l'étape 13, aucun outil Notion connecté disponible. Mémoire Claude inchangée. Son état de projet est ancien ; il mériterait une actualisation par Claude vers l'étape 26, le projet retenu et les trente entrées restantes.

Régénération du plan avec les imports explicites :

```sh
python3 -I -c 'import runpy,sys; sys.path.insert(0,"scripts"); sys.argv=["scripts/plan_thumb_inline.py","work/thumb_inline_remaining_scoped_after/snapshot.json","work/thumb_special_pair_revalidated_plan","--aliases","work/thumb_aliases_with_call_via.json","--names","Func_12518","Func_fa674"]; runpy.run_path(sys.argv[0],run_name="__main__")'
```

Vérification principale, utiliser un nouveau nom de sortie pour préserver la preuve enrichie :

```sh
python3 -I scripts/verify_thumb_recovery.py work/thumb_special_pair_final_plan/plan.json work/thumb_special_pair_scoped_before work/thumb_special_pair_scoped_after work/thumb_special_pair_scoped_reopened /tmp/step26-recheck.json
```
