# Lot 33 terminé, 2026-10-17

27 projets Ghidra intermédiaires, rejetés ou remplacés archivés dans `work/archives/step33/projects.tar.gz` (SHA256 `5a6bfdca75c13eb506592ac19ba8ff7ba765c992f974ae87a4c34ab8a4d4c673`), vérifiés, restaurés à l'essai puis supprimés (922 468 352 octets libérés). Le seul projet retenu, `work/ghidra_thumb_special_pair_scoped/step9.gpr`, est intact. Une référence `archive:NOM` désigne un projet archivé : restauration par `python3 -I scripts/archive_projects.py restore --project NOM --destination DOSSIER_HORS_PROJET`. Index SQLite sans contenus : `work/project_index.sqlite`, régénération et vérification par `scripts/project_index.py`. Rapport `work/step33.md`, preuve `work/step33_archive_verification.json`. Aucun prochain lot lancé.

# Golden Sun × REA : étape 32 terminée, 2026-10-17

**Référence HTML5 comparée et revue favorablement.** Rapport `work/step32.md`, preuve `work/step32_html5_verification.json`, revue indépendante Sol/medium `work/step32_independent_review.md`. Relevé Luna/low `work/step32_html5_findings.md`. JSON reproduit à l'octet : SHA256 `72b7590b6c6b1cffe6541054256bfe55c3c4546a03a62211506b5131a81120f9`.

- Troisième référence propre `external/goldensun_html5`, commit `b8b086dc4a15025778acd1ce861c4ef7d6fda426`, shallow/blob:none/sparse. 259 blobs source/documentation présents, 367 absents. Aucun média, atlas JSON ou base de contenu téléchargé ; shaders JS/GLSL autorisés sous assets/filters. Inventaire exact dans `work/external_references.json` et `external/README.md`.
- Moteur TypeScript/JavaScript Phaser CE 2.19.0, viewport 240 × 160, atlas/animations nommées, huit directions et miroir de combat par scale.x négative. Représentations distinctes du GBA ; aucune identité des pixels, palette 224, seize tuiles ou raster `32-x` déduite. Pas d'exécution du moteur HTML5.
- Licence MIT pour logiciel/documentation avec conservation des notices ; droits des médias séparément réservés par son README. Pas de modification des trois références externes, aucun build/dépendance/sous-module, aucun Ghidra.
- **Lot 33 prévu, non lancé :** archives des projets Ghidra intermédiaires/rejetés/remplacés après contrôle intégrité/SHA256, projet retenu et preuves intacts ; index SQLite sans contenus, régénérable/vérifiable. Attendre l'ordre explicite de Wladimir après le prochain `/clear`, voir `CLEAR_HANDOFF.md`.

Configuration prochaine revue Sol/medium, principal Sol/high et relevés Luna/low inchangés. Notion/mémoire restent à Claude. Aucun prochain lot lancé.

## Amont conservé : étape 31 terminée

**Comparaison PPU mGBA exécutée : zéro écart sur 1 024 pixels pour chacune des deux orientations de SPR_000/animation 0/frame 1/mode 0.** Rapport `work/step31.md`, preuve `work/step31_ppu_verification.json`, revue indépendante favorable Sol/high `work/step31_independent_review.md`. JSON reproduit à l'octet : SHA256 `f0b08f80c25fc00bbcd60b85536c478ea72e98b6f92f643b92f4a65baebeeec8`. Aucun prochain lot lancé.

- Entrée du visualiseur forcée par une seule écriture PC après initialisation système native, avant titre. Aucun accès naturel par menus établi. ROM et mémoire non patchées, aucun sprite injecté.
- Objets, couches, allocations, caches, slots, upload, OAM, DMA et VBlank produits par le jeu dans le cœur complet de mGBA 0.10.5 ; les shims du banc Unicorn ne s'appliquent pas à cette exécution.
- Tuiles et palette OBJ 224 entrées identiques au banc ; OAM normalisé concordant ; mapping OBJ 1D observé par DISPCNT. Miroir `32-x` confirmé au framebuffer, flip ordinaire faux sur 246 pixels. Capture avec VRAM/palette/OAM stables sur la frame.
- RGB mGBA par réplication des bits, distinct de l'expansion analytique étape 30 ; octet haut framebuffer = métadonnées, pas alpha. Registres bruts BLDY=0, sans fondu actif. Comparaison inclut fond et transparence.
- Limites : entrée PC forcée, BIOS HLE, PPU logiciel plutôt que GBA physique, ombres coupées, deux témoins d'une seule frame/mode. Pas de Ghidra ni installation supplémentaire. Dumps/PNG/états privés dans `work/step31_private`, non publiables. Claude garde Notion et mémoire.

Reproduction et frictions détaillées dans le rapport. En-têtes de la bibliothèque installée téléchargés/extraits sous `work/step31_tools/headers` ; compilation locale de l'adaptateur, aucun paquet ajouté. Reprise : `CLEAR_HANDOFF.md`.

## Amont conservé : étape 30 terminée

**Jalon reconstruction RGB locale atteint et revu favorablement.** Rapport `work/step30.md`, preuve reproductible `work/step30_rgb_verification.json`, revue `work/step30_independent_review.md`, inventaire `work/step30_emulator_findings.md`. Aucun prochain lot lancé.

- Deux PNG RGBA privés de 32 × 32 dans `work/step30_private/` (0700, fichiers 0600), aucune image publiée. SPR_000/animation 0/frame 1/mode 0, directions 0 et 0x8000.
- Seize tuiles natives et palette OBJ 224 entrées relues dans le banc étape 29 ; détuillage identique au tampon natif réexécuté de l'étape 28. Zéro différence pixel après la transformation de référence de chaque direction. 258 pixels opaques, 42 couleurs et 766 pixels transparents par image.
- Miroir affine Q8 (-256,0,0,256), centre entier (16,16) : source_x = 32 − destination_x, convention dérivée du renderer mGBA. Diffère du flip 31-x sur 246 positions ; équivaut ici au flip décalé d'un pixel à droite. Colonne source zéro transparente. Ce calcul reste analytique, sans PPU exécuté.
- JSON reproduit à l'octet, SHA256 `8f1d0555c6ea4d44d52daa2d3fbdbd4d9b18f9f04ad99a9f4a7c52675410eda6`. Vérificateur indépendant des PNG : chunks/CRC/zlib et 4 096 octets RGBA de chaque image contrôlés.
- Aucun émulateur GBA détecté dans PATH ou paquets dpkg/apt, Flatpak absent ; inventaire Snap indisponible (expiration). Aucune installation. Validation PPU future : état ou entrées reproductibles atteignant le sprite, dumps privés VRAM/palette/OAM et registres d'affichage, comparaison normalisée au banc. Un émulateur seul ne supprime pas les objets synthétiques.
- Aucun Ghidra ouvert ou modifié. Mapping OBJ 1D supposé, objets/tas/cache/slots synthétiques, DMA simulé et shims LDM hérités. Pas de jeu, affichage PPU, fondu ou LCD observé. Notion et mémoire restent sous responsabilité Claude, statut à confirmer séparément.

Reproduction : `uv run --offline --no-project --with unicorn==2.1.4 python scripts/audit_sprite_rgb.py work/step30_rgb_verification.json`. Scripts 28 et 29 inchangés. Reprise : `CLEAR_HANDOFF.md`.

## État antérieur conservé : étape 29

**Jalon SPR_000/animation 0 : tampon vers tuiles VRAM, palette OBJ commune et miroir affine jusqu'aux attributs/matrices OAM. Rapport : work/step29.md ; preuve : work/step29_upload_verification.json ; revue indépendante favorable : work/step29_independent_review.md. Reprise : CLEAR_HANDOFF.md. Aucun prochain lot lancé.**

Banc Unicorn 2.1.4 : initialisation Func_bb20 native avec allocations et DMA simulés, copie RAM de l'uploader Func_a418 vérifiée/exécutée, huit témoins synthétiques de tuiles, deux compositions et deux placements isolés (directions 0 et 0x8000), générateur OAM copié/exécuté en RAM, tranche DMA OAM du VBlank. Reproduction indépendante du JSON identique, plus parseur distinct retrouvant les empreintes des indices et tuiles.

- SPR_000, animation 0, direction 0 : frame 1, 32 × 32 indices, seize tuiles de 64 octets, 1 024 octets transférés. Palette OBJ 224 entrées depuis 0x0800779c vers 0x05000200 ; entrées 224..255 antérieures. 258 pixels non nuls, 42 couleurs brutes distinctes.
- Direction 0x8000 : mêmes tuiles, miroir par matrice Q8 (-256,0,0,256). Changement de direction conservant la frame : retour miroir modifié sans nouvel upload.
- Attributs OAM et matrice contrôlés après génération en RAM et transfert simulé vers 0x07000000. Tranche VBlank 0x08003686..0x080036a7 seulement, trois combinaisons de flags inactifs vérifiées sans transfert.
- Objets, couche, tas, cache et pointeurs fournis au banc. Allocations/libérations et DMA3 simulés, trois corrections LDM héritées. Pas de DISPCNT/PPU/rendu écran exécuté, pas d'interruption ou jeu complet. Aucun accès commercial au visualiseur établi.
- Adresse VRAM 0x060100c0 propre au cache synthétique. Palette brute et RGBA analytique ne sont pas des couleurs finales observées. Aucun export d'image ou payload.

Aucun lancement ni changement Ghidra aux étapes 27, 28 et 29 ; aucun nom ni type adopté. Le système décrit par Alchemy préexistait à nos contrôles, ne pas le présenter comme découvert indépendamment.

Amont conservé : work/step28.md et work/step28_decode_verification.json. Seize modes vérifiés ; mode 12 lit le code ROM à 0x08009bb8 comme table, intention inconnue. Les cinq frames de l'animation 0 ne sont pas effectivement compressées malgré le codec 3. Le témoin compressé frame 5 écrit aussi un zéro à l'offset 1024 ; aucune corruption en jeu établie. Ces enquêtes restent séparées du jalon 29.

Claude Bridge default prend en charge les questions, Notion et les mémoires. Codex garde les fichiers du projet ; mémoire Claude en lecture seule. Notion était à l'étape 13 à l'ouverture ; attendre la confirmation de Claude pour connaître son actualisation.

## Projet validé

`work/ghidra_thumb_special_pair_scoped/step9.gpr`, programme `gs_us_map.elf`.
**Baseline conservée : 2 593 fonctions ; 2 223/2 253 entrées ROM reconnues, soit 98,67 % ; 30 entrées absentes au début de l'étape 34.**
Rapport `work/step26.md`, preuve `work/thumb_special_pair_scoped_verification.json`, inventaire `work/step26_remaining.json`.
Projet sauvegardé, fermé, rouvert et contrôlé. Second passage idempotent : snapshots, cibles, pools et C identiques. Tous les processus Ghidra de cette reprise sont terminés.

La baseline REA reste 1 914 procédures et 1 544 entrées reconnues. Les gains sont guidés par la référence. Étape 26 : deux fonctions, 674 instructions et 1 420 octets ajoutés. Vingt mots de pool : seize nouvelles unités undefined4 et quatre pointeurs préexistants conservés. Aucun override RETURN nécessaire. Anciens noms/corps de fonctions, instructions, données définies, octets et permissions des blocs mémoire conservés.

Les deux C terminent sans avertissement. Func_12518 conserve ses quatre plages et sa boucle sans épilogue de retour. Exports_185000 reste une base paire 0x08185000. Func_fa674 contient exactement SWI 0x2a puis BX LR ; le C représente l'interruption sans établir sa sémantique BIOS ni son ABI. Les prototypes et l'équivalence C complète ne sont pas établis.

## Copies et preuves à préserver

Le plan autorisé `work/thumb_special_pair_final_plan/` reste inchangé. Sa régénération `work/thumb_special_pair_revalidated_plan/` donne le même contenu et les mêmes empreintes après normalisation des chemins de provenance relatifs/absolus. Voir `work/thumb_special_pair_preflight.json`.

`archive:ghidra_thumb_special_pair_probe/` est une copie d'analyse, à ne pas promouvoir. ArmAnalyzer y a créé une donnée hors périmètre à 0x03001c90 : `work/thumb_special_pair_probe_differences.json`. La copie propre retenue n'a pas cette annotation. L'export approuvé contient zéro RETURN : `work/thumb_special_pair_approved_returns.json`.

Audits retenus : `thumb_special_pair_scoped_before/`, `scoped_recovery/`, `scoped_after/`, `scoped_reopened/`, `scoped_repeat/` et `scoped_repeated/`, tous sous `work/` avec le préfixe `thumb_special_pair_`. Revue C `work/thumb_special_pair_c_review.json`, revue indépendante `work/thumb_special_pair_independent_review.md`. L'étape 25 et ses preuves restent intactes dans `archive:ghidra_thumb_inline_remaining_scoped/`.

## Suite non exécutée

Le lot tampon/VRAM/palette/miroir est terminé à l'étape 29. Prochain lot à choisir : validation en émulateur complet du mapping/PPU et du visualiseur, ou reconstruction des instances RAM dans Ghidra. Aucun de ces lots lancé. L'accès au visualiseur, le mode 12 et le témoin compressé restent distincts.

Références externes auditées : `external/alchemy/` et `external/game-tools-collection/`, clones partiels à historique court, sans modifications locales, commits initiaux conservés. Voir `external/README.md` et `work/external_references.json` pour les révisions et le sparse. L'éditeur est celui de RyudoSynbios, distinct d'Atrius. Le SHA1 anglais publié par Alchemy correspond à notre ROM ; son build complet annoncé reste non vérifié. Aucun sous-module, dépendance ou build externe lancé. Unicorn 2.1.4 est disponible dans le cache uv pour le banc local.

Étape 34 terminée : les 30 entrées ont été récupérées dans le candidat cumulatif `work/ghidra_step34_runtime_arm_scoped/step9.gpr`. Le candidat a été fermé, rouvert et comparé à la baseline retenue `work/ghidra_thumb_special_pair_scoped/step9.gpr`, qui reste intacte ; le candidat n'a pas été promu. Résultat : 2 593 à 2 623 fonctions, 5 239 instructions ajoutées, 142 unités de données ajoutées et quatre unités `undefined2` source-confirmées remplacées. La ROM, les permissions mémoire, les fonctions et instructions préexistantes sont inchangées. Voir `work/step34.md` et `work/step34_aggregate_verification.json`.

Les 30 fonctions sont nommées dans `work/step34_all_targets.tsv`. Les rapports des lots sont dans `work/step34_*_verification.json`. Les fonctions copiées par DMA dans des buffers runtime restent hors de cette étape et sont listées dans `work/step34.md`.

Les appels de code copié par DMA restent à reconstruire dans leurs buffers runtime : notamment Func_9bb8, Func_55d8 copiant Func_20f4 vers la pile, Func_d304 copiant Func_a494 vers un bloc alloué. Le rappel ci-dessus mesure les entrées de stockage ROM.

## Règles et pièges

- Principal seul à lancer ou modifier Ghidra. Une seule instance par projet. Copier seulement un projet fermé, vers un dossier absent.
- `JAVA_TOOL_OPTIONS=-Dapplication.cachedir=~/.cache/ghidra` avant analyzeHeadless.
- Aucun rollback imbriqué : peut annuler tout le lot. RecoverThumb peut laisser une modification partielle en cas d'échec, donc copie jetable et vérification obligatoire.
- ArmAnalyzer peut modifier les données référencées hors des corps ciblés. Ne l'exécuter que sur la copie d'analyse. Exporter seulement les RETURN approuvés, puis les appliquer sur la copie propre.
- Premier essai de l'étape 21 `ghidra_thumb_literal_medium` REJETÉ pour annotations hors périmètre. Conserver `work/step21_attempt.md` et ses preuves. Variante validée : `ghidra_thumb_literal_medium_scoped`.
- `plan_thumb_inline.py` vérifie SWI et immédiat/opcode exact ; `Symbols` résout Exports_185000 par le label source et le premier stub vérifié. Ne pas convertir la base de table en pointeur Thumb.
- Avec `python3 -I`, les imports voisins du planificateur demandent un chemin de scripts explicite. Exemple dans `work/step26.md`. Aucun script modifié durant cette reprise.
- Mémoire Claude en lecture seule. Ne jamais publier ROM, ELF ou textes extraits.
- Notion et mémoires via Claude Bridge default dans cette session. Statut d'actualisation à confirmer auprès de Claude ; les fichiers locaux font foi.

## Scripts et agents

Étape 29 : `audit_sprite_upload.py output.json`, banc décrit dans `work/step29.md`. Reproduction : `uv run --offline --no-project --with 'unicorn==2.1.4' python scripts/audit_sprite_upload.py work/step29_upload_verification.json`. Aucun Ghidra ni build externe. Relevés agent de relevé et agent de relevé, revue agent de revue. Rapports persistés dans `work/step29_*`. Revue favorable et JSON identique, aucun besoin de relancer ces agents.

`audit_sprite_decode.py output.json` : vérifie la ROM et les sources Alchemy, confronte neuf tables, puis exécute des chemins ARM/Thumb isolés. Reproduction : `uv run --offline --no-project --with 'unicorn==2.1.4' python scripts/audit_sprite_decode.py work/step28_decode_verification.json`. Aucun Ghidra. Les limites du banc, son adaptation LDM et le témoin hors animation 0 sont détaillés dans `work/step28.md`.

Étape 28 : agent de relevé (Luna/low), relevé statique, corrigé après confrontation directe ; agent de revue (Sol/high), revue indépendante et reproduction du JSON. Rapports `work/step28_modes_findings.md` et `work/step28_independent_review.md`. Aucun agent n'a lancé Ghidra. Le principal a résolu les tables et piloté le banc.

`audit_semantic_references.py output.json` : comparaison en lecture seule des TSV Alchemy avec la ROM GS1 anglaise, vérification des commits et arbres propres, 512 métadonnées et 2 062 slots d'animations. Preuve `work/step27_reference_verification.json`, aucune extraction de payload dans les sorties.

Étape 27 : agent de relevé (Luna/low), relevés et parseur éditeur ; agent de revue (Sol/high), revue indépendante du rapport et des preuves. Rapports `work/step27_gtc_findings.md` et `work/step27_independent_review.md`. Aucun agent n'a lancé Ghidra. Les agents mentionnés ci-dessous sont ceux de l'étape 26.

`RecoveryAudit.java targets.tsv outputdir` : snapshots globaux et C/listings. TSV adresse puis nom.
`RecoverThumb.java targets.tsv repo_function_boundaries.tsv outputdir` : récupération guidée sans analyse générale.
`LiteralAudit.java plan.json output.json` : valeurs et unités des pools, absence de chevauchement code.
`ExportApprovedReturns.java plan.json output.json` : lecture seule, RETURN liés au plan/octets/TMode/P-code/motif source.
`ApplyApprovedAnalysis.java plan.json approved-returns.json` : précontrôle complet, seuls RETURN et slots sans donnée définie. Préserve toute unité existante même partielle. Idempotent.
`verify_thumb_recovery.py plan.json before after reopened output.json` : conservation globale, corps/octets/branches/pools et persistance du C ; pas d'équivalence sémantique générale.

Sous-agents de cette reprise : agent de relevé (Luna/low, relevés source) et agent de revue (Sol/high, revue indépendante favorable). Ils n'ont lancé ni modifié Ghidra. Les erreurs de comptage et d'adresses du relevé initial ont été corrigées par confrontation directe aux sources et au C. Les preuves et le rapport final font foi.
