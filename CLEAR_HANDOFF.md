# Reprise après le lot 33 terminé

Lot 33 terminé le 2026-10-17 : archive des projets Ghidra intermédiaires vérifiée et restaurée à l'essai, projets supprimés, projet retenu `work/ghidra_thumb_special_pair_scoped/step9.gpr` intact, index SQLite `work/project_index.sqlite` construit. Lire `work/step33.md`. Les références `archive:NOM` des documents désignent un projet archivé, à restaurer avec `scripts/archive_projects.py restore`. Aucun prochain lot lancé, attendre l'ordre de Wladimir.

# Reprise Golden Sun × REA, étape 32 terminée

Le lot 32 de comparaison avec `jjppof/goldensun_html5` est terminé, revue indépendante favorable Sol/medium. Lire `RUN_STATE.md`, `work/step32.md`, `work/step32_html5_verification.json` et `work/step32_independent_review.md`. Le relevé Luna/low est `work/step32_html5_findings.md`. JSON reproduit à l'octet : SHA256 `72b7590b6c6b1cffe6541054256bfe55c3c4546a03a62211506b5131a81120f9`. Aucun prochain lot lancé.

Clone propre `external/goldensun_html5`, commit `b8b086dc4a15025778acd1ce861c4ef7d6fda426`, `--depth 1 --filter=blob:none`, sparse source uniquement. 259 blobs présents, 367 absents ; aucun média, atlas JSON ou base de contenu récupéré, même dans le stockage Git. `assets/filters` est du code JS/GLSL, seule exception source sous assets. Licence MIT du moteur et documentation, notices à conserver ; les médias restent réservés dans son README. Révision et règles dans `work/external_references.json` et `external/README.md`. Aucun build/dépendance/sous-module ou Ghidra.

Le moteur HTML5 emploie des atlas image/JSON, des animations nommées, huit directions et un miroir de combat par échelle X négative. Ce n'est pas une décompilation : aucune correspondance pixel/ROM, palette OBJ 224, seize tuiles ou centrage GBA `32-x` établie par ce dépôt. Les preuves étapes 28 à 31 conservent leur autorité. Aucun runtime Phaser exécuté.

**Prochain lot prévu : lot 33, en attente de l'ordre de Wladimir après le prochain `/clear`. Ne pas le lancer automatiquement.** Son périmètre archive vérifiée + index SQLite est détaillé plus bas. Configuration : principal Sol/high, relevés Luna/low, revue Sol/medium. Claude garde Notion et mémoire ; Codex garde analyse/fichiers. Mémoire en lecture seule.

## Amont conservé : étape 31 terminée

Le lot 31 autorisé via Claude a exécuté le visualiseur natif dans mGBA 0.10.5 et a reçu une revue indépendante favorable Sol/high. Preuve `work/step31_ppu_verification.json`, rapport `work/step31.md`, revue `work/step31_independent_review.md`. JSON reproduit à l'octet : SHA256 `f0b08f80c25fc00bbcd60b85536c478ea72e98b6f92f643b92f4a65baebeeec8`. Aucun prochain lot lancé. Lire ces fichiers et `RUN_STATE.md` avant tout travail.

**Entrée forcée, pas accès naturel :** démarrage ROM intacte, initialisation système native jusqu'au PC pipeline `0x08002eda`, puis une seule écriture du PC cible `0x08012519`. Pas d'injection mémoire. Le jeu construit ses objets, tas, caches, tuiles, palette et OAM, et exécute les DMA et VBlank dans le cœur complet. BIOS HLE mGBA. L'accès par menus ou touches seules reste non établi.

SPR_000/animation 0/frame 1/mode 0 : zéro différence sur les 1 024 pixels de chaque rectangle (258 pixels de sprite, 766 pixels de fond) avec expansion RGB mGBA. Palette OBJ 224 entrées et seize tuiles identiques au banc ; attributs OAM comparés après normalisation des positions/slots ; matrice réelle (-256,0,0,256). Miroir `32-x` confirmé par framebuffer, flip `31-x` faux sur 246 pixels. VRAM/palette/OAM entiers stables sur la frame capturée.

Reproduction : commandes de compilation et d'exécution dans `work/step31.md`. Adaptateur `scripts/mgba31.c`, interface `scripts/probe_mgba31.py`, preuve `scripts/audit_mgba_ppu.py`. Bibliothèque déjà installée `/usr/lib/x86_64-linux-gnu/libmgba.so.0.10`, exécutable `/usr/games/mgba`. Seuls les en-têtes du paquet correspondant ont été téléchargés/extraits localement, aucun paquet supplémentaire installé. Sources étapes 28 à 30 inchangées.

Données sous `work/step31_private/` (0700, fichiers 0600), ne jamais publier ni afficher ROM, PNG ou blocs extraits. Pas de Ghidra. Limites restantes : entrée PC forcée, BIOS HLE, PPU logiciel plutôt que matériel, ombres désactivées, deux témoins seulement. Claude conserve Notion et mémoire ; Codex n'y écrit pas.

Bridge default raccordé dans cette reprise au chat `01a148e6-cf4a-7c52-9f0d-384fb2100141`, distinct du précédent `01a148de-ddc7-7ab1-9f1f-81151045d7f3`. Tout nouveau clear exige une nouvelle identification ; ne réutiliser aucun ancien UUID. Les indications de routage historiques ci-dessous ne sont plus valides.

## Lot 33 prévu, en attente d'ordre après le prochain clear

Ne pas lancer ce lot à la suite automatique du lot 32. Wladimir donnera son ordre après le prochain `/clear`.

1. Archiver par compression les projets Ghidra intermédiaires, rejetés ou remplacés (dont `ghidra_thumb_special_pair_probe` et anciens scoped). Le projet retenu `work/ghidra_thumb_special_pair_scoped/step9.gpr` reste intact et ouvrable. Les preuves et rapports référencés restent en place. Rien n'est supprimé avant vérification d'intégrité de l'archive et SHA256.
2. Créer une base SQLite d'index, sans contenus : chaque étape, ses fichiers, leur statut retenu/rejeté/remplacé, SHA256 de la preuve, liens vers rapports et revues. Fournir un script de régénération et de vérification.

Configuration à partir du lot 32 : principal Sol/high, relevés Luna/low, revue indépendante Sol/medium. La revue 31 était déjà terminée en Sol/high lorsque le changement est arrivé.

## Amont conservé : étape 30 terminée

Le lot 30 autorisé par Wladimir via Claude est terminé et revu favorablement. Deux images RGBA privées ont été reconstruites depuis les seize tuiles et la palette OBJ de 224 entrées du banc natif : SPR_000, animation 0, frame 1, mode 0, directions 0 et 0x8000. Zéro différence avec la référence étape 28 après transformation propre à chaque direction. 258 pixels opaques, 42 couleurs et 766 pixels transparents par image. Aucun prochain lot lancé.

Lire d'abord `RUN_STATE.md`, `work/step30.md`, `work/step30_rgb_verification.json`, `work/step30_independent_review.md` et `work/step30_emulator_findings.md`. Les lectures étape 29 ci-dessous restent l'amont technique.

Le miroir affine centre (16,16) suit source_x = 32 − destination_x, d'après le modèle mGBA cité, et diffère du flip ordinaire sur 246 positions. La colonne source zéro est transparente dans ce témoin. Les PNG sont uniquement dans `work/step30_private/` (0700, fichiers 0600) ; ne pas les publier ni afficher via un outil de conversation. JSON reproduit à l'octet : SHA256 `8f1d0555c6ea4d44d52daa2d3fbdbd4d9b18f9f04ad99a9f4a7c52675410eda6`.

Reproduction : `uv run --offline --no-project --with unicorn==2.1.4 python scripts/audit_sprite_rgb.py work/step30_rgb_verification.json`. Un dossier privé peut être fourni après le chemin JSON. Scripts 28/29 inchangés. Relevé de l'agent de relevé (Luna/low), revue agent de revue (Sol/high), rapports persistés, aucun besoin de les recontacter.

Aucun émulateur GBA détecté dans PATH ou paquets dpkg/apt. Flatpak absent, inventaire Snap expiré donc indisponible. Aucune installation. La suite PPU demanderait un émulateur et un état de sauvegarde ou des entrées atteignant le sprite, puis dumps privés VRAM/palette/OAM et registres d'affichage. Ne pas confondre injection de données synthétiques dans un renderer et observation du jeu commercial.

Objets/tas/cache/slots toujours synthétiques, DMA simulé, shims LDM hérités, mapping OBJ 1D supposé. Pas de PPU, jeu complet ou accès commercial au visualiseur exécuté. Aucun Ghidra ouvert ou modifié. La mémoire reste en lecture seule pour Codex. Claude prend Notion et mémoire, leur actualisation doit être confirmée séparément. Le bridge default a été vérifié pour le nouveau chat `01a148de-ddc7-7ab1-9f1f-81151045d7f3`, distinct de l'ancien `01a148cf-c672-7100-ad4e-1ca48769e688` ; ne pas réutiliser ce routage sans contrôle après un prochain clear.

## Amont conservé : étape 29

Wladimir a demandé de poursuivre jusqu'au prochain jalon majeur, avec sous-agents. Le lot SPR_000, animation 0, direction 0x0000, tampon vers VRAM/palette/miroir et OAM, est terminé. Le témoin 0x8000 contrôle le miroir de la même frame. Aucun prochain lot lancé. Les fichiers locaux font foi.

## Lectures de reprise

1. RUN_STATE.md, état et règles Ghidra.
2. work/step29.md, résultat, protocole, limites et sources.
3. work/step29_upload_verification.json et work/step29_independent_review.md.
4. work/step28.md et son JSON pour les seize modes et le décodage amont.
5. external/README.md et work/external_references.json pour les références fixées.

## Jalon atteint

- Vrai compositeur Func_aa0c exécuté jusqu'au retour : 1 024 indices, seize tuiles 8 × 8 en 8 bpp, 256 écritures CPU de quatre octets. Copie RAM de Func_a418 vérifiée et exécutée.
- Huit témoins synthétiques de dimensions multiples de huit confrontent l'uploader à un modèle par coordonnées.
- Func_bb20 exécuté avec heap et DMA simulés : palette OBJ commune de 224 entrées depuis 0x0800779c vers 0x05000200. Les entrées 224..255 restent antérieures. Frame 1 mode 0 : 258 pixels non nuls, 42 indices/couleurs distincts, tous dans la palette chargée.
- Directions 0 et 0x8000 : mêmes tuiles. Placement Func_b168 natif : miroir affine Q8 (-256,0,0,256), aucun flip du tampon. Coordonnées synthétiques identiques pour comparaison.
- Func_3e10 copie Func_1dc8 en RAM, l'exécute et libère sa copie. Attributs et coefficients OAM contrôlés dans le tampon puis à 0x07000000.
- Tranche 0x08003686..0x080036a7 du gestionnaire VBlank exécutée : DMA3 0x84000100, 1 024 octets vers OAM si les deux flags sont posés. Les trois autres combinaisons ne transfèrent rien.
- Changement de direction conservant la même frame : retour miroir actualisé, aucun nouvel upload.
- Revue indépendante et reproduction du JSON identique : work/step29_independent_review.md.

## Bornes de la preuve

Unicorn 2.1.4, objets/couche/tas/cache/slot décodeur synthétiques ; allocations/libérations et DMA3 immédiats simulés. Trois corrections LDM non alignés héritées de l'étape 28. Pas de parcours du jeu, de DISPCNT exécuté, de mapping PPU, de rendu écran ou d'interruption complète. Le fondu matériel n'est pas simulé. Le constructeur et les répertoires de ressources restent fournis au banc.

L'adresse VRAM 0x060100c0 et le tampon OAM 0x02013000 sont propres au banc. L'ombre est chargée, mais son placement est désactivé pour isoler l'image. Le visualiseur commercial n'est toujours pas observé en jeu. Les noms et structures étaient déjà décrits dans Alchemy.

## Ghidra et références à préserver

Projet retenu : work/ghidra_thumb_special_pair_scoped/step9.gpr, programme gs_us_map.elf. 2 593 fonctions, 2 223/2 253 entrées ROM reconnues (98,67 %), trente absentes. Aucun lancement ni changement Ghidra aux étapes 27, 28 et 29. Aucun nom/type importé.

Principal seul aux commandes Ghidra, une instance par projet. Mutation sur copie neuve d'un projet fermé, audits et réouverture avant promotion. Ne pas refaire les contrôles étape 26 sans raison. La copie ghidra_thumb_special_pair_probe reste exclue : donnée hors périmètre à 0x03001c90.

Alchemy : commit 1517ff0750d988f570b6efcd06bf30d0f64c9d2a. Game Tools Collection : commit ea0efd9b161fd39308e61ce180d409c7b11613cf. Aucun build ni changement des références. work/repo/ reste une archive sans Git. Ne publier ni ROM, ELF, image ni payload extrait.

## Reproduction

Depuis la racine :
~~~sh
uv run --offline --no-project --with 'unicorn==2.1.4' python scripts/audit_sprite_upload.py work/step29_upload_verification.json
~~~
Banc étape 28 inchangé : scripts/audit_sprite_decode.py.

## Suite à choisir

Validation en émulateur complet du mapping/PPU et du visualiseur, ou reconstruction des instances de code RAM dans Ghidra à partir des preuves acquises. Aucun de ces lots lancé. Mode 12, témoin compressé et trente entrées absentes restent des enquêtes séparées.

## Coordination

Claude Bridge default est connecté pour les questions de Wladimir, Notion et les mémoires. Codex garde l'analyse et les fichiers du projet ; la mémoire Claude reste en lecture seule. Les envois de coordination sont autorisés par Wladimir dans cette session. Ne pas supposer ce routage valide après un clear.

Relevés étape 29 : deux agents de relevé. Revue : agent de revue. Résultats dans work/step29_* ; aucun besoin de les recontacter après lecture de leurs rapports.

Notion était à l'étape 13 à l'ouverture. Son actualisation relève de Claude et doit être confirmée séparément ; ce fichier ne la certifie pas. Ne pas déduire une écriture mémoire de la seule existence de ce handoff. STEP8_HANDOFF.md conserve l'historique ancien.
