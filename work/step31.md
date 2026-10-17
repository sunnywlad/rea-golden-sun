# Étape 31 : rendu du visualiseur natif dans mGBA

Le 17 octobre 2026, **les deux rectangles de SPR_000, animation 0, frame 1, mode 0 concordent avec le rendu du PPU logiciel mGBA 0.10.5, sans aucun écart sur leurs 1 024 pixels chacun**. Chaque témoin comporte 258 pixels de sprite et 766 pixels laissant apparaître le fond. Le miroir utilise bien `source_x = 32 − destination_x` ; le flip ordinaire `31 − x` diffère du rendu sur 246 pixels.

Le visualiseur commercial et ses objets s'exécutent réellement dans le cœur complet. **Son entrée est toutefois forcée par une écriture du compteur programme, après initialisation du système. Aucun accès par les menus ou par une séquence de touches seule n'est établi.** Aucun sprite, tas, palette, attribut OAM ou bloc VRAM n'est injecté dans mGBA.

Preuve : [step31_ppu_verification.json](step31_ppu_verification.json). [Revue indépendante favorable](step31_independent_review.md) : JSON reproduit à l'octet, SHA256 `f0b08f80c25fc00bbcd60b85536c478ea72e98b6f92f643b92f4a65baebeeec8`, puis parseur distinct des dumps et du framebuffer avec les mêmes résultats. Le lot s'arrête à ce jalon ; aucun lot suivant lancé.

## Exécution reproductible

L'exécutable installé est `/usr/games/mgba`, hors du PATH usuel ; il utilise `/usr/lib/x86_64-linux-gnu/libmgba.so.0.10`. Le programme SDL a été essayé avec `SDL_VIDEODRIVER=dummy` et `SDL_AUDIODRIVER=dummy`. Son débogueur peut avancer des frames mais n'offre pas de commande d'export binaire VRAM/palette/OAM dans son aide. Le protocole final utilise directement la même bibliothèque installée, avec un adaptateur C et ctypes, sans interface graphique.

Les en-têtes de **la même version Ubuntu** ont été téléchargés avec `apt-get download libmgba-dev`, puis extraits sous `work/step31_tools/headers` par `dpkg-deb -x`. Aucun paquet supplémentaire n'a été installé. Le SHA256 du paquet téléchargé, `1c8d05a75c2d41f183fda8445bd607601f818b2adc000aaaf769ed6e68cbeea6`, correspond à celui d'apt. Le téléchargement a nécessité l'accès réseau hors sandbox après un premier essai sans réseau. Aucun sudo utilisé.

Depuis la racine du projet :

```sh
cc -shared -fPIC -O2 -include mgba/flags.h -I work/step31_tools/headers/usr/include scripts/mgba31.c -Wl,-l:libmgba.so.0.10 -o work/step31_tools/mgba31.so
uv run --offline --no-project --with unicorn==2.1.4 python scripts/audit_mgba_ppu.py work/step31_ppu_verification.json
```

Sources locales : [mgba31.c](../scripts/mgba31.c), [probe_mgba31.py](../scripts/probe_mgba31.py), [audit_mgba_ppu.py](../scripts/audit_mgba_ppu.py). Les trois scripts des étapes 28 à 30 restent inchangés. La preuve consigne leurs empreintes, celles de la bibliothèque et des en-têtes, et la ROM privée est contrôlée par son SHA1 avant exécution et relue identique après. L'adaptateur compilé a pour SHA256 `28af35a6a694ea7b4d4d497c7525389b95be578e01274502be6c949a4773ca0b`, contrôlé par la revue et consigné ici plutôt que dans le JSON. La reproduction suppose cet adaptateur, ou sa recompilation avec la commande indiquée.

## Entrée, commandes et synchronisation

1. Démarrage de la ROM non modifiée avec le BIOS HLE intégré de mGBA. Le véritable système initialise ses interruptions, mémoire, tas, tables et ressources, puis attend dix frames. Pas d'état de sauvegarde externe requis.
2. Après **231 729 pas**, arrêt avant le BL de `0x08002ed8` vers `_Func_8a8e4`. Le PC avec avance du pipeline Thumb vaut `0x08002eda`, CPSR `0x6000003f`, SP `0x03007ef4`. Le titre n'a pas encore chargé son décor. Une seule écriture du PC cible l'entrée Thumb `0x08012519` de `Func_12518`/`Ui_RunIconMonitor`.
3. Le visualiseur natif s'initialise et tourne 120 frames. Il sélectionne initialement SPR_000 et l'animation 1. Les commandes **Gauche, relâchement, L, relâchement, Start, relâchement, A, relâchement**, trois frames chacune, passent en édition d'animation, choisissent l'animation 0, coupent les ombres puis appliquent cette animation. A est nécessaire : changer le numéro affiché ne relance pas à lui seul l'animation.
4. Capture des mémoires, exécution d'une frame supplémentaire, seconde capture et lecture du framebuffer. **Les 98 304 octets VRAM, 1 024 octets palette et 1 024 octets OAM sont identiques entre ces deux captures.** La frame rendue utilise donc un état vidéo stable, sans confondre les attributs d'une frame avec l'image de la précédente.

Le chemin d'accès naturel reste une inconnue distincte : le seul littéral ROM `0x08012519` trouvé est celui du dernier stub d'export de `Exports_9000`, à `0x080092b0` (littéral à `0x080092b4`). Les sources locales consultées ne montrent pas d'appelant naturel à ce visualiseur. Cet inventaire ne prouve pas qu'aucun dispatch indirect ne puisse l'atteindre.

## Comparaison des mémoires et de l'image

| Témoin | OAM réel | Rectangle | Tuiles réelles | Matrice |
|---|---:|---|---|---|
| Direction 0 | 4 | (184, 66), 32 × 32 | 0x06010080, 1 024 octets | Non affine |
| Direction 0x8000 | 3 | (72, 66), 32 × 32 | 0x06011080, 1 024 octets | Index 1 : (-256, 0, 0, 256) |

Dans chaque cas, les seize tuiles réelles sont identiques à celles du banc réexécuté. Leur détuillage redonne le tampon natif de l'étape 28. La palette OBJ réelle de 224 entrées est identique à celle chargée par le banc et à la référence étape 30. Les positions, slots de tuiles et indices de matrice dépendent du cache et de l'ordre des objets : les attributs OAM sont comparés après normalisation de ces champs. Les bits de taille, format, mode affine et priorité concordent ; la matrice réelle est relue dans son propre slot OAM.

Les registres enregistrés dans mGBA établissent `DISPCNT=0x1140` : mode 0, BG0 et OBJ actifs, mapping OBJ 1D, aucune fenêtre. `MOSAIC=0`, `BLDCNT=0xfe`, `BLDALPHA=0`, `BLDY=0`. Les registres non lisibles sur le bus sont examinés avec `rawRead16` dans la mémoire de registres interne de mGBA : une lecture bus de BLDY donnait 1 par open bus, ce n'était pas le coefficient effectivement enregistré.

Le framebuffer public mGBA contient des mots de 32 bits : RGB dans les 24 bits bas, **métadonnées de composition dans l'octet haut**, qui ne constitue pas un alpha. La comparaison ignore cet octet et emploie l'expansion mGBA `(canal5 << 3) | (canal5 >> 2)`. L'étape 30 emploie `floor(canal5 × 255 / 31)`, une autre convention qui peut différer d'une unité ; la preuve reconfirme son empreinte analytique avant de comparer les couleurs selon la convention mGBA.

Les deux rectangles, y compris leurs 766 pixels transparents remplacés par le backdrop observé, concordent sur **1 024/1 024 pixels**. Le rendu miroir diffère du flip ordinaire sur 246 pixels. La colonne destination zéro est hors texture ; la colonne source zéro de ce sprite est transparente. Il s'agit bien d'une confrontation au framebuffer exécuté, pas seulement de deux formules analytiques comparées entre elles.

## Frictions conservées

- Une première entrée dans le visualiseur depuis l'intérieur du callback VBlank n'a pas fourni un contexte valable pour sa boucle d'attente. Cet essai n'entre pas dans la preuve finale.
- Une entrée après 600 frames du titre produisait les bonnes tuiles et les bons objets, mais conservait BG0 du titre de priorité 0 devant les OBJ de priorité 2. Tous les pixels opaques du rectangle étaient différents. L'entrée retenue intervient avant le chargement du titre et ne nécessite aucun effacement graphique artificiel.
- Le quatrième octet du framebuffer ne pouvait pas servir d'alpha ; le code mGBA confirme les flags internes conservés dans cet octet.
- Une lecture des registres via le bus a été distinguée de leur stockage interne pour ne pas prendre une valeur open bus pour un état du fondu.
- Le SDL a créé un fichier `.sav` vide lors du sondage initial. Ce fichier a été déplacé sous le dossier privé ; aucune sauvegarde antérieure n'a été écrasée.

## Limites levées et restantes

**Levé dans ce témoin :** objets, couches, tas, cache, slots, constructeurs, décodeur copié en RAM, allocations/libérations, chargement palette, DMA matériel émulé, VBlank, mapping OBJ et renderer tournent dans mGBA à partir du code du jeu. Les shims LDM et DMA immédiats du banc Unicorn ne sont pas appliqués au cœur complet. Le banc demeure une référence indépendante dont les anciennes limites sont conservées dans ses rapports.

**Restant :** une entrée forcée par PC, un BIOS HLE plutôt que le BIOS Nintendo, le PPU logiciel de mGBA plutôt qu'une GBA physique, deux orientations d'une seule frame de SPR_000/animation 0/mode 0, et les ombres désactivées. L'accès naturel au visualiseur, les autres modes, la compression témoin et le fondu en transition ne sont pas validés par ce lot. Aucune équivalence générale du jeu n'en découle.

Tous les dumps, états et PNG restent dans `work/step31_private/` (0700, fichiers 0600), sans affichage dans la conversation ni publication. Les PNG PPU sont des rectangles de scène avec fond opaque, distincts des PNG RGBA analytiques transparents de l'étape 30. Aucun Ghidra ouvert ou modifié. Notion et mémoire restent du ressort de Claude, leur actualisation n'est pas attestée ici.

## Sources

- Sources du jeu déjà auditées : `work/repo/rom_c0/src/rom_2e00.s`, initialisation et BL à 0x08002ed8 ; `work/repo/rom_9000/src/rom_1219c.s`, Func_12518 ; `work/repo/rom_9000/src/exports.s`, export du visualiseur ; `external/alchemy/games/tbs/src/field/field.c:7078-7381`, contexte et commandes. Les correspondances externes préexistaient, elles ne constituent pas une découverte indépendante.
- [Interface mCore, version 0.10.5](https://github.com/mgba-emu/mgba/blob/0.10.5/include/mgba/core/core.h), fonctions d'exécution, mémoire et registres.
- [Cœur GBA, version 0.10.5](https://github.com/mgba-emu/mgba/blob/0.10.5/src/gba/core.c), `runFrame`, `step`, `setKeys`, `readRegister`/`writeRegister`, accès mémoire.
- [Conversions de couleurs, version 0.10.5](https://github.com/mgba-emu/mgba/blob/0.10.5/include/mgba/core/interface.h), `mColorFrom555`.
- [Framebuffer logiciel, version 0.10.5](https://github.com/mgba-emu/mgba/blob/0.10.5/src/gba/renderers/video-software.c#L646-L668), copie des mots RGB et flags vers le buffer ; [flags de composition](https://github.com/mgba-emu/mgba/blob/0.10.5/include/mgba/internal/gba/renderers/video-software.h).
