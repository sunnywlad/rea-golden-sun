# Étape 29 : relevé palette du visualiseur

Relevé du 17 octobre 2026, limité aux références locales fixées et à des comptages en lecture seule de la ROM privée. Aucun build, réseau, Ghidra, image ou payload extrait. Seul ce rapport est créé par cet agent. Le rapport principal et la preuve native de l'étape 29 prévalent sur ce relevé statique.

## Conclusion bornée

Le chemin d'initialisation du visualiseur charge une palette OBJ commune et fixe : 224 demi-mots de `0x0800779c` vers `0x05000200`. Les objets sont configurés en 8 bpp. La palette ne dépend ni du numéro de SPR ni de son animation dans ce chemin. Les 32 entrées OBJ `224..255` ne sont pas initialisées par cet appel. Le fondu demandé par le visualiseur passe par les registres de mélange matériel, sans réécrire les demi-mots de palette.

Cela suffit pour associer les indices de SPR_000/animation 0/direction 0x0000/mode 0 aux couleurs brutes de la palette chargée. Cela ne suffit pas à prouver l'image réellement affichée : le scheduler, le VBlank, les états antérieurs des registres et les autres écritures éventuelles du moteur entier ne sont pas exécutés ici.

## Palette choisie et étendue du DMA

1. `field.c:7141-7147` : le bloc `restart` du visualiseur appelle `ObjectSystem_Initialize(2)` après remise à zéro du scheduler et du cache VRAM.
2. `field.c:1455-1464` : `ObjectSystem_Initialize` appelle `ObjectSystem_Configure(controlMode)`.
3. `field.c:1087-1111` : `ObjectSystem_Configure` appelle `Palette_LoadBasicObjColors()` indépendamment de `mode`. L'équivalent natif `Func_bb20` appelle `Func_4838` à `work/repo/rom_9000/src/rom_b798.s:536-538`.
4. `work/repo/rom_c0/src/rom_45e8.s:271-279` : `Func_4838` place dans DMA3 la source `.L779c`, la destination `0x05000200` et le contrôle `0x800000e0`. Le bit de transfert 32 bits est absent : 224 transferts de 16 bits, soit `0x1c0` octets. Les adresses couvertes sont `0x05000200..0x050003bf`, donc indices OBJ `0..223`.
5. Même source, lignes 285-286 : `.L779c` est le bloc ROM `[0x779c,0x795c)`, exactement `0x1c0` octets. `Func_45e8` en retourne aussi l'adresse, lignes 4-7.

`external/alchemy/games/common/include/system/io_reg.h:65-70` distingue le backdrop/BG à `0x05000000` de la palette OBJ à `0x05000200`. `PLTT_BACKDROP = 0x01e0` dans `field.c:7137` ne change donc aucune entrée OBJ. Il ne faut pas présenter ce fond comme la couleur OBJ 0.

Les 32 entrées OBJ restantes occupent `0x050003c0..0x050003ff`. Leur contenu antérieur n'est pas établi par ce chemin. Il n'y a pas de preuve de mise à zéro de cette plage ici.

## 8 bpp et partage entre objets

`field.c:1248-1256` décrit et construit les deux parties de l'objet : image et ombre. Pour l'image, l'attribut 0 reçoit `shape | 0x2000`, l'attribut 2 `tile | 0x800`. L'ombre reçoit `0x6000` dans l'attribut 0. Les deux portent donc le bit de couleurs 256 (8 bpp), comme l'indique également le commentaire Alchemy. Il n'y a pas de sélection de banque de seize couleurs par SPR dans ce constructeur. Le paramètre de dessin modifie les **indices** avant upload ; il ne choisit pas un autre fichier de palette.

Les métadonnées de SPR_000 ne fournissent pas de palette à ce chemin. `ResourceSlot_Load` intervient après l'initialisation de la palette (`field.c:7146-7147`). Les quatre couches sont composées dans le même tampon d'indices ; elles ne disposent pas de quatre palettes OBJ autonomes.

Cette conclusion concerne les objets de ce système et ce visualiseur. Elle n'établit pas que tous les écrans et tous les moteurs de Golden Sun emploient cette seule palette.

## Écritures ultérieures et fondu

Le visualiseur initialise `REG_BLDCNT = 0x3f42`, le backdrop et `REG_DISPCNT = 0x1140`, puis appelle `Fade_FromBlack(1)` (`field.c:7135-7139`; natif `rom_1219c.s:500-527`).

`Fade_FromBlack` correspond à `Func_3bb4` dans ce point d'appel natif : `work/repo/rom_c0/src/rom_3adc.s:97-123` écrit des octets d'état et un masque `0x3e` dans l'état IWRAM, sans écrire en palette. Son actualiseur `Func_3adc` (même source, lignes 4-66) écrit `REG_BLDCNT` aux lignes 29-31 et `REG_BLDY` aux lignes 48-50. Ce fondu peut modifier la couleur affichée par le PPU tout en conservant la palette brute.

Le callback `Battle_PlaceActorsByFormationKind` (`field.c:7588-7643`) choisit pour le kind 5 huit angles espacés de `0x2000`, puis appelle `Render_ApplyProjectedPlacement`. Il ne charge ni ne transforme de palette. Le chemin de placement (`field.c:494-577`) appelle le compositeur, prépare la matrice affine et enfile les parties image/ombre. Le compositeur (`field.c:161-445`) décode, applique éventuellement le contour, transfère les indices et met à jour l'objet ; aucun de ces appels directs ne réécrit les couleurs OBJ.

Les drapeaux initiaux du visualiseur valent seulement `shadowsEnabled = 1`, recopié dans chaque objet (`field.c:7120`, `7170-7171`). Le contour du compositeur exige `obj->flags & 2` (`field.c:384-426`) : il n'est donc pas actif pour cet état initial. Le basculement de l'ombre dans la boucle du visualiseur reste entre 0 et 1 (`field.c:7224-7231`).

Il existe bien un autre mécanisme capable de réécrire toutes les palettes : `PaletteFade_Update` dans `graphics/palette/palette.c:649-687` enfile les DMA BG et OBJ aux lignes 684 et 686. Son initialisation (`PaletteFade_Init`, lignes 957-968) n'est pas appelée dans la chaîne directe du visualiseur examinée. Il ne faut pas confondre ce mécanisme avec `Fade_FromBlack`. Ce relevé n'est toutefois pas un audit exhaustif de tous les callbacks internes de `WaitFrames` et du VBlank.

## Comptages sur les octets privés, sans publication des couleurs

ROM vérifiée par SHA1 : `5c4695205413df7db52b9a184815a07783999971`. Les 448 octets de palette ont pour SHA256 `c0fdc449509d31d4df26babcfdfc2bdc4e08dafe550cbf71966c8b09d9883e7e`.

| Ensemble mesuré | Résultat |
| --- | ---: |
| Demi-mots chargés | 224 |
| Valeurs de demi-mot distinctes, palette entière | 223 |
| Valeurs distinctes aux indices 1..223 | 223 |
| Demi-mots dont le bit 15 vaut 1 | 0 |
| Frame 1, mode 0 : positions couvertes | 1024 |
| Frame 1, mode 0 : pixels écrits / positions sautées | 258 / 766 |
| Frame 1, mode 0 : indices distincts écrits | 42 |
| Frame 1, mode 0 : indice écrit minimal / maximal | 10 / 222 |
| Frame 1, mode 0 : couleurs BGR555 distinctes des pixels écrits | 42 |

Le format brut à trois canaux de cinq bits est cohérent avec `graphics/palette/palette.c:674-676`, `715-718` et `725-728` : bleu aux bits 10..14, vert aux bits 5..9, rouge aux bits 0..4. Aucune expansion en RGB888, correction gamma, simulation d'écran ou couleur littérale n'est publiée ici. Les 42 couleurs sont celles du **tampon décodé avant composition PPU**, pas un décompte de couleurs observées sur écran.

La limite 223 du flux de dessin est une limite du codec, pas celle d'un pixel 8 bpp. Les octets `224..255` sont des commandes de saut **à l'entrée du décodeur**. Une conversion peut néanmoins écrire ces mêmes nombres comme indices de sortie. La palette de base couvre tous les indices réellement écrits en mode 0 par cette frame.

Incidence bornée du mode 12 : appliqué à cette frame, il produit 72 écritures d'indices `224..255`, réparties entre cinq indices distincts, et treize écritures de zéro. Le chargement de base ne fixe pas les couleurs des cinq indices hauts. Il n'est donc pas possible de déduire leur couleur effective à partir de cette seule palette. Ce comptage complète le constat de l'étape 28 sans établir l'usage voulu du mode 12.

## Reproduction des comptages

Lecture directe, sans exécution du jeu : lire la ROM privée, vérifier son SHA1, dépaqueter `rom[0x779c:0x795c]` par `struct.unpack('<224H', ...)`, compter les valeurs et leur masque `0x7fff`. Pour la frame 1, parcourir depuis `0x18d6ad` jusqu'au premier zéro : un octet `1..223` écrit son indice ; un octet `224..255` avance de `octet - 223` positions. Le comptage obtient une étendue de 1024 et 258 écritures. Les 42 valeurs distinctes d'indices sont toutes dans la plage chargée. Le mode 12 remplace chaque indice d'entrée par `rom[0x9bb8 + indice]` avant le comptage. Aucun octet de ces tableaux ou flux ne doit être exporté.

Tous les chemins de sources abrégés `field.c` se rapportent à `external/alchemy/games/tbs/src/field/field.c`, commit conservé `1517ff0750d988f570b6efcd06bf30d0f64c9d2a`. Les fichiers externes ont été consultés sans modification. Le script reproductible et les assertions natives du principal doivent confirmer les constantes et comptages retenus dans le rapport final.
