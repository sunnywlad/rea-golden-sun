# Étape 32 — relevé statique du moteur Golden Sun HTML5

## Périmètre et provenance

- Référence locale : `external/goldensun_html5`, HEAD `b8b086dc4a15025778acd1ce861c4ef7d6fda426`.
- `README.md:5,9-11,21` décrit un moteur HTML5 Phaser CE 2.19, destiné à produire un jeu « GS-like », et non à reproduire exactement le moteur original. Le code annonce TypeScript et un bundle Webpack.
- Licence source : `LICENSE.txt:1-6`, MIT, copyright Joao Paulo Oliveira Fernandes (2020).
- Relevé fondé sur les sources déjà présentes, sans build, lancement, téléchargement, ni accès à des données d’assets de jeu.

## Architecture observée

- `base/SpriteBase.ts:4-8` présente `SpriteBase` comme dépositaire des informations spritesheet, animations, actions et de méthodes qui les génèrent.
- `base/SpriteBase.ts:104-109` associe à une action les URL d’une image de spritesheet et d’un JSON.
- `base/SpriteBase.ts:134-149` charge ces ressources par `game.load.atlasJSONHash`.
- `base/SpriteBase.ts:41-61` associe à chaque action une liste d’animations et un ou plusieurs nombres de frames; `:64-98` associe une fréquence à chaque animation. `:152-160,162-187,193-201` génère les noms de frames, enregistre les animations et produit les séquences de frames. Le code permet ainsi des animations de champ par direction sous forme de séquences de frames séparées.
- `base/ControllableChar.ts:1501-1509` stocke une direction numérique, la convertit en nom d’animation, puis peut jouer l’action courante.
- `base/utils.ts:48-70` définit huit directions et leur associe des clés d’animation (`right`, `down_right`, etc.). Cette représentation est un index de direction / nom de frame, pas un champ direction GBA observé ici.

## Couleur, palette et transformation

- `base/ControllableChar.ts:159-170,272-276` garde des filtres Phaser, dont Colorize, Levels, ColorBlend, Hue, Tint et Gray.
- `base/ControllableChar.ts:1420-1444` applique temporairement un tint RGB à un sprite, puis remet les trois composantes à `-1` pour restaurer les composantes source.
- `assets/filters/tint.js:4-6,17-23` définit les uniformes rouge, vert et bleu. Chaque composante choisie remplace la composante source par `alpha * composante`; une composante à `-1` conserve la composante source. C’est un traitement RGB sur texture, pas une table de couleurs indexées/palette matérielle dans ces lignes.
- `base/battle/PlayerSprite.ts:276-295` crée le sprite de personnage et lui associe plusieurs filtres disponibles, notamment Tint et Colorize. `:276-278` fixe l’ancrage du personnage à `(0.5, 1)` et son échelle initiale. `:189-194` expose aussi le tint natif Phaser.
- Mécanisme de miroir explicite en combat : `base/battle/BattleStage.ts:604` réinitialise l'échelle positive, puis `:613-618` inverse `scale.x` lorsque `cos(relative_angle) <= 0`. La branche positive ne change plus rien après cette réinitialisation. Cela établit un flip horizontal de sprite dans cette scène de combat. Le miroir dépend de la position relative et constitue un mécanisme distinct du choix des huit animations de champ (`base/utils.ts:48-70`, `base/ControllableChar.ts:1501-1509`).
- Aucune preuve dans les fichiers cités ne décrit les 224 couleurs de l’objet REA, des indices de palette par pixel, ou une matrice affine Q8 de sprite GBA.

## Comparaison avec les étapes 30 et 31

- **Concordance conceptuelle, limitée :** les deux systèmes ont une notion de sprite dirigé et de modification colorimétrique. HTML5 choisit des animations nommées par direction (`base/utils.ts:48-70`, `base/ControllableChar.ts:1501-1509`), et dispose séparément d’un flip de combat par échelle négative (`base/battle/BattleStage.ts:613-618`). REA observe les orientations `0x0` et `0x8000` dans `work/step31_ppu_verification.json`.
- **Différence de représentation :** REA documente une image de 32×32 pixels, 16 tuiles, 224 entrées de palette et une matrice Q8 `[-256, 0, 0, 256]` pour le cas `0x8000` (`work/step30_rgb_verification.json`, cas correspondants; `work/step31_ppu_verification.json`, cas `0x0` et `0x8000`). HTML5 décrit des frames d’atlas et des noms d’animation; son filtre Tint agit sur les composantes RGB de texture. Les sources montrent un flip horizontal en combat, mais ne l’associent pas au champ GBA `0x8000`. Il n’est donc pas établi qu’il reproduise le décalage de miroir `32-x` mesuré en étape 31, ni le raster des pixels.
- **Inconnue des pixels :** les sources disponibles ne démontrent ni identité, ni différence, pixel par pixel, avec le rendu REA/PPU. Aucun rendu exécuté ne permet d’attribuer à Phaser le comportement de miroir pixel `31-x` ou `32-x`. Le relevé ne calcule pas et ne valide pas le raster Phaser. Les résultats REA de l’étape 31 confirment le rendu mGBA pour les deux cas visés; ils ne valident pas le rendu HTML5.

## Références REA utilisées

- `work/step30_rgb_verification.json`: format BGR555 et expansion analytique (`color_format`, `channel_expansion`); cas de frame 1 mode 0, 32×32, 16 tuiles, 224 entrées de palette, matrice identité puis miroir Q8.
- `work/step31_ppu_verification.json`: cas `0x0` et `0x8000`, matrice identité et `[-256,0,0,256]`; concordance RGB PPU / référence avec zéro mismatch pour ces cas (`opaque_pixel_mismatches: 0`, `all_1024_pixel_mismatches: 0`).
- Portée explicitement limitée à deux orientations SPR_000 (`0x0` et `0x8000`), frame 1, mode 0, et au PPU logiciel mGBA selon `step31_ppu_verification.json: limits`.
- Note historique : le commentaire de `base/battle/BattleAnimation.ts:1-16` donne une procédure d’extraction des graphismes depuis MFT et évoque des tailles de palette de `0x80`/`0x20` octets pour les formats 8/4 bits. C’est une note d’extraction concernant GS2, pas une validation de la palette OBJ 224 couleurs de Golden Sun 1 observée par REA.
