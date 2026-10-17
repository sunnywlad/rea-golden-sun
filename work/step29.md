# Étape 29 : SPR_000, du tampon vers VRAM, palette et miroir

Lot du 17 octobre 2026. Le banc poursuit l'étape 28 au-delà de son arrêt avant upload : tuiles VRAM, palette OBJ commune, placement affine, préparation OAM puis tranche du transfert VBlank. L'exemple est SPR_000, animation 0, direction `0x0000`, mode 0 ; `0x8000` est le témoin miroir de la même frame 1. Aucun jeu complet, écran ou Ghidra exécuté. Aucun nom/type importé.

## Résultat

- Le tampon de 32 × 32 indices est réorganisé en **seize tuiles de 8 × 8, un octet par pixel**, par la vraie routine ROM copiée en RAM. Les 1 024 octets transférés correspondent au modèle indépendant par coordonnées.
- Le système charge **224 entrées de palette OBJ communes**, de `0x0800779c` vers `0x05000200`. Cette frame en mode 0 utilise 42 indices non nuls distincts, tous couverts par cette palette, donc 42 couleurs brutes distinctes pour ses 258 pixels écrits.
- Le miroir ne change pas les tuiles. Le placement produit une **matrice affine Q8 `(-256, 0, 0, 256)`**, recopiée dans les emplacements de coefficients OAM. Le témoin sans miroir reste sans matrice à échelle unitaire et rotation nulle.
- Le générateur OAM s'exécute depuis sa copie RAM. Le transfert du tampon OAM vers `0x07000000` est contrôlé sur le code natif de sa tranche VBlank, avec DMA simulé. Les deux flags doivent autoriser ce transfert.
- Une direction qui conserve la même frame change le résultat miroir sans allouer, libérer ni uploader de nouveau tampon.

Le projet Ghidra conservé reste celui de l'étape 26 : `work/ghidra_thumb_special_pair_scoped/step9.gpr`, 2 593 fonctions, 2 223/2 253 entrées ROM reconnues, trente absentes. Les adresses RAM du banc ne sont pas des instances reconstruites dans ce projet.

## Sources et preuve

Script : [audit_sprite_upload.py](../scripts/audit_sprite_upload.py). Preuve : [step29_upload_verification.json](step29_upload_verification.json). Le script réutilise [audit_sprite_decode.py](../scripts/audit_sprite_decode.py) sans le modifier. Empreintes des sources et du script dans le JSON.

Relevés délégués : [palette](step29_palette_findings.md), [miroir et OAM](step29_mirror_findings.md). Revue indépendante : [step29_independent_review.md](step29_independent_review.md). Le présent rapport et la preuve native font foi sur les relevés statiques.

ROM privée identifiée par SHA1 `5c4695205413df7db52b9a184815a07783999971`. Alchemy conservé au commit `1517ff0750d988f570b6efcd06bf30d0f64c9d2a`, arbre propre. Aucun build, téléchargement ni changement des références externes. Les noms Alchemy décrivaient déjà ces routines ; leur contrôle sur notre ROM n'est pas une découverte indépendante du système.

## Initialisation et tuiles

`Func_bb20` (`ObjectSystem_Configure(2)` dans Alchemy) est exécuté entièrement. Les allocations de slots 3, 4 et 53 sont simulées ; ses instructions de mise à zéro, de chargement de palette et de préparation de l'uploader s'exécutent. Les écritures DMA3 sont interceptées et appliquées comme transferts mémoire immédiats : palette, effacement des deux pools, tuiles de l'ombre et copie de l'uploader.

Le slot 53 reçoit une copie des `0x7c` octets de `Func_a418`, ROM `0x0800a418..0x0800a493`. Le banc vérifie cette copie avant de l'exécuter. Sources : `work/repo/rom_9000/src/rom_b798.s:511-575`, `rom_92b8.s:546-580`, `external/alchemy/games/tbs/src/field/field.c:1087-1111`, `graphics/tile/convert_map.s:55-91`.

Le compositeur `Func_aa0c` s'exécute cette fois jusqu'à son retour. Après décodage il appelle le vrai cache `Func_3fa4(slot, 1024, 0)` et l'uploader RAM avec `(pixels, 32, 32, 0x06010000 + tile × 32)`. Il écrit l'index de tuile dans l'attribut 2 en conservant ses bits hauts, remet dirty à zéro et libère le tampon. Sources : `rom_a97c.s:750-815`, `work/repo/rom_c0/src/rom_3e58.s:184-260`, `field.c:428-444`.

Dans le cache synthétique du banc, les 64 premiers octets sont réservés au slot 94. L'initialisation place ensuite l'ombre dans les 128 octets suivants. Le sprite reçoit donc **tile 6, destination `0x060100c0`**, avec attribut 2 `0x0806`. Ce choix de cache n'est pas une adresse observée dans une partie. Les unités de l'index sont de 32 octets ; une tuile 8 bpp occupe 64 octets, donc 32 unités pour ce sprite de seize tuiles.

Pour tout pixel `(x,y)` de ce tampon, l'offset de sortie vérifié est :

`((y // 8) × 4 + x // 8) × 64 + (y % 8) × 8 + x % 8`.

Le code écrit exactement 256 mots de quatre octets couvrant les 1 024 octets attendus. Deux compositions natives isolées, directions `0x0000` et `0x8000`, donnent les mêmes empreintes :

| Tampon | SHA256 |
| --- | --- |
| Indices linéaires | `f01624f44bdb1e51b5deb68f5d73b17188c158e4fd9a2a9f2e19fd4f2e3798ae` |
| Tuiles VRAM | `6c873b8165bf02dd8ecc18244e54f4bbd1d16773f1fa3ab2851c03665d9c85a9` |

Huit motifs synthétiques supplémentaires confrontent directement l'uploader au modèle : 8 × 8, 16 × 8, 8 × 16, 16 × 16, 32 × 32, 64 × 32, 32 × 64 et 64 × 64. Les positions écrites et la garde après destination sont vérifiées. Cela ne couvre pas les dimensions non multiples de huit tronquées par le début de la routine.

## Palette effectivement chargée dans ce chemin

`Func_4838`, appelée par `Func_bb20`, programme DMA3 : source `0x0800779c`, destination `0x05000200`, contrôle `0x800000e0`. Ce sont 224 demi-mots, soit 448 octets, indices OBJ 0..223. Le banc confronte la destination à la ROM et contrôle que les entrées 224..255 conservent leur sentinelle antérieure. Source : `work/repo/rom_c0/src/rom_45e8.s:271-286`.

Le constructeur décrit par Alchemy utilise des objets 8 bpp et ne choisit pas de banque de seize couleurs par SPR (`field.c:1248-1256`, `rom_b798.s:779-810`). Le banc fournit un objet synthétique reproduisant le format carré 32 × 32, les ajustements `(0,2)` lus dans la métadonnée et la priorité OAM 2. Il n'exécute pas ce constructeur ni le chargement réel des répertoires de ressources.

Pour la frame 1 en mode 0 : 258 pixels non nuls, 766 positions transparentes après effacement, 42 indices non nuls distincts entre 10 et 222. Leurs 42 valeurs de palette sont distinctes. Le JSON conserve seulement une empreinte de leur correspondance RGBA analytique : canaux cinq bits étendus par `floor(canal × 255 / 31)`, alpha nul pour l'indice zéro. Aucune image, couleur littérale ni payload extrait n'est enregistré. Cette expansion est une convention de calcul, pas une simulation colorimétrique de l'écran GBA.

Le visualiseur fixe `DISPCNT = 0x1140` et appelle `Fade_FromBlack(1)` avant son initialisation (`field.c:7135-7147`). Cette configuration reste relevée statiquement ; le banc n'exécute pas DISPCNT ni le rendu PPU. Le fondu concerné passe par `BLDCNT/BLDY`, pas par un changement de palette brute (`work/repo/rom_c0/src/rom_3adc.s:4-66,97-123`). Il ne faut donc pas assimiler les couleurs brutes calculées aux couleurs finales affichées.

Le relevé auxiliaire compte 72 écritures d'indices hauts et treize écritures zéro si le mode 12 est appliqué à cette frame. Les entrées OBJ 224..255 ne sont pas déterminées par le chargement de base. Le lot natif ci-présent reste en mode 0 ; l'intention du mode 12 reste inconnue.

## Miroir et OAM

Le vrai `Func_b168` (`Render_ApplyProjectedPlacement`) est exécuté dans deux bancs neufs avec position synthétique `(144,0,96,0)` en Q16, échelles unitaires et rotation nulle. Les mots d'échelle du visualiseur à `0x08013584` sont vérifiés égaux à `(65536,65536)`. La position choisie sert à comparer les deux directions au même emplacement ; elle ne prétend pas reproduire deux positions du cercle du visualiseur.

L'objet de 32 × 32, ajustement vertical 2, est placé en `(128,66)`. Le retour miroir du compositeur est consommé par le placement :

| Direction | Frame | Attributs OAM 0, 1, 2 | Matrice Q8 |
| --- | ---: | --- | --- |
| `0x0000` | 1 | `0x2042`, `0x8080`, `0x0806` | aucune |
| `0x8000` | 1 | `0x2142`, `0x8080`, `0x0806` | `-256, 0, 0, 256` |

Le miroir utilise le mode affine de l'attribut 0 et l'index de matrice de l'attribut 1. `Func_3d28` reçoit l'effet `(-256,256,0)` et écrit la matrice à `0x03001d40` dans ce banc, compteur initial nul. Aucun flip logiciel du tampon ni choix d'une autre frame n'est nécessaire. Sources : `rom_b074.s:130-405`, `work/repo/rom_c0/src/rom_3d04.s:24-106`, `field.c:524-574`.

Après mise en liste par `Func_3dec`, le banc exécute `Func_3e10`. Ce wrapper alloue `0xe0` octets, y copie le code `Func_1dc8` par DMA3, exécute cette copie puis la libère. Le banc contrôle les octets copiés et l'entrée effective dans cette adresse RAM. Le générateur écrit les attributs dans un tampon synthétique à `0x02013000`, puis les coefficients de matrice aux offsets 6, 14, 22, 30. Sources : `rom_3d04.s:111-158`, `work/repo/rom_c0/src/rom_1b70.s:164-222`.

Le tampon est ensuite fourni dans le slot 52 et les flags de transfert sont posés par le banc. Les instructions `0x08003686..0x080036a7` de `Func_3650` sont exécutées, avec arrêt avant le transfert des registres BG. Elles programment la copie des 1 024 octets vers `0x07000000`, contrôle DMA3 `0x84000100`. Les deux flags à `0x03001e44` et `0x03001d18` sont aussi essayés dans les trois autres combinaisons : aucun transfert OAM. Source : `work/repo/rom_c0/src/rom_3650.s:29-45`.

La liaison complète de cette fonction au VBlank est établie statiquement dans le relevé miroir. Le banc n'installe pas l'IRQ, ne déclenche pas de véritable interruption et n'exécute pas le reste du gestionnaire. Le slot 52 est réaffecté après les compositions : le décodeur préchargé et le tampon OAM ne coexistent pas dans ce slot dans le banc.

## Protocole, limites et suite

Depuis la racine :

```sh
uv run --offline --no-project --with 'unicorn==2.1.4' python scripts/audit_sprite_upload.py work/step29_upload_verification.json
```

Les objets, couche, tas, cache initial, pointeur de décodeur et flags VBlank sont synthétiques. Les allocations/libérations et DMA3 immédiats sont simulés. Les trois adaptations de LDM non alignés de l'étape 28 restent actives, avec 74 interventions par composition de cette frame. Les transferts CPU de l'uploader et l'assembleur des attributs/matrices s'exécutent réellement dans Unicorn sur les octets ROM. Cela n'est pas une validation du bus GBA, du timing ou du matériel.

Aucun parcours du jeu complet, affichage, mapping PPU, fondu effectif, superposition de scènes ou accès commercial au visualiseur n'est établi. La preuve ne couvre ni les autres animations, ni l'affichage des seize modes, ni les conséquences du témoin compressé de l'étape 28. L'ombre est chargée par l'initialisation, mais le placement du témoin désactive son drapeau pour isoler l'image.

Le jalon VRAM/palette/miroir est atteint pour l'exemple borné. Prochain lot à choisir : validation en émulateur complet de l'état d'affichage et du visualiseur, ou reconstruction des instances RAM dans Ghidra avec les preuves déjà acquises. Les trente entrées manquantes et les enquêtes mode 12/témoin compressé restent séparées. Aucun prochain lot lancé.

Notion et les mémoires sont pris en charge par Claude Bridge. Les fichiers locaux font foi ; le statut de leur actualisation est indépendant de cette preuve technique.
