# Étape 32 : référence comparative Golden Sun HTML5

**Le dépôt HTML5 fournit une architecture de comparaison, pas une nouvelle preuve sur la ROM.** Ses sprites utilisent des atlas image/JSON, ses animations des noms et cadences Phaser, et son miroir de combat une échelle X négative. Aucune identité avec les seize tuiles, la palette OBJ de 224 entrées ou le centrage GBA `32-x` n'est établie par ce code.

Le clone demandé est propre, figé à **b8b086dc4a15025778acd1ce861c4ef7d6fda426**, branche master, depuis [jjppof/goldensun_html5](https://github.com/jjppof/goldensun_html5/tree/b8b086dc4a15025778acd1ce861c4ef7d6fda426). Relevé Luna/low : [step32_html5_findings.md](step32_html5_findings.md). Preuve statique : [step32_html5_verification.json](step32_html5_verification.json). [Revue indépendante favorable Sol/medium](step32_independent_review.md), JSON reproduit à l'octet, SHA256 `72b7590b6c6b1cffe6541054256bfe55c3c4546a03a62211506b5131a81120f9`.

## Périmètre du clone

```sh
git clone --depth 1 --filter=blob:none --no-checkout https://github.com/jjppof/goldensun_html5.git external/goldensun_html5
```

Sélection sparse non-cone : `base/`, `types/`, `assets/filters/`, et les fichiers racine `LICENSE.txt`, `README.md`, `package.json`, `tsconfig.json`, `.gitattributes`, `.gitignore`. `assets/filters/` contient exclusivement du code JavaScript/GLSL de filtres ; il ne s'agit pas de médias extraits. Les atlas JSON, bases de contenu, images, fontes et sons du jeu sont exclus.

La preuve ne se limite pas aux fichiers visibles : elle énumère les objets effectivement présents avec `git cat-file --batch-all-objects`, puis les confronte aux chemins de l'arbre Git. Sur **626 fichiers suivis**, **259 blobs source/documentation sont présents**, **367 restent absents**. Aucun blob présent ne correspond à un chemin exclu. Les octets de chacun des fichiers présents retrouvent leur identifiant blob Git ; le manifeste SHA256 permet une seconde vérification.

Une première vérification `git status` a tenté de récupérer des règles Git manquantes, puis a échoué faute de réseau. `.gitattributes` et `.gitignore` ont été inclus explicitement pour rendre le contrôle local reproductible. Le premier appel `sparse-checkout add --no-cone` a aussi été refusé par Git : le mode s'applique à `set/init`, `add` reprend le mode courant. Après correction, le clone est propre. Le script de preuve désactive la récupération paresseuse des blobs avec `GIT_NO_LAZY_FETCH=1`.

Aucun build, `npm install`, exécution du moteur, sous-module ou installation de dépendance. Les clones Alchemy et Game Tools Collection conservent leurs révisions et sélections. [external_references.json](external_references.json) et [external/README.md](../external/README.md) consignent la troisième référence.

## Licence et règles lues

Le [LICENSE.txt figé](https://github.com/jjppof/goldensun_html5/blob/b8b086dc4a15025778acd1ce861c4ef7d6fda426/LICENSE.txt) porte la licence MIT et le copyright 2020 Joao Paulo Oliveira Fernandes. Le texte autorise utilisation, copie, modification, publication, redistribution et sous-licence du logiciel, sous conservation de la notice de copyright et de permission dans les copies ou parties substantielles ; il exclut la garantie. Le [README, lignes 55–56](https://github.com/jjppof/goldensun_html5/blob/b8b086dc4a15025778acd1ce861c4ef7d6fda426/README.md#L55-L56) réserve séparément les médias Golden Sun à Nintendo/Camelot. La licence du moteur n'est pas une permission de redistribuer les médias du jeu.

Aucun fichier AGENTS.md, CLAUDE.md ou CONTRIBUTING dans l'arbre de cette révision. README et règles `.gitattributes` lus. Le [wiki développeurs](https://github.com/jjppof/goldensun_html5/wiki/Introduction-for-developers#some-coding-guidelines), consulté le 17 octobre 2026, demande notamment du typage TS, des enums pour les états internes, des noms explicites, et le formatage avant une contribution. Ces règles concernent le développement du moteur ; aucun fichier suivi du clone n'a été modifié. La page wiki n'est pas figée par le commit du dépôt et ne sert pas de donnée reproductible dans la comparaison.

## Architecture utile

Le README décrit un moteur semblable à Golden Sun, sans viser une identité exacte, sur **Phaser CE 2.19.0**. Le code principal est TypeScript, avec des shaders JavaScript et du JavaScript historique ; qualifier tout le dépôt de simple moteur JavaScript serait incomplet.

- `base/GoldenSun.ts:155-173,189-197,240-244,588-631` crée le jeu WebGL, initialise les bases/classes puis met à jour héros, carte, combat et caméra. L'antialiasing est coupé, les coordonnées de rendu sont arrondies. `base/magic_numbers.ts:1-3` fixe le viewport 240 × 160 et une cadence cible de 60 FPS. Ce viewport concorde avec le format de capture mGBA, sans prouver un timing matériel identique.
- `base/initializers/assets_loader.ts:10-36` nomme les bases de contenu ; `base/initializers/npcs.ts:11-27` transforme les champs de configuration en `SpriteBase`. Les fichiers de contenu eux-mêmes restent exclus.
- `base/SpriteBase.ts:104-109,134-149` associe une image et un JSON à une action puis utilise `atlasJSONHash`. `:152-199` génère les noms de frames, de zéro à `frames_count-1`, et les inscrit dans le gestionnaire d'animations avec leur cadence et leur bouclage.
- `base/ControllableChar.ts:588-604,1501-1509` règle ancrage/position/échelle et sélectionne l'animation à partir de la direction nommée. `base/battle/PlayerSprite.ts:272-295` construit séparément les sprites de personnage/ombre et leurs filtres ; `base/battle/BattleStage.ts:593-618` règle orientation et échelle du combat.

## Confrontation aux étapes 28 à 31

| Sujet | Preuve ROM et mGBA | Référence HTML5 | Conclusion |
|---|---|---|---|
| Image et tuiles | SPR_000 frame 1 : 32 × 32 indices, seize tuiles 8 × 8 en 8 bpp, upload natif vers OBJ VRAM | Atlas image + JSON et frames nommées ; pas de dimension fixe du témoin identifiée dans les sources seules | Représentation différente. Les tuiles de carte de `Map.ts` ne prouvent rien sur les seize tuiles OBJ. Aucun pixel ou atlas téléchargé pour comparer. |
| Palette | 224 entrées OBJ BGR555 effectivement chargées, indice 0 transparent, 42 couleurs opaques pour ce témoin | Texture échantillonnée en RGBA et opérations de filtres RGB ; exemples de couleurs de menu dans le code | Pas de correspondance démontrée avec la palette OBJ commune. Une couleur RGB de menu ou un effet tint n'est pas une entrée identifiée de cette palette. |
| Animation | Script ROM, animation 0, frame identifiée 1 par le banc ; données identiques en VRAM mGBA | Noms `action/animation/NN`, nombre de frames, cadence et bouclage fournis par les bases de contenu | Concept commun, format et identifiants différents. Une frame d'atlas numérotée 0 ne signifie pas automatiquement la frame ROM 0 ou 1. Cadences et ordre du témoin inconnus. |
| Directions | Angle natif sur 16 bits ; témoins 0 et 0x8000, sélection propre aux métadonnées du sprite | Enum à huit valeurs : right=0, down_right=1, down=2, down_left=3, left=4, up_left=5, up=6, up_right=7 ; angles en radians | Correspondance conceptuelle seulement. Aucun appariement exact des noms, axes/origines et slots SPR_000 prouvé. |
| Miroir | OAM affine Q8 (-256,0,0,256) ; `32-x` observé dans mGBA, `31-x` faux sur 246 pixels | En combat, `scale.x` devient négative lorsque `cos(relative_angle) <= 0` ; ancrage personnage (0.5,1) | Même intention de miroir horizontal. Aucun Q8/OAM ni centrage discret GBA établi côté Phaser. Le raster HTML5 n'a pas été exécuté. |

Le miroir du combat se lit explicitement dans [BattleStage.ts:613-617](https://github.com/jjppof/goldensun_html5/blob/b8b086dc4a15025778acd1ce861c4ef7d6fda426/base/battle/BattleStage.ts#L613-L617), avec l'ancrage dans [PlayerSprite.ts:277](https://github.com/jjppof/goldensun_html5/blob/b8b086dc4a15025778acd1ce861c4ef7d6fda426/base/battle/PlayerSprite.ts#L277). Le chemin de champ examiné choisit des animations distinctes par nom dans [ControllableChar.ts:1501-1509](https://github.com/jjppof/goldensun_html5/blob/b8b086dc4a15025778acd1ce861c4ef7d6fda426/base/ControllableChar.ts#L1501-L1509) et [utils.ts:48-81](https://github.com/jjppof/goldensun_html5/blob/b8b086dc4a15025778acd1ce861c4ef7d6fda426/base/utils.ts#L48-L81). Ces deux mécanismes ne doivent pas être confondus.

Le filtre [tint.js:18-22](https://github.com/jjppof/goldensun_html5/blob/b8b086dc4a15025778acd1ce861c4ef7d6fda426/assets/filters/tint.js#L18-L22) remplace ou conserve des composantes RGB de la texture selon les uniformes ; ce n'est pas une recherche dans la palette BGR555 à 224 entrées. `pixel_shift.js:25-36` décale des coordonnées UV : son nom ne démontre pas une compensation d'un pixel du miroir GBA.

Le commentaire historique de `base/battle/BattleAnimation.ts:1-40` décrit une extraction à partir d'une MFT et cite `gs2mapcodecompressor`, des tailles de palette 0x80/0x20 et des manipulations de pointeurs. C'est une note d'extraction, pas le code d'un chargeur de palette OBJ GS1 ni une validation du banc. Ses valeurs et sa pertinence exacte pour cette ROM ne sont pas adoptées ; aucun outil ou procédé d'extraction décrit dans ce commentaire n'a été exécuté.

## Preuve et arrêt

```sh
python3 scripts/audit_html5_reference.py work/step32_html5_verification.json
```

Le script n'importe ni n'exécute le code TypeScript/JavaScript. Il contrôle commit/origine/sparse/propreté, objets Git présents, identifiants des blobs et SHA256 des sources, puis relève les constantes et emplacements de code examinés. Il reconfronte les résumés aux preuves conservées des étapes 28 à 31. Les ancres sont des contrôles textuels de provenance ; elles ne démontrent pas à elles seules la sémantique de l'exécution. Les conclusions restent bornées aux chemins lus.

Aucun nom ou type importé dans Ghidra, resté fermé. Aucun média récupéré, montré ou publié. Aucun lot suivant lancé. Le **lot 33 est prévu dans CLEAR_HANDOFF.md mais attend l'ordre de Wladimir après le prochain `/clear`** : archive vérifiée des anciens projets Ghidra et index SQLite régénérable, sans suppression prématurée ni modification du projet retenu. Notion et mémoire restent à Claude.
