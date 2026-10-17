# Étape 32 : revue indépendante de la référence HTML5

**Avis favorable pour une comparaison statique bornée.** Le moteur HTML5 du commit `b8b086dc4a15025778acd1ce861c4ef7d6fda426` est une réécriture Phaser CE 2.19.0. Ses sources établissent des animations par noms de frames d'atlas, huit directions nommées, des filtres RGB sur texture et un retournement horizontal de sprite en combat. Elles ne prouvent aucune correspondance de pixels, de palette ou de chronologie avec SPR_000 dans la ROM.

## Contrôles indépendants

- `python3 scripts/audit_html5_reference.py /tmp/step32-independent-replay.json` reproduit `work/step32_html5_verification.json` à l'octet. SHA256 commun : `72b7590b6c6b1cffe6541054256bfe55c3c4546a03a62211506b5131a81120f9`.
- J'ai comparé séparément les identifiants de l'arbre Git à la liste locale de `git cat-file --batch-all-objects`, avec `GIT_NO_LAZY_FETCH=1`. L'arbre compte 626 blobs : 259 présents et 367 absents. Parmi les présents : 232 sous `base/`, 16 sous `assets/filters/`, 5 sous `types/` et 6 fichiers racine. Aucun média, atlas JSON ou base de données du jeu n'est présent. Les seuls JSON locaux détectés sont les configurations `package.json` et `tsconfig.json`. `assets/filters/` contient des sources JavaScript et GLSL. Le dépôt est propre, au commit annoncé, avec filtre `blob:none`.
- `base/SpriteBase.ts:134-201` charge un couple image/JSON via `atlasJSONHash`, génère des noms de frames puis enregistre des animations avec leurs fréquences. `base/initializers/npcs.ts:20-26` fournit nombres de frames et fréquences à cette classe. `base/utils.ts:49-70` définit huit noms de direction ; `base/ControllableChar.ts:1501-1509` en sélectionne un pour l'animation. Aucune de ces lignes ne donne une correspondance avec les identifiants, scripts ou directions de la ROM.
- `base/battle/BattleStage.ts:597-618` remet d'abord l'échelle du sprite à `(scale, scale)`, puis rend l'axe X négatif si `cos(relative_angle) <= 0`. Le test inverse à `:613-615` est sans effet sur l'échelle après cette remise à zéro. Il s'agit d'un miroir de scène de combat, pas d'une preuve de la convention GBA `32 − x`.
- `assets/filters/tint.js:18-22` lit une texture et écrit des canaux RGB, avec conservation du canal source si l'uniforme vaut `-1`. La palette OBJ BGR555 et ses 224 entrées proviennent des étapes 29 et 30, pas de ce filtre.

## Portée comparative

Les étapes 28 et 29 établissent la frame 1, les seize tuiles et la palette chargées par le chemin natif isolé. L'étape 30 reconstruit les couleurs depuis cette palette. L'étape 31 confronte deux directions de SPR_000 au PPU logiciel mGBA : `0x0000` et `0x8000`, matrice miroir Q8 `[-256,0,0,256]`, zéro écart sur 1 024 pixels par cas, contre 246 écarts pour un simple flip `31 − x` dans le cas miroir (`work/step31_ppu_verification.json`). Cette preuve reste circonscrite au banc et au rendu mGBA. Aucun test Phaser ne tranche `31 − x` contre `32 − x`.

## Point de formulation

`work/step32_html5_findings.md:25` a été corrigé : `BattleStage.ts:604` réinitialise l'échelle positive, puis `:613-618` inverse `scale.x` lorsque `cos(relative_angle) <= 0`. La branche positive ne change rien après cette réinitialisation. Cette formulation correspond au code et ne modifie pas la conclusion comparative.

Revue en lecture seule des références externes. Aucun build, aucune dépendance installée, aucune exécution JavaScript, aucun sous-module initialisé, aucun Ghidra lancé. La revue ne valide pas les données absentes de l'atlas ni le rendu Phaser.
