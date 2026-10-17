# Étape 30 : reconstruction RGB locale et contrôle du miroir

Lot du 17 octobre 2026, SPR_000, animation 0, frame 1, mode 0, directions `0x0000` et `0x8000`. Deux PNG RGBA de 32 × 32 sont produits uniquement en local dans `work/step30_private/` (dossier 0700, fichiers 0600). Ils ne sont ni affichés dans la conversation ni publiés. Aucun Ghidra, émulateur ou jeu lancé, aucune installation.

## Résultat

Les seize tuiles natives de 64 octets, relues dans la VRAM simulée du banc, redonnent exactement les 1 024 indices du tampon natif de l'étape 28. La palette de 224 entrées est relue dans la mémoire OBJ du banc après son initialisation native. Les empreintes de ces deux entrées concordent avec l'étape 29. Le banc de l'étape 28 est réexécuté séparément pour chacun des deux témoins.

Après transformation correspondant à chaque direction, la comparaison complète des indices puis des pixels RGBA avec cette référence donne **zéro différence** dans les deux cas. Chaque image contient **258 pixels opaques, 42 couleurs opaques distinctes et 766 pixels transparents**. L'indice zéro porte alpha zéro ; les autres portent alpha 255.

Cette égalité ne signifie pas que l'image miroir soit identique au tampon non transformé. Avant transformation, les indices détuillés sont égaux au tampon de l'étape 28 dans les deux directions. Pour la direction miroir, la référence reçoit ensuite une transformation indépendante par projection des pixels source ; le chemin VRAM utilise un échantillonnage inverse par matrice.

## Couleurs et discrétisation du miroir

Pour le mot couleur BGR555 lu en petit-boutiste : rouge = bits 0..4, vert = bits 5..9, bleu = bits 10..14. Chaque canal est étendu par `floor(canal5 × 255 / 31)`. C'est une convention RGB analytique, sans correction d'écran LCD. Les valeurs RGB masquées par alpha zéro sont conservées ; elles ne participent pas au comptage des couleurs opaques. L'empreinte RGBA sans miroir retrouve celle de l'étape 29.

Le cas sans miroir est non affine dans OAM. L'identité Q8 sert uniquement à reconstruire son rectangle local. Le cas miroir utilise les coefficients effectivement produits dans OAM : `(-256,0,0,256)`.

L'échantillonnage inverse est centré en `(16,16)`, sans double taille. Pour le miroir horizontal, il donne `source_x = 32 − destination_x`. La première colonne de destination se trouve hors texture et devient transparente. La colonne source zéro est écartée ; elle est entièrement transparente dans cet exemple, ce qui préserve les 258 pixels opaques.

Un retournement ordinaire `source_x = 31 − destination_x` diffère sur **246 positions**. Le miroir affine reconstruit équivaut ici à ce retournement décalé d'un pixel à droite. Le calcul ne doit pas être remplacé silencieusement par un simple renversement de lignes.

Cette convention est dérivée du [renderer logiciel mGBA](https://github.com/mgba-emu/mgba/blob/master/src/gba/renderers/software-obj.c), initialisation des accumulateurs aux lignes 221–222 et incrément avant lecture aux lignes 30–34, branche `master` consultée le 17 octobre 2026. Elle reste un modèle analytique, aucune comparaison au PPU exécuté ou au matériel n'a été réalisée. Le relevé auxiliaire ne fige pas un commit mGBA.

## Preuve et reproduction

Script : [audit_sprite_rgb.py](../scripts/audit_sprite_rgb.py). Preuve sans payload : [step30_rgb_verification.json](step30_rgb_verification.json). Relevé local : [step30_emulator_findings.md](step30_emulator_findings.md). [Revue indépendante favorable](step30_independent_review.md) : JSON reproduit à l'octet, SHA256 `8f1d0555c6ea4d44d52daa2d3fbdbd4d9b18f9f04ad99a9f4a7c52675410eda6`. Un vérificateur distinct a relu les tuiles et la palette, puis contrôlé les CRC, la décompression et les 4 096 octets RGBA de chaque PNG.

Depuis la racine :

```sh
uv run --offline --no-project --with unicorn==2.1.4 python scripts/audit_sprite_rgb.py work/step30_rgb_verification.json
```

Le second argument facultatif après le JSON choisit le dossier privé des PNG. Ce chemin ne figure pas dans la preuve, qui reste comparable à l'octet lors d'une reproduction dans `/tmp`. Les noms, dimensions, tailles et empreintes PNG sont consignés, jamais leurs octets. Le script utilise la bibliothèque standard pour encoder le PNG RGBA, sans dépendance d'image ajoutée. Les scripts des étapes 28 et 29 restent inchangés.

La preuve vérifie aussi les attributs et matrices OAM contre ceux de l'étape 29, le décompte des pixels, le décalage par rapport au flip ordinaire, les empreintes du tampon natif et des tuiles, ainsi que l'identité des trois scripts et des JSON amont. La reproduction exige la ROM privée de SHA1 `5c4695205413df7db52b9a184815a07783999971` et Unicorn déjà en cache.

## Émulateur et validation restante

Aucun émulateur GBA n'a été détecté parmi les exécutables et paquets vérifiés, notamment mGBA. Le périmètre et la disponibilité de chaque inventaire sont détaillés dans le relevé auxiliaire. Cela n'exclut pas un binaire manuel hors PATH ou sous un autre nom. Aucune installation n'est autorisée dans ce lot.

Pour contrôler le rendu dans un PPU émulé, il faut un émulateur disponible et un état de sauvegarde, ou une séquence d'entrées reproductible, qui atteigne réellement SPR_000/frame 1 et les deux orientations. Il faut alors capturer, au même instant, les dumps privés VRAM, palette OBJ, OAM et registres d'affichage : DISPCNT, mélange/fondu, fenêtres et mosaïque s'ils interviennent. Les adresses et l'index de tuile du banc sont synthétiques : comparer les données et attributs normalisés, sans exiger les mêmes pointeurs ou le même slot OAM en jeu.

La comparaison attendue porte sur les seize tuiles, la palette effectivement active, la taille et le mode OBJ, le mapping 1D/2D et la matrice, puis sur le rectangle affiché en tenant compte du centre affine et des effets de scène. Un état fabriqué en injectant ces données dans un PPU validerait le modèle d'affichage, mais ne prouverait pas que le jeu commercial construit ces objets ou permet l'accès au visualiseur. Un émulateur est utile pour cette étape ; sa seule présence ne supprime pas les objets synthétiques du banc actuel. Le matériel GBA demanderait une validation distincte.

## Limites et arrêt

Objets, couche, tas, cache, slots et flags VBlank restent synthétiques ; DMA3 immédiat simulé et trois corrections LDM héritées. Mapping des tuiles OBJ 1D supposé pour la reconstruction, sans exécution DISPCNT. Pas de PPU, bus GBA, fondu, mélange de scènes, correction LCD, jeu complet ou accès au visualiseur observé. Les couleurs obtenues ne sont pas des couleurs finales mesurées à l'écran.

Le lot se termine à la reconstruction locale et à sa revue. Aucun lot suivant lancé. Mode 12, témoin compressé, reconstruction RAM Ghidra et accès commercial au visualiseur restent distincts. Notion et la mémoire relèvent de Claude ; leur actualisation ne découle pas de ce rapport.
