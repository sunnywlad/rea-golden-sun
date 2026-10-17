# Étape 30, revue indépendante

Verdict favorable pour la **reconstruction RGBA analytique privée** de SPR_000, animation 0, frame 1, mode 0, directions `0x0000` et `0x8000`. Le contrôle porte sur les données natives du banc isolé et sur les deux PNG produits localement. Il ne valide pas un affichage PPU ou matériel.

## Reproduction et empreintes

Commande exécutée depuis la racine du projet, sans réseau ni installation :

```sh
uv run --offline --no-project --with 'unicorn==2.1.4' python scripts/audit_sprite_rgb.py /tmp/step30_review.json /tmp/step30_review_private
```

`/tmp/step30_review.json` est **identique à l'octet** à [step30_rgb_verification.json](step30_rgb_verification.json), SHA256 commun `8f1d0555c6ea4d44d52daa2d3fbdbd4d9b18f9f04ad99a9f4a7c52675410eda6`. Les deux PNG privés reproduits ont les empreintes SHA256 `53e4232dbb18b7d254c18b1bb5cfed222912d8cdc066932149644287f170581f` (direction `0x0000`, 488 octets) et `4d3058e2b81b9c43be65008c2391bffb92180ba7818660c72d0fe1d5672ccfb4` (direction `0x8000`, 478 octets). Les empreintes correspondent au JSON. Le dossier privé est en mode 0700 et les PNG en 0600. Aucun PNG n'a été ouvert visuellement ni publié.

## Contrôles distincts

Un vérificateur temporaire situé dans `/tmp/step30_review_check.py` a relancé le compositeur de l'étape 28 et le chemin natif de l'étape 29 pour chaque direction. Il a relu directement les 1 024 octets de tuiles en VRAM simulée et les 448 octets de palette en RAM OBJ. La palette OBJ égale octet par octet les 224 mots little-endian de la ROM à l'offset `0x779c`. Une boucle distincte par tuile, ligne et colonne reconstitue exactement le tampon de l'étape 28, SHA256 `f01624f44bdb1e51b5deb68f5d73b17188c158e4fd9a2a9f2e19fd4f2e3798ae`. Les tuiles ont dans les deux cas le SHA256 `6c873b8165bf02dd8ecc18244e54f4bbd1d16773f1fa3ab2851c03665d9c85a9` ; la palette, `c0fdc449509d31d4df26babcfdfc2bdc4e08dafe550cbf71966c8b09d9883e7e`.

Le vérificateur a parsé les PNG sans employer l'encodeur du script principal : signature, ordre et longueur des chunks `IHDR`, `IDAT`, `IEND`, CRC de chaque chunk, dimensions 32 × 32, profondeur 8 bits, type RGBA 6, zlib complet et 32 filtres de scanline égaux à zéro. Il a reconstruit séparément les canaux depuis les mots BGR555 et comparé **les 4 096 octets RGBA décodés** à ceux des PNG. Les deux comparaisons réussissent. Pour chaque direction : 258 indices non nuls et pixels opaques, 42 mots couleur distincts parmi ces indices, 766 pixels alpha zéro. Les indices zéro conservent leurs canaux RGB masqués, conformément au JSON.

La projection du miroir a été recalculée avec `source_x = 32 - destination_x`, source hors limites remplacée par l'indice zéro. Elle produit 32 échantillons hors texture, une colonne de destination transparente et zéro différence d'indice ou de pixel RGBA avec le PNG miroir. Le retournement ordinaire `source_x = 31 - destination_x` diffère sur 246 positions. La colonne source zéro est entièrement transparente dans ce seul témoin, ce qui conserve le nombre de pixels opaques. La matrice `(-256, 0, 0, 256)` vient du placement/OAM natif de l'étape 29. La convention de centre entier est confirmée par le code primaire du [renderer logiciel mGBA](https://github.com/mgba-emu/mgba/blob/master/src/gba/renderers/software-obj.c#L194-L222), dont la [boucle incrémente avant lecture](https://github.com/mgba-emu/mgba/blob/master/src/gba/renderers/software-obj.c#L26-L42). La branche `master` consultée n'est pas fixée à un commit.

J'ai relu [step30.md](step30.md) et le [relevé émulateur](step30_emulator_findings.md). Leurs conclusions techniques concordent avec ces contrôles. L'inventaire Snap a expiré et demeure indisponible ; le rapport principal n'en tire pas une absence garantie d'émulateur.

## Limites

Le vérificateur distinct réutilise les bancs Unicorn des étapes 28 et 29 pour obtenir les octets natifs ; il contrôle indépendamment leur assemblage en tuiles et couleurs ainsi que le décodage PNG, sans refaire un second émulateur ARM. Objets, cache, positions, DMA immédiat et corrections LDM demeurent ceux du banc. Le mapping OBJ 1D, l'absence de double taille/mosaïque/mélange, le modèle de centre mGBA et l'expansion `floor(canal5 × 255 / 31)` sont des hypothèses de cette reconstruction. Ni DISPCNT/PPU, ni jeu commercial, ni LCD physique n'ont été exécutés. Aucune mutation Ghidra ou mémoire Claude ; aucune image, ROM ou payload extrait publié.
