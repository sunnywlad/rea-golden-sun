# Étape 30 : émulateurs installés et convention de miroir affine

Relevé en lecture seule du 17 octobre 2026. Aucun émulateur, ROM, jeu, Ghidra ou payload lancé ou installé. Aucun fichier projet hors de ce rapport modifié.

## Inventaire local

Commandes exécutées depuis `<racine du projet>` :

```sh
for c in mgba mGBA mgba-qt mgba-sdl mgba-sdl3 visualboyadvance visualboyadvance-m vba vbam retroarch mednafen; do command -v "$c" 2>/dev/null; done
dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | rg -i 'mgba|visualboy|vbam|retroarch|mednafen'
flatpak list --app --columns=application,version,branch
snap list
apt list --installed 2>/dev/null | rg -i 'mgba|visualboyadvance|vbam|retroarch'
```

- Aucune de ces commandes d’émulateur n’est présente dans le `PATH`.
- La recherche des paquets dpkg installés et de la liste apt n’a retourné aucun résultat mGBA, VBA/VBAM, RetroArch ou Mednafen.
- `flatpak` est absent, son inventaire n’est donc pas disponible.
- `snap` existe, mais `snap list` ne termine pas dans le délai de cinq secondes : `timeout` retourne 124 et aucun texte d’erreur n’est émis. L’inventaire Snap est indisponible dans cette vérification, il ne compte pas comme inventaire vide.

Codes de retour observés lors de la reprise avec sorties capturées : recherche `PATH`, 1 (aucune commande trouvée) ; pipeline dpkg + filtre, 1 (aucune correspondance) ; tentative Flatpak, 127 (`flatpak: command not found`) ; `timeout 5 snap list`, 124 (délai dépassé, sortie vide) ; filtre apt, 1 (aucune correspondance) ; tests `command -v flatpak` et `command -v snap`, respectivement 1 et 0. Les erreurs de `dpkg-query` et `apt` étaient redirigées vers `/dev/null` dans les commandes réellement exécutées, donc aucune erreur textuelle de ces programmes n’est consignée.

Contrôle complémentaire du principal, sans pipeline ni suppression de stderr : `dpkg-query -W` avec le même format retourne 0, 1 942 lignes et stderr vide ; `apt list --installed` retourne 0, 1 936 lignes et le seul avertissement sur la stabilité de son interface CLI. Le filtrage Python des deux stdout par `mgba|visualboy|vbam|retroarch|mednafen` ne trouve aucune correspondance. Les deux inventaires de paquets ont donc bien abouti.

Conclusion limitée : aucun émulateur GBA parmi les noms du `PATH` et paquets dpkg/apt filtrés n’est détecté. Flatpak n’est pas installé et l’inventaire Snap n’a pas abouti. Cela n’exclut pas une installation manuelle sous un autre nom, dans un conteneur ou dans un emplacement non couvert par ces contrôles. mGBA n’est pas détecté par les contrôles exécutés.

## Matrice miroir et centre des pixels

Les preuves locales de l’étape 29 établissent que `Func_b168` demande une matrice Q8 `(-256, 0, 0, 256)` pour le témoin miroir à échelle unitaire, et que `Func_3d28` écrit les coefficients correspondants dans OAM. Le banc a vérifié les mots `0x0000ff00, 0x01000000` et les attributs OAM (`work/step29_mirror_findings.md`, lignes 8–11 et 17 ; `work/step29.md`, section « Miroir et OAM »). Cela établit la matrice native, mais pas à lui seul une formule indexée `31-x` sur un tampon source.

Pour contrôler la convention du rendu transformé, le code primaire mGBA `src/gba/renderers/software-obj.c` initialise l’accumulateur X comme `mat.a * (inX - 1 - (totalWidth >> 1)) + ... + (width << 7)` (lignes 194–222) puis incrémente l’accumulateur avant la lecture du pixel (lignes 26–42). Pour un objet 32×32, visible sans rognage, avec `mat.a=-256`, `mat.b=mat.c=0`, `mat.d=256`, et ligne source/destination centrée, ceci donne, pour `x_dest=0..31`, `x_source=32-x_dest` avant le contrôle de bornes. La valeur 32 est hors de l’objet et ne dessine donc pas au premier pixel ; les pixels dessinés sont `x_dest=1..31` associés à `x_source=31..1`, tandis que la colonne source 0 n’est pas atteinte sur cette ligne. Cette discrétisation n’est pas le flip horizontal pur `31-x_dest` : elle manifeste le décalage d’un pixel de l’inversion autour du centre géométrique entier.

Le calcul confirme qu’une convention de centre entier peut produire un décalage discret, avec une limite importante : la seule matrice ne suffit pas à figer la correspondance pixel-à-pixel. Il faut inclure l’initialisation d’accumulateur, l’incrément avant lecture, les bornes et le centre de la boîte transformée. La convention étudiée est celle du renderer logiciel mGBA, pas une observation indépendante sur matériel GBA ni une validation du visualiseur Golden Sun. Une comparaison utile du tampon étape 28 doit conserver séparément le résultat mGBA, le flip pur `31-x`, et l’éventuel décalage dû à l’origine/centrage; ne pas déclarer l’un comme rendu matériel établi par ce relevé.

Sources consultées :

- Preuve locale : `work/step29_mirror_findings.md`, `work/step29.md` et `work/step29_upload_verification.json`.
- Source primaire mGBA : [software-obj.c](https://github.com/mgba-emu/mgba/blob/master/src/gba/renderers/software-obj.c), macro `SPRITE_TRANSFORMED_LOOP` (lignes 26–42) et calcul de `xAccum` (lignes 194–222). Le fichier a été lu sur la branche `master` le 17 octobre 2026 ; ce relevé ne fige pas un commit mGBA.
