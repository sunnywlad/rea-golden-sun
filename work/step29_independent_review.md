# Étape 29 : revue indépendante

Revue du 17 octobre 2026. Avis favorable sur le jalon borné SPR_000, animation 0, mode 0, directions `0x0000` et `0x8000`. Aucun défaut bloquant relevé dans le script, la preuve ou le rapport principal. Aucun script, référence externe, mémoire ou projet Ghidra modifié par cette revue.

## Reproduction

Depuis la racine du projet :

```sh
uv run --offline --no-project --with unicorn==2.1.4 python scripts/audit_sprite_upload.py /tmp/step29_review.json
cmp /tmp/step29_review.json work/step29_upload_verification.json
```

Exécution réussie ; comparaison identique à l'octet près. SHA256 des deux JSON : `5951e5e942ac07d8fb1e96ded582d0594e951960aae70501fe0d147ed781879c`. Script contrôlé : SHA256 `5d09e713090d0f86f416f2048dda6e23fd662fead4bd7fff911968676d21c60f`.

Un comptage séparé, sans importer le script ni son modèle, a parcouru le flux non compressé de la frame 1 dans la ROM privée : étendue 1 024, 258 écritures, 42 indices non nuls et 42 valeurs de palette distinctes. Une réorganisation indépendante par la formule d'offset tuile du rapport retrouve les empreintes des indices linéaires et des tuiles natives. Aucun octet de flux, palette, image ou payload extrait enregistré.

## Points contrôlés

- Le modèle d'ordre des tuiles est fondé sur les coordonnées, distinct de l'assembleur. Les huit témoins synthétiques et les deux compositions vérifient la copie ROM→RAM de l'uploader puis ses écritures effectives, la couverture destination et la garde des témoins. L'index OAM utilise des unités de 32 octets : tile 6 désigne bien `0x060100c0`, avec seize tuiles 8 bpp de 64 octets.
- `Func_bb20` et `Func_4838` établissent la copie de 224 demi-mots vers la palette OBJ. Les entrées 224..255 restent antérieures au chargement. Les 42 indices du témoin mode 0 sont tous couverts ; cela ne suffit pas pour le mode 12.
- `Func_b168` consomme le retour miroir sans modifier les tuiles. Les attributs `0x2042/0x2142`, `0x8080`, `0x0806` et la matrice `(-256,0,0,256)` correspondent aux instructions de placement. Le miroir emploie la matrice affine ; le banc n'invente pas un retournement logiciel des pixels.
- Le wrapper `Func_3e10` copie les `0xe0` octets du générateur OAM, exécute effectivement cette adresse RAM puis la libère. La tranche `0x08003686..0x080036a7` contrôle ensuite la programmation du DMA OAM et ses quatre combinaisons de flags. Les demi-mots de matrice sont vérifiés après le transfert simulé.
- Les références locales du rapport ont été confrontées aux routines citées, notamment `rom_b798.s`, `rom_92b8.s`, `rom_a97c.s`, `rom_b074.s`, `rom_45e8.s`, `rom_3d04.s`, `rom_1b70.s`, `rom_3650.s`, `rom_3adc.s` et `field.c`. Une précision mineure de plage a été signalée au principal : la priorité du constructeur est posée à `rom_b798.s:807-810`.

## Limites maintenues

Cette revue reproduit le même moteur Unicorn et le même banc ; elle n'est pas une validation indépendante du matériel. Objet, couche, tas, cache initial, slot du décodeur et flags sont synthétiques. Allocation/libération et DMA3 immédiat restent simulés. Les trois adaptations LDM héritées restent nécessaires ; les 74 interventions par composition sont visibles dans la preuve.

Les témoins d'uploader portent sur des dimensions multiples de huit. L'OAM n'est contrôlée qu'avec un objet et au plus une matrice ; ni la saturation de liste ni les scènes composées ne sont couvertes. Le slot 52 est réaffecté au tampon OAM après décodage, comme indiqué dans le rapport. La tranche VBlank n'installe aucune IRQ et n'exécute pas le gestionnaire complet. DISPCNT, mapping PPU, fondu, mélange et affichage ne sont pas exécutés. L'empreinte RGBA est analytique ; elle ne prouve pas les couleurs finales de l'écran ni l'accès au visualiseur commercial.
