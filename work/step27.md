# Étape 27 : audit comparatif Alchemy et Game Tools Collection

Lot terminé le 16 octobre 2026. Analyse statique des deux révisions fixées, confrontation à l'assembleur local, au C Ghidra déjà sauvegardé et à la ROM privée. Aucun lancement Ghidra, aucun renommage, aucun type importé, aucun jeu exécuté. Le projet validé de l'étape 26 reste retenu : `ghidra_thumb_special_pair_scoped/step9.gpr`, 2 593 fonctions, 2 223/2 253 entrées ROM reconnues et trente absentes.

## Conclusion

**Alchemy explique déjà l'essentiel du fonctionnement statique de Func_12518.** Sa fonction `Ui_RunIconMonitor`, ses helpers et ses trois structures correspondent à l'interface étudiée. Les dimensions, le choix d'animation, les quatre couches et la priorité de composition sont désormais étayés localement. Le paramètre 0..15 atteint le décodeur de pixels ; Alchemy le nomme encore `param`.

**Game Tools Collection décrit la même table GS1 USA/Europe.** Son template donne huit champs, un pas de vingt octets et 512 entrées. Il n'explique ni Func_12518 ni les helpers du visualiseur. La section Sprites est `planned: true` ; Directions et Animations sont désactivés dans le formulaire. Ces déclarations ne prouvent pas une édition fonctionnelle testée.

Il ne faut donc plus présenter ces structures, le choix d'animation ou la priorité comme des découvertes sémantiques inédites de cette analyse. Notre apport de ce lot est leur vérification sur notre ROM, la correspondance avec les adresses locales et la délimitation des affirmations externes.

## Révisions et preuves

- Alchemy : `1517ff0750d988f570b6efcd06bf30d0f64c9d2a`, [source fixée de field.c](https://github.com/PascalPixel/alchemy/blob/1517ff0750d988f570b6efcd06bf30d0f64c9d2a/games/tbs/src/field/field.c#L7070).
- Game Tools Collection : `ea0efd9b161fd39308e61ce180d409c7b11613cf`, [template GS1 fixé](https://github.com/RyudoSynbios/game-tools-collection/blob/ea0efd9b161fd39308e61ce180d409c7b11613cf/src/lib/templates/golden-sun/romEditor/template.ts#L2398).
- ROM : SHA1 recalculé `5c4695205413df7db52b9a184815a07783999971`. Elle correspond à l'édition anglaise annoncée par Alchemy. Aucune transposition d'adresse TLA.
- Vérification reproductible : `scripts/audit_semantic_references.py`, résultat `work/step27_reference_verification.json`. Les empreintes SHA256 des TSV et des sources consultées y sont consignées.
- Relevé éditeur : `work/step27_gtc_findings.md`. Revue indépendante : `work/step27_independent_review.md`. Le principal a confronté les résultats aux sources et résolu l'indirection du pointeur.

Les chemins Alchemy ci-dessous partent de `external/alchemy/`. Les chemins éditeur partent de `external/game-tools-collection/`. `work/repo/` reste l'archive historique gsret/goldensun, sans métadonnées Git.

## Correspondance des fonctions

« Forte » signifie une correspondance statique étayée par calculs, offsets, constantes, appels et contrôle de flux. Cela ne signifie pas que la fonction C externe a été recompilée et comparée octet par octet dans ce lot.

| Fonction locale | Nom Alchemy | Source précise | Preuve locale | Statut |
| --- | --- | --- | --- | --- |
| Func_12518, 0x08012518 | Ui_RunIconMonitor | `games/tbs/src/field/field.c:7070-7381` | `work/repo/rom_9000/src/rom_1219c.s:438-1193`, C `work/thumb_special_pair_scoped_after/08012518_Func_12518.c` : quatre descripteurs, dix objets, modes 0..3, mêmes bornes et branche Select | Correspondance forte ; qualification debug et accessibilité séparées ci-dessous |
| Func_185008, 0x08185008 | Resource_GetMetadataRecord | `games/tbs/src/system/resource/metadata_get_record.c:4-9` ; `games/common/include/system/metadata_lookup.h:11-33` | `work/repo/rom_185000/src/rom_185008.s:3-13`, getter ROM : masque 0xfff, pas 20, base 0x08185024 | Calcul vérifié ; borne physique de 4096 entrées non démontrée |
| Func_12af8 | Ui_FindNextNumberWithMetadata | `field.c:7383-7410` | `rom_1219c.s:1195-1224` : pas ±1, retour dans 0..511, largeur non nulle | Vérifié pour les usages observés ; helper non sûr pour tous les pas |
| Func_bc70 | ResourceObject_Create | `field.c:1176-1263` | `work/repo/rom_9000/src/rom_b798.s:671-836` : largeur/hauteur vers forme/taille OAM, recherche parmi 64 objets, pas 0x38, ajout d'une couche | Correspondance forte ; rendu effectif non exécuté |
| Func_b8ac | ResourceMetadata_Register | `field.c:881-916` | `rom_b798.s:155-232` : ajout au tableau +0x28, maximum quatre couches | Correspondance forte |
| Func_12d20 | Ui_SetGridColumnParameter | `field.c:7521-7536` | `rom_1219c.s:1479-1498` : dix objets, index & 3, entrée +5 | Offset et destination vérifiés ; sens détaillé des valeurs inconnu |
| Func_12d48 | Ui_SetGridColumnPriority | `field.c:7521-7536` | `rom_1219c.s:1500-1519` : même parcours, entrée +6 | Priorité de composition vérifiée |
| Func_12d70 | Ui_FillGridColumnFromMetadata | `field.c:7540-7568` | `rom_1219c.s:1521-1582` : compte +5, table de scripts, choix d'animation, timers décalés de 16 | Choix et initialisation de script vérifiés |
| Func_12de8 | Ui_SetGridColumnNumber | `field.c:7571-7584` | `rom_1219c.s:1584` et suite : identifiant écrit puis Func_b868 | Correspondance forte |
| Func_aa0c | Sprite_ComposeAnimationFrame | `field.c:161-445` | `work/repo/rom_9000/src/rom_a97c.s:85-815`, notamment `:486-630` : tri des couches, décodage, paramètre en r2 | Consommateurs ciblés vérifiés, fonction entière non auditée |
| Func_9bb8 | Render_DecodeFrame | `games/tbs/src/graphics/render/decode.s:14-145` | `work/repo/rom_9000/src/rom_92b8.s:6-166` : dispatch ARM, seuil pixel 0xdf, seize offsets de modes, cache de conversion | Correspondance statique forte, sémantique complète des modes réservée au prochain lot |

Les noms restent des propositions documentées. Aucun nom n'a été adopté dans Ghidra.

## La table de vingt octets

Le template utilise `pointer: 0x185020` et `pointerDataType: uint24`, pas une base directe. Le parseur choisit l'adresse régionale puis lit la valeur à cette adresse (`src/lib/utils/parser.ts:327-345`). Le type uint24 est lu little-endian (`bytes.ts:534-536`, `prototype.ts:41-50`). Dans notre ROM, ce littéral contient le pointeur GBA `0x08185024` ; ses 24 bits bas donnent l'offset fichier `0x185024`. **Il n'existe aucun décalage de quatre octets entre les tables.** L'hypothèse initiale d'en-tête dans le relevé intermédiaire a été écartée.

Source des champs Alchemy : `games/common/include/system/metadata_lookup.h:11-33`. Source éditeur : `src/lib/templates/golden-sun/romEditor/template.ts:2398-2464`.

| Offset | Alchemy | Game Tools Collection | Preuve et statut dans ce lot |
| --- | --- | --- | --- |
| +0, u8 | width | Width | 512 valeurs identiques au TSV ; sélecteur teste ce champ ; dimensions consommées par Func_bc70. Vérifié statiquement |
| +1, u8 | height | Height | 512 valeurs identiques ; paire largeur/hauteur vers forme/taille OAM. Vérifié statiquement |
| +2, u16 LE | scale | Scale | 512 valeurs identiques ; nom partagé. Usage exact, unité et relation à l'échelle d'objet non audités ici |
| +4, u8 | drawKind | Directions | 512 valeurs identiques ; code de sélection d'une table de directions dans `field.c:272-309`. Ce champ n'est pas un simple nombre de directions |
| +5, u8 | animationCount | Animations | 512 comptes identiques aux listes TSV, y compris références partagées ; borne consommée par Func_12d70. Vérifié |
| +6, s8 | adjustX | Offset X, déclaré uint8 | 512 valeurs identiques en lecture signée. Unité et tous les consommateurs non audités ; ne pas importer le type non signé de l'éditeur automatiquement |
| +7, s8 | adjustY | Offset Y, déclaré uint8 | 512 valeurs identiques en lecture signée ; Func_12d70 le copie vers AnimationObject+0x23. Différence de signe avec l'éditeur explicitée |
| +8, u8 | boxX | non exposé | 512 valeurs identiques ; interprétation géométrique précise non validée ici |
| +9, u8 | boxY | Collision Diameter | 512 valeurs identiques ; Alchemy utilise `boxY >> 1` pour le rayon d'acteur (`field.c:1553,1567`). Sémantique collision appuyée par la source externe, pas audit complet local de collision |
| +10, u8 | frameCodec | non exposé | 512 valeurs identiques ; copié dans AnimationEntry.mode ; branches locales pour 1 et 3 dans Func_aa0c. Rôle de sélecteur de décodage étayé, formats complets non validés |
| +11 | bourrage implicite du type C | non exposé | Octet nul dans les 512 enregistrements. Aucun sens propre établi |
| +12, pointeur 32 bits | frames | non exposé | Nullité concordante ; utilisé comme répertoire de frames par les consommateurs. 54 des 367 entrées sélectionnables ont ce champ nul et passent par un chargement alternatif (`field.c:1147-1148`) ; pas une preuve de ressource vide |
| +16, pointeur 32 bits | animation | non exposé | Table de pointeurs de scripts ; toutes les séquences référencées comparées à la ROM. Adresses absolues externes non reconstruites |

La table du visualiseur contient 367 largeurs non nulles et 145 nulles. Le getter accepte douze bits d'identifiant, ce qui ne prouve ni 4096 enregistrements valides ni un contrôle de bornes. Les versions européennes ont leurs propres emplacements de pointeur dans le template ; seul le cas USA/Europe anglais a été confronté à cette ROM. Le template TLA distinct ne contient ici qu'un éditeur de sauvegarde, pas ce ROM editor.

## Les trois structures associées

`IconColumn` est déjà défini par Alchemy dans `field.c:7070-7077`. Son layout correspond au descripteur local : identifiant s16 +0, animation s16 +2, activation u8 +4, priorité s8 +5, paramètre s8 +6. Le pas de huit octets est vérifié dans l'assembleur ; +7 est compatible avec le bourrage C et n'a pas d'usage identifié dans cette fonction. Les lectures signées +5/+6 sont explicites dans `rom_1219c.s:617-635`.

`AnimationEntry`, `games/common/include/field/animspr.h:9-23`, décrit la couche de 0x18 octets : identifiant +0, timer +2, type de directions +4, paramètre +5, priorité +6, codec +7, frames +8, table de scripts +0xc, script courant +0x10, position +0x14, pas temporel +0x15, frame +0x16 et frame de base +0x17. Les offsets utilisés par Func_12d20/48/70 et les consommateurs ciblés concordent. Tous les champs n'ont pas reçu un audit comportemental complet.

`AnimationObject`, même en-tête `:67-93`, décrit l'objet de 0x38 octets : deux parties image/ombre de douze octets, échelle +0x18, slot +0x1c, flags +0x1d, rotation +0x1e, dimensions +0x20/+0x21, offsets +0x22/+0x23, états +0x24..+0x27 et quatre pointeurs de couches à +0x28. Les pas et pointeurs observés concordent. Ce sont des layouts GBA à pointeurs de 32 bits ; les assertions externes n'ont pas été compilées dans ce lot.

Le paramètre local 0..3 atteint `AnimationEntry.priority` et trie les couches sur `(priority << 8) | index` avant décodage dans le tampon de pixels. Une valeur supérieure à trois écarte la couche ; l'interface emploie huit pour la masquer (`rom_a97c.s:486-555`, `rom_1219c.s:622-627`, `field.c:314-358`). C'est une priorité de composition interne, distincte des deux bits de priorité OAM dans `AnimationSpritePart`.

Le paramètre local 0..15 atteint `AnimationEntry.param`, puis r2 du décodeur copié depuis Func_9bb8 (`rom_a97c.s:584-630`, `field.c:358-381`). Le chemin codec 1 ne l'emploie pas ; le chemin codec 3 le traite différemment quand il est nul. Le nom de travail retenu est **draw_parameter**, sans l'assimiler à une palette OAM ou une rotation. Alchemy contient déjà le dispatch des seize modes ; ses effets détaillés n'ont pas encore reçu de vérification reproductible ici.

## Vérification des données Alchemy

`games/tbs/src/graphics/sprite/sprites.s:1-13` sélectionne le TSV international pour l'édition anglaise. Le générateur `tools/ags-graphics/sprite.c:92-138,169-218` explique les champs, les références partagées et le suffixe `OWNER:N`, qui limite le nombre d'animations sans décaler la table. Les lignes `animations` peuvent réutiliser des scripts déjà définis.

Le script de ce lot relit ces sources, vérifie les deux commits, refuse les arbres Git modifiés et contrôle le SHA1 ROM. Résultats sans écart :

- 512 enregistrements et 4 608 comparaisons des neuf champs numériques explicités dans le TSV.
- 512 comptes d'animations, dont la limitation de SPR_071 à quatre séquences de SPR_055.
- 1 024 contrôles de nullité des pointeurs frames/animations, dont 344 attendus nuls.
- 2 062 emplacements de scripts comparés intégralement sur leur longueur TSV, soit 15 738 octets avec répétitions ; 1 997 couples distincts adresse/longueur.
- 512 octets +11 nuls ; 367 entrées sélectionnables retrouvées.

Les payloads graphiques, les valeurs relocalisées de tous les pointeurs et le C externe n'ont pas été reconstruits. Pour les scripts, le contrôle compare la plage de longueur déclarée par le TSV ; il ne détermine pas indépendamment la longueur réelle. La concordance confirme ce contenu, pas à elle seule les noms d'opcodes ni leur rendu. Les scripts restent des octets hexadécimaux dans les TSV ; les interprétations d'opcodes se trouvent dans `field.c:137-268` et doivent être vérifiées par leurs consommateurs. Aucun bloc extrait n'est ajouté au rapport.

Reproduction depuis la racine, vers une nouvelle sortie :

```sh
python3 -I scripts/audit_semantic_references.py /tmp/step27-reference-recheck.json
```

## Faits, hypothèses et inconnues

**Faits vérifiés dans ce lot :** correspondances statiques ci-dessus, même table via indirection, données TSV concordantes, choix d'animation, ordre de composition des couches et transmission du paramètre au décodeur. Ces éléments sont déjà expliqués au moins en partie dans les références.

**Hypothèse étayée :** interface interne de test/visualisation de sprites. Alchemy l'appelle debug sprite viewer et nomme `gDebugMode` la cellule mise à deux. Les mécanismes de contrôle et les dix instances appuient cette qualification ; un nom externe et une entrée exportée ne prouvent pas l'accès en partie commerciale.

**Affirmation externe écartée pour cette ROM :** le commentaire `field.c:7085-7086` dit que Select recharge les ressources de far-call. L'appel correspondant est Func_2f0c, un stub retournant zéro (`work/repo/rom_c0/src/rom_2e00.s:111-114`, ROM contrôlée). Les arguments seuls ne prouvent aucun rechargement. Le chemin entier appelle aussi Func_40e8 puis recommence l'initialisation ; ses autres effets sont conservés. Ne pas réintroduire l'hypothèse de chargement sous couvert du nom externe.

**Inconnues restantes :** sens complet des seize modes de dessin, résultat visible de la composition et des codecs, conventions complètes scale/boxX/boxY, tous les consommateurs des champs, appelant effectif et conditions d'entrée du visualiseur, équivalence binaire complète d'Alchemy. La revendication de reconstruction complète d'Alchemy reste non vérifiée ici. Aucun résultat sur les trente fonctions encore absentes n'est ajouté.

## Lot suivant retenu, non exécuté

Suivre une couche de **SPR_000, animation 0**, depuis son script et le choix de direction dans Func_aa0c jusqu'au décodeur Func_9bb8 et au tampon de pixels. Priorité : documenter les seize valeurs du draw_parameter et les chemins qui les contournent. Commencer par les sources Alchemy déjà présentes, puis vérifier le dispatch, les tables de conversion et un exemple reproductible dans la ROM. Séparer le décodeur d'image de la priorité matérielle OAM. Un rendu ou une émulation demandera son propre protocole et ses preuves ; l'accessibilité du visualiseur est un lot distinct.

Il n'est pas nécessaire de rouvrir Ghidra pour cette première lecture. Si des noms/types deviennent assez étayés pour une annotation, le principal seul exécutera une copie neuve du projet fermé, avec audits et réouverture avant promotion.

## Bilan du lot

Les deux clones restent propres aux commits initiaux. Le sparse-checkout Alchemy a été élargi aux ressources système, aux graphiques et au générateur ags-graphics ; celui de l'éditeur aux utilitaires et types. L'essai réseau dans le sandbox a échoué en DNS ; la récupération des blobs manquants a réussi via élévation autorisée. Aucun sous-module, dépendance, build ou test des projets externes lancé. Aucun processus Ghidra lancé par les agents de ce lot.

Luna/low a relevé le template et confirmé son parseur. Sol/high a relu indépendamment les correspondances et limites, puis le rapport et le script du principal. Mémoire Claude inchangée ; son entrée Golden Sun mérite une actualisation par Claude vers l'étape 27, le projet de l'étape 26 conservé et cette orientation sémantique. Notion reste non actualisé depuis l'étape 13 ; aucun outil Notion n'a été utilisé.
