# Étape 28 : SPR_000, animation 0, jusqu'au tampon de pixels

Lot terminé le 16 octobre 2026. Lecture des références fixées, vérification des tables sur la ROM et exécution ARM/Thumb isolée sous Unicorn 2.1.4. Aucun jeu exécuté, aucune ouverture ni mutation Ghidra. Projet retenu inchangé : `ghidra_thumb_special_pair_scoped/step9.gpr`, 2 593 fonctions, 2 223/2 253 entrées ROM reconnues, trente absentes. Aucun nom ni type importé.

## Résultat

Le comportement des seize valeurs de `draw_parameter` est établi pour le décodeur `Func_9bb8`. Les modes 1 à 5 sont cinq permutations d'indices. Les modes 6 et 9 à 11 réduisent les indices par quatre autres tables. Les modes 7, 8, 13, 14 et 15 remplissent la silhouette par une valeur constante. Le mode 0 conserve les indices.

**Le mode 12 utilise du code ROM comme table.** Le calcul aboutit à `0x08009bb8`, début du décodeur lui-même. Son effet numérique est vérifié ; son intention ne l'est pas. Il ne faut pas lui inventer un nom de couleur ou un effet artistique.

La chaîne demandée est vérifiée jusqu'aux 1 024 octets du tampon pour les huit directions échantillonnées et les seize modes, soit 128 compositions. Le banc fournit un objet et une couche synthétiques, des pointeurs ROM et le slot du décodeur déjà chargé. Il exécute le vrai code ROM du compositeur, des helpers retenus et du décodeur. Cela ne prouve ni l'accès au visualiseur ni un rendu à l'écran.

## Sources et preuve

- Rapport reproductible : `work/step28_decode_verification.json`. Script : `scripts/audit_sprite_decode.py`.
- ROM privée : SHA1 `5c4695205413df7db52b9a184815a07783999971`.
- Alchemy conservé au commit `1517ff0750d988f570b6efcd06bf30d0f64c9d2a`, arbre propre. Game Tools Collection reste à la révision de l'étape 27 ; aucun nouveau usage de son parseur.
- Sources Alchemy : `games/tbs/src/field/field.c:161-445`, `field/facing.c:28-31`, `graphics/sprite/sprites.tsv:2`, `graphics/sprite/spr_000.tsv:1`, `graphics/render/decode.s:14-150`, `system/resource/colconv.s:1-8`, `field/remap.s:1-7`.
- Sources assembleur local : `work/repo/rom_9000/src/rom_a97c.s:4-815`, `rom_92b8.s:6-166`, `rom_1219c.s:1521-1582`, `work/repo/rom_c0/src/rom_770.s:430-474`.
- Les empreintes du script et des sources réellement utilisées figurent dans le JSON. Les sorties contiennent des adresses, comptages et empreintes, sans image ni payload ROM extrait.
- Relevé délégué : `work/step28_modes_findings.md`. Revue indépendante : `work/step28_independent_review.md`. Le rapport principal et la preuve reproductible prévalent sur le relevé intermédiaire.

## Chaîne concrète de l'animation

L'enregistrement de SPR_000 est à `0x08185024`. Il donne 32 × 32 pixels, `drawKind = 5`, 38 animations et `frameCodec = 3`. Le répertoire de frames est à `0x0819baf8`, la table d'animations à `0x081879a8`, le script 0 à `0x08187824`. Ces pointeurs sont lus dans la ROM, pas déduits de noms externes.

`Func_12d70` initialise la couche choisie avec ce script, `kind = 5`, `step = 16`, position zéro, frame de base zéro et frame courante 255. Les dix objets reçoivent des timers `16 × index` (`rom_1219c.s:1521-1582`). Le banc utilise le premier, timer initial zéro. Il demande explicitement l'animation 0 ; le visualiseur initialise normalement son indice d'animation à 1 (`field.c:7130`). Aucune sélection de l'animation 0 en jeu n'a été observée.

Le script contient deux commandes de deux octets, vérifiées sur la ROM et le TSV :

1. Frame de base 0, durée 4. Le compositeur ajoute `4 << 4 = 64` au timer.
2. `0xf1`, argument 0 : maintien. La position recule de deux, la frame de base reste inchangée.

Le code correspondant est à `rom_a97c.s:173-263` et `field.c:215-267`. Sur sept appels isolés à direction fixe, les timers sont `64, 48, 32, 16, 0, 0, 0`, la position reste 2 et seul le premier appel redessine. Le banc reproduit entre les appels la remise à zéro du flag dirty normalement faite après l'upload, hors de son point d'arrêt.

Pour `kind = 5`, le secteur vaut `dir >> 12`. Le compositeur ajoute les trois bits bas de l'entrée de direction à la frame de base. Le bit 7 signale le miroir pour la couche 0 (`field.c:288-310`, `rom_a97c.s:385-439`). Le miroir n'est pas appliqué dans `Func_9bb8` : le tampon d'indices reste identique pour une même frame. Le flag calculé est également contrôlé dans la pile du compositeur.

| Direction fournie au banc | Frame choisie | Miroir signalé | Pointeur frame ROM |
| --- | ---: | --- | --- |
| 0x0000 | 1 | non | 0x0818d6ab |
| 0x2000 | 0 | non | 0x0818d554 |
| 0x4000 | 3 | non | 0x0818d916 |
| 0x6000 | 0 | oui | 0x0818d554 |
| 0x8000 | 1 | oui | 0x0818d6ab |
| 0xa000 | 2 | oui | 0x0818d7d1 |
| 0xc000 | 4 | non | 0x0818da89 |
| 0xe000 | 2 | non | 0x0818d7d1 |

Ces huit directions échantillonnent la table à seize secteurs. Elles ne constituent pas une observation des angles d'une partie. La table complète est présente dans `facing.c:28-31` et dans la ROM à `0x080130ac`.

Les cinq frames ont toutes un en-tête de deux octets nul. Dans ce cas, `Func_a97c` retourne `source + 2`, sans recopier de flux vers le scratch. `Func_d30` retourne aussi `source + 2`. Le compositeur poursuit alors par `Func_9bb8` avec le mode demandé, y compris le mode 0. **Un codec 3 ne signifie donc pas que cette frame est effectivement compressée.**

| Frame | Octets du flux, terminateur compris | Pixels écrits | Pixels sautés | Étendue destination |
| --- | ---: | ---: | ---: | ---: |
| 0 | 341 | 305 | 719 | 1024 |
| 1 | 292 | 258 | 766 | 1024 |
| 2 | 323 | 286 | 738 | 1024 |
| 3 | 369 | 332 | 692 | 1024 |
| 4 | 357 | 321 | 703 | 1024 |

Exemple de départ : direction `0x0000`, animation 0, mode 0. Le code choisit la frame 1 à `0x0818d6ab`, saute l'en-tête nul, puis le décodeur lit le flux à `0x0818d6ad`. Il écrit 258 indices et laisse 766 positions intactes dans le tampon préalablement mis à zéro. Le JSON conserve l'empreinte des 1 024 octets pour chaque mode et chaque direction.

## Les seize modes du décodeur

Soit `v` l'octet lu dans le flux de dessin. Dans `Func_9bb8`, zéro termine le flux sans écriture. `1..223` produit un pixel. `224..255` avance la destination de `v - 223`, soit 1 à 32 octets, sans écriture. **223 est un pixel, pas un saut.** Une sortie de table est écrite telle quelle ; elle n'est pas réinterprétée comme commande de flux.

Pour les modes de conversion, la base est le littéral `0x080091b8`, puis `base + 256 × key`. Le cache copie 224 octets et les indexe par `v`. Les modes 1..6 gardent `key = mode`. Seuls les modes 9..12 exécutent la soustraction de deux. Les tables Alchemy ci-dessous sont confrontées sur leurs 256 octets, soit 2 304 octets au total. Le décodeur n'utilise que les indices 1..223.

| Mode | Effet exact pour 1 ≤ v ≤ 223 | Source de conversion | Valeurs de sortie distinctes sur ces 223 entrées |
| ---: | --- | --- | ---: |
| 0 | écrit v | chemin direct | 223 |
| 1 | écrit table[v], key 1 | 0x080092b8, colconv0.tsv | 223 |
| 2 | écrit table[v], key 2 | 0x080093b8, colconv1.tsv | 223 |
| 3 | écrit table[v], key 3 | 0x080094b8, colconv2.tsv | 223 |
| 4 | écrit table[v], key 4 | 0x080095b8, colconv3.tsv | 223 |
| 5 | écrit table[v], key 5 | 0x080096b8, colconv4.tsv | 223 |
| 6 | écrit table[v], key 6 | 0x080097b8, remap0.tsv | 13 |
| 7 | écrit 15 | constante | 1 |
| 8 | écrit 15 | même handler que 7 | 1 |
| 9 | écrit table[v], key 7 | 0x080098b8, remap1.tsv | 38 |
| 10 | écrit table[v], key 8 | 0x080099b8, remap2.tsv | 38 |
| 11 | écrit table[v], key 9 | 0x08009ab8, remap3.tsv | 38 |
| 12 | écrit table[v], key 10 | 0x08009bb8, 224 octets du code ROM | 48, dont zéro |
| 13 | écrit l'octet global lu à 0x03001c90 | fixé à 3 par Func_12518 | 1 par appel |
| 14 | écrit 1 | constante | 1 |
| 15 | écrit 0 | constante | 1 |

Sources du dispatch, des constantes et du lookup : `rom_92b8.s:64-160`. Les modes 1..5 permutent exactement 1..223, sans produire zéro. Les quatre remap n'en produisent pas non plus. Le mode 12 donne zéro pour dix indices d'entrée et peut produire des octets supérieurs à 223. Cela affecte réellement l'exemple : en frame 1, il reste 245 pixels non nuls parmi 258 positions écrites. Les modes 7 et 8 sont identiques dans ce décodeur, sans preuve qu'ils aient le même rôle pour tous ses appelants.

Le mode 15 efface les positions couvertes par les pixels de la couche. Il préserve les positions sautées. Ce comportement est contrôlé sur un fond non nul ; son résultat entièrement nul sur une couche isolée ne signifie pas qu'il n'a rien écrit. Un autre setter protège les couches déjà en mode 15 (`field.c:697-714`), règle distincte de l'effet du décodeur.

Le mode 13 lit la valeur globale une fois par appel. Six valeurs globales, dont 0 et 255, ont été vérifiées. La valeur 3 est propre à l'initialisation du visualiseur (`rom_1219c.s:461-467`, `field.c:7123`), pas une constante intrinsèque du mode.

Le cache est mono-entrée : clé à `copie_RAM + 0x1d8`, table à `copie_RAM + 0x1e4`. Il ne contient pas des pixels calculés. La séquence `1,1,9,9,1,7,1,12,12` écrit respectivement `224,0,224,0,224,0,0,224,0` octets de table. Les modes constants n'invalident pas le cache.

## Chemins qui contournent le paramètre

Le dispatch est à `rom_a97c.s:574-630`, équivalent à `field.c:362-381`.

| Codec et condition | Chemin vérifié statiquement | Ce que couvre l'exécution isolée |
| --- | --- | --- |
| 1 | Func_5340(frame, pixels), aucun draw_parameter transmis | lecture des instructions seulement ; ce codec n'est pas celui de SPR_000 |
| 3, paramètre non nul | allocation 0x400, Func_a97c, Func_9bb8 avec le paramètre, libération | les quinze modes non nuls sur les frames 0..4 |
| 3, paramètre nul, en-tête nul | Func_d30 retourne source+2, puis appel du décodeur en mode 0 | huit directions de l'animation 0 |
| 3, paramètre nul, en-tête non nul | Func_d30 décompresse et dessine directement, retourne zéro ; pas d'appel à Func_9bb8 | témoin distinct, frame 5 |
| autre codec | appel direct à Func_9bb8 avec le paramètre | décodeur testé séparément ; branche du compositeur non exécutée dans les 128 cas |

`Func_d30` s'exécute à `0x030005c0` après la copie du bloc ROM `0x770..0x1b6f` en IWRAM. Sa version compressée s'arrête sur un token LZ nul, pas sur un octet pixel nul (`rom_770.s:430-474`). La frame 5 à `0x0818dbf0`, hors animation 0, sert de témoin positif avec un en-tête 122 et 345 octets après décompression.

**Observation auxiliaire vérifiée :** pour cette frame 5, le dessin fusionné produit les mêmes 1 024 premiers octets que la décompression suivie du mode 0. Il écrit aussi le zéro terminal à l'offset destination 1024, puis termine avec une destination avancée de 1025. Le décodeur séparé s'arrête avant d'écrire ce zéro. Le banc dispose d'un espace plus grand pour observer cette écriture. Cela établit une différence de contrat et une écriture au-delà du rectangle nominal dans ce témoin, sans établir une corruption visible, l'implantation effective de l'allocateur en jeu ou la généralité à toutes les frames.

## Protocole et limites

Commande depuis la racine du projet :

```sh
uv run --offline --no-project --with 'unicorn==2.1.4' python scripts/audit_sprite_decode.py work/step28_decode_verification.json
```

Unicorn a été téléchargé dans le cache uv, sans environnement ni dépendance installée dans les dépôts externes. Le premier essai hors ligne n'avait aucun paquet en cache ; l'essai réseau sandbox a échoué sur DNS. La récupération hors sandbox a ensuite réussi. Aucun build Alchemy, sous-module ou éditeur lancé.

Le banc copie `0x1e4` octets du décodeur à l'adresse choisie `0x02001000` et réserve son buffer dans le même espace RAM. Il précharge le slot `0x03001f20`, comme un chemin où le décodeur existe déjà. L'allocation et la libération ordinaires sont remplacées par des hooks, mais la mise à zéro, le compositeur, les helpers de flux et le décodeur exécutent leurs instructions d'origine. Arrêt à `0x0800af12`, avant contour, upload, OAM et affichage. Les adresses du heap et du code alloué sont des choix du banc, pas des adresses observées dans une partie.

Unicorn lit les LDM non alignés autrement que la mémoire GBA. Un témoin minimal l'a confirmé pour plusieurs modèles de CPU. Le banc remplace donc uniquement les trois `ldmia r0!, {r3}` du mode 0 lorsqu'ils sont non alignés : lecture du mot à `r0 & ~3`, écriture dans r3, incrément de r0 de quatre en gardant ses bits bas, flags conservés. Il vérifie l'opcode avant remplacement. Cette règle correspond à [GBALoadMultiple dans mGBA, lignes 1424-1502](https://github.com/mgba-emu/mgba/blob/master/src/gba/memory.c#L1424-L1502), source primaire consultée le 16 octobre 2026. **Ces cas sont une exécution assistée par cette correction mémoire, pas une validation matérielle indépendante de celle-ci.**

Les 390 comparaisons synthétiques couvrent tous les indices pixel 1..223, tous les sauts 224..255, les quatre alignements, les quatre emplacements d'un terminateur dans un mot et six valeurs du remplissage global. Un fond 0xa5 permet de distinguer saut et écriture de zéro. Le banc compare aussi les cinq flux de frames aux retours du helper natif, les 80 décodages frame/mode, les 128 compositions et la séquence de cache. Aucune équivalence générale de tout le moteur n'en découle.

## Faits, hypothèses, inconnues

**Faits vérifiés :** script et adresses SPR_000, sélection des cinq frames, timeline de maintien, seize chemins du paramètre, neuf tables identiques aux TSV, particularité du mode 12, cache, pixels produits dans le banc et contournements de codec décrits ci-dessus.

**Hypothèses :** les conversions correspondent à des recolorations et à des silhouettes d'effets. Les tables remap réduisent effectivement les indices, mais « gris », « ombre », « feu » ou tout nom de couleur précis demanderait les palettes et leurs usages. Le mode 12 pourrait être une valeur exposée par erreur ou un comportement conservé intentionnellement ; rien ne tranche. L'écriture supplémentaire du témoin compressé pourrait être absorbée par l'allocateur, ce qui n'est pas vérifié.

**Inconnues :** couleurs RGB et palettes effectives, usages commerciaux du mode 12, conséquences de l'écriture du témoin compressé dans le heap réel, mélange de plusieurs couches dans une scène, accès au visualiseur depuis le jeu commercial, rendu final et timing matériel. Le chargement réel des slots de ressources n'est pas rejoué : le banc fournit les répertoires ROM. Les trente entrées manquantes, le build complet Alchemy et la reconstruction des instances RAM dans Ghidra restent hors de ce lot.

## Reprise proposée

Prochain lot distinct : suivre ce tampon de 32 × 32 indices vers le transfert de tuiles, la palette et l'attribut de miroir, avec un seul exemple SPR_000/animation 0/direction 0x0000. Établir d'abord l'organisation mémoire des tuiles et la palette réellement choisie. Garder séparées l'enquête sur le mode 12, l'audit du témoin compressé et l'accessibilité du visualiseur. Aucun de ces lots n'est lancé ici.

Wladimir a ensuite demandé d'enregistrer en mémoire et d'arrêter. Cette instruction a autorisé la mise à jour de l'entrée Golden Sun et de son index vers l'étape 28. Travail arrêté ; aucun prochain lot lancé. Notion n'a pas été actualisé.
