# Étape 28 : relevé statique des modes de Func_9bb8

État du relevé initial, complété par le principal : les neuf TSV sont désormais confrontés à la ROM dans `step28_decode_verification.json`. Modes 1..5 : colconv0..4 ; mode 6 : remap0 ; modes 9..11 : remap1..3. Le mode 12 lit le début du code ROM de Func_9bb8. Les réserves TSV ci-dessous décrivent la portée du relevé seul ; elles sont levées par cette preuve ultérieure. Le rapport final est `step28.md`.

Lecture seule des sources Alchemy et de l’assembleur ROM local. Aucune exécution, mutation Ghidra ou comparaison de rendu n’a été faite. « Fait » désigne ici le comportement directement encodé dans les instructions. La signification graphique des indices convertis reste une hypothèse tant qu’un exemple pixel reproductible n’est pas confronté au rendu.

## Résultat du dispatch

Le mode est `r2`, fourni par `AnimationEntry.param` (appel local `rom_a97c.s:623-630`, et branche codec 3 `:587-603`). Pour `r2 == 0`, Func_9bb8 prend le chemin brut (`rom_92b8.s:7-62`). Tout mode non nul est indexé dans une table de seize offsets relatifs (`rom_92b8.s:89-110`). La table équivalente d’Alchemy est `decode.s:92-100`.

| draw_parameter | Chemin et effet sur les octets source non nuls | Source locale |
|---:|---|---|
| 0 | Parcours brut ; conserve la valeur sous `& 0xff` | `rom_92b8.s:7-62` |
| 1–6 | Table de conversion ; sélection par la valeur du mode, sans soustraction | `rom_92b8.s:94-101,115-153` |
| 7–8 | Remplace chaque octet source non nul par `0x0f` | `rom_92b8.s:102-103,78-88` |
| 9–12 | Table de conversion, sélectionnée par `mode-2`, donc indices 7 à 10 dans le bloc de conversion | `rom_92b8.s:104-107,112-153` |
| 13 | Remplace chaque octet source non nul par l’octet lu depuis `iwram_1c90` | `rom_92b8.s:108,64-70,80-88` |
| 14 | Remplace chaque octet source non nul par `0x01` | `rom_92b8.s:109,75-76,80-88` |
| 15 | Remplace chaque octet source non nul par `0x00` | `rom_92b8.s:110,71-73,80-88` |

Pour les modes 1–6, `r2` reste égal au mode lorsqu’il atteint `.L9d00`. Pour les modes 9–12, `.L9cfc` applique `r2 -= 2` avant de rejoindre `.L9d00`. Le littéral de base vaut `Data_92b8 - 0x100` (`rom_92b8.s:159-160`), donc l’adresse de copie est `(Data_92b8 - 0x100) + key*256`: mode 1 sélectionne `Data_92b8` ; mode 9 sélectionne `Data_92b8 + 0x600`. Le code copie 224 octets vers `Data_9d9c` (`:115-140,162-165`), puis pour chaque octet source `v` non nul et inférieur à `0xe0`, produit la valeur `Data_9d9c[v]` (`:147-153`). C’est une consultation de table ; aucune formule arithmétique n’est appliquée à la valeur traduite. Le tableau texte Alchemy `colconv*.tsv` expose des tables de correspondance 16×16 (`external/alchemy/games/tbs/src/system/resource/colconv0.tsv:1-17`, mêmes lignes dans `colconv1.tsv` à `colconv4.tsv`), mais le rapprochement exact de chaque TSV avec chaque bloc ROM n’est pas établi dans ce relevé.

## Règles communes de flux, skip et transparence

- Le mode 0 lit des mots et traite leurs octets ; les remplissages et conversions lisent directement des octets (`rom_92b8.s:11-12,85-87,147-153`). Le mode 0 peut éviter les tests individuels de terminaison quand l'AND des quatre octets est non nul. Un AND nul renvoie vers les tests individuels et ne prouve pas qu'un octet est nul (`:37-62`).
- Dans le brut, chaque octet est masqué à 8 bits. Zéro termine immédiatement le décodage sans écrire de pixel (`:17-18`, puis `:22-23`, etc.). Les valeurs 1..0xdf, y compris `0xdf` (223), sont émises comme pixels. Pour `v > 0xdf`, soit 0xe0..0xff, le code avance la destination de `v-0xdf` octets sans écrire de pixel (`:19-21`).
- Les modes de remplissage et lookup suivent la même règle : zéro termine ; 1..0xdf produit un pixel ; 0xe0..0xff avance la destination de `v-0xdf` sans écriture (`:80-88`, `:147-153`). Les valeurs produites sont la constante du mode de remplissage ou la valeur de table correspondante.
- Le décodeur traite zéro comme terminateur de flux, et les octets 0xe0..0xff comme commandes d’avancement/skip. Le mode 15 peut produire un octet pixel égal à zéro pour chaque octet source non nul et inférieur à 0xe0 (`:71-73,80-88`). Le consommateur aval détermine l’effet visuel de cet octet.

## Cache de table

Le cache conserve une seule clé à `Data_9d90` et une table convertie de 0xe0 octets à `Data_9d9c` (`rom_92b8.s:115-140,156-165`). Si la clé calculée égale celle mémorisée, la copie est évitée (`:116-119,141-143`). Sinon la clé est remplacée et 224 octets sont copiés depuis `(Data_92b8 - 0x100) + key*256` (`:119-140,159-160`). C’est un cache mono-entrée partagé par les modes lookup. Il ne met pas en cache les pixels décodés.

Le pointeur de table commence 0x100 octets avant `Data_92b8` (`:159-160`). Ainsi mode 1 lit à `Data_92b8`, tandis que mode 9 lit à `Data_92b8+0x600`; les adresses dépendent directement du code `key` établi par le dispatch.

## Chemins de Func_aa0c qui contournent le paramètre

`Func_aa0c` appelle le décodeur copié en RAM et trie les couches avant dessin (`rom_a97c.s:85-128,486-555`). Le dispatch des codecs est explicite :

- Codec 1 appelle `Func_5340(frame, pixels)` sans passer le paramètre (`rom_a97c.s:574-583`).
- Codec 3, paramètre nul : appelle `Func_d30` indirectement avec la frame et le tampon de pixels (`rom_a97c.s:607-615`). Si le retour est nul, la branche se termine. Si le retour est non nul, une routine indirecte est appelée avec `r2=0` (`:615-621`). Alchemy décrit le premier appel comme `Iwram_Decompress`, puis appelle le décodeur seulement si le retour est non nul (`field.c:374-377`).
- Codec 3, paramètre non nul : alloue 0x400 octets, décompresse vers ce tampon, appelle le décodeur avec le paramètre de couche, puis libère (`rom_a97c.s:587-606`; Alchemy `field.c:367-372`).
- Tout autre codec appelle le décodeur directement avec le paramètre de couche (`rom_a97c.s:622-630`; Alchemy `field.c:379-381`).

Le contournement est donc certain pour le codec 1 ; pour le codec 3 à paramètre nul, la décompression peut produire les pixels elle-même et l’appel ultérieur éventuel reçoit zéro. La source ne permet pas d’affirmer le résultat de tous les retours des routines indirectes sans résoudre leur cible runtime.

## Faits, hypothèses, inconnues

**Faits statiques :** dispatch 0..15 ci-dessus ; `0xdf` est un pixel émis, le skip commence à `0xe0` ; zéro termine le flux ; traduction par lookup indexée par l’octet source ; cache mono-entrée ; chemins codec 1 et 3 indiqués.

**Hypothèse :** les tables `colconv*.tsv` représentent les mêmes conversions que certains blocs binaires ROM, et ces substitutions sélectionnent des palettes ou plages de couleurs. Les sources consultées ne suffisent pas à faire une association exacte entre numéros de TSV, clés ROM et sens visuel.

**Inconnues :** sémantique graphique des valeurs converties, association déterministe des tables TSV aux modes/indices, signification de l’octet `iwram_1c90`, comportement du consommateur aval pour les pixels zéro, et contenu exact des entrées de lookup hors des premières 224 valeurs. Aucun rendu SPR_000 n’a été exécuté ou comparé.

## Corrections après relecture

- Modes 1–6 vont directement à `.L9d00` ; aucun mode 1 brut n’existe. Seuls les modes 9–12 passent par `.L9cfc` et soustraient deux.
- La base du lookup est `Data_92b8 - 0x100`. Cela donne `Data_92b8` pour le mode 1 et `Data_92b8 + 0x600` pour le mode 9.
- `0xdf` est émis comme pixel dans tous les chemins. Le skip commence à `0xe0`.
- Dans Func_aa0c, codec 3 à paramètre nul appelle `Func_d30` avant le test du retour, pas `Func_4938`.
