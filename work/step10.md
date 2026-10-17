# Étape 10 : audit des 50 cibles indéterminées

## Résultat

Les 50 cibles sont des adresses de données du bloc de textes compressés généré par les outils du dépôt. Aucune fonction supplémentaire identifiée ou créée.

Les adresses impaires effectivement interrogées par REA se répartissent en 25 adresses dans les payloads compressés et 25 dans les tableaux de longueurs. Les adresses paires obtenues en effaçant le bit bas se répartissent en 26 et 24, car cette opération déplace certains pointeurs de données d'un octet. Il ne faut pas appliquer cette normalisation Thumb à un pointeur de données ordinaire.

- 49 cibles ont une référence depuis la table StringPointers : 24 champs de payload et 25 champs de longueurs.
- La cible paire 0x08060802, interrogée à 0x08060803, est aussi dans le payload compressé. Ses cinq occurrences source sont hors de StringPointers ; leur rôle de pointeur n'est pas établi par le seul mot ROM correspondant.
- Les 50 cibles sont absentes des entrées de fonctions du projet sauvegardé à l'étape 9.
- Inspection REA des adresses paires : 43 statuts `undecodable` et 7 `decoded`, aucun propriétaire de fonction. Ici `undecodable` signifie absence d'instruction analysée à cette adresse, pas impossibilité de décoder ces octets.
- Les sept unités déjà désassemblées appartiennent aux données confirmées : preuve supplémentaire qu'une instruction affichée n'établit pas la présence de code. Exemple : 0x08046a28 est affichée `vpmax.f16 d4,d11,d14`.
- Le projet Ghidra et la ROM n'ont pas été modifiés pendant cet audit.

## Preuve de la nature des données

Le dépôt génère `rom_15000/data/strings/strings.s` lors du build. Ce fichier était absent de l'archive source ; l'extraction initiale de plages `.incrom/.incdata` ne pouvait donc pas couvrir ces données.

Sources primaires locales :
- `work/repo/Makefile:110` : extraction des textes depuis la ROM, puis génération de l'assembleur et des blocs compressés.
- `work/repo/tools/unpack_strings.c:12` : Huffman à 0x3842c, StringPointers à 0x736b8, 10 722 textes.
- `work/repo/tools/unpack_strings.c:228` : lit les paires de pointeurs payload/longueurs et avance dans le payload selon les longueurs.
- `work/repo/tools/pack_strings.c:465` : génère `strings.s` dans `.rodata`, avec Huffman, payloads, tableaux de longueurs et StringPointers.
- `work/repo/stage1.ld:140` : lie ce fichier généré dans la section des données en lecture seule.

Les 42 paires et les longueurs reconstruisent 84 plages continues sur [0x08038434, 0x080736b7). Les 50 adresses interrogées sont à l'intérieur. Le SHA1 correspond à la ROM USA de référence.

Vérification indépendante : compilation et exécution des deux outils C du dépôt. Décompression de 10 722 textes, puis recompression ; **42/42 payloads et 42/42 tableaux de longueurs identiques octet pour octet à la ROM**. Preuve : `work/string_roundtrip/roundtrip.json`. Les textes et blocs extraits restent locaux, ils ne doivent pas être publiés.

## Précision de la piste clôturée

Sur les 3 358 cibles positives sans fonction REA baseline :
- 227 débuts de fonctions Thumb confirmés par le dépôt ;
- 3 131 adresses de données, dont les 50 données générées désormais classées ;
- aucune cible indéterminée.

Précision de la piste brute pour identifier de nouvelles entrées : **227/3 358 = 6,76 %**. Sur toutes les 3 540 cibles positives, y compris les fonctions déjà reconnues : **409/3 540 = 11,55 %**.

Le filtrage par les données du dépôt laisse les 227 entrées de référence, mais ce résultat utilise la référence et ne mesure pas une détection autonome. À l'étape 9, 226 de ces entrées ont été créées et sauvegardées ; le cas de queue partagée reste intact. Le rappel du projet reste 1 770/2 253 (78,56 %).

## Reproduire

```sh
python3 -I scripts/unknown_reference.py work/pointer_validation.json work/repo 'work/rom/Golden Sun (USA, Europe).gba' work/unknown50.tsv
python3 -I scripts/strings_roundtrip.py work/repo 'work/rom/Golden Sun (USA, Europe).gba' work/string_roundtrip
```

Inventaire et sources : `work/unknown50.tsv`, `work/unknown50.json`. Preuves d'instructions REA : `work/unknown50_rea_inspection.json`. Scripts durables : `scripts/unknown_reference.py`, `scripts/strings_roundtrip.py`.

## Suite

Étudier la représentation de Func_f9ac0 et de sa queue partagée avec Func_f9b10. La présence de branches vers un bloc interne ne justifie pas de supprimer le corps existant. La mémoire attend la fin de session.
