# Étape 27 — comparaison Game Tools Collection / Func_12518

Audit local en lecture seule de `external/game-tools-collection`, commit `ea0efd9b161fd39308e61ce180d409c7b11613cf`. Le dépôt est un clone shallow, partial (`blob:none`) avec sparse-checkout. `git status --short` est vide. Les templates Golden Sun et The Lost Age étaient présents au départ ; le principal a ajouté `src/lib/utils` et `src/lib/types` pour contrôler le parseur. Le manifeste `work/external_references.json` reflète cet élargissement. Les constats d’absence ci-dessous sont limités aux chemins effectivement inspectés et à l’arbre Git du commit, pas à d’autres dépôts ou à toutes les recherches existantes.

## Conclusion

L’éditeur connaît explicitement une table « Sprites » de 512 entrées de 0x14 (20) octets, et propose des noms pour plusieurs champs. Son pointeur USA/Europe est `0x185020` et le template indique `pointerDataType: "uint24"`. Le parseur lit trois octets little-endian à cette adresse, ce qui donne l’offset ROM `0x185024`; dans la ROM locale, les quatre octets sont `24 50 18 08`, soit le pointeur GBA `0x08185024`. C’est exactement l’adresse de départ calculée par le getter local, avec le préfixe GBA `0x08` omis dans la valeur 24 bits utilisée comme offset. Le prétendu delta de quatre octets est donc résolu : `0x185020` est l’emplacement du littéral pointeur, pas le début des enregistrements. Le template qualifie les entrées de sprites et nomme dimensions, offsets, échelle, diamètre de collision, directions et animations. Il ne décrit pas les animations ni les champs +10..+19.

## Version et adresses

- Le validateur de `src/lib/templates/golden-sun/romEditor/template.ts:11-50` associe l’entrée `europe_usa` à l’identifiant ROM `Golden_Sun_AAGSE01` (`:15-20`). Le bloc `japan` a séparément `AAGSJ01` (`:21-25`); les versions France, Allemagne, Italie et Espagne ont leurs propres identifiants (`:27-49`). C’est donc le template **Golden Sun 1** et son entrée **Europe/USA** qui est pertinent ici.
- La table Sprite utilise un vecteur de six emplacements de pointeur région/ROM : `[0x185020, 0x17c020, 0x187820, 0x185e20, 0x185020, 0x187820]`, taille d’élément 0x14, 512 instances (`src/lib/templates/golden-sun/romEditor/template.ts:2398-2411`). La première valeur correspond à `europe_usa` d’après la structure du validateur et des pointeurs régionaux du template. Pour GS1 USA/Europe, l’emplacement du littéral pointeur est donc **0x185020**.
- TLA se trouve dans un template distinct, `src/lib/templates/golden-sun-the-lost-age/`; l’arbre Git du commit contient seulement `saveEditor/template.ts` et `saveEditor/utils.ts` sous ce chemin. Aucun pointeur de table Sprite GS1 n’est attribuable à TLA sur la base de ce bloc.
- Le getter local est décrit comme `0x08185024 + 20 × (id & 0xfff)` dans `work/semantic_func12518.md` (section « Faits établis ») et son source est cité comme `repo/rom_185000/src/rom_185008.s:3-13`. À `work/rom/Golden Sun (USA, Europe).gba`, fichier-offset `0x185020`, lecture hexadécimale : `24 50 18 08` (`xxd -g1 -s 0x185020 -l 8`). Dans le template, `pointerDataType: "uint24"` est posé à `:2402-2406`. `parseContainer` choisit le pointeur selon la région (`src/lib/utils/parser.ts:327-332`), puis lit le type déclaré à l’adresse de pointeur avec `getInt` (`:334-345`). `getInt` traite `uint24` comme little-endian (`src/lib/utils/bytes.ts:534-536`), et `getUint24` assemble les trois octets little-endian (`src/lib/utils/prototype.ts:41-50`). Les trois premiers octets `24 50 18` donnent donc l’offset fichier `0x185024`; le quatrième octet `08` est le préfixe de l’adresse GBA du getter, non inclus dans l’offset 24 bits de l’éditeur. L’implémentation confirme sans ambiguïté l’indirection et la concordance avec la table locale.

## Champs déclarés par l’éditeur

Source unique : `src/lib/templates/golden-sun/romEditor/template.ts:2413-2464`.

| Offset | Étiquette éditeur | Déclaration | État interprétatif |
| --- | --- | --- | --- |
| +0 | Width | uint8 (`:2415-2419`) | Connu par l’éditeur; cohérent avec les dimensions observées localement. |
| +1 | Height | uint8 (`:2421-2425`) | Connu par l’éditeur; cohérent avec les dimensions observées localement. |
| +2..+3 | Scale | uint16 (`:2439-2443`) | Étiquette et largeur connues; sens exact et endianness effective non validés ici contre le rendu. |
| +4 | Directions | uint8, disabled (`:2451-2456`) | Nom proposé par l’éditeur, champ désactivé. Sémantique à valider par consommateurs. |
| +5 | Animations | uint8, disabled (`:2458-2463`) | Nom proposé par l’éditeur. Localement, `Func_12d70` utilise le champ +5 comme borne d’indice d’un tableau référencé par la ressource (`work/semantic_func12518.md`, section faits établis), ce qui appuie un rôle de compte/bornage d’animations sans identifier la structure complète. |
| +6 | Offset X | uint8 (`:2427-2431`) | Nom de champ déclaré; le caractère signé, l’unité et la relation aux coordonnées restent à vérifier. |
| +7 | Offset Y | uint8 (`:2433-2437`) | Même réserve que +6. |
| +8 | aucun | — | Inconnu dans le template consulté. |
| +9 | Collision Diameter | uint8 (`:2445-2449`) | Nom déclaré par l’éditeur, mais l’interprétation collision n’est pas corroborée ici par le code local examiné. |
| +10..+19 | aucun | — | Inconnus dans ce template. |

Le fait que les champs +4 et +5 soient `disabled: true` signifie que le template ne permet pas leur édition via ces items; cela ne prouve pas qu’ils soient inutilisés. La section entière est marquée `planned: true` (`:2398-2401`), donc les étiquettes expriment au minimum la connaissance codée dans un éditeur dont cette interface est planifiée.

## Sprites, animations et Func_12518

- Le nom « Sprites » et la numérotation `Sprite %d`, 512 instances, 20 octets viennent du template (`:2398-2411`). Le local décrit aussi 512 enregistrements, dont 367 sélectionnables sur le critère du premier octet non nul et 145 ignorés (`work/semantic_func12518.md`, section faits établis). L'indirection contrôlée dans le parseur et la ROM démontre l'identité de la table, sans décalage de base.
- L’éditeur ne fournit, dans le bloc relevé, aucune table de séquences d’animation, aucun format de frame, aucune procédure de rendu, ni correspondance explicite avec `Func_12518` ou `Func_185008`. Une recherche dans les chemins sparse indiqués au manifeste n’a trouvé aucun identifiant de ces fonctions ni l’adresse `0x08185024`; cela n’est pas une affirmation sur l’ensemble du dépôt hors sparse-checkout.
- Le dossier TLA distinct ne contient pas de template ROM editor dans l’arbre du commit inspecté; ses seuls fichiers template listés sont save-editor. Les pointeurs alternatifs du vecteur dans le template GS1 ne doivent donc pas être réinterprétés comme des adresses TLA.
- La sélection faite par Func_12518 parcourt bien la table désignée par le même pointeur que le template de l’éditeur : correspondance directe du littéral ROM avec l’adresse du getter, en plus de la cardinalité (512) et de la taille (20) concordantes. Les significations de Width/Height demeurent à valider par rendu. Inconnus : rôle concret des paramètres du descripteur local, format des séquences d’animation et accessibilité de l’interface dans le jeu.

## Portée et limites

Les faits éditeur proviennent du commit local précisé, pas d’un site consulté. Le sous-agent n'a utilisé ni réseau, build, test ni Ghidra ; le principal a récupéré les utilitaires manquants sans changer la révision ni les sources suivies. Le sparse-checkout comprend désormais les chemins `src/lib/templates/golden-sun`, `src/lib/templates/golden-sun-the-lost-age`, `src/lib/types` et `src/lib/utils` (état vérifié après élargissement). `src/lib/types.ts:261-263` déclare le champ `pointerDataType`; l’indirection est établie par le parseur et ses helpers cités ci-dessus. L’arbre Git complet a aussi été interrogé par `git ls-tree`. Les conclusions négatives sur les descripteurs/fichiers sont bornées au template et aux chemins relevés. Les noms des champs du template ne sont pas des validations indépendantes de leur comportement dans la ROM. Les inconnues de ce relevé éditeur doivent être lues avec le bilan croisé `step27.md`.
