# Étape 8 : fonctions Thumb manquées et précision des pointeurs

ROM USA SHA1 : `5c4695205413df7db52b9a184815a07783999971`.
ELF mappé : même SHA256 et mêmes 1 914 adresses de procédures que le résultat précédent.
Référence : désassemblage local `work/repo/`, hors overlays.
Commandes et provenance : `work/pointer_run_metadata.json`, `work/pointer_validation.json`.

## Résultat

- Les 676 fonctions Thumb manquées ont été interrogées à leur adresse `addr|1`.
- 444 ont au moins un mot pointeur impair aligné dans la ROM.
- Parmi ces 444, 227 ont une référence REA et 217 n'en ont aucune.
- Parmi les 232 sans mot pointeur impair aligné, aucune n'a de référence REA.
- Couverture : 227/444 = 51,1 % des fonctions avec pointeur ; 227/676 = 33,6 % des fonctions Thumb manquées.
- Ces 227 sont des entrées de fonction du dépôt, pas des fonctions créées dans REA. Leur ajout éventuel porterait le rappel global de 1 544/2 253 (68,5 %) à 1 771/2 253 (78,6 %), sous réserve de récupération réussie.

## Précision sans filtrer par les fonctions de référence

Le scan indépendant parcourt les mots little-endian alignés sur quatre octets. Il retient les valeurs impaires dont l'adresse, bit Thumb effacé, appartient à la ROM. Il déduplique les cibles avant de consulter le dépôt.

- 8 463 cibles interrogées : 3 540 avec xrefs, 4 923 sans, aucune erreur.
- 409 des 3 540 cibles positives sont des débuts de fonctions Thumb du dépôt (11,6 %).
- 182 étaient déjà des fonctions REA ; après exclusion de ces entrées connues, restent 3 358 cibles.
- Parmi ces 3 358 : 227 fonctions confirmées, 3 081 adresses de données du dépôt, 50 cibles indéterminées.
- Précision pour de nouvelles fonctions : au moins 227/3 358 = 6,8 %, au plus 277/3 358 = 8,3 % si les 50 indéterminées sont toutes des fonctions.
- Exclure les données connues du dépôt réduit la liste à 277 cibles, dont 227 fonctions confirmées (au moins 81,9 %). Ce filtrage dépend du dépôt de référence.

Les données sont établies par 1 467 plages `.incrom` / `.incdata` dans les sections `.rodata` ou `.data`, hors overlays. Les macros utilisent des intervalles [début, fin). Exemple : les cibles 0x08029b02, 0x08029bfc et 0x08029c2c appartiennent aux plages de `work/repo/rom_15000/src/rom_19ebc.s:913` et `:915`.

## Vérification des sources

- 3 367 cibles positives ont au moins une source xref égale à l'emplacement d'un mot ROM portant le pointeur attendu.
- 173 cibles positives n'ont que d'autres sources, notamment des instructions ; elles restent des références analysées, pas des mots pointeurs confirmés à ces sources.
- Parmi les 227 fonctions manquées retrouvées, 186 ont une source mot pointeur exacte ; 41 ont d'autres sources de référence.
- Aucune source xref n'est hors de la ROM.
- 8 695 requêtes distinctes, aucune erreur ; aucune fonction créée.

## Reproduire

```sh
python3 -I scripts/pointer_candidates.py scan 'work/rom/Golden Sun (USA, Europe).gba' work/repo_funcs.txt work/procs.json work/pointer_candidates.json
python3 -I scripts/pointer_candidates.py summarize work/pointer_candidates.json work/pointer_xrefs.json work/pointer_summary.md
python3 -I scripts/validate_pointer_xrefs.py work/pointer_candidates.json work/pointer_xrefs.json 'work/rom/Golden Sun (USA, Europe).gba' work/repo work/pointer_validation.json --extra-xrefs work/missed_no_pointer_xrefs.json
```

Les requêtes MCP `xrefs` sont faites sur les 8 463 `pointer_value` de l'inventaire, puis sur les 232 fonctions manquées absentes de celui-ci. Les résultats sauvegardés contiennent l'adresse interrogée, l'identifiant de preuve, le sujet SHA256 et `normalized_result`. La liste nominative des 227 fonctions est dans `work/missed_thumb_xrefs.json`.

## Prochaine étape

Récupération contrôlée dans Ghidra des 227 entrées confirmées, avec le mode Thumb explicite, puis comparaison des adresses et de la décompilation. Examiner les 50 cibles indéterminées avant d'élargir la liste. REA n'expose toujours pas de création de fonction.
