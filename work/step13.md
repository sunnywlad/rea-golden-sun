# Étape 13 : création des 23 entrées ROM déjà décodées

## Résultat sauvegardé

Projet de travail : `archive:ghidra_decoded23/step9.gpr`, programme `gs_us_map.elf`.

- 23 entrées créées : 20 ARM et trois Thumb.
- 2 164 fonctions au total, contre 2 141 avant ce lot.
- 1 794/2 253 entrées du dépôt reconnues, rappel 79,63 %.
- Thumb : 1 755/2 201 ; ARM : 39/52 (75 %).
- Aucun ajout hors du lot, aucune entrée initiale perdue.
- Les 2 141 noms et corps de fonctions préexistants sont conservés.
- Toutes les empreintes SHA256 des blocs mémoire initialisés sont identiques avant/après.
- Octets, TMode, première instruction et références vers chacune des 23 entrées inchangés.
- Réouverture : mêmes 2 164 fonctions et mêmes corps. Second passage : 23 entrées préexistantes, aucune nouvelle création.
- 23 statuts de décompilation « completed ». Une fonction porte deux avertissements.

La création utilise `CreateFunctionCmd` sur des instructions existantes. Aucun désassemblage forcé, effacement d'unité de code ou changement de contexte. Le rappel reste une mesure des débuts de code stockés en ROM, pas une validation complète de leurs corps ou du code chargé en RAM.

Preuves : `work/decoded_recovery/before.json`, `after.json`, `targets.json`, `verification.json`, `work/decoded_verified/`.

## Comparaison avec le dépôt

| Sonde | Résultat |
|---|---|
| Func_f0008, ARM | Séquence SMULL/SMLAL et accumulation de trois produits 64 bits concordantes ; deux paramètres sur pile pris en compte, corps 28 octets. |
| Func_185008, Thumb | Calcul base +20×(r0 &0xfff) concordant ; table et pools hors du corps, 18 octets. |
| Func_f4008, Thumb | Instructions et appels concordants, mais signature C de retour 64 bits non validée, sans avertissement. |
| Func_9bb8, ARM | Corps incomplet, 220 octets, deux avertissements. Le second dispatch calculé et ses handlers ne sont pas reconstruits complètement. |

La revue complète des quatre sondes est dans `work/decoded_recovery/probe_review.md`. Elle ne valide pas les 23 fonctions ligne par ligne.

### Signature suspecte sans avertissement

Dans Func_f4008, l'assembleur charge zéro dans r0, puis restaure LR dans r1 avant `bx r1`. Ghidra infère `longlong Func_f4008(void)` et produit `return (ulonglong)unaff_lr << 32`.

Le registre de retour bas r0 reste bien nul. Le défaut observé porte sur le type et la largeur de retour inférés : le mot haut vient du registre utilisé pour revenir à l'appelant. L'assembleur ne déclare pas de prototype et l'appelant ROM repéré ignore le résultat, donc on ne peut pas établir un retour source C sur 64 bits. La première revue qualifiait trop fortement la valeur de retour d'« incorrecte » ; elle a été corrigée pour distinguer type inféré et valeurs des registres.

Sources : `work/repo/rom_f4000/src/rom_f4008.s:13`, `:19` ; appelant `work/repo/rom_8a000/src/rom_8a5f8.s:561`.

### Corps incomplet malgré « completed »

Func_9bb8 a trois plages attribuées :
- 0x08009bb8–0x08009bd3 ;
- 0x08009bd8–0x08009c8b ;
- 0x08009cd0–0x08009cdb.

La source décrit un dispatch calculé à 0x08009cd8, une table de 16 offsets signés de demi-mots à 0x08009cdc, puis des handlers et du traitement/cache à 0x08009d00 et au-delà. Ces branches ne sont pas reconstruites complètement. Le C annonce une table de sauts non récupérée et traite l'indirect comme un appel.

Les données inline ne sont pas incluses dans le corps comme instructions. Cela ne compense pas les blocs de code manquants. Une entrée reconnue et un statut de décompilation réussi ne prouvent donc pas une récupération complète du contrôle de flux.

Source : `work/repo/rom_9000/src/rom_92b8.s:89` à `:166`.

## Reproduction

Script durable : `scripts/RecoverDecoded.java`, arguments lot TSV et dossier de sortie. Format TSV : mode, adresse hexadécimale, nom du dépôt. Il vérifie instruction exacte et TMode attendu, conserve les fonctions déjà présentes, utilise la commande intégrée et exporte tous les corps/empreintes, C et listings complets.

```sh
# Sur une copie du projet après étape 11 :
~/ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless ~/rea-golden-sun/archive:ghidra_decoded23 step9 -process gs_us_map.elf -noanalysis -scriptPath ~/rea-golden-sun/scripts -postScript RecoverDecoded.java ~/rea-golden-sun/work/recover_decoded_rom.tsv ~/rea-golden-sun/work/decoded_recovery
# Réouverture en lecture seule :
~/ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless ~/rea-golden-sun/archive:ghidra_decoded23 step9 -process gs_us_map.elf -noanalysis -readOnly -scriptPath ~/rea-golden-sun/scripts -postScript RecoverDecoded.java ~/rea-golden-sun/work/recover_decoded_rom.tsv ~/rea-golden-sun/work/decoded_verified
```

Le champ global « all_function_names_and_bodies_unchanged » du premier passage est faux parce que 23 fonctions ont été ajoutées. La vérification distincte des seuls noms/corps préexistants est vraie dans `verification.json`.

## Prochaine étape

Compléter le contrôle de flux de Func_9bb8 : lire la table et ses cibles dans la ROM, comparer au dépôt, puis tester une récupération des blocs manquants dans une copie du projet. Préserver les données inline et vérifier le C après cette réparation.

Il reste 459 entrées non reconnues : 446 Thumb et 13 ARM. Parmi elles, douze appartiennent au bloc explicitement chargé en IWRAM ; les autres comprennent 443 entrées ROM non définies et quatre cas de code lu comme données. La session REA reste sur sa baseline ; le projet Ghidra séparé est l'état de travail.
