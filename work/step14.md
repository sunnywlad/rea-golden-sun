# Étape 14 : contrôle de flux de Func_9bb8 récupéré (2026-10-16)

## Résultat retenu

Projet courant : `archive:ghidra_func9bb8/step9.gpr`, programme `gs_us_map.elf`, copie du projet de l'étape 13. Le projet source `archive:ghidra_decoded23/step9.gpr` est conservé.

- Corps de `Func_9bb8` : **432 octets, 108 instructions**, contre 220 octets auparavant. 53 instructions ajoutées, soit 212 octets.
- Les deux dispatchs sont présents dans la décompilation : quatre cas d'alignement à `0x08009bd0`, seize cas à `0x08009cd8`.
- Le nombre de fonctions reste **2 164**, et le rappel des entrées de stockage ROM **1 794/2 253 (79,63 %)**. Cette étape améliore un corps existant.
- Les empreintes de tous les blocs mémoire initialisés, les permissions, les modes TMode, les unités de données inline et les noms/corps des autres fonctions sont conservés. Les empreintes et les autres fonctions concordent également avec les exports de l'étape 13.
- Fermeture/réouverture et second passage effectués. La vérification finale compare les exports complets après sauvegarde, y compris les annotations, et le C. Résultat détaillé : `func9bb8_final/verification.json`.

Il s'agit d'une récupération Ghidra guidée par le dépôt de référence. REA reste sur sa baseline ; aucun gain de découverte autonome ne lui est attribué.

## Table et limites code/données

Le dispatch exécute `add r4, r2, r2`, `ldrsh r4, [pc, r4]`, puis `add pc, r4`. Le PC lu par la dernière instruction vaut `0x08009ce0`. Les seize demi-mots signés occupent **`0x08009cdc–0x08009cfb`**, et les destinations valent `0x08009ce0 + offset`.

| Cas | Offset signé | Destination ROM |
|---|---:|---|
| 0 | -288 | 0x08009bc0 |
| 1 à 6 | 32 | 0x08009d00 |
| 7 et 8 | -52 | 0x08009cac |
| 9 à 12 | 28 | 0x08009cfc |
| 13 | -80 | 0x08009c90 |
| 14 | -60 | 0x08009ca4 |
| 15 | -68 | 0x08009c9c |

Sources : ROM vérifiée par SHA1, `repo/rom_9000/src/rom_92b8.s:89-110`, et `func9bb8_repair/table.json`. Le vérificateur Python dérive les adresses depuis le source assembleur, puis confronte les expressions de la table aux demi-mots ROM.

Plages finales du corps :

- `0x08009bb8–0x08009bd3` : 28 octets ;
- `0x08009bd8–0x08009c8b` : 180 octets ;
- `0x08009c90–0x08009cdb` : 76 octets ;
- `0x08009cfc–0x08009d8f` : 148 octets.

Les nouvelles instructions sont celles des handlers `0x08009c90–0x08009ccf` et du traitement/cache `0x08009cfc–0x08009d8f`. Le NOP non atteint à `0x08009bd4–0x08009bd7`, le littéral `0x08009c8c–0x08009c8f`, la table, les littéraux/cache `0x08009d90–0x08009d9b` et le buffer `0x08009d9c–0x08009e7b` restent hors du corps. Leurs unités de listing ne sont pas effacées ou redéfinies.

## Méthode et contrôle du C

`scripts/Func9bb8Flow.java` désassemble uniquement les plages de code confirmées, sans analyse automatique et sans réécrire TMode. Il ajoute sept références `COMPUTED_JUMP` aux destinations distinctes de `0x08009cd8`, enregistre un override de table avec `JumpTable.writeOverride`, puis recalcule le corps avec `CreateFunctionCmd.fixupFunctionBody`. C'est le mécanisme de `Ghidra/Features/Decompiler/ghidra_scripts/SwitchOverride.java:137-147` dans l'installation locale.

Les symboles d'override `case_0..case_6` indexent les sept destinations distinctes ; ils ne représentent pas les valeurs de l'argument. L'export du décompilateur restitue bien les **seize labels réels 0..15**, avec leurs répétitions de destination. Une seule instruction préexistante change dans les exports : `0x08009cd8`, qui reçoit les références de saut attendues.

Le C contient les handlers de remplissage, le chargement conditionnel des 224 octets de table dans le buffer, le traitement des octets d'entrée et le dispatch d'alignement déjà connu. Les alertes de table non récupérée et d'indirect traité comme appel ont disparu. Deux avertissements restent : override manuel et symboles globaux chevauchants.

**Limites de validation :**

- La correspondance des cas est vérifiée pour `r2` initial dans **0..15**. L'assembleur ne borne pas l'index. Le `default` du C regroupe les cas 1..6 et peut donner une interprétation artificielle des valeurs hors table. Aucune équivalence n'est établie pour ces valeurs.
- Le C exporté utilise les adresses de stockage ROM pour les accès PC-relatifs au cache et au buffer. L'instance exécutée en RAM n'est pas reconstruite dans ce projet. Ne pas interpréter ces écritures comme des écritures effectives dans la cartouche.
- La complétude du corps et les destinations des dispatchs sont vérifiées statiquement. Aucune exécution du jeu ni comparaison dynamique C/ARM n'est effectuée.

## Provenance de la copie RAM

Trois sources DMA sont explicitement `Func_9bb8`, après appel à `Func_48b0` avec index `0x34` et allocation de `0x2c4` octets :

| Appelant | Source | Taille copiée | Contrôle DMA3 |
|---|---|---:|---|
| Func_aa0c | `repo/rom_9000/src/rom_a97c.s:110-127` | **0x1e4** octets | 0x84000079 |
| Func_c880 | `repo/rom_9000/src/rom_c880.s:18-30` | 0x2c4 octets | 0x840000b1 |
| Func_c62c | `repo/rom_9000/src/rom_c004.s:836-848` | 0x2c4 octets | 0x840000b1 |

Dans Func_aa0c, le nombre de mots est `(Data_9d9c - Func_9bb8)/4` : le buffer est réservé mais n'est pas copié. Les deux autres chemins copient jusqu'à `0x08009e7b`, buffer inclus. Les trois copient le code, la table et les littéraux/cache.

`Func_48b0`, `repo/rom_c0/src/rom_4858.s:40-74`, conserve le pointeur dans le slot `iwram_1e50 + 4 × 0x34 = iwram_1f20`. Si le slot est déjà occupé, il renvoie ce pointeur. Sinon, il réserve dans l'arène IWRAM, puis dans EWRAM si nécessaire, ou renvoie zéro en cas d'épuisement. L'adresse du slot est fixe ; l'adresse du code alloué dépend de l'état mémoire. Aucune adresse runtime unique n'est déduite de ces sources.

La copie DMA est démontrée. Le chemin d'appel indirect vers le pointeur alloué n'a pas été établi dans les fonctions examinées ; la reconstruction d'une instance RAM et la vérification de son appel restent à faire.

## Preuves et reproduction

- `func9bb8_inspect/` : copie initiale ouverte en lecture seule, corps 220 octets ;
- `func9bb8_repair/` : premier passage, corps 432 octets ;
- `func9bb8_verified/` : première réouverture, état et C identiques ;
- `func9bb8_repeat/` : second passage, structure inchangée, précision du nom Func_c62c dans le commentaire d'entrée ;
- `func9bb8_final/` : réouverture finale et vérification croisée avec source, ROM et étape 13.

```sh
# Sur une copie de ghidra_decoded23, jamais sur le projet source :
JAVA_TOOL_OPTIONS=-Dapplication.cachedir=~/.cache/ghidra $GHIDRA_INSTALL_DIR/support/analyzeHeadless archive:ghidra_func9bb8 step9 -process gs_us_map.elf -noanalysis -scriptPath scripts -postScript Func9bb8Flow.java repair work/func9bb8_repair

# Après fermeture, ouvrir en lecture seule :
JAVA_TOOL_OPTIONS=-Dapplication.cachedir=~/.cache/ghidra $GHIDRA_INSTALL_DIR/support/analyzeHeadless archive:ghidra_func9bb8 step9 -process gs_us_map.elf -noanalysis -readOnly -scriptPath scripts -postScript Func9bb8Flow.java inspect work/func9bb8_final

python3 -I scripts/verify_func9bb8.py
```

Le vérificateur consomme les exports des premier et second passages et de la réouverture finale. Conserver leurs dossiers séparés pour ne pas écraser l'état initial. Il compare les structures au second passage ; seul le commentaire de nom d'appelant est corrigé pendant ce passage.

L'inspection initiale a signalé un échec d'entretien du cache sous `/var/tmp`, hors des chemins accessibles. Les exécutions suivantes utilisent `application.cachedir` dans le home ; aucune élévation de permission nécessaire.

Revue indépendante Sol/high : table ROM, 432 octets, 108 instructions, mapping des labels, invariants et première réouverture confirmés. Elle a précisé la différence de taille copiée par Func_aa0c et la limite du `default` hors domaine.

## Suite

459 entrées de référence restent absentes, inventaire inchangé. Prochaine étape proposée : préparer un lot témoin parmi les 443 entrées ROM non définies, avec limites code/données et modes confirmés avant création. Garder séparés les douze cas du bloc rom_770 chargé en IWRAM et les quatre cas code/donnée. Pour Func_9bb8, l'éventuelle suite concerne l'instance RAM et les appels indirects, pas un nouveau gain de rappel ROM.

Les deux pages Notion n'ont pas été actualisées : aucun outil Notion connecté n'est disponible dans cette session. Le fichier de reprise local fait foi après l'étape 14. Aucun fichier de mémoire modifié.
