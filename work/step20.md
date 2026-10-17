# Étape 20 : quinze fonctions avec pools littéraux finaux (2026-10-16)

Projet courant validé : **`archive:ghidra_thumb_literal_pilot/step9.gpr`**, `gs_us_map.elf`. **2 330 fonctions**, **1 960/2 253 entrées ROM (87,00 %)**. Récupération guidée ; baseline REA inchangée.

- Quinze créations exactes, **100 instructions /200 octets** de code.
- **21 mots de pool**, 84 octets de données, hors des corps de fonctions. Les fenêtres d'entrée à borne suivante totalisent308octets :200code+84littéraux+24alignement/interstice.
- Analyse ARM ciblée :21nouvelles unités `/undefined4`, exactement sur ces21slots. Aucune autre donnée, ancienne instruction, ancien corps/nom ou mémoire modifiée.
- Quinze C terminés sans avertissement. Réouverture, second passage, snapshots, cibles, mots de pool et C identiques.

Preuves : `thumb_literal_pilot_plan/`, `thumb_literal_pilot_before/`, `thumb_literal_pilot_recovery/`, `thumb_literal_pilot_after/`, `thumb_literal_pilot_repeat/`, `thumb_literal_pilot_reopened/`, **`thumb_literal_pilot_verification.json`**.

## Planificateur et garde code/données

`scripts/plan_thumb_literals.py` accepte seulement un pool final émis par `.func_end`. Il refuse toute directive ou macro interne, expression inconnue, LDR optimisé non reconnu, branche ambiguë, instruction inaccessible ou donnée dont l'adresse chevaucherait le code ou dépasserait la fonction suivante.

Pour chaque pseudo-LDR, il vérifie dans la ROM le registre et l'opcode Thumb littéral, calcule le slot `((instruction+4)&~3)+4×imm8`, puis compare le mot32bits à l'expression source. Résolution AST limitée aux opérations arithmétiques/bitwise admises, sans exécution de code. Symboles vérifiés via `wram.sym`, `include/gba.inc`, déclarations de fonctions/données, alias de stubs et remappage exact du bloc rom_770. Les pointeurs Thumb et les adresses de données sont traités selon leurs déclarations.

Les expressions et sources sont conservées dans le plan avec empreintes. La structure des branches est également redécodée depuis les opcodes ROM. Le CFG syntaxique suppose que les appels reviennent ; ce n'est pas une preuve générale de comportement runtime ou de pile.

`LiteralAudit.java` exporte indépendamment chaque slot, ses octets, sa valeur et son unité de données, et vérifie l'absence d'instruction qui le recouvre. `verify_thumb_recovery.py` conserve toutes les anciennes données et n'autorise de nouvelle unité que sur un slot approuvé exact de quatre octets. Il exige la même valeur et la même preuve après réouverture. Aucun assouplissement global des invariants.

## Revue des quinze C

Opérations source retrouvées sur les quinze sondes : gardes puis stores, masque/combinaison halfword, indexation, accès au champ d'un objet, calcul de pointeur et écriture MMIO halfword à `REG_BG0VOFS=0x04000012`.

Les constantes sont notamment `iwram_1e70`, `iwram_1e8c`, `iwram_1ebc`, `iwram_1ee4`, `ewram_40`, `ewram_2240`, `ewram_3030/300c/3034/3010`, `0xf1ff`, `0xeac` et `0xea6`. Elles correspondent aux21mots ROM et aux définitions source. Les noms des quinze fonctions et leurs instructions sont dans le plan.

Limite restante : `Func_5e70` a un retour C `undefined4/unaff_lr` inféré depuis l'épilogue, sans résultat métier établi dans la source. Les objets RAM ne sont pas initialisés comme dans une partie réelle ; aucun test d'exécution du jeu n'est effectué.

Revue indépendante Sol/high du planificateur, des invariants, de la garde et de la réouverture ; Luna/low des21littéraux et desquinzeopérations C. Les estimations initiales par distance entre entrées incluaient données et alignement ; les tailles de code retenues sont celles du plan et du corps Ghidra.

## Suite

**293 entrées restent absentes**, dont275Thumb ROM non définies. Sur celles-ci,206passent encore le planificateur de pools finaux (les quinze pilotes sont retirés),69sont exclues pour une raison explicite. Un lot de **148 fonctions de taille ≤128octets** est lancé :8 134octets/3 839instructions,317LDRvers294motsdepool. Copie `ghidra_thumb_literal_medium`, plan `thumb_literal_medium_plan/`. Ne pas promouvoir sans audit global, comparaison des corps et pools, puis réouverture.

Les 58candidates de plus de128octets seront examinées séparément. Les69exclusions demandent source/données/contrôle de flux spécifiques. Les autres familles demeurent2ARM ROM,12entrées de stockage rom_770 et4code/donnée.

Notion en attente ; mémoire non modifiée.
