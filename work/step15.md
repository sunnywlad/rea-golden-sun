# Étape 15 : pilote de dix entrées Thumb non définies (2026-10-16)

Projet courant : `archive:ghidra_thumb_pilot/step9.gpr`, programme `gs_us_map.elf`, copie de l'étape 14.

## Résultat

- Dix créations exactes, aucune autre entrée ajoutée, aucune perte : **2 174 fonctions**.
- Rappel des entrées de stockage ROM : **1 804/2 253 (80,07 %)**. Récupération guidée par le dépôt, baseline REA inchangée.
- **27 instructions, 62 octets** de code ajoutés. Toutes les adresses, longueurs, octets et destinations des appels concordent avec le plan source approuvé.
- Les 191 259 instructions préexistantes ont des signatures identiques après récupération. Les 23 047 unités de données définies, les noms/corps des fonctions préexistantes et tous les octets/permissions mémoire sont conservés.
- Réouverture en lecture seule et second passage : dix fonctions préexistantes, aucune création ; snapshots, exports des cibles et C identiques.

| Fonction | Octets | Résultat C |
|---|---:|---|
| Func_3808 | 2 | Retour simple conforme |
| Func_c0c4 | 2 | Retour simple conforme |
| Func_1a5a0 | 2 | Retour simple conforme |
| Func_209cc | 4 | Retourne 1, conforme |
| Func_91c3c | 2 | Retour simple conforme |
| Func_9294c | 2 | Retour simple conforme |
| Func_c9c9c | 12 | Appel réel présent, retour final mal décompilé |
| Func_d5274 | 12 | Appel réel présent, retour final mal décompilé |
| Func_d8988 | 12 | Appel réel présent, retour final mal décompilé |
| Func_d9adc | 12 | Appel réel présent, retour final mal décompilé |

Les quatre wrappers font `push {lr}`, affectent r1, appellent une fonction existante, puis `pop {r0}; bx r0`. Le C conserve l'appel avec la constante r1 attendue (1, 1, 4 et 3), mais ajoute un appel fictif via `UNRECOVERED_JUMPTABLE` avant de revenir. Deux avertissements par wrapper. Les corps et instructions sont récupérés ; leur C n'est pas validé comme équivalent. Ne pas fabriquer de table de sauts pour ces retours.

Sources et instructions exactes : `thumb_pilot_plan/plan.json`, dérivé des définitions du dépôt ; exemples `repo/rom_c9000/src/rom_d5258.s:20-26`, `rom_c91dc.s:1345-1351`, `rom_d8948.s:44-50`, `rom_d9ab8.s:28-34`.

## Garde renforcée

Dans `scripts/RecoverThumb.java`, le contrôle des sorties était conditionné à la présence d'octets de corps hors de l'intervalle autorisé. Une branche vers une destination extérieure encore indéfinie pouvait ne produire aucun de ces octets et contourner le contrôle. Le script contrôle maintenant systématiquement les sorties directes et les fallthroughs, puis vérifie les éventuelles queues connues.

Limites restantes : les sauts calculés sans destination résolue ne sont pas validés par cette boucle, et les bornes entre débuts de fonctions ne distinguent pas seules les données inline du code. Le pilote utilise donc des sources sans pools ni directives internes et compare exactement le code créé au plan. Les modifications partielles d'une tentative échouée restent possibles dans RecoverThumb ; ne promouvoir aucune copie dont les vérifications échouent.

`scripts/RecoveryAudit.java` est un export en lecture seule : signatures de toutes les instructions (octets, mode au début de l'instruction, flow, références), unités de données définies, corps/noms et empreintes/permissions mémoire. Il exporte les instructions complètes et le C de chaque cible, sans la troncature à 160 instructions de l'ancien script.

La conservation du mode est démontrée aux débuts des instructions préexistantes et à ceux des nouvelles instructions. Cet export ne prouve pas l'absence de changements de contexte sur toutes les adresses restées indéfinies.

## Preuves

- `thumb_pilot_plan/` : dix sources et limites approuvées ;
- `thumb_pilot_before/`, `thumb_pilot_after/` : audits globaux ;
- `thumb_pilot_recovery/` : résultats du script de création ;
- `thumb_pilot_repeat/`, `thumb_pilot_reopened/` : second passage et réouverture ;
- `thumb_pilot_verification.json` : vérification automatique passée ;
- scripts `plan_thumb_recovery.py`, `RecoveryAudit.java`, `verify_thumb_recovery.py`.

```sh
python3 -I scripts/verify_thumb_recovery.py work/thumb_pilot_plan/plan.json work/thumb_pilot_before work/thumb_pilot_after work/thumb_pilot_reopened work/thumb_pilot_verification.json
```

Revue indépendante Sol/high : invariants et réouverture confirmés, six feuilles conformes, quatre défauts de retour C identifiés. Luna/low a vérifié les sources, bornes et le lot suivant.

## Suite

449 entrées restent absentes, dont 433 ROM non définies (431 Thumb +2 ARM), douze cas du bloc rom_770 copié en IWRAM et quatre cas code/donnée. Un inventaire de travail `thumb_literal_free_candidates/plan.json` sélectionne 141 Thumb sans directives internes ni pseudo-littéraux. Un filtre supplémentaire taille ≤32 octets, cibles directes résolues et retours simples retient 87 candidates. Les alias `_Func_*` et `Func_af0_from_thumb` sont exclus tant que leurs adresses propres ne sont pas résolues.

Prochain lot : ces petites fonctions contrôlables depuis le source. La réparation éventuelle des quatre retours calculés doit rester une expérience séparée, guidée par la preuve du LR empilé et dépilé.

Notion en attente, aucun outil connecté disponible. Mémoire non modifiée.
