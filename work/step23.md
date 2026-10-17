# Étape 23 : dix fonctions et les trampolines call_via

Projet validé après réouverture et second passage : `archive:ghidra_thumb_call_via_scoped/step9.gpr`, programme `gs_us_map.elf`. **2 546 fonctions**, rappel ROM **2 176/2 253 = 96,58 %**, soit 77 entrées absentes. Baseline REA inchangée, récupération guidée.

`resolve_call_via.py` vérifie le modèle de macro dans `lib/call_via.s`, l'alignement Thumb et la présence au linker, puis retrouve la séquence complète et unique de quinze paires BX-reg/NOP à **0x080072e4**. Les noms vont de `_call_via_r0` à `_call_via_r12`, puis sp et lr. Les adresses des trampolines sont démontrées, leurs destinations finales dépendent des registres runtime. Les quatorze premiers corps existent déjà dans Ghidra ; aucun nouveau trampoline n'est compté comme entrée de référence.

L'extension des alias est contrôlée de nouveau par le planificateur contre les octets de la ROM et le registre attendu. Les quinze cas valides passent ; quatre corruptions d'adresse, de bytes ou de registre sont rejetées. Preuves : `thumb_aliases_with_call_via.json`, `call_via_resolution_checks.json`.

Les dix fonctions devenues planifiables ajoutent 1 285 instructions et 2 788 octets. Leurs 78 LDR visent 67 mots de pool. Huit slots préexistants sont conservés et 59 unités undefined4 créées. Une copie d'analyse fournit dix retours RETURN ; seule leur application contrôlée et les pools sont ajoutés à la copie propre. Anciennes fonctions, instructions et données, mémoire et permissions inchangées. Snapshots, preuves littérales et C identiques après réouverture. Second passage sans création. Dix décompilations terminées, aucun avertissement ; quatre largeurs avec LR suspectes.

Trois sondes source/C : Func_bd7a4 effectue bien trois séquences d'écritures DMA avant l'appel via r0 chargé depuis iwram_c4. Func_d304 alloue 0x4e8 octets, programme une copie DMA depuis Func_a494, appelle via r6 puis libère le bloc. Func_55d8 réserve une zone de 0xd0 octets sur la pile, programme la copie de Func_20f4 puis appelle le trampoline via sp. Ces deux dernières routines démontrent d'autres appels à du code copié en RAM. Le C restitue les écritures DMA mais le projet n'instancie pas les corps dans ces buffers runtime. Ne pas présenter ces appels indirects comme entièrement résolus.

Preuves : `thumb_call_via_plan/`, `thumb_call_via_approved_returns.json`, `thumb_call_via_scoped_before/`, `thumb_call_via_scoped_recovery/`, `thumb_call_via_scoped_after/`, `thumb_call_via_scoped_repeat/`, `thumb_call_via_scoped_reopened/`, `thumb_call_via_scoped_verification.json` et journaux correspondants.

Suite : 59 Thumb ROM ordinaires restent, plus 2 ARM ROM, 12 entrées de stockage rom_770 et 4 cas code/donnée. Nouveau planificateur `plan_thumb_inline.py`, encore à valider dans Ghidra : 45 candidates à pools explicites ou internes, avec corps en plusieurs plages. Pilote de dix fonctions dans `thumb_inline_pilot_plan/` : 222 instructions, 470 octets et 39 mots de pool. La promotion exige les mêmes invariants globaux et la conservation des pools hors corps.

Revue finale par le principal, sous-agents limités en usage. Notion non synchronisé depuis l'étape 13. Mémoire Claude inchangée.
