# Étape 21 : 148 fonctions à pools finaux, variante conservatrice validée

Projet retenu : `archive:ghidra_thumb_literal_medium_scoped/step9.gpr`, programme `gs_us_map.elf`. Passage de 2 330 à **2 478 fonctions** ; rappel des entrées ROM de référence : **2 108/2 253 = 93,56 %**. La baseline REA reste 1 914 procédures et 1 544 entrées reconnues. Les nouvelles fonctions sont récupérées avec la référence, sans revendication de découverte autonome.

Le premier essai `ghidra_thumb_literal_medium` est rejeté et conservé comme preuve. Son analyse ARM a supprimé trois anciennes unités de données et ajouté douze unités hors pools. Voir `step21_attempt.md`. Aucun octet ROM ou RAM n'avait changé : il s'agissait d'annotations.

La correction repart d'une copie propre de l'étape 20. L'analyseur ARM du premier essai fournit 129 sites de retour. `ExportApprovedReturns.java` lie cet export au SHA256 du plan et vérifie les corps, octets, TMode, P-code et motifs source adjacents `pop {rN}; bx rN`. Après récupération des fonctions sans analyse automatique, `ApplyApprovedAnalysis.java` applique seulement ces RETURN et crée les mots de pool encore indéfinis. Toute donnée déjà définie, même partiellement dans un slot, est conservée. Pas d'effacement, pas d'analyse générale, pas de transaction imbriquée.

Résultat vérifié :

- 148 fonctions, 3 839 instructions et 8 134 octets de code exacts par rapport au plan source/ROM.
- 317 lectures littérales sur 294 mots distincts. Exactement 294 nouvelles unités undefined4, toutes sur les pools approuvés, sans chevauchement d'instructions.
- Toutes les anciennes fonctions, instructions, données définies, empreintes mémoire et permissions conservées. Le script contrôle aussi les signatures avant/après son application.
- Fermeture et réouverture : snapshots, preuves littérales et C identiques. Deuxième passage : 129 retours et 294 slots préexistants, aucune nouvelle modification.
- Les 148 décompilations terminent sans avertissement. Les 148 C sont identiques octet pour octet à ceux de la copie ayant subi l'analyse ARM complète du lot, malgré la conservation des anciennes annotations.

Sondes C confrontées au source : Func_4718 et Func_473c bornent respectivement le paramètre à 1..8 et 1..10 avant leurs appels et la soustraction d'adresse ; Func_c454 conserve l'appel puis l'écriture de paramètre à +0x68 ; Func_4198 conserve la recherche dans vingt entrées espacées de huit octets et les accès halfword à REG_IME. Son écriture inhabituelle du bas de l'adresse de REG_IME provient bien du `strh r3,[r3]` source. Son retour CONCAT44(LR,index) reste un artefact de signature inférée.

Limites : 28 C présentent une largeur de retour avec LR suspecte et 99 retournent directement unaff_lr. Ce relevé n'établit pas leurs prototypes réels. Aucun prototype forcé. Les sondes ne prouvent pas l'équivalence sémantique de tous les C. La revue indépendante finale n'a pas pu être exécutée : les deux sous-agents ont atteint leur limite d'utilisation. Le principal a relu les scripts et exécuté tous les contrôles.

Preuves : `thumb_literal_medium_plan/`, `thumb_literal_medium_approved_returns.json`, `thumb_literal_medium_scoped_before/`, `thumb_literal_medium_scoped_recovery/`, `thumb_literal_medium_scoped_after/`, `thumb_literal_medium_scoped_repeat/`, `thumb_literal_medium_scoped_reopened/`, `thumb_literal_medium_scoped_verification.json`, `thumb_literal_medium_c_review.json` et journaux correspondants.

Restent 145 entrées de référence : 127 Thumb ROM ordinaires, 2 ARM ROM, 12 entrées de stockage rom_770 exécutées en IWRAM, 4 cas code/donnée. Parmi les 127 Thumb, le plan suivant sélectionne 58 fonctions à pools finaux plus longues : 14 420 octets, 6 625 instructions et 306 mots littéraux. Les 69 autres demandent un traitement distinct.

Notion non synchronisé depuis l'étape 13 : aucun outil connecté disponible. Les fichiers locaux font foi. Mémoire Claude inchangée.
