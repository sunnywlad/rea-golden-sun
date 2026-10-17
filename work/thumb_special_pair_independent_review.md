# Revue indépendante de l'étape 26

Revue réalisée en lecture seule par agent de revue, modèle Sol, effort high. Compte rendu consigné par le principal d'après le retour final du sous-agent. Aucun lancement ou modification Ghidra par le sous-agent.

**Avis : favorable à la validation, sans réserve bloquante.**

- Deux fonctions conformes au plan, 674 instructions et 1 420 octets. Zéro avertissement de décompilation. Aucun RETURN à exporter ou appliquer.
- Ajouts limités aux deux fonctions, leurs instructions et seize unités de pool approuvées. Quatre pointeurs existants conservés. Aucun ancien objet fonction/instruction/donnée ni bloc mémoire modifié selon les snapshots audités.
- Comparaison indépendante des empreintes de `snapshot.json`, `targets.json`, `literals.json` et des deux C dans `thumb_special_pair_scoped_after/`, `thumb_special_pair_scoped_reopened/` et `thumb_special_pair_scoped_repeated/` : identiques. Deux statuts `preexisting_function` au second passage, aucune donnée recréée.
- Contrôle source/C : quatre entrées initialisées, dix entrées rendues, écritures à 0x05000000 et 0x04000000. Exports_185000 = 0x08185000 paire. SWI 0x2a et BX LR conservés.
- Les douze empreintes de provenance du plan correspondent aux fichiers locaux.
- La copie probe a créé une donnée hors pools à 0x03001c90. Cette mutation est absente de la copie scoped retenue.

Limites : les dispositions, octets, flux et décompilations persistantes sont établis. L'équivalence sémantique complète du C, le comportement BIOS du SWI et les types/noms de la table d'exports ne sont pas établis.

Sources de la revue : `thumb_special_pair_scoped_verification.json`, `thumb_special_pair_probe_differences.json`, `thumb_special_pair_scoped_repeat/targets.json`, `thumb_special_pair_scoped_reopen.console.log`, les trois dossiers d'audit final et les sources `repo/rom_9000/src/rom_1219c.s:438-1193`, `repo/rom_f9000/src/rom_f9ef8.s:958-961`, `repo/rom_185000/src/exports.s:3-6`. Les garanties du vérificateur restent celles de `scripts/verify_thumb_recovery.py`.
