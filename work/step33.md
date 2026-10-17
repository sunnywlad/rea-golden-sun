# Lot 33 : archive des projets Ghidra et index SQLite, 2026-10-17

## Résultat

- 27 projets Ghidra intermédiaires, rejetés ou remplacés archivés puis supprimés. Le projet retenu `work/ghidra_thumb_special_pair_scoped/step9.gpr` n'a jamais été archivé ni touché (16 entrées, empreintes inchangées au manifeste).
- Archive `work/archives/step33/projects.tar.gz`, 487 402 572 octets (465 Mio), SHA256 `5a6bfdca75c13eb506592ac19ba8ff7ba765c992f974ae87a4c34ab8a4d4c673`. Manifeste `work/archives/step33/manifest.json` (mode, mtime, taille, SHA256 de chaque membre). Reçu de suppression `work/archives/step33/prune_receipt.json`.
- Espace net libéré : 922 468 352 octets. Preuve résumée : `work/step33_archive_verification.json`.
- Aucun Ghidra lancé, aucune installation, aucun contenu de ROM ou d'image publié.

## Taxonomie des statuts

- `rejected` : un seul projet, `ghidra_thumb_literal_medium`, explicitement rejeté (`work/step21_attempt.md`).
- `replaced`, rôle `historical project` : 18 projets d'étapes remplacés par un suivant.
- `replaced`, rôle `unpromoted experiment` : 8 probes ou copies d'analyse non promues, dont `ghidra_thumb_special_pair_probe`.
- Le statut décrit la conservation du projet, pas la validité de la preuve : les rapports et preuves des étapes restent en place.

## Contrôles avant suppression

1. Revue indépendante des scripts (deux passes), corrections appliquées : reprise de `prune`, `restore` indépendant des JSON protégés et du projet retenu, nettoyage sur échec de `prepare`.
2. `verify` : SHA de l'archive, chaque membre contre les sources vivantes, projet retenu et JSON protégés.
3. Restauration d'essai de `ghidra_thumb_special_pair_probe` hors du projet, vérifiée au manifeste, `diff -rq` identique.
4. Revue indépendante de l'archive : SHA conforme, 27 noms attendus, aucun membre du projet retenu, aucun chemin absolu ni `..`, extraction complète des 27 projets identique aux sources. Verdict GO.
5. `prune` lancé par Wladimir via l'orchestrateur, `verify` repassé ensuite.

## Chemins dans les documents

- Les 48 références `work/ghidra…` vers un projet archivé dans les `.md` (`RUN_STATE.md`, `STEP8_HANDOFF.md`, `work/step9.md`, `step11` à `step25`) sont devenues `archive:NOM`. 47 occurrences subsistent : la 48e, dans `step33_status.md`, a disparu quand ce fichier a été réécrit comme clos. Pour consulter un projet : `python3 -I scripts/archive_projects.py restore --project NOM --destination DOSSIER_HORS_PROJET`.
- Seul le projet retenu garde un chemin `work/ghidra_thumb_special_pair_scoped/…`.
- Exceptions volontaires : trois JSON de preuve conservent leur chemin d'origine (`work/remaining_summary.json`, `work/step25_remaining.json` vers des projets archivés ; `work/step26_remaining.json` vers le retenu). Ce sont des preuves hachées, les modifier changerait leur empreinte. Le catalogue `work/step33_catalog.json` cite aussi les anciens chemins comme préfixes de rattachement.

## Index SQLite

`work/project_index.sqlite`, sans contenus : étapes, artefacts, statut, SHA256, liens vers rapports, preuves et revues, emplacement dans l'archive des membres archivés. Régénération depuis la racine du projet : `python3 scripts/project_index.py build`. Vérification : `python3 scripts/project_index.py verify` (reconstruit et compare octet à octet). L'index hache les documents du dépôt : toute édition après le build le rend périmé, il faut alors régénérer.
