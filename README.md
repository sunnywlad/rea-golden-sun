# Golden Sun × REA

Analyse de la ROM de Golden Sun (USA) par rétro-ingénierie : récupération de fonctions Thumb/ARM dans Ghidra, puis compréhension d'un chemin de rendu de sprite jusqu'à la vérification pixel par pixel dans un émulateur.

Ce dépôt contient l'analyse, les scripts, les rapports et les empreintes. Il ne contient aucun contenu du jeu.

## Chapitres

1. **Découverte** (étapes 0 à 6) : cartographie de la ROM et mise en place du banc d'analyse.
2. **Récupération Ghidra** (étapes 7 à 26) : récupération des fonctions Thumb, résolution des alias et des appels indirects, couverture finale de 98,67 %.
3. **Sémantique SPR_000** (étapes 27 à 32) : décodage, téléversement VRAM/palette/OAM et miroir du sprite SPR_000, confirmés dans le PPU de mGBA, puis comparaison avec une référence HTML5 tierce.
4. **Rangement parallèle** (lot 33) : archivage vérifié des projets Ghidra intermédiaires et index SQLite des étapes.

État courant : `RUN_STATE.md` et `CLEAR_HANDOFF.md`. Un rapport par étape dans `work/stepNN.md`.

## Reproduire une preuve

1. Fournir sa propre ROM Golden Sun (USA, Europe), SHA1 `5c4695205413df7db52b9a184815a07783999971`, dans `work/rom/`.
2. Ouvrir le rapport de l'étape voulue : il donne la commande exacte et le SHA256 attendu du JSON de preuve.
3. Lancer le script d'audit indiqué, par exemple `scripts/audit_sprite_rgb.py` pour l'étape 30.
4. Comparer le SHA256 du JSON produit à celui du rapport.

Les étapes 31 et suivantes demandent mGBA 0.10.5 (voir `work/step31.md`). Les projets Ghidra archivés se restaurent avec `scripts/archive_projects.py restore`. L'index SQLite se régénère avec `scripts/project_index.py`.

## Règle de non-publication

Ne jamais publier :

- la ROM, un ELF dérivé, une image, un état de sauvegarde ;
- un bloc de données extrait de la ROM ;
- un projet Ghidra.

Le jeu relève du droit d'auteur de Nintendo et Camelot. L'analyse, les scripts, les rapports et les empreintes sont publiables.

Le `.gitignore` fonctionne en liste blanche, et un hook `pre-commit` refuse les extensions et chemins interdits :

```
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```
