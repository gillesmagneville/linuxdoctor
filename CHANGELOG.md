<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté

- Module **storage** : usage espace disque (`df -kPT`) et usage inodes
  (`df -iPT`), un finding par système de fichiers réel (les
  pseudo-systèmes de fichiers — tmpfs, proc, overlay, etc. — sont exclus),
  4 paliers de sévérité (< 80 % / 80-89 % / 90-94 % / ≥ 95 %).
- `ModuleError::Command`, pour les modules qui exécutent une commande
  externe plutôt que de lire un fichier.

## [0.1.0] - 2026-08-04

### Ajouté

- Moteur core : `Context` (lecture `/proc`, `/sys`, `/etc/os-release`), trait
  `Module`, `engine` avec isolation des erreurs par module.
- Modèles canoniques : `Severity` (4 niveaux), `Confidence` (%, raison),
  `Category`, `Finding`.
- Module **memory** : `vm.swappiness`, pression de swap (3 paliers), mémoire
  critique.
- Module **cpu** : informations CPU, pression de charge (3 paliers),
  surcharge soutenue (fenêtres 1/5/15 min).
- Trois sorties : terminal (couleurs ANSI), JSON, TUI interactif (ratatui).
- 35 tests (31 unitaires + 4 d'intégration), tous fixture-driven — aucun
  test ne dépend de l'état réel du système.
- `PROJECT_CONTEXT.md` (vision, principes) et `ARCHITECTURE.md` (contrat
  technique canonique).
