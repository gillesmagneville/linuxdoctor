<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contribuer à LinuxDoctor

Merci de l'intérêt porté à ce projet ! Ce document explique comment
signaler un problème, proposer une amélioration, ou contribuer du code.

## Signaler un bug

Ouvrez une issue en précisant :

- la distribution et la version du noyau (`uname -r`, `/etc/os-release`)
- la commande exacte utilisée (`linuxdoctor audit`, `linuxdoctor tui`, ...)
- le comportement observé vs attendu
- si possible, la sortie de `linuxdoctor audit --output json`

## Proposer une amélioration

Ouvrez une issue décrivant le besoin avant d'écrire du code, en particulier
pour un nouveau module de diagnostic — c'est plus facile de discuter des
seuils et de la sévérité avant qu'après.

## Contribuer du code

1. Forkez le dépôt et créez une branche depuis `main`.
2. Vérifiez que tout passe avant de proposer une pull request :

   ```bash
   cargo build --locked
   cargo test --locked
   cargo fmt --check
   cargo clippy --locked --all-targets -- -D warnings
   ```

   Ces quatre commandes sont exactement celles de l'intégration continue
   (`.github/workflows/ci.yml`), qui les exécute aussi avec Rust 1.75, la
   version minimale supportée. N'utilisez donc pas d'API plus récente que
   1.75 (par exemple `Option::is_none_or`, stabilisée en 1.82).

3. Décrivez dans la pull request ce qui change et pourquoi.

## Ajouter un nouveau module de diagnostic

C'est le type de contribution le plus courant, et l'architecture est conçue
pour que ça n'implique de toucher qu'un seul dossier. Pour un module
`<name>` :

1. Créez `src/modules/<name>/{mod.rs, collect.rs, analyze.rs}` en suivant
   exactement le patron de `src/modules/memory/` ou `src/modules/cpu/` :
   - `collect.rs` — uniquement de la lecture (E/S). Aucune interprétation.
   - `analyze.rs` — fonctions pures `RawData -> Vec<Finding>`, testables
     sans toucher au système de fichiers.
2. Ajoutez une ligne dans `all_modules()` (`src/modules/mod.rs`).
3. Ajoutez une ligne de description du module dans `module_summary()`
   (`src/manpage.rs`) : c'est ce qui apparaît dans la section MODULES de
   `man linuxdoctor`, et un test échoue tant qu'elle manque.
4. Rien d'autre ne doit changer — ni le moteur, ni `Context`, ni les sorties
   terminal/JSON/TUI ; `--modules`, la complétion du shell et la page de
   manuel connaissent le nouveau module automatiquement.

Voir `ARCHITECTURE.md` pour le contrat exact (types, sévérité, confiance).

### Lancer des commandes externes

Passez toujours par `core::command::command()`, jamais par
`std::process::Command` : cela force la locale `C` **et** applique une
limite de temps (10 s par défaut, réglable par `--timeout`).

- Outil susceptible d'être lent même en bonne santé (réveil d'un disque,
  initialisation d'un pilote) : ajoutez `.slow()` (double délai).
- Plusieurs appels au même outil (par exemple une commande par VM) :
  utilisez un `ToolSession` — au premier délai dépassé, les appels suivants
  sont ignorés au lieu d'attendre chacun leur propre limite.
- Une commande par élément indépendant (un disque, une carte) :
  `core::parallel::parallel_map` les lance en parallèle, résultats dans
  l'ordre.
- Une commande arrêtée pour délai dépassé est consignée automatiquement
  dans les `notes` du module (« données incomplètes ») ; rien à faire de
  plus côté module. Traitez simplement l'erreur comme n'importe quel
  « l'outil n'a pas donné de données ».

### Règles pour chaque `Finding`

- Chaque diagnostic doit être appuyé par une preuve observable (`evidence`),
  pas une supposition.
- La confiance ne doit jamais dépasser ce que l'évidence justifie
  réellement (voir l'échelle dans `ARCHITECTURE.md`).
- Le texte d'explication doit enseigner quelque chose, pas juste répéter la
  donnée brute — voir « Explain instead of dumping data » dans
  `PROJECT_CONTEXT.md`.
- Évitez le ton alarmiste. « Ce n'est pas nécessairement un problème » est
  souvent la phrase juste.

## Style de code

- `cargo fmt` avant de proposer une pull request.
- Rust stable uniquement, pas de fonctionnalités nightly.
- Un module ne doit jamais appeler un autre module directement — uniquement
  via le `Context` partagé en lecture seule.
- Toute nouvelle dépendance doit se justifier (voir « Dependency
  Philosophy » dans `ARCHITECTURE.md`) — la bibliothèque standard est
  toujours préférée quand c'est raisonnable.

## Documentation

Si votre changement modifie le comportement observable (nouveau module,
nouvelle option CLI, nouveau format de sortie), mettez à jour
`CHANGELOG.md` dans la même pull request, sous `[Non publié]`.

## Questions

Pour toute question qui ne rentre pas dans les cas ci-dessus, ouvrez
simplement une issue.

## Licence

En contribuant, vous acceptez que vos contributions soient publiées sous la
même licence que le projet (GPL-3.0-only).
