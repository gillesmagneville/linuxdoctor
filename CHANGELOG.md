<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté

- **Rapport Markdown** : `linuxdoctor audit --output markdown` (alias `md`)
  produit un document complet — en-tête (machine, date, version), tableau
  récapitulatif par module, puis chaque constat avec sa gravité, sa
  confiance, ses preuves, son explication et ses recommandations (étapes
  numérotées, commandes dans des blocs `bash`). Les tableaux alignés par
  les modules sont rendus en blocs de code pour garder leurs colonnes. Tout
  texte venant de la machine (nom d'hôte, noms de processus, messages
  d'erreur des outils) est échappé : il ne peut pas casser la mise en page
  ni injecter de balise.
- **Rapport HTML** : `linuxdoctor audit --output html` produit une page
  unique et autonome (CSS intégré, aucun JavaScript, aucun fichier ni accès
  réseau externe), thèmes clair et sombre, lisible jusque sur téléphone,
  avec des constats repliables (ouverts à partir de Warning). La gravité
  n'est jamais indiquée par la seule couleur. Les chaînes dynamiques sont
  échappées et la page porte une `Content-Security-Policy` stricte.
- **`--min-severity info|warning|error|critical`** (`audit`) : filtre
  d'**affichage** qui masque les constats moins graves. Il ne cache jamais
  un module en erreur, ignoré ou aux données incomplètes, et tous les
  formats indiquent combien de constats ont été masqués (ligne finale en
  terminal, bandeau « Filtered view » en Markdown et HTML, objet `filter`
  en JSON).
- **`--fail-on info|warning|error|critical|never`** (`audit`) : seuil du
  **code de sortie**. Le code 1 est renvoyé dès qu'un constat atteint le
  seuil ; `never` renvoie toujours 0. Le verdict porte sur le rapport
  **complet**, avant le filtre d'affichage : masquer des constats ne peut
  pas transformer un audit en échec en audit réussi. Quand l'option est
  donnée explicitement, une phrase sur la sortie d'erreur explique l'échec
  (la sortie standard reste un JSON/Markdown/HTML propre).
- **Clé `filter` dans le JSON** (uniquement quand `--min-severity` est
  utilisé) : `{"min_severity": "...", "hidden_findings": N}`, juste après
  `schema_version`. Ajout d'un champ : `schema_version` reste à 1.
- Modules `core::gate` (décision de réussite/échec), `output::common`
  (éléments partagés par les rendus-documents) et `output::markdown` /
  `output::html`.

### Modifié

- Le code de sortie passe par `core::gate`. Sans `--fail-on`, le comportement
  est inchangé : code 1 dès qu'un constat Error ou Critical existe (et
  pour une erreur d'exécution), code 2 pour une erreur d'utilisation.
  `linuxdoctor tui` garde ce seuil par défaut et n'a pas les nouvelles options.
- Un module dont un outil a été interrompu (« données incomplètes ») est
  présenté en Markdown/HTML comme « ⚠ Incomplete data » et non comme « OK »,
  comme dans le terminal.

### Tests

- `tests/export_and_gate.rs` : 14 tests de bout en bout avec le vrai binaire
  (formats Markdown/HTML, alias `md`, `--min-severity`, `--fail-on`, code de
  sortie pour chaque seuil, le filtre d'affichage ne change jamais le code de
  sortie, erreurs d'utilisation = code 2).
- Tests unitaires des rendus (échappement de contenu hostile, balises
  autorisées dans le HTML, structure des tableaux/blocs de code), de
  `core::gate`, du filtrage du rapport et de l'analyse des arguments.
- Les rendus ont aussi été validés avec un analyseur CommonMark, un analyseur
  HTML5 strict et un navigateur sans interface (clair, sombre, largeur de
  téléphone).

## 2026-10-14

### Ajouté

- **`schema_version` dans le JSON** : `linuxdoctor audit --output json`
  commence par `"schema_version": 1`. Règle : ajouter un champ ne change
  pas la version (les lecteurs ignorent les clés inconnues) ; supprimer,
  renommer ou changer le sens d'un champ l'incrémente. Les autres champs
  ne bougent pas. Constante `output::json::SCHEMA_VERSION`, documentée
  dans `ARCHITECTURE.md` (« Schema version »).
- **Intégration continue GitHub Actions** (`.github/workflows/ci.yml`),
  sur chaque push vers `main` et chaque pull request : `cargo fmt
  --check`, `cargo clippy --all-targets -- -D warnings` (stable), puis
  `cargo build` et `cargo test` avec Rust 1.75.0 (version minimale) et
  stable. Tout est lancé avec `--locked` pour respecter les versions
  figées de `Cargo.lock`. Le format v4 de `Cargo.lock` (Cargo ≥ 1.78) est
  illisible par Cargo 1.75 : la tâche 1.75 repasse l'en-tête en v3 dans
  l'exécution de CI uniquement — avec des dépendances 100 % « registry »,
  le contenu est identique.
- **Module mémoire entièrement refondu** : 13 contrôles (`MEM001` à
  `MEM013`) répartis en six thèmes, qui sont aussi les sous-menus du TUI :
  - *Used memory* : `MEM007` détaille la mémoire utilisée par nature
    (anonyme des programmes, cache, mémoire partagée, noyau) et les
    principaux consommateurs par mémoire privée (RssAnon), regroupés par
    nom de programme ; `MEM004` (vue d'ensemble) et `MEM003` (mémoire
    critique) sont conservés.
  - *Page cache* : `MEM008` (cache réellement récupérable, mythe de
    `drop_caches`, `vfs_cache_pressure`) ; `MEM005` (pages sales).
  - *Shared memory* : `MEM006` — `Shmem`, remplissage de tmpfs et
    `/dev/shm`, segments SysV orphelins (`nattch = 0`) avec la commande
    `ipcrm -m` pour les supprimer.
  - *Swap* : `MEM001` (swappiness jugé selon le type de swap : zram, SSD,
    disque rotatif), `MEM002` (activité de swap, programmes les plus
    swappés, trafic de swap depuis le démarrage), `MEM010` (configuration :
    absence de swap, priorité zram, taux de compression, algorithme,
    zswap + zram redondants, `page-cluster`).
  - *Pressure* : `MEM009` — PSI (`/proc/pressure/memory`), éliminations
    OOM depuis le démarrage, récupération directe.
  - *Kernel tuning* : `MEM011` (surallocation et `CommitLimit`),
    `MEM012` (Transparent Huge Pages, hugepages réservées inutilisées),
    `MEM013` (slab non récupérable, tables de pages, ZFS ARC,
    `min_free_kbytes`, ballon).
- **Recommandations en étapes numérotées**, avec les commandes sur leurs
  propres lignes (jamais exécutées par l'outil), dimensionnées pour la
  machine : taille du fichier de swap suggérée, `vm.overcommit_ratio`
  laissant 20 % de marge, plafond `zfs_arc_max`, etc. Le TUI affiche le
  titre « Recommendation: » en gras et les commandes en cyan ; la sortie
  terminal les indente sous un titre en gras.
- Nouvelles sources de données, toutes facultatives : `/proc/vmstat`,
  `/proc/pressure/memory`, `/proc/swaps`, `/sys/block/zram*`,
  `/proc/<pid>/status`, `/proc/sysvipc/shm`, `df -t tmpfs`, fichiers de
  THP et de `vm.*`, `arcstats` de ZFS. Une source absente supprime
  seulement les contrôles qui en dépendent. L'audit mémoire reste
  rapide (~35 ms, ~60 ms avec 2000 processus).
- `MemoryRawData::from_meminfo()` : construit les données à partir du
  seul texte de `/proc/meminfo` (utile pour les tests et les exemples).
- Page d'accueil du module : les problèmes (Warning et plus) passent
  en premier, la vue d'ensemble `MEM004` ferme la page.

### Changé

- `Cargo.toml` déclare `rust-version = "1.75"` : une chaîne d'outils plus
  ancienne s'arrête avec un message clair au lieu d'erreurs de compilation
  obscures. Les scripts de construction ne sont pas affectés (ils ne
  réécrivent que la ligne `version = ` en début de ligne).
- **Mise en forme et Clippy sur tout le projet** : `cargo fmt` appliqué à
  l'ensemble du code (19 fichiers reformatés, sans changement de
  comportement) et les 7 avertissements Clippy qui restaient corrigés
  (`trim()` inutile avant `split_whitespace()`, `splitn(2, …)` remplacé
  par `split_once`, `format!` sans argument, fermeture inutile dans
  `cli.rs`). `cargo clippy --all-targets -- -D warnings` passe sans
  avertissement ; la mention « avertissements Clippy » de la section
  « Limites connues » ci-dessous est donc réglée.
- **Sémantique de « Cached » corrigée** : la ligne `Cached` de
  `/proc/meminfo` contient la mémoire partagée (`Shmem`) ; le cache
  « de fichiers » est désormais calculé sans elle, et la mémoire
  récupérable compte buffers, cache de fichiers et slab récupérable.
- Les seuils de pages sales sont calculés sur la mémoire « dirtyable »
  (libre + cache de fichiers) et non sur la RAM totale, avec trois zones :
  écriture en arrière-plan (Info), ralentissement des écritures
  (Warning), blocage (Error). Les réglages `dirty_*_bytes` l'emportent
  sur les ratios. Une limite en pourcentage qui dépasse 4 GiB sur un
  gros serveur est signalée en Info avec des plafonds optionnels.
- Un swap rempli à 80 % ou plus est maintenant un Warning (avant : Info
  même à 97 %).
- La mémoire partagée attachée à des segments SysV (PostgreSQL, Oracle…)
  est considérée comme légitime et n'entre plus dans le jugement en
  pourcentage.
- `src/modules/memory/analyze.rs` n'est plus qu'un coordinateur : la
  logique vit dans `used`, `cache`, `shared`, `swap`, `pressure`,
  `tuning`, `kernel` et `format`.

### Corrigé

- `tests/hung_tools.rs` : les faux outils définissent aussi `docker` et
  `podman` (sortie 127). Avec un vrai `docker` lent, le test pouvait
  dépasser la limite de 1 s et échouer de façon intermittente.

### Tests

- 4 tests unitaires pour l'enveloppe JSON (`schema_version` présent,
  numérique, premier champ, seul ajout au niveau supérieur) et 2 tests de
  bout en bout avec le vrai binaire (`tests/json_schema.rs`).
- 219 tests unitaires pour le module mémoire, dont des invariants vérifiés sur huit scénarios : confiance
  d'au moins 60 %, étapes numérotées pour tout résultat au-dessus d'Info,
  aucun `{}` résiduel, pas d'unités MiB/GiB, JSON sérialisable. 10 tests
  d'intégration (`tests/memory_module.rs`) : serveur sain de 64 Go,
  poste saturé, zram mal priorisé, segments SysV orphelins, ZFS ARC,
  rendu terminal et JSON. Total : 567 tests de bibliothèque, 7 CLI,
  45 d'intégration (619, tous verts).
- Vérifié sur un système réel : segment SysV orphelin, fichier de 900 Mo
  dans `/dev/shm`, processus de 3 Go, vraie élimination OOM, vrai swap
  (fichier de 256 Mo) et rendu dans un vrai terminal (TUI sous tmux).

### Limites connues

- La version minimale de Rust (1.75) n'a pas pu être vérifiée ici (le
  compilateur local est en 1.97) ; le nouveau code évite les API
  postérieures connues (par exemple `Option::is_none_or`).
- Compatibilité avec Rust 1.75 : non vérifiable en local (rustup bloqué dans
  l'environnement de développement), mais **vérifiée par l'intégration
  continue** — la tâche « Tests (Rust 1.75.0) » est passée au vert sur la
  pull request #1, comme les tâches stable, fmt et Clippy.

## 2026-10-07

### Ajouté

- **Délai maximal pour chaque commande externe.** Jusqu'ici, un `virsh`
  dont le démon ne répondait plus, un `smartctl` sur un disque en
  difficulté ou un `nvidia-smi` bloqué figeait tout l'audit — et le TUI
  avec lui, sans message. Chaque commande lancée via
  `core::command::command()` a maintenant une limite de **10 s** par
  défaut, réglable avec `--timeout <secondes>` (1 à 3600, avant ou après
  la sous-commande). `smartctl`, `nvidia-smi` et `docker/podman stats`
  disposent du double (réveil d'un disque en veille, initialisation du
  pilote). Au-delà, la commande est tuée et l'audit continue.
- **Données incomplètes visibles, jamais silencieuses.** Un délai dépassé
  est consigné dans un nouveau champ `notes` du résultat de chaque
  module (présent dans le JSON). Le mode terminal affiche
  `↳ incomplete data: 'virsh list --all --name' did not finish within
  10s and was stopped` sous le module ; le TUI affiche un bandeau jaune
  sur la page du module, avec le rappel de `--timeout`. Un module avec
  des notes reçoit un ⚠ au lieu d'un ✓ : une coche verte affirmerait plus
  que ce que les données permettent. Les notes sont rattachées au bon
  module même quand les modules tournent en parallèle (suivi par thread).
- **Garde-fou par outil (`ToolSession`).** Les ~9 appels `virsh` faits
  pour chaque VM, et les 3 appels `nvidia-smi`, partagent une session :
  au premier délai dépassé, les appels suivants sont ignorés. Un
  `libvirtd` bloqué coûte une limite, pas (nombre de VM × 9) limites.
- **Modules exécutés en parallèle** (`std::thread::scope`, aucune
  dépendance ajoutée) : un module lent ne retarde plus que lui-même.
  L'ordre du menu et des résultats est inchangé. Une erreur **ou une
  panique** dans un module est isolée dans son `error` ; si le système
  refuse un thread, le module tourne en ligne plutôt que d'être perdu.
- **Requêtes SMART en parallèle** (`core::parallel::parallel_map`, 8 à la
  fois au plus, résultats dans l'ordre des disques) : un serveur à une
  douzaine de disques n'attend plus chaque `smartctl` l'un après l'autre.
- Tests : 33 nouveaux tests unitaires (30 bibliothèque + 3 CLI : limite de temps, sortie
  volumineuse sans interblocage, petit-enfant gardant le tube ouvert,
  ordre des résultats, concurrence réelle et plafond de threads,
  isolation d'une panique, attribution des notes au bon module,
  progression, `--timeout`, rendus terminal/TUI) et 3 tests de bout en
  bout (`tests/hung_tools.rs`) qui lancent le vrai binaire contre de
  faux `virsh` qui se bloquent. Contrôle par mutation : sans le
  garde-fou de session, le test « blocage en cours de route » échoue
  (6,1 s au lieu de 1,2 s).

### Changé

- `core::command::command()` renvoie désormais un `Cmd` (même usage :
  `arg`, `args`, `output`, plus `timeout` et `slow`) au lieu d'un
  `std::process::Command`. Une commande trop lente renvoie une erreur
  `ErrorKind::TimedOut` ; « outil absent » reste `NotFound`.
- Le rappel de progression est maintenant
  `on_progress(terminés, total, en_cours)`. L'écran de démarrage/
  rafraîchissement du TUI affiche par exemple
  `10/11 done — waiting for virtualization` : avec des modules
  simultanés il n'y a plus un seul « module courant ».
- Le JSON gagne un champ `notes` par module (ajout compatible : les
  champs existants ne bougent pas).

### Mesures (honnêtes)

Binaire release, mêmes faux outils lents (`virsh`, `smartctl` sur 6
disques, `mokutil`, `dmesg`, 1 s chacun) :

| Version | Durée de l'audit |
|---|---|
| avant (séquentiel) | 10,1 s |
| modules en parallèle seulement | 6,1 s |
| + SMART en parallèle | **2,0 s** |

Avec les outils réels de cette machine d'essai (rapides, pas de disque
physique ni de GPU), la durée est la même, ~0,1 s : le gain n'apparaît
que lorsque des outils sont réellement lents, ce qui est précisément le
cas qui posait problème. Le reste de ces 2 s est le module `firmware`,
qui enchaîne `mokutil` puis `dmesg` en interne.

### Limites connues

- Seul le processus lancé est tué à l'échéance, pas ses éventuels
  descendants ; ils n'empêchent toutefois jamais l'audit de continuer
  (les tubes sont abandonnés à l'échéance).
- Un processus bloqué en attente d'E/S non interruptible (montage NFS
  mort, disque défaillant) ne peut pas être tué par le noyau avant le
  retour de l'E/S : l'audit continue sans l'attendre, mais le processus
  peut rester en sommeil disque jusqu'à son retour.
- Le fichier `config.toml` décrit dans ARCHITECTURE.md n'existe toujours
  pas ; `--timeout` est pour l'instant le seul réglage.
- Cette étape a été compilée et testée avec `rustc` 1.97 (la 1.75 n'était
  pas installable dans l'environnement d'essai). Le code nouveau n'utilise
  que des API stables depuis ≤ 1.75 (`thread::scope`, `spawn_scoped`,
  `thread_local!` avec `const`, `recv_timeout`), vérifié par relecture ;
  la CI prévue à l'étape suivante compilera explicitement avec 1.75.

## 2026-09-14

### Changé — politique de gestion de version revue

Correction de la correction précédente : la resynchronisation manuelle
faite le 10/09 (voir plus bas) traitait le mauvais symptôme. Signalé
par l'utilisateur : ce n'est pas que ses builds locaux dépassaient ce
qui était livré ici — c'est l'inverse. Son `VERSION` local restait
bloqué à `0.4.0` malgré plusieurs lancements de `build-deb.sh` avec
des options d'incrément, alors qu'il aurait dû atteindre `1.3.0`.

Vérifié en profondeur avant de conclure : la logique d'incrémentation
elle-même fonctionne correctement — 4 lancements successifs réels
(`--major`, `--minor`, `--minor`, `--minor`) enchaînent bien
`0.4.0 → 1.0.0 → 1.1.0 → 1.2.0 → 1.3.0`, confirmant qu'un incrément se
compose correctement d'un lancement à l'autre. La cause la plus
probable côté utilisateur : `fpm` n'est pas un paquet système, il
s'installe via `gem install --user-install fpm` — s'il n'est pas
présent, chaque lancement échoue proprement à la vérification des
outils, avec un message clair, **sans jamais toucher `VERSION`**
(comportement volontaire : aucun incrément sans build entièrement
réussi). Confirmé par un test dédié : lancement sans `fpm` disponible
→ échec propre, `VERSION` inchangé, exactement le symptôme rapporté.

**Décision** : `VERSION` (et le champ `version` de `Cargo.toml`) ne
sont plus inclus dans les livraisons de code source à partir de
maintenant. Ce fichier appartient exclusivement à l'environnement local
de l'utilisateur, avancé uniquement par ses propres lancements réussis
de `build-deb.sh`/`build-rpm.sh` — le faire avancer aussi côté
livraison créait exactement le problème inverse de celui visé : chaque
nouvelle livraison écrasait la progression locale de l'utilisateur.
Vérifié que les deux scripts démarrent proprement à `0.1.0` en
l'absence totale de `VERSION` (cas d'une extraction neuve). Les entrées
de ce changelog utiliseront désormais une date plutôt qu'un numéro de
version inventé ici, pour la même raison — ce numéro n'est plus de mon
ressort.

### Ajouté

- Nouveau module **firmware**, placé dans le menu juste après `kernel`
  et avant `virtualization` (la virtualisation activée au BIOS est un
  prérequis logique de ce que fait ce dernier) — vérifié en conditions
  réelles, pas seulement dans le code.
  - **Réponse honnête à la question posée** : non, il n'existe aucune
    API Linux universelle pour lire l'intégralité du menu de
    configuration BIOS/UEFI (courbes de ventilateur, profils XMP,
    ordre de démarrage détaillé, bascule CSM) — ce module ne prétend
    pas le faire. Certains constructeurs (Dell, Lenovo) ont des outils
    propriétaires pour une partie de leurs réglages spécifiques ; pas
    couvert ici, périmètre bien plus vaste et fragile.
  - **Ce qui est couvert, entièrement vérifié avant codage** : identité
    du firmware (fabricant/version/date/révision) via
    `/sys/class/dmi/id/*` — lecture sysfs pure, aucun outil externe,
    aucun root requis (confirmé via plusieurs sources indépendantes) ;
    mode de démarrage (UEFI vs Legacy/CSM) et état du Secure Boot (via
    `mokutil`, laissé "indéterminé" plutôt que deviné depuis les
    octets bruts de la variable EFI quand l'outil est absent — les
    sources divergeaient sur l'offset exact) ; extensions de
    virtualisation (VT-x/AMD-V) ; IOMMU/VT-d ; présence d'un TPM.
  - **Virtualisation activée au BIOS** : la sévérité n'augmente que
    lorsque `dmesg` confirme explicitement "disabled by bios" — la
    simple absence du flag `vmx`/`svm` reste ambiguë (CPU sans support
    réel vs désactivé au BIOS, deux cas indiscernables depuis cette
    seule donnée) et ne fait donc jamais monter la sévérité seule,
    juste baisser la confiance en conséquence.
  - **IOMMU/VT-d** : croise le paramètre noyau demandé (`/proc/cmdline`)
    avec l'état réellement actif (`/sys/class/iommu/`) — un
    paramètre demandé mais jamais actif signale un blocage au niveau
    BIOS, avec un renvoi direct vers les modules GPU (passthrough
    SR-IOV) et Virtualization (VFIO) déjà existants.
  - Nouvelle catégorie canonique `Firmware`, ajoutée à l'enum et à la
    liste de vision de `PROJECT_CONTEXT.md` (même précédent que pour
    GPU).

## [1.3.0] - 2026-09-10

### Note sur ce saut de version (0.4.0 → 1.3.0)

Pas de changement de code dans cette entrée — resynchronisation de
`VERSION`/`Cargo.toml` uniquement. Signalé comme incohérent par
l'utilisateur : `VERSION` restait à `0.4.0` alors qu'il en était à
`1.3.0` sur sa propre machine. Cause identifiée : deux mécanismes
d'incrémentation distincts et non synchronisés entre eux —
`build-deb.sh`/`build-rpm.sh` incrémentent `VERSION` directement sur la
machine où ils sont lancés (localement, indépendamment de toute
conversation), tandis que chaque livraison faite ici incrémente sa
propre copie sans visibilité sur l'état local de l'utilisateur.
Resynchronisé sur `1.3.0` (l'état local rapporté) plutôt que de
continuer sur une base désynchronisée à `0.4.0`.

## [0.4.0] - 2026-09-10

### Ajouté

- Module **gpu** enrichi avec plusieurs informations supplémentaires
  demandées explicitement — chacune vérifiée avant d'être codée, avec
  un piège de fiabilité réel trouvé et intégré honnêtement plutôt que
  passé sous silence.
  - **Horloges cœur/mémoire séparées**, pour les deux fabricants —
    NVIDIA via `clocks.gr`/`clocks.mem`, AMD via `pp_dpm_sclk`/
    `pp_dpm_mclk` (la ligne marquée d'un astérisque indique l'état
    actif parmi tous les états DPM disponibles).
  - **Vitesse et largeur du port PCIe** (actuel + maximum), lues de
    façon générique via les fichiers sysfs PCI standards
    (`current_link_speed` etc.) — applicable à n'importe quel
    fabricant, pas seulement AMD/NVIDIA. **Piège de fiabilité trouvé et
    documenté** : un ticket GitHub réel sur `amdgpu_top` rapporte que
    `current_link_speed` peut parfois afficher la valeur *maximale*
    plutôt qu'une vraie lecture en temps réel sur certaines
    combinaisons noyau/pilote — le texte produit porte cette mise en
    garde plutôt que de prétendre à une précision non garantie, et
    cette seule donnée ne fait jamais monter la sévérité.
  - **Version CUDA maximale supportée par le driver** (`GPU001`,
    depuis l'en-tête texte de `nvidia-smi` — pas un champ de requête
    `--query-gpu`, contrairement à ce qu'on pourrait attendre).
    Explicitement étiquetée comme telle et distinguée de la version du
    *toolkit* CUDA réellement installée (`nvcc --version`) — une
    confusion documentée comme fréquente dans plusieurs sources
    indépendantes trouvées pendant la recherche.
  - **Nombre de cœurs CUDA — délibérément absent.** Confirmé non exposé
    par `nvidia-smi`, y compris via `compute_cap` (qui donne
    l'architecture, pas le nombre de cœurs, et peut en plus faire
    échouer la requête entière sur d'anciens drivers). C'est une
    caractéristique matérielle fixe par modèle ; l'ajouter aurait
    nécessité une table de correspondance modèle→specs qui deviendrait
    fausse dès la sortie d'une nouvelle carte — refusé plutôt que
    deviné.
  - Petite correction cosmétique au passage : le nom du fabricant ne se
    répète plus quand la description du GPU l'inclut déjà (ex. "NVIDIA
    NVIDIA GeForce RTX 4090" → "NVIDIA GeForce RTX 4090").



### Ajouté

- Nouveau module **gpu**, placé dans le menu juste après `numa` (avec
  les autres ressources matérielles : memory/cpu/numa/gpu/storage,
  avant les modules services/diagnostic) — vérifié en conditions
  réelles, pas seulement dans le code.
  - Détection générique via `/sys/class/drm/card*` (filtré des entrées
    de connecteur type `card0-DP-1`), classification du fabricant à
    partir du `PCI_ID` lu dans `uevent` (`0x10de` NVIDIA, `0x1002`
    AMD/ATI — distinct de `0x1022`, l'ID PCI propre d'AMD pour ses
    CPU/chipsets, volontairement pas confondu avec un GPU — `0x8086`
    Intel).
  - **AMD** : entièrement via sysfs direct, aucun outil externe —
    `mem_info_vram_total`/`used` (octets), `gpu_busy_percent`/
    `mem_busy_percent` (%), `hwmon/*/temp1_input` (**millidegrés**),
    `power1_average` (**microwatts**), `fan1_input` (RPM). Chaque
    chemin et unité confirmé via la documentation noyau elle-même et
    plusieurs captures réelles indépendantes (dont la bibliothèque Rust
    `amdgpu-sysfs`), pas supposé.
  - **NVIDIA** : un seul appel `nvidia-smi --query-gpu=...
    --format=csv,noheader,nounits` couvrant toutes les cartes NVIDIA à
    la fois, corrélées aux entrées DRM par adresse PCI normalisée
    (`nvidia-smi` utilise un domaine à 8 chiffres hex, le reste du
    projet à 4 — normalisation dédiée, testée). Cas géré explicitement :
    `power.draw` peut valoir littéralement `"[Not Supported]"` selon
    l'état d'alimentation de la carte. Remontée des process consommant
    du GPU (`--query-compute-apps`) uniquement quand une seule carte
    NVIDIA est présente — avec plusieurs cartes, aucune attribution par
    process n'est fournie plutôt que de risquer une mauvaise
    corrélation.
  - **Sévérité basée sur la température uniquement** : utilisation,
    VRAM et puissance élevées restent en Info (signe normal d'une carte
    qui travaille, pas un problème en soi — même raisonnement que les
    métriques de ressources du module virtualization). Pour AMD, la
    température est comparée au seuil critique *propre à cette carte*
    (`temp1_crit`, une vraie donnée) ; pour NVIDIA, faute d'équivalent
    aussi direct, un seuil générique plus conservateur est utilisé, avec
    une confiance explicitement réduite en conséquence. Driver manquant
    détecté séparément et toujours au moins en Warning, sans jamais
    faire descendre la sévérité d'une carte par ailleurs en surchauffe.
  - **Limite assumée** : le chemin `nvidia-smi`/sysfs AMD n'a pu être
    vérifié qu'au niveau du parsing (fixtures basées sur des formats
    réels confirmés) — `/sys/class/drm` étant une structure du noyau,
    impossible de la simuler sans modifier le code de production
    juste pour les tests, et ce sandbox n'a aucun GPU réel disponible.



Première version "publiée" au sens propre depuis le scaffold initial
0.1.0 — jusqu'ici, chaque changement s'accumulait sous "Non publié"
sans jamais faire l'objet d'un incrément de version, ce qui a été
signalé comme un problème réel : `VERSION` restait figé à `0.1.0`
malgré une évolution substantielle du projet. À partir de maintenant,
chaque changement livré incrémente `VERSION`/`Cargo.toml` et "publie"
la section correspondante avec une date, au lieu de laisser
s'accumuler indéfiniment sous "Non publié".

Cette version regroupe tout ce qui a été construit depuis le scaffold
initial (memory/cpu/numa/storage/systemd + TUI de base) : les modules
network, kernel, ntp et virtualization ; l'enrichissement profond de
memory, storage (SMART), et virtualization (VMs/conteneurs hôtes,
pinning CPU/NUMA, passthrough/SR-IOV, stats internes aux VMs) ; la
refonte du TUI (sous-menus, en-tête vivant, écran de progression,
rafraîchissement manuel) ; et plusieurs corrections de bugs réels
(faux positif SR-IOV, sensibilité à la locale de `virsh`, invite de
confirmation bloquante dans les scripts de build, comportement par
défaut de `linuxdoctor` sans sous-commande).

### Modifié

- `linuxdoctor` sans sous-commande ouvre maintenant le TUI par défaut,
  quand stdin **et** stdout sont un vrai terminal (`std::io::IsTerminal`,
  bibliothèque standard depuis Rust 1.70, aucune nouvelle dépendance) —
  correspond à l'usage attendu une fois le paquet installé. Repli
  automatique sur le comportement `audit` (texte, comme avant) dès que
  ce n'est pas le cas (redirection, pipe, script/cron/CI), pour que les
  usages non-interactifs existants (`linuxdoctor > rapport.txt`,
  `linuxdoctor | grep ...`) continuent de fonctionner exactement comme
  avant plutôt que d'échouer contre un TUI qui n'a nulle part où
  s'afficher. `linuxdoctor audit` et `linuxdoctor tui` restent
  disponibles pour forcer explicitement l'un ou l'autre mode.
  Vérifié avec un vrai pseudo-terminal (`tmux`) : lancement sans
  argument ouvre bien le TUI, sortie propre par `q` ; redirection vers
  fichier et pipe vers `grep` restent bien en mode texte, inchangés.
  Logique de décision extraite dans une fonction pure et testable
  séparée de la détection I/O réelle — même principe "collecte fine +
  cœur testable" que les modules de diagnostic.

### Clarifié

- `build-rpm.sh` ajoute un "-1" au nom du fichier `.rpm` généré (ex.
  `linuxdoctor-1.5.2-1.x86_64.rpm`) — signalé comme anormal par un
  utilisateur. **Vérifié en profondeur, ce n'est pas un bug** : c'est le
  champ "Release" du format RPM, distinct du champ "Version" dans la
  convention NEVRA (Nom-Epoch:Version-Release.Architecture), fixé à `1`
  par défaut par `fpm` en l'absence de `--iteration` explicite. Le
  format `.deb` n'a pas cette notion, d'où l'absence de ce suffixe côté
  `build-deb.sh` — ce qui expliquait la confusion. Vérification complète
  effectuée (pas seulement relue) : les 4 options de version (1/2/3/4,
  aussi bien via flags CLI que via le menu interactif numéroté, avec un
  vrai pseudo-terminal) donnent un résultat strictement identique et
  correct dans les deux scripts — `VERSION` et `Cargo.toml` ne
  contiennent jamais ce suffixe, dans aucun scénario testé. Message de
  succès de `build-rpm.sh` enrichi d'une note explicite là-dessus, pour
  que ça ne reste plus jamais ambigu.

### Corrigé

- **Bug réel signalé par un utilisateur** : `VERSION` (et `Cargo.toml`)
  n'était jamais mis à jour lors des builds, sans message d'erreur
  visible. Cause trouvée en exécutant réellement les scripts (avec un
  faux `fpm` pour contourner l'absence de `rubygems.org` dans ce
  sandbox) plutôt qu'en les relisant seulement : l'invite de
  confirmation `read -p "Construire ? [o/N]"` existait **même** quand un
  flag de version explicite (`--patch` etc.) était déjà passé. Dans tout
  contexte sans terminal interactif attaché à l'entrée standard (lancé
  depuis un script, un outil, une automatisation), `read` reçoit un EOF
  immédiat — et avec `set -e` en tête de script, ça tuait le script
  instantanément, **avant même la compilation**, sans aucun message,
  laissant `VERSION`/`Cargo.toml` inchangés. Reproduit et confirmé
  précisément avant de corriger (`bash build-deb.sh --patch < /dev/null`
  → code de sortie 1, aucune sortie).
  - `build-deb.sh` et `build-rpm.sh` détectent maintenant si l'entrée
    standard est un vrai terminal (`[ -t 0 ]`). Sans terminal ET sans
    flag de version → message d'erreur clair demandant d'en passer un,
    au lieu d'un blocage ou d'une mort silencieuse. Sans terminal MAIS
    avec un flag déjà fourni → confirmation automatique (le flag exprime
    déjà l'intention), avec un message explicite indiquant que c'est
    arrivé.
  - Nouveau flag `--yes`/`-y` pour sauter la confirmation explicitement,
    même en session interactive.
  - Revérifié après correction, dans les deux scripts, sur les quatre
    scénarios : flag + pas de terminal (fonctionne maintenant), aucun
    flag + pas de terminal (échoue proprement avec message clair),
    `--yes` explicite, et le rollback existant en cas d'échec de `fpm`
    (toujours intact, non affecté par ce correctif).

### Corrigé

- Module **virtualization** : précision d'affichage du stockage. Un
  petit-mais-réel allocation (ex. un disque qcow2 fraîchement créé)
  s'arrondissait visuellement à "0.0 GB" avec un seul chiffre après la
  virgule, indistinguable d'un vrai échec de lecture — signalé comme bug
  par un utilisateur. Nouveau formateur à unité adaptative (GB → MB →
  KB selon la magnitude) plutôt qu'un simple `{:.1} GB` fixe. Investigué
  en profondeur avant de corriger : `virsh domblkinfo` avec `target`
  (`vda`) vs `source` (chemin hôte complet) comme identifiant donnent en
  fait le **même résultat** dans cette version de libvirt (10.0.0,
  testé contre un vrai domaine avec un vrai disque qcow2, démon
  `libvirtd` lancé manuellement dans ce sandbox) — donc le symptôme
  exact rapporté n'a pas pu être reproduit à l'identique. Basculé vers
  `target` quand même par robustesse (recommandé par les exemples
  officiels libvirt, fonctionne aussi pour du stockage basé sur des
  pools comme `virt-manager` en crée par défaut, contrairement à
  `source` qui peut ne pas être un chemin de fichier direct dans ce cas).

### Ajouté

- Module **virtualization** : détail par VM très enrichi, vérifié avec
  un vrai `libvirtd` lancé manuellement dans ce sandbox (aucun `/dev/kvm`
  disponible ici, donc démarrage impossible, mais définition de domaine,
  `domblklist`, `domblkinfo`, `domiflist` tous testés contre un domaine
  inactif réel).
  - **CPU pinning + nœud NUMA intégré par groupe** : au lieu d'un résumé
    NUMA séparé de l'agrégat, chaque groupe de pinning affiche
    directement son nœud ("vCPUs 0-1: host 0-3 (NUMA node 0)").
  - **Croisement avec les CPUs isolés de l'hôte** : réutilise
    `cpu::collect::collect().all_isolated_cpus()` — indique si les vCPUs
    épinglées tombent sur des CPUs réservés/isolés du scheduler général,
    pas seulement lesquelles.
  - **Descriptions matérielles PCI** (`lspci -s <adresse>`) : chaque
    périphérique passthrough/SR-IOV affiche maintenant à quel matériel
    il correspond, pas seulement son adresse. Piège géré : une adresse
    valide mais absente donne une sortie vide avec un code de sortie 0,
    pas une erreur — vérifié empiriquement.
  - **Statistiques mémoire internes à l'invité** (`virsh dommemstat`,
    format confirmé via 4 sources concordantes) : pourcentage utilisé
    réellement par le système d'exploitation invité, avec mise en garde
    explicite quand la valeur "unused" est à 0 (peut être un vrai zéro
    ou un pilote de ballon sans collecte périodique activée — les deux
    sont indiscernables depuis cette seule donnée).
  - **Utilisation CPU approximative** : delta entre deux échantillons
    `virsh dominfo` pris avant/après le reste de l'enrichissement de
    cette VM (pas une pause dédiée — le mot "approximative" dans le
    texte reflète honnêtement une fenêtre d'échantillonnage courte et
    variable, pas une mesure précise sur durée fixe comme celle de
    l'en-tête TUI).
  - **Interfaces réseau** (`virsh domiflist`, bien plus simple qu'un
    reparsing XML — donne directement type/source/modèle/MAC en
    colonnes) : type, source, modèle. Pas de "vitesse" inventée pour les
    NICs paravirtualisées (virtio n'a pas de débit fixe) — à la place,
    une note honnête sur ce qu'implique chaque modèle courant.
  - Coût à connaître : environ 10 appels `virsh`/`lspci` supplémentaires
    par VM désormais — significatif pour un hôte avec plusieurs VMs,
    toujours dans l'esprit "scan complet, pas rafraîchissement continu"
    du reste de l'outil.

### Ajouté

- Module **virtualization** : détail par VM encore enrichi — pinning CPU
  vers les nœuds NUMA effectifs, politique NUMA configurée, périphériques
  en passthrough/SR-IOV.
  - **Nœuds NUMA effectifs** : donnée dérivée, pas directement fournie
    par `virsh` — croise le pinning vCPU (`virsh vcpupin`) avec la
    topologie NUMA réelle de l'hôte (`/sys/devices/system/node/*/
    cpulist`, lue directement, sans passer par le pipeline complet du
    module NUMA — même principe que `live_stats.rs`). Réutilise le
    `parse_cpu_list` déjà partagé entre les modules CPU et NUMA plutôt
    que d'en dupliquer un troisième.
  - **Politique NUMA configurée** (`virsh numatune`) : mode et nodeset
    explicitement définis, distinct du calcul ci-dessus (l'un est la
    politique configurée, l'autre est où les vCPUs tournent réellement
    une fois épinglées). Reste honnêtement `None` quand rien n'est
    configuré plutôt que de deviner une valeur par défaut.
  - **Périphériques passthrough/SR-IOV** (`virsh dumpxml`) : deux formes
    XML distinctes gérées séparément, confirmées par la documentation
    officielle libvirt et des exemples réels — `<hostdev type='pci'>`
    pour le passthrough générique (GPU, etc.) et
    `<interface type='hostdev'>` spécifiquement pour les VFs SR-IOV
    réseau (avec l'adresse MAC). Parsé via une petite machine à états
    ciblée sur le format de sortie de `virsh dumpxml` — pas un parseur
    XML général — avec un piège géré explicitement : l'élément `<mac>`
    apparaît *après* la fermeture de `<source>` dans l'ordre du
    document, donc capturé en attente jusqu'à la fermeture du bloc
    plutôt qu'au moment de lire l'adresse PCI.
  - Adresses PCI acceptées en hexadécimal (`0x06`) ou décimal (`11`)
    selon la forme XML rencontrée — les deux existent dans des exemples
    réels de la documentation.

### Ajouté

- TUI : en-tête vivant, écran de progression au démarrage, rafraîchissement
  manuel — trois demandes liées, une seule refonte cohérente.
  - **En-tête en temps réel** : une deuxième ligne affiche CPU%, Mem%
    (utilisée/totale en GB) et espace disque de `/` (`%`), rafraîchie
    automatiquement environ une fois par seconde tant que le TUI est
    ouvert — sans action de l'utilisateur. Codes couleur (vert/jaune/
    rouge selon des seuils 70%/90%). Le CPU% est calculé par delta entre
    deux lectures de `/proc/stat` (technique standard sous Linux — une
    seule lecture ne donne pas de "% d'usage instantané", seulement des
    compteurs cumulés depuis le boot), donc affiche "…" le temps qu'un
    deuxième échantillon soit disponible (~1s après l'ouverture).
    Nouveau module `output/live_stats.rs`, délibérément séparé du
    pipeline des `Module` de diagnostic — ce sont des jauges d'affichage,
    pas des findings avec preuve/explication/recommandation, et les
    relancer en entier à chaque tick (y compris les appels `smartctl`
    par disque) serait à la fois inutile et bien trop lent pour un
    rafraîchissement à la seconde.
  - **Écran de progression** : au lancement, une jauge centrée affiche
    quel module est en cours de scan et où on en est (N/total) —
    important pour un scan avec un module plus lent (`smartctl` par
    disque dans Storage, `virsh`/`docker` dans Virtualization) qui
    pouvait auparavant donner l'impression d'un terminal figé.
  - **Rafraîchissement manuel (`r`)** : relance le pipeline complet des
    modules sans quitter le programme, avec le même écran de progression.
    La sélection de module courante est préservée si elle existe encore
    dans les nouvelles données. Le compteur "findings from Ns ago" dans
    l'en-tête distingue explicitement la fraîcheur des deux types de
    données : les jauges de l'en-tête sont toujours à jour, les findings
    affichés datent du dernier scan/rafraîchissement.
  - **Changement d'architecture nécessaire** : `TuiApp` possède
    maintenant son `Report` directement (au lieu de l'emprunter) — sans
    ça, impossible de le remplacer lors d'un rafraîchissement. Ça a
    changé la signature de plusieurs méthodes internes (retournent des
    `String`s possédées plutôt que des `&str` empruntés) pour éviter un
    conflit d'emprunt avec les `ListState` mutables de `ratatui`.
    `core::engine::run_audit()` reste inchangé pour la commande `audit`
    non-interactive ; un nouveau `run_audit_with_progress()` accepte un
    callback de progression, utilisé uniquement par le TUI.
  - **Vérifié avec un vrai pseudo-terminal** (`tmux`, pas seulement le
    rendu headless `TestBackend`) : écran de progression capturé en plein
    scan réel, en-tête confirmé vivant sur plusieurs secondes (CPU% se
    résout après le deuxième tick, compteur d'âge incrémente), touche
    `r` confirmée déclenchant un vrai nouveau scan avec préservation de
    la sélection, sortie propre par `q`.

### Corrigé

- **Bug réel signalé par un utilisateur** : sur un système en locale
  française, `virsh dominfo` remontait un `state: unknown` pour
  **toutes** les VMs (y compris celles en fonctionnement), et le résumé
  affichait "0 currently running" malgré des VMs actives. Cause : `virsh`
  traduit ses libellés de champs via gettext (`State:` devient autre
  chose selon la locale), et le parseur cherchait la chaîne anglaise
  exacte. Correctif : nouvel utilitaire partagé
  `core::command::command()` qui force `LC_ALL=C`/`LANG=C` sur **tous**
  les appels de sous-processus du projet (pas seulement `virsh`) — ce
  ne sont pas juste des variables non définies, elles écrasent
  explicitement l'héritage de l'environnement parent (vérifié : lancer
  `linuxdoctor` lui-même sous `LC_ALL=fr_FR.UTF-8` produit toujours des
  messages d'erreur `virsh`/`docker` en anglais). Reproduction exacte du
  mécanisme non confirmée dans ce sandbox (le paquet `libvirt-l10n`
  d'Ubuntu minimal n'installe aucun fichier de traduction réel — vérifié
  en comparant `virsh` sous locale C et sous `fr_FR.UTF-8` généré
  manuellement), donc traité honnêtement comme "cause la plus probable,
  corrigée par une pratique défensive standard" plutôt que "cause
  confirmée à 100%".

### Ajouté

- Module **virtualization** : détail par VM enrichi.
  - Épinglage vCPU (`virsh vcpupin`, format confirmé via `virsh help` et
    des captures réelles de la documentation libvirt/Red Hat, pas
    deviné) — quels CPUs hôtes chaque vCPU peut utiliser, regroupé pour
    la lisibilité ("vCPUs 0-1: host 0-3; vCPUs 2-3: host 4-7").
  - Stockage par VM (`virsh domblklist --details` + `domblkinfo`) — par
    disque : capacité configurée et espace réellement alloué sur
    l'hôte (la donnée qui compte pour un format "thin-provisionné"
    comme qcow2). Les lecteurs CD-ROM vides sont exclus. Correction en
    cours de route : j'avais supposé par erreur un drapeau `--bytes`
    pour `domblkinfo` par analogie avec `domblkstat` — vérifié via
    `virsh help domblkinfo` que ce drapeau n'existe pas, corrigé avant
    de livrer.

### Ajouté

- Module **virtualization** enrichi : inventaire côté hôte, en plus de la
  détection côté invité (`VIRT001`, inchangée). Distinction importante :
  `VIRT001` répond "dans quoi cette machine tourne-t-elle", ces nouveaux
  checks répondent "qu'est-ce que cette machine héberge".
  - `VIRT002`/`VIRT003` (VMs, via `virsh`) : résumé toujours présent
    (`VIRT002`) + un finding par VM (`VIRT003`, dans un sous-menu dédié).
    État à trois niveaux, pas un simple booléen : `virsh` absent, `virsh`
    présent mais hyperviseur injoignable (aucun `libvirtd`, ou pas de
    permission — comportement vérifié empiriquement : `virsh list --all`
    sort en code 1 avec `"failed to connect to the hypervisor"`), ou
    disponible. Par VM : état, vCPUs, mémoire max configurée, mémoire
    réellement utilisée (seulement si en fonctionnement — sinon
    `virsh dominfo` reflète la cible du "balloon", pas un usage réel).
  - `VIRT004`/`VIRT005` (conteneurs, via `docker` puis `podman` en repli)
    : même structure résumé + détail par conteneur. Utilise `.State`
    (mot simple : `running`/`exited`) plutôt que `.Status` (texte humain)
    pour déterminer l'état, avec consommation CPU/mémoire en direct
    (`docker stats --no-stream`) pour les conteneurs en fonctionnement.
  - **Vérifié contre de vrais outils, pas seulement des fixtures** :
    `virsh` et `docker` installés dans ce sandbox pour de vrai
    (`libvirt-clients`, `docker.io` via apt), `dockerd` lancé
    manuellement, une image minimale construite depuis un busybox
    statique (import sans réseau, le pull Docker Hub étant bloqué par la
    liste blanche réseau), deux vrais conteneurs créés (un en
    fonctionnement, un arrêté). Le binaire `linuxdoctor` compilé a
    tourné contre ce vrai démon et remonté les vraies statistiques de
    ressources en direct. Le cas "outil installé mais démon injoignable"
    a aussi été confirmé en réel pour `virsh` et `docker`, avec les
    messages d'erreur exacts capturés.
  - Coût mesuré : +75-110ms sur ce sandbox (plusieurs appels
    `virsh`/`docker`/`podman`, dont des tentatives de connexion à un
    socket absent) — largement dans la cible <2s, mais un coût réel à
    connaître sur un hôte où le module tourne fréquemment.

### Ajouté

- Module **virtualization** : détection de la technologie de
  virtualisation via `systemd-detect-virt`. Différence importante par
  rapport aux modules systemd/ntp : cet outil **fonctionne sans que
  systemd soit PID 1** (il sonde DMI/CPUID/marqueurs d'environnement
  directement, pas de bus D-Bus vers PID 1) — vérifié empiriquement sur
  ce sandbox avant de coder, donc pas de restriction `is_available()`.
  Piège de code de sortie à noter : l'outil sort en code **non-zéro**
  précisément quand rien n'est détecté (`none`) — vérifié dans sa propre
  documentation — donc la sortie standard est capturée indépendamment du
  code de sortie, sinon chaque machine bare-metal remonterait une
  fausse erreur de collecte.
  - `VIRT001` (toujours présent, Info — être virtualisé n'est ni bon ni
    mauvais en soi) distingue les quatre cas : bare metal, VM seule,
    conteneur seul, ou imbriqué (conteneur sur VM). Repli sur le flag
    CPUID `hypervisor` de `/proc/cpuinfo` si l'outil n'est pas installé
    (signal plus faible : confirme une virtualisation matérielle sans
    dire laquelle).
  - Vérifié en conditions réelles sur ce sandbox : `docker` sur `kvm`
    (imbrication réelle, pas un fixture) — correctement identifié et
    expliqué.

### Ajouté

- Module **ntp** : statut de synchronisation d'horloge et mode de
  l'horloge matérielle (RTC), via `timedatectl show`.
  - `NTP001` (statut de synchro) : lit `NTPSynchronized=`, qui vient du
    flag `STA_UNSYNC` du **noyau** lui-même (`adjtimex(3)`) — autoritaire
    quel que soit le démon en charge (systemd-timesyncd, chrony, ntpd),
    puisqu'ils mettent tous à jour le même état noyau. Confiance
    délibérément réduite (`strong_indication`, pas
    `direct_observation`) quand ce champ indique un problème : un ticket
    de support Red Hat confirme que c'est un faux négatif connu avec
    certaines configs chrony/ntpd (chrony sans `rtcsync`, ntpd avec
    `-x`) qui ne mettent pas à jour ce flag noyau — vérifié avant de
    coder, pas supposé.
  - `NTP002` (mode RTC) : `LocalRTC=` — RTC en heure locale n'est pas
    en soi un problème (réglage courant en dual-boot Windows), donc
    reste en Info, présenté comme contexte à confirmer plutôt que comme
    un verdict.
  - Même mécanisme de disponibilité que le module systemd
    (`/run/systemd/system`) — `timedatectl` fait partie du cœur de
    systemd, donc dépend de la même condition.

### Ajouté

- Module **kernel** enrichi : quatre nouveaux checks, toujours présents.
  - `KERN003` (infos de build) : parse `/proc/version` — utilisateur/hôte
    de build, compilateur, tag de build. Piège évité : les chaînes de
    compilateur contiennent souvent leurs propres parenthèses imbriquées
    (`gcc (Ubuntu 13.2.0-...) 13.2.0`), donc le parseur compte la
    profondeur plutôt que de chercher naïvement la première parenthèse
    fermante — vérifié à la fois sur ce sandbox (noyau Firecracker
    personnalisé) et sur un exemple `/proc/version` de style Ubuntu.
  - `KERN004` (reboot requis) : `/var/run/reboot-required`
    (convention Debian/Ubuntu). Sur les autres familles de distributions,
    l'absence du marqueur est rapportée honnêtement comme "non
    confirmé", pas comme "aucun redémarrage nécessaire" — ce fichier
    n'existe pas du tout ailleurs.
  - `KERN005` (statut ASLR) : `kernel.randomize_va_space` — désactivé
    (0) remonte en Warning, partiel (1) ou complet (2) reste Info.
  - `KERN006` (paramètres de boot notables) : scan ciblé de
    `/proc/cmdline` pour `mitigations=off` (Warning — désactive les
    mitigations Spectre/Meltdown), `nomodeset`, mode single/emergency.
    Pas un linter exhaustif de la ligne de commande, juste quelques
    signaux bien choisis.

### Ajouté

- Module **kernel** : statut de taint (`/proc/sys/kernel/tainted`, les 20
  bits transcrits depuis la documentation officielle du noyau —
  https://docs.kernel.org/admin-guide/tainted-kernels.html — pas
  supposés) et historique des kills OOM (via `dmesg`, se dégrade
  proprement si l'accès est refusé — `kernel.dmesg_restrict` limite
  souvent ça à root). `KERN001` combine tous les bits actifs en un seul
  finding (ce sont des conditions hétérogènes, pas une liste
  d'instances similaires comme des sockets ou des systèmes de fichiers).
  Sévérité au pire signal actif (ex. une Machine Check Exception ou un
  soft lockup priment sur un simple module propriétaire chargé, qui est
  courant et anodin).

### Corrigé

- Module **network** : `NET002` traitait le taux de perte RX/TX comme un
  signal fiable sans tenir compte du SR-IOV. Sur une interface avec des
  VFs actives, le trafic dirigé par le matériel vers une VF peut être
  compté dans le `rx_dropped` de la fonction physique sans indiquer un
  vrai problème de câble/duplex — phénomène documenté (rapporté y compris
  par un ingénieur Intel sur i40e). Détection via
  `/sys/class/net/<iface>/device/sriov_numvfs` (interface sysfs standard
  du noyau, pas de pattern-matching sur le nom de l'interface) : si des
  VFs sont actives, la sévérité descend d'un palier et la confiance
  passe explicitement en "weak indication", avec le contexte dans
  l'explication et une recommandation adaptée (comparer avec le trafic
  des interfaces VF elles-mêmes plutôt que soupçonner le câble en premier).

### Ajouté

- Module **network** : aperçu par interface, taux d'erreurs/pertes gradué
  (avec seuil d'échantillon minimum — en dessous de 100 paquets, un taux
  n'est pas statistiquement significatif, donc rapporté en Info plutôt que
  de risquer une fausse alerte), passerelle par défaut, configuration DNS.
  Aucune commande externe : tout vient de `/proc/net/dev`,
  `/proc/net/route` (avec décodage des adresses IPv4 hexadécimales
  little-endian du noyau), `/sys/class/net/*` et `/etc/resolv.conf`.
  `NET001`/`NET002` sont groupés par interface pour le sous-menu TUI.

### Ajouté

- Module **storage** : santé SMART par périphérique physique, dans un
  sous-menu dédié — distinct des instances par point de montage
  (`STOR001`/`STOR002`), puisque SMART se lit par device (`/dev/sda`),
  pas par montage.
  - `STOR003` (résumé, toujours présent) : nombre de devices candidats
    examinés (`/sys/block`, filtré des loop/ram/zram/dm/md/optiques) et
    combien supportent SMART. Distingue explicitement "smartctl non
    installé", "aucun device ne supporte SMART" et, si pertinent,
    ajoute un indice permissions (root généralement nécessaire pour
    l'accès brut au device — détecté via `/proc/self/status`, pas de
    nouvelle dépendance).
  - `STOR004` (un par device, dans le sous-menu) : parse le JSON de
    `smartctl -a --json=c` (`smartmontools` ≥ 7.0), gère séparément les
    attributs ATA ("big four" : secteurs réalloués/en attente/
    non-corrigibles) et le journal santé NVMe (`critical_warning`,
    `percentage_used`, `media_errors`). Sévérité graduée sur le signal
    le plus fort trouvé — un statut global "PASSED" n'empêche pas une
    remontée en ERROR si les attributs individuels dérivent, puisque le
    seuil PASSED/FAILED de SMART est souvent plus laxiste que la
    dérive de ces attributs pris un par un.

### Ajouté

- TUI : sous-menus de navigation. Les modules dont les findings portent
  2+ valeurs `instance` distinctes (sockets CPU, systèmes de fichiers,
  nœuds NUMA, unités en échec) affichent désormais uniquement leurs
  findings globaux au niveau module, avec une invite (`▸ N items —
  press Enter for detail`) pour accéder au détail par instance. `Entrée`
  pour entrer, `Échap` pour ressortir ; `PgUp`/`PgDn` navigue la liste
  active à chaque niveau (modules, puis instances une fois entré).
  En dessous de 2 instances, tout reste affiché à plat comme avant —
  descendre dans un sous-menu pour "une seule chose" n'aurait apporté
  que de la friction.
  - Mécanisme générique : nouveau champ `Finding.instance: Option<String>`
    dans le modèle canonique — le TUI ne connaît pas quels IDs sont "par
    instance" pour quel module, ça vient entièrement des données. Les
    modules concernés (`cpu` pour `CPU004`, `storage` pour
    `STOR001`/`STOR002`, `numa` pour `NUMA001`, `systemd` pour `SYSD002`)
    posent juste `.instance(...)` sur le finding builder.

### Modifié

- TUI : navigation inversée — PgUp/PgDn changent maintenant de module,
  ↑/↓ (et `j`/`k`, déplacés avec les flèches) défilent le panneau de
  détail. Le défilement passe aussi de 5 lignes par pression à 1 ligne,
  plus adapté à des touches fléchées (PgUp/PgDn n'ont plus de rôle de
  défilement, donc plus besoin d'un grand saut).

### Ajouté

- Module **memory** : trois nouveaux checks, toujours présents.
  - `MEM004` (Memory Usage Overview) : distingue mémoire réellement
    utilisée (`MemTotal - MemAvailable`) du cache réclamable — répond
    directement à la confusion classique "pourquoi `free` affiche si peu
    de mémoire libre".
  - `MEM005` (Dirty Page / Writeback Pressure) : compare le pourcentage
    de pages "dirty" aux seuils **réellement configurés** du système
    (`vm.dirty_ratio`, `vm.dirty_background_ratio` — lus, pas supposés
    aux valeurs par défaut), avec repli honnête si le tuning par octets
    (`vm.dirty_bytes`) est utilisé à la place (évite un faux positif sur
    seuil à zéro).
  - `MEM006` (Shared Memory Usage) : usage de `Shmem` (tmpfs, `/dev/shm`,
    segments SysV/POSIX) — non réclamable comme le cache, donc surveillé
    séparément, avec pistes de résolution concrètes (`du -sh /dev/shm`,
    `ipcs -m`, `df -h -t tmpfs`).
  - `MEM002` enrichi : croise le `vm.swappiness` configuré avec l'usage
    swap observé — un swappiness bas (≤10) qui swap quand même est un
    signal plus fort qu'à la valeur par défaut.

### Ajouté

- Module **numa** : mécanisme de comparaison automatique de la topologie.
  - `NUMA002` (renommé "Memory Balance Across Nodes") est maintenant
    **toujours** présent dès 2 nœuds — avant, il ne s'affichait que si un
    déséquilibre était détecté, ce qui rendait son absence ambiguë (même
    leçon que `CPU005`).
  - `NUMA003` (nouveau) : comparaison **structurelle** de la topologie —
    nombre de CPUs et capacité mémoire par nœud, distincte de l'usage
    (`NUMA002`). Détecte les nœuds sans mémoire locale (nœuds de calcul
    purs, ex. associés à un accélérateur), les nœuds sans CPU (nœuds
    mémoire pure), et les asymétries de capacité (ratio ≥ 2×). Chaque
    déséquilibre détecté est accompagné d'une recommandation concrète
    (`numactl --hardware`, `--cpunodebind`/`--membind`).

- Module **systemd** : état système global (`systemctl is-system-running`)
  et un finding par unité en échec (`systemctl --failed`). Deuxième
  module à utiliser `is_available()` — vérifie `/run/systemd/system`
  (le marqueur standard utilisé par `sd_booted()` de libsystemd), pas
  seulement la présence du binaire `systemctl` (qui peut être installé
  sans que systemd soit le PID 1, comme dans ce sandbox de développement).
  `SYSD001` est toujours présent, même système sain — même principe que
  `CPU005`.
- Module **numa** : un finding par nœud NUMA (CPUs, mémoire), détection de
  déséquilibre mémoire entre nœuds (`NUMA002`). Premier module à utiliser
  `is_available()` — se désactive proprement sur un système sans NUMA.
- Module **cpu** : refonte complète pour les machines multi-sockets.
  `/proc/cpuinfo` est maintenant entièrement parsé (pas seulement la
  première ligne `model name`) et regroupé par socket physique.
  - `CPU001` (vue d'ensemble machine) et `CPU004` (détail par socket,
    un finding par socket) remplacent l'ancien finding agrégé unique.
  - `CPU004` indique, pour chaque socket, les cœurs disponibles et ceux
    isolés du planificateur — pas seulement un total machine.
  - `CPU005` lit maintenant **quatre** mécanismes distincts d'isolation :
    `isolcpus=` (`/sys/devices/system/cpu/isolated`), `nohz_full=`
    (`/sys/devices/system/cpu/nohz_full` — fichier séparé, précédemment
    mentionné dans le texte mais jamais lu), les partitions cpuset isolées
    cgroup v2 (`cpuset.cpus.isolated`, trouvées par parcours borné de
    `/sys/fs/cgroup`), et — ajouté suite à un retour précis sur un cas
    réel — la restriction de `system.slice` via `AllowedCPUs=`
    (`systemctl set-property --runtime system.slice AllowedCPUs=<cpus>`,
    une technique de hook libvirt courante pour réserver des cœurs à une
    VM au démarrage : `cpuset.cpus.effective` de `system.slice` est
    comparé à l'ensemble des CPUs en ligne, le complément est considéré
    réservé).
    `CPU005` est désormais **toujours** présent, même sans isolation
    détectée, pour ne pas laisser croire que l'outil n'a pas vérifié. Le
    pinning de vCPU au niveau de l'hyperviseur (`virsh vcpupin`) reste hors
    de portée : aucune interface noyau ne l'expose côté invité, quel que
    soit le mécanisme vérifié.
  - `CPU006` : CPUs "possible" mais non online
    (`/sys/devices/system/cpu/possible` diffé avec `/proc/cpuinfo`) —
    pertinent sur une VM où l'hyperviseur annonce plus de vCPUs qu'il
    n'en active.
- Module **storage** : usage espace disque (`df -kPT`) et usage inodes
  (`df -iPT`), un finding par système de fichiers réel (les
  pseudo-systèmes de fichiers — tmpfs, proc, overlay, etc. — sont exclus),
  4 paliers de sévérité (< 80 % / 80-89 % / 90-94 % / ≥ 95 %).
- `ModuleError::Command`, pour les modules qui exécutent une commande
  externe plutôt que de lire un fichier.

### Corrigé

- Module **storage** : les montages FUSE d'AppImage (type contenant
  `.AppImage`, quel que soit le nom de l'application) sont maintenant
  exclus, comme les autres pseudo-systèmes de fichiers.
- Module **cpu** : `CPU005` ne lisait que `/sys/devices/system/cpu/isolated`
  (`isolcpus=`) tout en prétendant couvrir `nohz_full=` dans son texte —
  ce dernier vit dans un fichier distinct, jamais lu. Les partitions
  cpuset isolées cgroup v2 n'étaient pas couvertes du tout. Les deux sont
  maintenant lues ; voir "Ajouté" ci-dessus pour le détail.

### Modifié

- Ordre d'affichage des modules : memory, cpu, numa, storage (NUMA juste
  après CPU, les deux étant liés à la topologie processeur).

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
