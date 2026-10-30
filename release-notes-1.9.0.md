## [1.9.0] - 2026-10-16

Chaque sortie dit quelle version de LinuxDoctor l'a produite, la TUI se filtre et
se cherche, et `diff` prévient quand il compare des rapports de versions
différentes. La disposition du rapport JSON ne change pas : `linuxdoctor_version`
est un champ ajouté, `schema_version` reste 1.

### Ajouté

- **`diff` prévient quand les deux rapports ne viennent pas de la même version de
  LinuxDoctor.** Les contrôles évoluent d'une version à l'autre : un constat qui
  apparaît ou disparaît peut venir du programme, pas de la machine. L'avertissement
  est dit avant les changements, comme celui des machines différentes, dans les trois
  formats (`> ⚠` en Markdown, `caveats` en JSON avec `"kind": "different_versions"`
  et les deux versions).
  - Il se déclenche si les deux versions enregistrées diffèrent, **et aussi** si un
    seul des deux rapports en enregistre une : toute version qui l'enregistre est plus
    récente que toute version qui ne le fait pas, donc les deux diffèrent
    forcément (l'autre est alors « not recorded »).
  - Il ne dit rien quand les versions sont égales, ni quand aucun des deux rapports
    n'en enregistre : il n'y a rien à conclure, et l'avertissement s'afficherait à
    chaque comparaison de rapports anciens.
  - Il n'ajoute ni ne masque aucun changement et ne modifie pas le code de sortie.
    Les versions viennent de fichiers : elles sont nettoyées dans le texte et
    échappées en Markdown.
  - Tests : unitaires (détection, rendu des trois formats, texte hostile) et
    `tests/version_shown.rs` avec le vrai binaire, y compris le code de sortie
    identique avec ou sans avertissement. Ils échouent quand on supprime
    l'avertissement, qu'on l'étend à deux rapports sans version ou qu'on retire le
    nettoyage.

- **La version de LinuxDoctor s'affiche en tête de chaque sortie.** Première
  ligne du rapport terminal (`LinuxDoctor 1.8.0 — machine`), première ligne sous
  le titre du rapport Markdown, premier fait de l'en-tête du rapport HTML,
  en-tête de la TUI et son écran de chargement, et en-tête de la comparaison
  produite par `diff`. Dans les rapports Markdown et HTML elle figurait déjà,
  mais en fin d'en-tête (« Generated … by LinuxDoctor ») ; elle est maintenant
  la première information, et la ligne « Generated » ne donne plus que la date.
  - **Le rapport JSON l'enregistre** : `linuxdoctor_version`, juste après
    `schema_version`. Ce n'est pas une modification de la disposition
    (`schema_version` reste 1) : un lecteur qui ignore les clés inconnues n'est
    pas touché. Les contrôles évoluent d'une version à l'autre ; un rapport
    conservé ne se comprend pleinement qu'avec la version qui l'a écrit.
  - **`diff` montre trois versions** : celle qui compare (titre du texte,
    « Compared with LinuxDoctor … » en Markdown, `linuxdoctor_version` en JSON)
    et celle qui a écrit chacun des deux rapports (entre parenthèses en
    terminal, colonne « Written by » en Markdown, `before` / `after` en JSON).
    Un rapport d'une version qui ne l'enregistrait pas (la 1.8.0 et les
    précédentes) n'en a pas : il est présenté comme
    « LinuxDoctor version not recorded » (`null` en JSON). Cette version vient
    d'un fichier, donc d'un texte non fiable : elle est nettoyée comme le reste
    (terminal) et échappée (Markdown).
  - Une seule source : la constante `linuxdoctor::VERSION` (celle de
    `--version`).
  - Tests : `tests/version_shown.rs` lance le vrai binaire et vérifie la version
    en tête de chaque format, dans `diff` (dont un rapport sans version et un
    rapport dont la version contient des séquences d'échappement), et que le
    fichier `VERSION` et `Cargo.toml` s'accordent (une release qui n'en met à
    jour qu'un des deux échoue). Des tests unitaires couvrent chaque rendu,
    l'en-tête et l'écran de chargement de la TUI. Ils échouent quand on retire
    l'affichage ou le nettoyage.

- **La TUI se filtre et se cherche.** Avec 13 modules et des dizaines de constats,
  voir seulement ce qui compte demandait de tout faire défiler.
  - **`f` choisit une sévérité minimale** : tout, avertissement et plus, erreur et
    plus, critique seul (les quatre niveaux de `--min-severity`).
  - **`/` cherche un texte**, sans tenir compte de la casse, dans l'identifiant, le
    titre, l'explication, la recommandation, l'instance et les preuves d'un constat.
    Entrée le garde, Échap l'oublie ; pendant la saisie, `q`, `r`, `f`, `j` et `k`
    sont des lettres, pas des commandes.
  - **Un écran filtré ne peut pas passer pour complet** : la barre du bas indique
    `Filter: … · N of M findings`, chaque module affiche le nombre de ses constats
    retenus (ceux qui n'en ont plus sont grisés), et chaque page rappelle combien de
    constats du module sont montrés. Un module en erreur ou ignoré garde son
    affichage.
  - **Le rapport n'est jamais modifié** : le ✓/⚠/✗ d'un module décrit toujours le
    module entier et le code de sortie de `linuxdoctor tui` tient compte de tous les
    constats, filtrés ou non.
  - **Les sous-éléments suivent le filtre** : si une seule instance reste, elle est
    montrée à plat, comme pour un module qui n'en a qu'une. L'écran passe au premier
    module qui a une correspondance quand le filtre change.
  - **Échap défait un niveau à la fois** : le sous-menu, puis le filtre, puis quitte.
    Sans filtre, rien ne change. La barre du bas fait maintenant deux lignes (l'état
    de l'affichage, puis les touches).
  - Le texte tapé est limité à 40 caractères et refuse les caractères de contrôle,
    puisqu'il est réaffiché.
  - Tests : `output::tui_filter` (sévérité, texte, longueur, casse) et la TUI sans
    terminal (touches, écran dessiné, couleurs des modules vides, sous-menus,
    actualisation, texte hostile sous filtre). Ils échouent quand on retire le saut
    vers le module qui correspond, le filtre de sévérité, le contrôle des touches
    Ctrl/Alt ou le rôle de Échap.

