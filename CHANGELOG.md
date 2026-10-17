<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté

- **`--profile server` : deux vérifications de plus, `SRV002` (les journaux survivent-ils
  à un redémarrage ?) et `SRV003` (un redémarrage attend-il depuis des jours ?).** Le module
  `server` en a maintenant trois, dans cet ordre ; `SRV003` n'apparaît que s'il y a quelque
  chose à dire. Comme `SRV001`, elles n'existent qu'avec le profil, et ne baissent aucune
  sévérité.
  - **`SRV002` — journaux conservés après un redémarrage.** Après un plantage, une coupure de
    courant ou un redémarrage que personne n'a demandé, les journaux sont le seul témoin de ce
    qui s'est passé, et sur un serveur que personne ne regardait c'est le seul. Le journal de
    systemd n'est sur disque que si `Storage=` le veut : `persistent`, ou `auto` (le défaut)
    **avec** un dossier `/var/log/journal` ; sinon il est en mémoire et part avec le
    redémarrage. La vérification lit `Storage=` comme journald le lit : `journald.conf`
    (le premier qui existe de `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`), puis les fichiers
    de `journald.conf.d` des mêmes dossiers, triés par nom quel que soit le dossier, un nom
    dans un dossier plus prioritaire cachant le même nom plus bas (un lien vers `/dev/null`
    aussi), la dernière valeur **valide** gagnant (les quatre mots sont exacts ; une valeur
    invalide est ignorée, donc ce qui précédait reste). Elle regarde aussi le dossier, et si
    les journaux classiques (`/var/log/syslog`, `/var/log/messages`) ont été écrits dans les
    7 derniers jours.
    - Journal sur disque, ou journaux classiques écrits : **Info** (90 %). Journal en mémoire
      et aucun journal classique : **Avertissement à 80 %**, avec les commandes pour le
      garder (changer `Storage=` dans le fichier qui dit `volatile` ou `none`, créer
      `/var/log/journal` avec `systemd-tmpfiles`, relancer journald, vérifier avec
      `--list-boots`). Pas plus de 80 % : la machine peut envoyer ses journaux ailleurs
      (collecteur syslog ou journal-remote, Promtail, Filebeat), ce que rien ici ne voit, et
      le texte le dit. Sans journal systemd : une Info qui dit que rien n'a été vérifié.
    - **Ce que `LOG008` ne fait pas** : il juge le journal d'après son seul dossier et ignore
      `Storage=`, donc il ne voit pas `Storage=volatile` par-dessus un dossier qui existe.
  - **`SRV003` — redémarrage laissé en attente.** Sur Debian et dérivées, une mise à jour qui
    ne prend effet qu'après un redémarrage écrit `/var/run/reboot-required` (`KERN004` dit
    qu'il est là). `SRV003` ajoute depuis combien de temps : rien pendant la première
    semaine (une fenêtre de maintenance à venir) ; ensuite un **Avertissement à 90 %**, avec
    l'âge en jours et les paquets de `/var/run/reboot-required.pkgs` (chacun une fois, dix
    nommés au plus, les autres comptés). La date est celle de la *dernière* mise à jour qui a
    demandé le redémarrage (chacune réécrit le fichier) : il attend **au moins** autant, et le
    texte le dit, ainsi qu'un noyau patché à chaud a déjà ses correctifs. Rien sans le
    marqueur (les autres familles n'en ont pas, `KERN004` le dit déjà), ni quand sa date est
    inconnue ou dans le futur.
  - Tout se lit dans des fichiers (aucun outil lancé), sous une racine que les tests
    remplacent par un arbre factice, et l'âge vient d'une horloge passée avec les données :
    `analyze` reste une fonction pure.
  - **Vérifié** avec le vrai binaire dans le conteneur de développement : journal présent
    (Info) ; dossier retiré et aucun journal classique (Avertissement avec les commandes) ;
    marqueur vieux de 12 jours avec trois paquets dont un en double (`SRV003` avec l'âge et
    deux paquets, `KERN004` inchangé), puis tout remis. Les tests de bout en bout ne peuvent
    pas déplacer la racine : ils comparent les constatations à ce que la machine dit
    elle-même. **Pas encore vu sur une machine réelle avec un journal en mémoire ni avec un
    redémarrage en attente depuis des semaines** : à regarder dans ton premier rapport.
  - Tests : 44 nouveaux (la lecture de `Storage=` et des fichiers sur de faux arbres :
    ordre, masquage, liens vers `/dev/null`, fichier énorme, noms hostiles, dates aux
    limites ; chaque verdict et chaque phrase ; les paquets ; l'ordre des constatations dans
    le module ; et deux tests de bout en bout). Ils échouent quand on casse le code : 146
    casseurs essayés, 146 détectés ; cinq avaient survécu à la première série (un chemin trop
    long pas coupé, les paquets au-delà de dix, l'horloge de lecture, une racine fausse) et
    les tests ont été resserrés. Un contrôle de type de fichier inutile a été retiré en route.

## [1.10.0] - 2026-10-17

Les profils de machine arrivent : `--profile hpc` (quatre vérifications propres aux
nœuds de calcul) et `--profile server` (les mises à jour de sécurité automatiques).
Le module GPU détaille les GPU Intel, et l'en-tête des rapports donne le vrai nombre de
CPU d'une machine dont certains sont isolés. Un profil se choisit, il ne se devine pas :
sans lui, les profils ne changent ni une sévérité ni un code de sortie. La disposition du rapport JSON ne change pas : `profile`
est un champ ajouté, absent quand aucun profil n'a été choisi, et `schema_version` reste 1.
Le côté dnf de `SRV001` n'a été vu que sur de faux fichiers, pas sur une vraie machine
Fedora ou RHEL.

### Ajouté

- **Profils de machine : `--profile hpc`** (ou `profile = "hpc"` en tête du fichier
  de configuration). Les vérifications jugent une machine « en général » ; certaines
  mesures veulent dire autre chose sur un type de machine précis. Une charge égale au
  nombre de CPU est de la contention sur un poste de travail, et un nœud de calcul qui
  fait son travail. Un profil le dit une fois, à un seul endroit (`src/profile.rs`),
  au lieu que chaque module devine. Pour `audit` et `tui` (`diff` n'en a pas : il lit
  celui que chaque rapport a enregistré).
  - **Choisi, jamais deviné.** Aucune détection : deux machines semblables ne doivent
    pas être jugées différemment pour une raison que personne ne voit. Sans profil,
    rien ne change, pas une sévérité.
  - **Un profil ne fait que baisser.** Chaque règle est un plafond : une constatation
    au-dessus est rapportée au plafond, une constatation en dessous est laissée telle
    quelle, et aucune règle ne peut rien relever. Ce n'est pas un détail de style : le
    code de sortie suit les sévérités, donc un profil qui aggraverait des
    constatations ferait échouer des audits qui passent aujourd'hui, à cause d'un
    réglage. Il ne supprime aucune constatation, ne touche ni aux preuves ni à la
    confiance, et n'a rien à dire d'un disque plein ou d'un service exposé (vérifié
    avec le vrai binaire : mêmes constatations, même code de sortie).
  - **Il dit ce qu'il a fait, dans la constatation.** Une constatation ajustée reçoit
    `severity_before_profile` et `profile` dans ses preuves, et un dernier paragraphe
    d'explication avec la raison (« Profile hpc: reported as info instead of
    critical. … »). Le rapport nomme aussi le profil : première ligne du rapport
    terminal, en-tête Markdown et HTML, bandeau de la TUI, et une clé `profile` en
    haut du JSON, **absente quand aucun profil n'a été choisi** (champ ajouté,
    `schema_version` reste 1).
  - **Appliqué au rapport terminé, avant le code de sortie et avant le filtre
    d'affichage** : `--fail-on` et le code de sortie par défaut jugent les sévérités
    que le rapport montre.
  - **`hpc`** (nœud de calcul, où des CPU pleinement occupés sont l'état normal) :
    `CPU002` (charge) et `CPU003` (surcharge soutenue, Critique sur toute autre
    machine) sont rapportées comme Info au plus ; les chiffres de charge restent dans
    les preuves. **À savoir** : sous `hpc`, un nœud sur-souscrit par erreur ressemble à
    un nœud qui travaille. Le profil retire l'alarme, pas le chiffre.
  - **`diff` prévient** quand deux rapports ont été écrits avec des profils
    différents, y compris *aucun* contre un profil (sans cela, une constatation
    « améliorée » entre un rapport sans profil et un rapport `hpc` le serait sur le
    papier seulement) : avertissement `different_profiles` en JSON, avant la liste des
    changements, sans jamais modifier un changement ni le code de sortie.
  - La page de manuel a une section `PROFILES` (générée depuis le code, donc toujours
    à jour) et décrit la clé `profile` du fichier de configuration ; l'exemple du
    fichier de configuration, dans le README comme dans la page de manuel, la montre.
  - Prévu ensuite, sans rien promettre : d'autres vérifications pour le profil `server`
    (voir plus bas).
- **Le module GPU donne maintenant des détails sur les GPU Intel** (pilotes `i915`
  et `xe`). Ils étaient reconnus mais sans aucune mesure, contrairement à AMD et
  NVIDIA. Lecture directe de sysfs, sans outil externe, dans le même `GPU002`.
  - **Fréquence** : fréquence réelle, maximum du matériel, et maximum autorisé. Si
    ce dernier est plus bas que ce que le matériel peut atteindre, le rapport le
    signale (un plafond a été posé par quelqu'un ou quelque chose ; le programme ne
    sait pas qui). Un GPU qui rapporte 0 MHz est dit « idle » (endormi dans son état
    d'économie d'énergie), pas « cadencé à 0 MHz ».
  - **Bridage** : le pilote dit si le GPU est retenu sous sa fréquence cible en ce
    moment et pourquoi (`pl1`, `pl2`, `pl4`, `thermal`, `ratl`, `prochot`, ...).
    Un bridage dû à la température est un **Avertissement**, même sur un GPU
    intégré qui n'a aucune mesure de température, avec une recommandation sur le
    refroidissement ; un bridage dû à une limite de puissance est expliqué mais
    reste une information (atteindre sa limite sous charge n'est pas une panne).
    Un nom de cause que le programme ne connaît pas est montré tel que le noyau le
    donne, sans explication inventée.
  - **Cartes dédiées** : température, ventilateur et limite de puissance, par la
    puce hwmon du pilote (choisie par son nom, pas par sa position). Avec `xe`, la
    température du boîtier et sa valeur critique (noyau 7.0) permettent de juger la
    température par rapport à la limite de la carte elle-même.
  - **Ce qui n'est volontairement pas lu** : l'utilisation et la VRAM (les pilotes
    Intel ne les donnent pas par sysfs), et `cur_freq` de `xe` (le noyau réveille le
    GPU pour y répondre, ce qu'un audit en lecture seule n'a pas à faire).
  - **Limite à connaître** : les chemins, unités et formats viennent des sources du
    noyau et de sa documentation ; ils n'ont pas encore été vérifiés sur un vrai
    GPU Intel. Chaque lecture est facultative : un fichier absent ou illisible
    laisse la mesure de côté, jamais une valeur devinée. Seul le premier GT
    graphique (`gt0`) est lu.
  - Tests : 33 nouveaux, dont des arborescences sysfs factices reproduisant les
    deux pilotes, l'ancienne disposition d'`i915`, les valeurs absentes ou
    absurdes, et un périphérique Intel confié à un autre pilote. Ils échouent
    quand on casse le code (21 casseurs essayés).
- **Le module GPU voit les cartes que le noyau n'expose pas dans `/sys/class/drm`.**
  Il ne regardait que ces cartes-là : une carte réservée à une machine virtuelle
  (`vfio-pci`), un GPU sans pilote, ou un GPU de calcul dont le pilote n'enregistre
  pas de carte graphique n'apparaissaient pas, et un serveur de calcul pouvait
  afficher « No GPU detected » alors qu'il en contient. Le module cherche maintenant
  aussi les contrôleurs d'affichage (classe PCI `0x03`) sur le bus PCI.
  - **Carte sous `vfio-pci`** : listée en Info, avec une phrase disant qu'elle est
    réservée au passage à une machine virtuelle et que c'est attendu sur un hôte de
    virtualisation. Le résumé `GPU001` les compte (« 1 of 3 is bound to vfio-pci »).
  - **GPU sans pilote** : un GPU NVIDIA, AMD ou Intel est un **Avertissement**, comme
    pour une carte DRM (avant, il était invisible). Un adaptateur d'un autre fabricant
    trouvé seulement sur le bus PCI (typiquement la puce vidéo du contrôleur de gestion
    d'un serveur, souvent laissée sans pilote exprès) est listé en Info, sans alerte.
    Le comportement des cartes DRM ne change pas.
  - **Ce qui est lu** pour ces cartes : le lien PCIe, et `nvidia-smi` pour les cartes
    NVIDIA que le pilote `nvidia` gère. Rien d'autre : sans carte DRM, sysfs n'offre
    pas de mesure. La preuve `drm_card: false` l'indique.
  - **`nvidia-smi` ne compte plus que les cartes qu'il voit.** Sans cela, une carte
    réservée à `vfio-pci` à côté d'une carte utilisée aurait fait croire à un
    système multi-cartes et supprimé l'attribution des processus à la carte utilisée.
  - Les fonctions virtuelles SR-IOV ne sont pas comptées comme des GPU à part
    entière.
  - Tests : 15 nouveaux (faux bus PCI, fusion avec les cartes DRM, analyse, et le cas
    complet d'un hôte avec une carte utilisée, une carte réservée et une puce de
    gestion). Ils échouent quand on casse le code (18 casseurs essayés).
- **Une limite de puissance connue s'affiche même quand la consommation ne l'est
  pas** (« Power limit: 190.0 W. »), pour tous les fabricants. Jusque-là, elle
  n'apparaissait que dans les preuves.
- **Le module GPU nomme les puces vidéo courantes au lieu d'écrire « unknown
  vendor ».** Le fabricant se lit dans l'identifiant PCI : ASPEED (la puce vidéo
  du contrôleur de gestion d'un serveur), Matrox, VMware, Red Hat (virtio, QXL) et
  Cirrus Logic. Le résumé `GPU001` compte « 1 ASPEED » et la preuve `vendor` dit
  `ASPEED`. Ce n'est qu'un nom : la façon de juger l'adaptateur ne change pas (pas
  d'alerte pour une puce de gestion sans pilote, ce qui est normal), et un
  fabricant non reconnu reste « unknown vendor ».
- **Un lien PCIe plus étroit que la carte sait faire n'est plus présenté comme une
  anomalie à aller vérifier sur le câble.** Le cas le plus courant est ordinaire :
  deux cartes se partagent les lignes de la carte mère et tournent chacune en x8.
  La constatation lit maintenant la largeur maximale du port auquel la carte est
  branchée (nouvelle preuve `pcie_port_width_max`) et le dit :
  - **le port ne porte pas plus** : « The port it is plugged into allows at most
    x8 » : c'est la disposition de la machine, pas un défaut de la carte ;
  - **le port pourrait porter plus** : le texte ne l'attribue pas au port et
    renvoie d'abord au manuel de la carte mère (lignes partagées, réglage du
    BIOS), puis à la fixation de la carte ;
  - **le port ne dit rien** : les causes ordinaires sont listées, sans en
    accuser une.
  Quand une autre carte de la machine tourne à la même largeur réduite, le texte
  le signale (les cartes qui se partagent des lignes les répartissent souvent à
  parts égales). Une vitesse inférieure est expliquée à part : un lien au repos
  ralentit pour économiser l'énergie, ce qui est normal ; et pour une carte
  réservée à `vfio-pci`, le texte dit que la vitesse de repos ne dit rien de la
  carte, puisqu'aucun pilote de cette machine ne la gère. Aucune sévérité ne
  change.
  - **Vérifié sur une vraie machine** (deux cartes, chacune derrière un port
    qui annonce x8) : les deux ports annoncent bien x8, et le rapport dit « The port it is plugged into allows at
    most x8 ». La largeur du port n'est lue que pour un périphérique qui a un
    lien PCIe à lui : la puce vidéo d'un contrôleur de gestion, derrière un pont
    PCIe-vers-PCI, n'en a pas, et la largeur de ce pont (x1) est celle du lien du
    pont, pas de la puce.
  - **Limite connue** : un port bifurqué qui annoncerait sa largeur d'origine
    (x16) alors que la carte mère la partage n'a pas été vu. Le texte tomberait
    dans le cas « le port pourrait porter plus », dont la formulation reste
    prudente et cite les lignes partagées en premier.
  - Tests : 27 nouveaux (faux arbre sysfs avec de vrais liens symboliques pour
    le port amont, chaque cas de largeur, les cartes qui se partagent des lignes,
    la vitesse seule, la carte réservée à une machine virtuelle, les puces
    nommées, et le cas complet de la machine qui a motivé tout cela). Ils
    échouent quand on casse le code (41 casseurs essayés, 40 détectés ; le
    dernier était une condition redondante, supprimée).

- **Un profil peut ajouter ses propres vérifications. Premier cas : `--profile hpc`
  ajoute le module `hpc`, avec la vérification du gouverneur CPU (`HPC001`).** Un profil
  ne fait que baisser des sévérités. Une vérification qui est fausse sur une machine et
  juste sur une autre (un poste de travail n'a pas tort de laisser ses CPU en
  `powersave`) ne peut donc pas être une règle : c'est un module, présent seulement quand
  le profil est choisi.
  - **Le mécanisme** (`src/profile.rs`, `engine::modules_for`) : `Profile::modules()`
    donne les modules du profil, qui ne sont pas dans `all_modules()`. `Context` ne
    change pas. `--modules` reste exact : `--modules memory --profile hpc` ne lance que
    `memory`. Nommer le module demande le profil : `--modules hpc` seul est refusé, avant
    toute exécution, avec le code 2 et un message qui dit quoi taper (« the module 'hpc'
    is added by the hpc profile: run with --profile hpc (or set profile = "hpc" in the
    configuration file) »), pour `audit` comme pour `tui`. Les identifiants sont connus
    de l'analyseur de la ligne de commande : complétions et page de manuel les listent
    (la page de manuel les range sous le profil, pas sous les modules de tout audit).
    `diff` n'a rien de nouveau à savoir : un module présent dans un seul rapport est
    déjà « non comparé », et l'avertissement `different_profiles` existe déjà.
  - **`HPC001` — gouverneur de fréquence des CPU.** Il lit `scaling_governor`,
    `scaling_driver` et, quand le pilote en a un, `energy_performance_preference` de
    chaque CPU. `powersave` ne veut pas dire la même chose partout, et c'est ce qui
    rend la vérification délicate : avec `intel_pstate` et `amd-pstate-epp`, le
    processeur choisit lui-même sa fréquence et `powersave` n'est qu'un penchant (jugé
    selon la préférence : vers la performance = Info, vers l'économie d'énergie =
    Avertissement, `default` ou valeur inconnue = Info qui le dit ; sans fichier de
    préférence, la fréquence suit la charge = Avertissement), alors qu'avec les autres
    pilotes (`acpi-cpufreq`, `intel_cpufreq`…) il bloque la fréquence au minimum
    (Avertissement). `performance` est Info ; `ondemand`, `conservative` et `schedutil`
    suivent la charge (Avertissement) ; des CPU qui n'ont pas tous le même gouverneur
    sont un Avertissement. Les Avertissements viennent avec les commandes pour passer
    en `performance` tout de suite et à chaque démarrage (un fichier `tmpfiles.d`, sans
    paquet supplémentaire), et rappellent qu'un outil comme tuned peut remettre l'ancien
    réglage. Une machine sans interface de fréquence (une machine virtuelle) obtient
    une Info qui dit qu'il n'y avait rien à vérifier, ce qui n'est pas la même chose
    que « la fréquence est bonne ». Les faits sur `powersave` viennent de la
    documentation du noyau (`intel_pstate`, `amd-pstate`).
  - **Aucun jugement ne dépasse l'Avertissement**, donc choisir le profil ne fait pas
    échouer l'audit par défaut (le code de sortie suit les Erreurs). Les niveaux de
    confiance suivent l'échelle du projet (90 quand le pilote et le gouverneur
    concordent, 80 ou 78 quand reste un facteur non confirmé, 70 quand le pilote est
    inconnu, et un mélange est au plus aussi sûr que sa partie la moins sûre).
  - **Pas encore vérifié sur une machine avec `cpufreq`** : le conteneur de
    développement n'en a pas. Le cas sans interface est vu avec le vrai binaire ; les
    autres le sont sur de faux arbres sysfs.
  - Tests : 45 nouveaux (lecture sur faux arbres, chaque branche du jugement avec
    chaque pilote, le mélange, l'enregistrement du module et son refus sans profil
    avec le vrai binaire, la page de manuel, les complétions, `diff`). Ils échouent
    quand on casse le code : 49 casseurs essayés, 46 détectés du premier coup ; les 3
    autres ont donné un test de plus (le pire des types de CPU décide), un cas de plus
    (`cpu+1`, qu'un simple `parse` accepterait) et une condition redondante supprimée.

- **`--profile hpc` : nouvelle vérification `HPC002`, la limite de mémoire verrouillée
  (RDMA).** Le module `hpc` en a maintenant deux : le gouverneur (`HPC001`) puis cette
  limite. Le RDMA (InfiniBand, RoCE) transfère la mémoire sans le CPU : le noyau la garde
  verrouillée en RAM et la compte dans `RLIMIT_MEMLOCK`, quelques MiB par défaut. Une tâche
  MPI qui en enregistre davantage échoue à enregistrer la mémoire, puis s'arrête ou passe
  sur un transport plus lent.
  - **Ce qu'il lit** : les périphériques RDMA (`/sys/class/infiniband`, avec la couche de
    liaison de chaque port : InfiniBand, ou Ethernet pour RoCE) et la ligne
    `Max locked memory` de `/proc/self/limits` (limites souple et dure), comparées à la RAM
    de la machine. La ligne n'est lue que si l'unité est `bytes` et que chaque limite est un
    nombre ou `unlimited`.
  - **Ce qu'il dit** : sans périphérique RDMA, une Info qui dit que la limite n'a pas
    d'importance ici (une carte dont le pilote n'est pas chargé n'apparaît pas dans la liste).
    Avec des périphériques : limite souple illimitée ou au moins égale à la RAM = Info ;
    plus basse = Avertissement, confiance 75 %, qui dit si la limite dure laisse les
    utilisateurs la relever eux-mêmes ou s'il faut être root, avec les commandes
    (`ulimit -l`, un fichier `limits.d` pour les connexions, `DefaultLimitMEMLOCK` pour les
    services systemd, puis les commandes de vérification). Limite illisible, ou finie avec une
    RAM inconnue : Info qui le dit, sans juger.
  - **Pourquoi seulement 75 %** : la limite lue est celle de la session qui a lancé
    l'audit. Les tâches lancées par un ordonnanceur ou par un service systemd ont les leurs ;
    le constat le dit dans chaque cas.
  - **Pas encore vu sur du matériel RDMA** : ni le conteneur de développement ni la machine
    de test n'en ont. La lecture est vérifiée sur de faux arbres sysfs (plusieurs
    périphériques, plusieurs ports, ordre quelconque du système de fichiers, noms hostiles) ;
    le chemin `/sys/class/infiniband` est celui de rdma-core. Le cas « aucun périphérique »
    est vu avec le vrai binaire.
  - Tests : 25 nouveaux (23 unitaires pour la lecture et le jugement, aux frontières
    comprises : limite égale à la RAM, limite dure égale à la RAM ; plus 2 de bout en bout,
    le test existant étant remplacé par trois, un par constat et un pour l'ordre). Ils
    échouent quand on casse le code : 64 casseurs essayés, 63 détectés ; le dernier est
    équivalent (retirer le `?` sur la colonne de la limite dure donne le même résultat, car
    l'unité manquante échoue de toute façon). Un test trop lâche (la commande `printf` de
    systemd sans saut de ligne final passait) a été resserré.

- **`--profile hpc` : deux constats d'information de plus, `HPC003` (équilibrage NUMA
  automatique) et `HPC004` (SMT).** Le module `hpc` en a maintenant quatre. Ce sont des
  Info, jamais un avertissement : savoir si le réglage aide dépend des tâches, que le nœud
  ne peut pas connaître. Ils disent comment le noyau est réglé et ce que cela veut dire
  selon le genre de tâche.
  - **`HPC003`** lit `/proc/sys/kernel/numa_balancing` (un champ de bits : le bit 0
    équilibre entre les nœuds, le bit 1 est le mode « tiering » de mémoire) et compte les
    nœuds NUMA. Sans interrupteur (noyau compilé sans), ou avec moins de deux nœuds, il le
    dit et dit que le réglage ne change rien. Avec plusieurs nœuds : *actif* = le noyau
    échantillonne la mémoire par des défauts de page et la déplace vers le nœud qui s'en
    sert, ce qui aide les tâches non liées à des nœuds mais coûte du temps, et que la
    documentation du noyau dit de désactiver pour une charge déjà liée à des nœuds NUMA
    (`numactl`, liaison MPI ou Slurm) ; les commandes pour le désactiver (tout de suite,
    puis à chaque démarrage) viennent avec le constat. *Inactif* = la mémoire reste sur le
    nœud où la tâche l'a touchée en premier. Les valeurs 2 (tiering seul) et 3 (les deux)
    sont décrites à part, sans commande (écrire 0 couperait aussi le tiering) ; une valeur
    avec d'autres bits est rapportée sans être interprétée.
  - **`HPC004`** lit `/sys/devices/system/cpu/smt/` (`control`, `active`) et, avec la
    `thread_siblings_list` de chaque CPU, combien de CPU logiques se partagent un coeur
    (« 56 logical CPUs on 28 cores, 2 threads per core » ; et il le dit quand les coeurs
    diffèrent, comme sur un processeur qui mêle coeurs de performance et d'efficacité).
    Il distingue *actif*, *inactif*, *forcé inactif* (impossible à remettre sans
    redémarrer) et *pas de SMT dans ce processeur*. Quand le SMT est actif et que le noyau
    permet de l'arrêter à chaud, il explique le compromis (le SMT aide les tâches qui
    attendent la mémoire et peut ralentir celles qui calculent sur tous les CPU logiques)
    et donne les commandes pour un fil par coeur : tout de suite, puis le paramètre de
    noyau `nosmt` avec la commande de génération de la configuration de démarrage de la
    famille de la distribution (`update-grub` ou `grub2-mkconfig`, rien d'inventé pour une
    autre).
  - **Vérifié** avec le vrai binaire dans le conteneur de développement (un seul nœud ;
    SMT absent du processeur) et sur de faux arbres sysfs pour les autres cas (deux nœuds,
    SMT actif, forcé inactif, coeurs de tailles différentes, noms hostiles). **Pas encore
    vu sur une machine à deux nœuds avec SMT actif**, la tienne en est une : à regarder
    dans le premier rapport.
  - Tests : 32 nouveaux (la lecture des interrupteurs, des nœuds, du SMT et de la topologie
    sur de faux arbres ; chaque état de chaque constat, les frontières — deux nœuds, plus
    de CPU logiques que de coeurs —, la précédence de `control` sur `active` puis sur la
    topologie ; et le test de bout en bout, qui compare avec les fichiers de la machine
    quand elle les a). Ils échouent quand on casse le code : 68 casseurs essayés, 68
    détectés.

- **Le profil `server` (`--profile server`) et sa première vérification, `SRV001` : les
  mises à jour de sécurité sont-elles installées automatiquement ?** Un serveur que
  personne ne regarde chaque jour est tenu à jour par un mécanisme, pas par une personne ;
  la vérification dit si le mécanisme du système est en place.
  - **Le profil ne baisse aucune sévérité** (la description le dit, et un test l'exige) :
    il n'y a rien à excuser sur un serveur. Il ajoute le module `server`, qui n'existe que
    quand le profil est choisi, comme `hpc` pour le sien. `--modules server` sans le profil
    est refusé (code 2) avec la phrase qui dit quoi lancer. Le choix reste explicite, par
    `--profile server` ou `profile = "server"` dans le fichier de configuration.
  - **Avec apt** (Debian, Ubuntu et dérivées) : `apt-config dump` (qui fusionne tout
    `apt.conf.d`, dans l'ordre où apt le fait), la présence de `unattended-upgrade`, la
    liste des origines autorisées, et les deux timers `apt-daily.timer` et
    `apt-daily-upgrade.timer`. Les intervalles sont lus comme le script d'apt les lit :
    `0` coupe, `always` ou un nombre (avec `s`, `m`, `h` ou `d`) allume, et `00` ou `0d`
    *allument* (le script compare le texte avec `0`, pas le nombre) ; `APT::Periodic::Enable`
    à `0` coupe toutes les tâches quoi que disent les autres réglages. **Avec dnf** (Fedora,
    RHEL et dérivées) : dnf 4 ou dnf 5, `dnf-automatic` installé ou non, `apply_updates` et
    `upgrade_type` du fichier `/etc/dnf/automatic.conf` (sur les valeurs par défaut du
    paquet avec dnf 5), et les timers. Les timers qui ne font que télécharger ou prévenir ne
    comptent pas comme une installation, et la constatation dit lequel est actif à la place.
  - **Honnête sur ce qu'elle ne sait pas.** Au pire un **Avertissement à 80 %**, jamais
    certain : une machine tenue à jour autrement (outil de configuration, Landscape,
    Satellite, fenêtre de maintenance) est correcte sans ce mécanisme, et la constatation
    le dit dans son texte. En place : Info à 90 %. Un outil qui ne répond pas (`apt-config`,
    `systemctl`) donne une Info « n'a pas pu être dit », jamais un avertissement. Une
    distribution qui n'est ni Debian ni Red Hat donne une Info qui dit qu'elle n'a **pas**
    été vérifiée. Elle ne dit pas non plus si la dernière exécution a réussi (elle indique
    le `journalctl` qui le dit).
  - Chaque problème a sa phrase et ses commandes (installer le paquet, activer les
    réglages dans `20auto-upgrades`, autoriser l'archive de sécurité, activer les timers —
    après `unmask` s'ils sont masqués), et seulement celles qu'il faut.
  - Un nouvel outil dans `src/core/command.rs` : `ToolSession::run_ignoring_status`.
    `systemctl is-enabled` répond sur sa sortie (`enabled`, `masked`, `not-found`…) et son
    code de retour ne veut rien dire ; la session existante jetait toute réponse d'un outil
    qui sortait en échec.
  - **Vérifié** avec le vrai binaire dans le conteneur de développement (Ubuntu) : sans le
    paquet, puis avec un faux paquet `unattended-upgrade` posé temporairement, et avec de
    faux `apt-config` et `systemctl` pour chaque cas. **Le côté dnf n'a été vu que sur de
    faux fichiers et d'après la documentation** (pas de machine Fedora ou RHEL sous la main) :
    à regarder dans le premier rapport sur une telle machine. La tienne est une Ubuntu, donc
    le côté apt.
  - Tests : 88 nouveaux (la lecture de `apt-config dump` et du fichier dnf sur de faux
    arbres, y compris un fichier énorme et des valeurs hostiles ; chaque problème, ses
    phrases et ses étapes ; le profil, les options et le refus du module sans profil ; et
    17 tests de bout en bout avec le vrai binaire et de faux outils). Ils échouent quand
    on casse le code : 220 casseurs essayés, 217 détectés. Les trois autres ont montré du
    code inutile, retiré (le cas particulier des commentaires `#` et `;` du fichier dnf,
    déjà exclus parce que le nom commence par la marque, et une branche dnf 5 qui ne
    pouvait jamais servir). Plusieurs tests trop lâches ont été resserrés en route.
  - Prévu ensuite, sans rien promettre : `SRV002` (journal persistant) et `SRV003`
    (redémarrage en attente depuis longtemps).

### Modifié

- Le message sur l'absence de pilote cite maintenant `amdgpu`, `i915` ou `xe`.
- La description du profil `hpc` (en-tête des rapports, page de manuel) dit maintenant
  aussi qu'il ajoute le module `hpc`.
  Elle dit aussi, ainsi que la phrase du module dans la page de manuel, qu'il vérifie la
  limite de mémoire verrouillée et qu'il rapporte l'équilibrage NUMA et le SMT.
- Le texte sur le lien PCIe d'une carte ne dit plus « worth checking the physical
  slot/cable » : il décrit ce qui est mesuré (`PCIe: 8.0 GT/s PCIe x8 (this card
  supports up to 8.0 GT/s PCIe x16).`), puis explique la largeur et la vitesse
  séparément. Les preuves `pcie_link_*` n'ont pas changé.

### Corrigé

- **Le nombre de CPU d'un rapport est celui de la machine, pas celui du processus.**
  Il venait de `available_parallelism()`, qui respecte l'affinité du processus et les
  limites de cgroup : sur une machine de 56 CPU dont 24 sont isolés pour une machine
  virtuelle, l'en-tête annonçait « 32 CPUs » alors que le module `hpc` en voyait 56. Le
  nombre vient maintenant de la liste des CPU en ligne du noyau
  (`/sys/devices/system/cpu/online`, par exemple `0-55` ou `0-27,56-83`), et
  `available_parallelism()` ne sert plus que de repli quand la liste est illisible.
  Cela touche l'en-tête des rapports (terminal, Markdown, HTML, interface), le champ
  `context.cpu_count` du JSON et la comparaison de machines de `diff` ; les modules, eux,
  ne s'en servent pas (le module CPU compte ses propres processeurs dans `/proc/cpuinfo`).
  - Vu avec le vrai binaire : confiné à un seul CPU par `taskset -c 0`, l'ancien annonçait
    « 1 CPUs », le nouveau le nombre réel.
  - Tests : 8 nouveaux (l'analyse de la liste : intervalles, trous, entrées refusées dont
    les signes et les listes inversées ; le repli ; et `tests/cpu_count.rs`, qui lance le vrai
    binaire confiné à un CPU et exige le même nombre qu'en liberté). Ils échouent quand on
    casse le code : 12 casseurs essayés, 10 détectés (dont deux seulement grâce au test de
    bout en bout). Restent un équivalent sur 64 bits (l'arithmétique contrôlée contre le
    débordement, qui ne sert qu'aux systèmes 32 bits) et un indiscernable ici (`possible`
    à la place de `online`, identiques sur cette machine).

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

## [1.8.0] - 2026-10-16

Un fichier de configuration pour garder ses options sans les retaper, et la
correction du plantage de `audit | head`. Le format du rapport JSON ne change
pas (`schema_version` reste 1).

### Ajouté

- **Un fichier de configuration, `~/.config/linuxdoctor/config.toml`** (sous
  `$XDG_CONFIG_HOME` quand il est défini), pour garder sans les retaper les
  options qu'on tape à chaque fois : `timeout`, `fail_on`, `min_severity`
  (valables pour `audit` et `diff`) et `output` (dans les sections `[audit]` et
  `[diff]`, car les deux commandes n'acceptent pas les mêmes formats). Le
  fichier est facultatif, comme chacune de ses lignes.
  - **Ce qu'on tape sur la ligne de commande l'emporte toujours**, option par
    option : le fichier ne remplit que ce qui n'a pas été tapé. Taper la valeur
    par défaut compte comme une saisie (`--output terminal` l'emporte sur
    `output = "markdown"`). Dans le fichier, la ligne d'une section l'emporte
    sur celle du haut.
  - **Les mots sont ceux de la ligne de commande**, lus par le même analyseur
    (`"md"` marche comme `--output md`) : une valeur ou un alias ajouté plus
    tard existe aux deux endroits à la fois.
  - **Une erreur est une erreur, jamais une devinette.** Clé inconnue, valeur
    refusée, fichier illisible, trop gros (plus de 64 Kio), qui n'est pas du
    texte UTF-8 ou qui n'est pas un fichier ordinaire : le programme s'arrête
    avec le code 2, avant d'avoir rien exécuté, en disant quel fichier et quelle
    ligne. Seule l'absence du fichier par défaut est normale.
  - **`--config FICHIER`** lit un autre fichier (qui doit exister) et
    **`--no-config`** ignore le fichier pour une exécution, y compris un fichier
    cassé. `man` et `completions` ne lisent jamais le fichier ; `tui` ne lit que
    `timeout`.
  - **Un niveau venant du fichier s'explique**, comme `--fail-on`, quand il
    donne le code de sortie 1 : `fail_on = "warning" in /home/vous/.config/…`.
    Le niveau par défaut reste silencieux.
  - `--modules` n'est volontairement pas configurable : un fichier qui
    restreindrait discrètement chaque audit donnerait des rapports d'apparence
    saine sur des vérifications jamais faites.
  - Le fichier est traité comme un texte non fiable : lu après un `stat` (un
    tube nommé ferait attendre `open` indéfiniment), borné, et la ligne citée
    dans une erreur est raccourcie et débarrassée de ses caractères de
    contrôle (l'affichage d'erreur de la bibliothèque TOML aurait recopié la
    ligne entière).
  - La page de manuel a une section FILES avec l'exemple complet ; le README a
    la section « The configuration file », et un test vérifie que l'exemple du
    README est exactement celui que le programme accepte.
  - Nouvelle dépendance : `toml` 0.9.6 (lecture seule : fonctionnalités `std`,
    `serde` et `parse`), fixée avec ses dépendances pour rester compilable avec
    Rust 1.75 (voir la « Toolchain note » du README).
  - Tests : 34 tests unitaires (`src/config.rs`) et 19 tests d'intégration avec
    le vrai binaire (`tests/config_file.rs`) ; ils échouent quand on inverse la
    priorité, qu'on oublie de lire le fichier ou qu'on perd l'origine du niveau.
    Un test vérifie aussi que chaque test qui lance le binaire l'isole du vrai
    fichier de configuration de celui qui exécute la suite.

### Modifié

- `audit --output` et `diff --output` n'ont plus de valeur par défaut dans
  `clap` : l'aide n'affiche plus « [default: terminal] » mais le dit dans son
  texte (« Default: terminal »). Le comportement est le même ; il fallait
  pouvoir distinguer « non tapé » de « tapé » pour que le fichier ne remplace
  que ce qui n'a pas été tapé.
- Le message de `--fail-on` sur la sortie d'erreur indique maintenant d'où vient
  le niveau (`--fail-on warning` ou la ligne du fichier) ; avec l'option tapée,
  il est identique à avant.

### Corrigé

- **`linuxdoctor audit | head` ne plante plus.** Quand le lecteur de la sortie
  disparaissait avant l'écriture (`| head -1`, un pager quitté aussitôt), les
  quatre formats d'`audit` paniquaient (message `failed printing to stdout:
  Broken pipe`, code de sortie 101) parce qu'ils écrivaient avec `print!`.
  Le texte est maintenant construit puis écrit avec l'écriture sûre déjà
  utilisée par `diff`, `man` et `completions` : un lecteur parti n'est pas une
  erreur. Le verdict ne change pas pour autant : le code de sortie reste celui
  de l'audit (1 si un constat atteint le niveau `--fail-on`) et un `--fail-on`
  explicite s'explique toujours sur la sortie d'erreur. Une vraie erreur
  d'écriture (disque plein) reste signalée et donne le code 1.
  - Tests : `tests/broken_pipe.rs` ferme le tube avant l'écriture (les audits
    sont assez longs pour que ce soit certain) et vérifie, avec le vrai
    binaire, l'absence de panique pour les quatre formats, le verdict conservé
    (faux `df` presque plein), le message de `--fail-on`, et `man`,
    `completions` et `diff`. Trois de ces tests échouent sans le correctif.

## [1.7.0] - 2026-10-16

La comparaison de deux rapports (`linuxdoctor diff`) et un correctif de
sécurité : le texte choisi par la machine auditée ne peut plus agir sur votre
terminal. Le format du rapport JSON ne change pas (`schema_version` reste 1).

### Sécurité

- **Le texte choisi par la machine auditée ne peut plus agir sur votre
  terminal.** Noms de processus, de machines virtuelles et de conteneurs,
  points de montage, noms d'utilisateurs, messages d'outils : n'importe lequel
  pouvait contenir une séquence d'échappement (effacer l'écran, changer le titre
  de la fenêtre, réécrire la ligne du dessus avec un retour chariot) ou un
  contrôle bidirectionnel qui inverse l'ordre d'affichage. Les rapports
  Markdown et HTML les transmettaient tels quels (un `cat rapport.md` suffisait
  à les déclencher), et le terminal comme la TUI ne les filtraient pas
  partout. Désormais le rapport terminal, Markdown, HTML et la TUI remplacent
  par `?` les caractères de contrôle et les contrôles bidirectionnels ; les
  retours à la ligne, l'indentation, les accents et les écritures de droite à
  gauche sont conservés, et un vrai audit complet (874 chaînes) n'est modifié
  en rien.
  - Un seul point d'entrée : `output::common::display_safe` copie le rapport en
    traitant **chaque** chaîne. Il décompose `Context`, `ModuleRunResult`,
    `Finding` et `Confidence` sans `..` : ajouter un champ texte à l'un d'eux
    empêche la compilation tant qu'il n'est pas traité, donc un rendu ne peut
    pas l'oublier. La fonction de nettoyage est `core::text::printable`.
  - Le JSON ne change pas, volontairement : il échappe déjà les caractères de
    contrôle (`\u001b`) et reste l'enregistrement fidèle de ce qui a été
    observé, ce que `linuxdoctor diff` compare.
  - Tests : un test par rendu (terminal, Markdown, HTML, mémoire tampon de la
    TUI, y compris après un `r`), un test sur le rapport entier, et
    `tests/hostile_names.rs` qui lance le vrai binaire contre un faux `df` dont
    le point de montage est fait de séquences d'échappement, dans les quatre
    formats et dans `diff`. Chacun échoue quand l'appel est retiré.

### Ajouté

- **Comparaison de rapports** : `linuxdoctor diff avant.json apres.json`
  compare deux rapports JSON (`audit --output json`) et indique ce qui a
  changé : constats **apparus**, **résolus**, **aggravés** ou **améliorés**
  (avec les valeurs de preuve qui ont bougé), les changements d'information
  seule (« Autres changements ») étant séparés pour qu'une nouvelle interface
  réseau ne passe pas pour une régression. Les faits de la machine (noyau,
  distribution, mémoire, CPU, redémarrage) sont listés en premier.
  - **Une absence n'est jamais une bonne nouvelle** : un constat qui a disparu
    n'est « résolu » que si son module est réellement allé au bout dans le
    second rapport. Un module en échec, ignoré ou absent est listé sous
    « Non comparés » (avec le nombre de constats qu'on n'a pas pu revérifier),
    et un module dont des commandes ont été interrompues marque les changements
    concernés d'un `?`.
  - Avertissements en tête quand la comparaison risque de ne rien valoir :
    machines différentes, rapports probablement inversés (le second date d'un
    démarrage antérieur), ou rapport écrit avec `--min-severity`.
  - `--output terminal|json|markdown` (alias `md`) ; le JSON est un document
    versionné (`schema_version`, `kind: "comparison"`). `-` lit l'un des deux
    rapports sur l'entrée standard.
  - `--min-severity` (filtre d'affichage, qui compte ce qu'il masque) et
    `--fail-on` (code de sortie, jugé sur la comparaison entière avant tout
    filtre) fonctionnent comme pour `audit`. Codes de sortie : **0** rien
    n'est apparu ni n'a empiré au niveau demandé (par défaut `error`), **1**
    un constat est apparu ou a empiré à ce niveau ou au-dessus, **2** la
    comparaison n'a pas pu se faire (fichier illisible, pas un rapport
    LinuxDoctor, format plus récent que le programme) ou erreur d'usage.
  - Les fichiers lus sont traités comme non fiables : titres, instances,
    preuves, messages d'erreur et noms de machine passent par
    `core::text::clean` pour le terminal et sont échappés pour le Markdown ;
    un fichier hostile ne peut pas envoyer de séquences d'échappement au
    terminal. Taille limitée à 64 Mio.
  - La page de manuel (code de sortie, exemples, description) et les
    complétions du shell connaissent la nouvelle commande.
- `core::text::clean` : le nettoyage du texte non fiable (caractères de
  contrôle, séquences d'échappement, contrôles bidirectionnels, troncature),
  déplacé du module Journaux pour servir aussi à `diff`. Le module Journaux
  le réexporte, son comportement est inchangé.
- `Severity` est désormais désérialisable (`serde`), ce que la lecture des
  rapports exige.
- Tests : 25 tests d'intégration du binaire réel (`tests/diff_command.rs` :
  codes de sortie, entrée standard, fichiers illisibles ou hostiles, trois
  formats, relecture d'un vrai rapport `audit`), 44 tests unitaires dans
  `src/diff/`, 6 dans la CLI et la page de manuel.

## [1.6.0] - 2026-10-15

Deux modules (Sécurité, Journaux), les rapports Markdown et HTML, les options
`--min-severity` et `--fail-on`, la page de manuel et les complétions du
shell. Un changement de comportement à connaître : `--modules` refuse
désormais un identifiant inexistant au lieu de produire un rapport vide.

### Ajouté

- **Page de manuel** : `linuxdoctor man` écrit sur la sortie standard la page
  `linuxdoctor(1)` (format roff), avec NOM, SYNOPSIS, DESCRIPTION, OPTIONS,
  COMMANDES (chacune avec ses propres options), MODULES, CODES DE SORTIE,
  EXEMPLES, VOIR AUSSI. Les options viennent de la définition clap que
  l'analyseur utilise réellement (via `clap_mangen`) et la liste des modules du
  registre `all_modules()` : la page ne peut pas contredire le programme. Elle
  est déterministe (pas de date, seulement la version), et le test
  d'intégration la fait relire par `groff -ww` quand il est installé, sans le
  moindre avertissement. Un module enregistré sans ligne de description dans
  `module_summary()` (`src/manpage.rs`) fait échouer un test.
- **Complétions du shell** : `linuxdoctor completions <bash|zsh|fish|elvish|
  powershell>` écrit le script de complétion (via `clap_complete`). Il propose
  les sous-commandes, les options, les valeurs de `--output`, `--min-severity`
  et `--fail-on`, et les identifiants de modules pour `--modules`.
- **Les paquets `.deb` et `.rpm` installent** la page de manuel
  (`/usr/share/man/man1/linuxdoctor.1.gz`, `gzip -9n`) et les complétions bash,
  fish et zsh (`vendor-completions` sur Debian/Ubuntu, `site-functions` sur
  Fedora/RHEL/openSUSE). `build-deb.sh` et `build-rpm.sh` les génèrent avec le
  binaire qu'ils viennent de compiler ; si une génération échoue, `Cargo.toml`
  est restauré comme pour les autres étapes.
- Dépendances : `clap_complete` 4.4.10 et `clap_mangen` 0.2.20 (donc `roff`
  0.2.2), figées sur ces versions car ce sont les dernières à accepter
  `clap` 4.4 et une version de Rust inférieure à 1.85. Elles n'ajoutent que
  trois paquets au `Cargo.lock` et ne changent aucune version existante.

- **Module Journaux** (`linuxdoctor audit --modules logs`) : lecture seule.
  Il lit le journal systemd (`journalctl -o json`), avec repli sur
  `/var/log/auth.log` ou `secure` et sur `dmesg`. Quatre sujets (sous-menus
  du TUI) :
  - **Authentification** (`LOG002` à `LOG004`) : échecs de connexion SSH des
    dernières 24 heures par adresse source et par nom de compte ; une
    connexion par mot de passe qui suit de nombreux échecs de la même adresse
    (la signature d'un mot de passe deviné : Critical à partir de 20 échecs,
    Warning à partir de 5) ; échecs `sudo`, `su` et console, et comptes
    refusés par `sudo`. Un échec compte une seule fois même si sshd journalise
    à la fois le compte refusé et la tentative de mot de passe.
  - **Erreurs système** (`LOG005`) : messages d'erreur depuis le démarrage,
    regroupés par service, avec le message que chacun répète le plus.
  - **Messages du noyau** (`LOG006`, `LOG007`) : erreurs de disque et de
    système de fichiers, système de fichiers passé en lecture seule,
    erreurs mémoire/PCIe corrigées ou non, tâches bloquées, bridage
    thermique, fautes du noyau, blocages de processeur, programmes qui
    plantent. Les arrêts par manque de mémoire (OOM) restent au module Noyau.
  - **Journal et fichiers de log** (`LOG008`, `LOG009`) : le journal survit-il
    à un redémarrage, sa taille face au plafond de journald, services dont
    journald a dû jeter des messages, fichiers de `/var/log` jamais tournés.
  Un constat de synthèse `LOG001` ouvre la page du module et liste ce qui
  demande de l'attention **et ce qui n'a pas pu être lu** : un journal
  illisible (pas de droits, journald absent, conteneur) n'est jamais présenté
  comme un journal tranquille, et la commande pour rejoindre les groupes
  `adm` et `systemd-journal` est donnée. Un suspect d'intrusion passe avant
  tout autre constat de même gravité. Le texte venu des logs (noms de compte
  choisis par un attaquant, noms de programmes) est débarrassé de ses
  caractères de contrôle — séquences d'échappement du terminal comprises —,
  borné en longueur, et n'entre dans une commande suggérée que s'il s'agit
  d'un simple mot ; les adresses n'y entrent que si ce sont de vraies
  adresses IP. Les commandes sont seulement proposées, jamais exécutées.
- `modules::recommend` fournit maintenant aussi la famille de distribution
  (`Family`, `family_of`) pour choisir entre `apt` et `dnf` ; le module
  Sécurité l'utilise au lieu de sa propre copie.
- `core::context::effective_uid()` : identifiant utilisateur effectif lu dans
  `/proc/self/status`, partagé par les modules Sécurité et Journaux.

- **Module Sécurité** (`linuxdoctor audit --modules security`) : lecture
  seule, utilisable sans root (root ajoute de la visibilité, et chaque
  constat dit ce qu'il n'a pas pu voir). Six sujets (sous-menus du TUI) :
  - **Services à l'écoute** (`SEC002`, `SEC003`) : tous les sockets TCP/UDP
    de `/proc/net/*`, accessibles du réseau ou seulement de la machine,
    avec le programme propriétaire quand c'est possible. Un catalogue de
    services qui ne devraient presque jamais être exposés (Telnet, API
    Docker non chiffrée, Redis, Memcached, bases de données, VNC, SNMP…)
    produit un constat par service exposé, avec des étapes pour le
    vérifier, le restreindre ou le filtrer.
  - **Pare-feu** (`SEC004`) : ufw, firewalld, nftables ou iptables. Une
    absence de pare-feu n'est un avertissement que si un port TCP (hors SSH)
    est réellement joignable ; le constat précise si les règles ont pu être
    lues.
  - **SSH** (`SEC005`) : configuration effective de `sshd_config` avec
    `Include` et blocs `Match` (connexion root, mots de passe vides ou
    autorisés, protocole 1, confiance par hôte, algorithmes faibles…),
    plafonnée à Warning quand sshd ne tourne pas. Les étapes mettent
    l'action sûre en premier : installer une clé avant de désactiver les
    mots de passe, valider avec `sshd -t`, garder une seconde session
    ouverte.
  - **Contrôle d'accès** (`SEC006`) : SELinux (enforcing, permissive,
    désactivé, et écart avec `/etc/selinux/config`) et AppArmor (profils
    chargés et appliqués), lus dans sysfs sans outil externe.
  - **Durcissement** (`SEC007`) : 19 réglages noyau/réseau jugés selon la
    valeur réellement appliquée, avec les commandes pour les rendre
    persistants dans `/etc/sysctl.d/` sans toucher aux fichiers de la
    distribution.
  - **Comptes et fichiers** (`SEC008`, `SEC009`) : comptes UID 0 supplémentaires,
    connexions sans mot de passe, hachages faibles (si `/etc/shadow` est
    lisible), droits de `/etc/passwd`, `/etc/shadow`, `sudoers`, de la
    configuration SSH et de `/tmp`.
  Un constat de synthèse `SEC001` ouvre la page du module et liste ce qui
  demande de l'attention ; tout ce qui est Warning ou plus reste sur cette
  page, le reste est rangé par sujet. Les commandes ne sont jamais
  exécutées, seulement proposées.
- Module `modules::recommend` : le constructeur d'étapes numérotées
  (`Steps`) et les commandes `sysctl`, extraits du module Mémoire pour être
  partagés.

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

- **`--modules` refuse maintenant un identifiant inconnu** (code de sortie 2,
  avec la suggestion « a similar value exists: 'memory' »), pour `audit` comme
  pour `tui`. Avant, une faute de frappe (`--modules memroy`) ne sélectionnait
  aucun module et produisait un rapport vide avec le code 0 : un résultat
  « propre » que personne n'avait vérifié. Une seule faute dans une liste
  (`memory,logz`) arrête toute l'exécution. Les identifiants sont ceux de
  `all_modules()`, donc un nouveau module est accepté (et complété) dès qu'il
  est enregistré.
- Le code de sortie passe par `core::gate`. Sans `--fail-on`, le comportement
  est inchangé : code 1 dès qu'un constat Error ou Critical existe (et
  pour une erreur d'exécution), code 2 pour une erreur d'utilisation.
  `linuxdoctor tui` garde ce seuil par défaut et n'a pas les nouvelles options.
- Un module dont un outil a été interrompu (« données incomplètes ») est
  présenté en Markdown/HTML comme « ⚠ Incomplete data » et non comme « OK »,
  comme dans le terminal.

### Tests

- `tests/docs_commands.rs` : 11 tests d'intégration avec le vrai binaire —
  `man` (page roff, tous les modules listés, sortie identique d'une exécution à
  l'autre, relecture par `groff -ww` sans avertissement), `completions`
  (bash, zsh, fish ; shell inconnu ou absent = erreur d'usage) et le contrôle de
  `--modules` (faute de frappe seule ou dans une liste, aussi pour `tui`, et un
  identifiant correct qui s'exécute toujours). Plus 17 tests unitaires
  (`cli.rs`, `manpage.rs`) : sections dans l'ordre, options communes
  documentées une seule fois, `help` absent, version dans l'en-tête sans date,
  scripts de complétion qui connaissent chaque module.
- `tests/logs_module.rs` : 14 tests d'intégration du module Journaux — un
  serveur tranquille (rien au-dessus d'Info), un serveur en difficulté (tous
  les constats attendus avec la bonne gravité), l'ordre des pages et les
  étapes numérotées, les conseils selon la famille de distribution, un
  contenu hostile (balises HTML/Markdown, séquences d'échappement du
  terminal, noms pouvant casser une commande) à travers les quatre
  formats, et le vrai binaire contre un faux `journalctl` placé en tête du
  `PATH` : journal simulé, code de sortie, journal illisible signalé, journal
  qui ne répond pas (arrêté après la limite de temps et signalé comme
  incomplet), et un test sur la machine hôte qui ne vérifie que la présence
  des constats, jamais leur gravité.
- 110 tests unitaires pour le module Journaux (analyseurs du journal, de
  syslog et de `dmesg`, des messages SSH/sudo/PAM, du noyau, de
  `journald.conf`, logique de repli entre sources, parcours de `/var/log`
  sans suivre les liens symboliques).
- `tests/security_module.rs` : 8 tests d'intégration du module Sécurité —
  un serveur bien tenu (rien au-dessus d'Info), un serveur négligé (tous les
  constats attendus avec la bonne gravité), l'ordre des pages et la présence
  d'étapes numérotées, les identifiants `SEC001` à `SEC009`, noms hostiles
  (balises HTML, Markdown, JavaScript) à travers les rendus Markdown et HTML,
  les quatre formats, et un test du vrai binaire sur la machine hôte qui ne
  vérifie que la présence des constats, jamais leur gravité (elle dépend de
  la machine).
- 139 tests unitaires pour le module Sécurité (analyseurs de `/proc/net/*`,
  `sshd_config`, `nft`/`iptables`, `passwd`/`shadow`/`group`, SELinux,
  AppArmor, réglages sysctl) sur des textes d'exemple, y compris les entrées
  mal formées.
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
