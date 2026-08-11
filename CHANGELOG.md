<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [Non publié]

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
