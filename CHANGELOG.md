<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **The documentation is now in English only.** `CHANGELOG.md` (every entry, from 0.1.0 on)
  and `CONTRIBUTING.md` were written in French; they are now in English, like `README.md`,
  `ARCHITECTURE.md` and `PROJECT_CONTEXT.md`, because LinuxDoctor is aimed at system engineers
  and advanced support staff. `CONTRIBUTING.md` says so in its "Documentation" section. No
  change to the program.

## [1.11.3] - 2026-10-25

Bug-fix release: only one thing changes in the program, the network module (`NET002`).
SR-IOV virtual interfaces (VFs) get their own explanation, instead of receiving the
cable-duplex-switch advice that only applies to a physical card.

### Fixed

- **SR-IOV virtual interfaces (VFs) now have their own explanation (`NET002`).**
  The report for `enp6s0v1` and `enp6s0v2` gave an RX drop rate without saying that it can be
  normal for a VF, and the old advice (cable, duplex, switch port) means nothing for a VF, which
  has no cable or link of its own. **This is not a code regression**: the SR-IOV note has existed
  since 1.0.0, and it was only ever written for the physical card (`enp6s0`, which sees its VFs
  through `sriov_numvfs`); the VFs themselves had no handling at all, in any version. They now
  have one, of the same kind as the physical card's:
  - an interface is recognized as a VF by the `physfn` link of its PCI device (which the kernel
    only creates for VFs); the physical card it depends on is named by its interface
    (`enp6s0`), or by its PCI address if it has none;
  - when drops or errors reach 0.1% of packets, the severity drops by one level and the
    confidence goes to 65%, as for the physical card; the explanation says that the interface is
    a VF of `enp6s0`, that it shares the link of its physical card and that the NIC may send it
    traffic that nothing consumes (broadcast, multicast); the sentence about the cable and the
    duplex is not given;
  - the recommendation says to look first at how the VF is used (its traffic, its MAC, VLAN and
    trust settings, which `ip link show` lists on the physical card), and only then at the cable
    and the port of the physical card;
  - a VF without drops has no note to carry (nothing to explain); the `sriov_vf_of` evidence
    names its physical card in every case.
  - Physical cards, with or without VFs, do not change by a single word.
  - Verified on fake `/sys` trees that reproduce the shape of the kernel's links (`device`,
    `physfn`, `net/`), up to the findings for `enp6s0v1` and `enp6s0v2`; **not on a real machine
    with VFs**: the development container has none. Whether the explanation is right for your
    card (here, that the VFs' drops really come from traffic that nothing consumes) remains to be
    confirmed on your side.
  - Tests: 12 new (reading the links: card named, PCI address, several interfaces, names cleaned
    and cut to 64 characters, physical card and virtual interface that are not VFs; the three
    drop cases of a VF; the physical card unchanged; a card with a single VF; and an end-to-end
    test on `enp6s0v1` and `enp6s0v2`).

## [1.11.2] - 2026-10-25

Bug-fix release: only one thing changes in the program, the storage module
(`STOR001`, `STOR002`). It no longer takes `efivarfs`, a mounted DVD or the kernel's
filesystems for full disks.

### Fixed

- **Kernel filesystems are no longer mistaken for full disks (`STOR001`,
  `STOR002`).** `efivarfs`, which holds the UEFI variables, came out as Critical (confidence
  89%) under "Filesystem Usage — /sys/firmware/efi/efivars", with the recommendation to
  delete files: `df` lists it because it has a small size, almost entirely used, whereas `proc`,
  `sysfs` or `cgroup2`, of zero size, are already hidden by `df`. It is not a disk that an
  administrator fills or can enlarge. Three changes, in `is_real_filesystem`:
  - `efivarfs`, `selinuxfs`, `resctrl` and `nfsd` join the list of ignored types (the other
    types in the report — `sysfs`, `proc`, `tmpfs`, `devtmpfs`, `cgroup2`,
    `securityfs` — were already there);
  - everything mounted under `/sys` or `/proc` is ignored, whatever its type, so that the next
    kernel filesystem does not repeat the same mistake. The path is compared component by
    component: `/sysroot` or `/proc-backup` remain disks;
  - media that are full by construction (`iso9660`, `udf`, `erofs`, `cramfs`, and `squashfs`
    which already was) are ignored by the same list as the one used by `STOR006`. A mounted DVD
    came out at 100%, as Critical, with "writes may already be failing".
  - The list remains an exclusion list, not an inclusion list: an inclusion list would silently
    make `lustre`, `gpfs`, `virtiofs` or the next real filesystem disappear.
  - Verified on realistic `df` text (an `efivarfs` line at 97% and a DVD at 100%, up to the
    findings produced); **not on a real UEFI machine**: the development container is not one.
    The exact text that `df` prints for `efivarfs` was therefore not captured on a real machine,
    only its shape.
  - Tests: 6 new (the 26 kernel types one by one, the 5 read-only media,
    the mounts under `/sys` and `/proc`, `/sysroot` and its like that remain disks,
    15 types of real filesystems that remain reported, and an end-to-end test on
    `df` text).

## [1.11.1] - 2026-10-18

Documentation release: the program is the same as 1.11.0 (not a single line of shipped code
changes). What changes is the README embedded in the packages: written for someone discovering
LinuxDoctor, and complete, because all the useful sections of the old README have come back into
it; and the screenshot of the interface that it shows is now in the packages too.

### Changed

- **The packages install the `docs/` folder.** `build-deb.sh` and `build-rpm.sh` only copied
  five files from the root into `/usr/share/doc/linuxdoctor/` (`README.md`, `CHANGELOG.md`,
  `PROJECT_CONTEXT.md`, `ARCHITECTURE.md`, `LICENSE`); the README's relative link to
  `docs/linuxdoctor-tui.png` was therefore broken once the package was installed. Both scripts now
  copy `docs/` next to the README (permissions are normalized afterwards like the rest).
  Verified on a copy of the scripts' set-up lines; **not yet seen in a real
  package**: `fpm` is not installed in the development container, the first
  build will show it (`dpkg -c linuxdoctor_1.11.1_amd64.deb | grep docs`).
- **The README is shorter at the start and addresses someone discovering LinuxDoctor**: target
  environments, distributions and packages, principles, what the tool diagnoses, installation,
  common commands, screenshot of the interface (`docs/linuxdoctor-tui.png`). This text has been
  kept as it was written; the sections of the old README that no longer appeared in it are added
  after it, removing nothing: **Quickstart from a source build**, **Reports, filtering and exit codes**,
  **Profiles**, **Comparing two reports**, **The configuration file** (with the exact example),
  **Manual page and shell completions**, **Speed and slow tools**, **Modules in detail** (the
  detail of each of the thirteen modules), **Runtime dependencies in detail**, **Toolchain note**
  (the five dependencies pinned for Rust 1.75, which `ci.yml` and `ARCHITECTURE.md` cite),
  **Packaging**, **Tests** and **Layout**.
  - **Text carried over as is, except where it had become wrong**: "Status" becomes "Modules in
    detail" (and "v1 scaffold" becomes "Thirteen modules"); "Quickstart" and "Runtime
    dependencies" get a title that does not clash with the short sections of the new text;
    the paragraph of "Packaging" that said `VERSION` is not part of the sources
    had been wrong since 1.9.0 and now says how a version is prepared (`VERSION`,
    `Cargo.toml` and `Cargo.lock` together, packages built with `--no-version-change`);
    "Layout" knows about `docs/`, the checks added to the `hpc` and `server` profiles, the RAID and
    the read-only mounts of `storage`, and two more test files; the end of the
    "Toolchain note" said "both" when there are five pins; a "see below" cross-reference
    becomes "see above".
  - **"Getting set up" is not carried over**: it described an archive to unpack and a
    first `git commit`, and "Option 2: Build from source" replaces it.
  - The test that requires the README to contain the example from `config::EXAMPLE` is
    restored (PR #34 had removed it while the section was missing).

## [1.11.0] - 2026-10-17

Eleven new checks, all read-only. The `--profile server` profile goes from one check to five:
`SRV002` (do the logs survive a reboot?), `SRV003` (has a reboot been waiting for days?),
`SRV004` (are updates waiting?) and `SRV005` (is a kernel newer than the running one
installed?). The `storage` module sees software RAID arrays and filesystems that have gone
read-only (`STOR005`, `STOR006`); the `kernel` and `network` modules judge the kernel tables
that are filling up (`KERN007`, `KERN008`, `NET005`); the `network` module sees a link
aggregate that has lost a card and a link that flaps (`NET006`, `NET007`). A profile is chosen,
it is not guessed: without `--profile`, only the `storage`, `kernel` and `network` checks are
added to the report, and no existing severity changes. The layout of the JSON report does not
change (`schema_version` stays 1).
What has not been seen on a real machine: the format of `/proc/net/bonding` (`NET006`) comes
from the kernel code and from examples, not from a real kernel; `/proc/mdstat` (`STOR005`) has
only been seen on real examples, not on a running array; `SRV004` and `SRV005` have not yet
been through a real production machine; the connection-tracking table (`NET005`) has only been
seen at 0%.

### Added

- **`--profile server`: two more checks, `SRV002` (do the logs survive a reboot?) and
  `SRV003` (has a reboot been waiting for days?).** The `server` module now has three, in that
  order; `SRV003` only appears if there is something to say. Like `SRV001`, they only exist
  with the profile, and lower no severity.
  - **`SRV002` — logs kept after a reboot.** After a crash, a power cut or a reboot that nobody
    asked for, the logs are the only witness of what happened, and on a server that nobody was
    watching they are the only one. The systemd journal is only on disk if `Storage=` wants it:
    `persistent`, or `auto` (the default) **with** a `/var/log/journal` directory; otherwise it
    is in memory and goes away with the reboot. The check reads `Storage=` the way journald
    reads it: `journald.conf` (the first one that exists among `/etc`, `/run`, `/usr/local/lib`,
    `/usr/lib`), then the files of `journald.conf.d` in the same directories, sorted by name
    whatever the directory, a name in a higher-priority directory hiding the same name lower
    down (a link to `/dev/null` too), the last **valid** value winning (the four words are exact;
    an invalid value is ignored, so what came before stays). It also looks at the directory, and
    at whether the classic logs (`/var/log/syslog`, `/var/log/messages`) have been written in
    the last 7 days.
    - Journal on disk, or classic logs written: **Info** (90%). Journal in memory and no classic
      log: **Warning at 80%**, with the commands to keep it (change `Storage=` in the file that
      says `volatile` or `none`, create `/var/log/journal` with `systemd-tmpfiles`, restart
      journald, check with `--list-boots`). No more than 80%: the machine may send its logs
      elsewhere (syslog or journal-remote collector, Promtail, Filebeat), which nothing here
      can see, and the text says so. Without a systemd journal: an Info that says nothing was
      checked.
    - **What `LOG008` does not do**: it judges the journal from its directory alone and ignores
      `Storage=`, so it does not see `Storage=volatile` on top of a directory that exists.
  - **`SRV003` — reboot left pending.** On Debian and derivatives, an update that only takes
    effect after a reboot writes `/var/run/reboot-required` (`KERN004` says it is there).
    `SRV003` adds for how long: nothing during the first week (a maintenance window to come);
    then a **Warning at 90%**, with the age in days and the packages from
    `/var/run/reboot-required.pkgs` (each one once, ten named at most, the others counted). The
    date is that of the *last* update that asked for the reboot (each one rewrites the file): it
    has been waiting **at least** that long, and the text says so, as well as that a live-patched
    kernel already has its fixes. Nothing without the marker (the other families do not have
    one, `KERN004` already says so), nor when its date is unknown or in the future.
  - Everything is read from files (no tool is run), under a root that the tests replace with a
    fake tree, and the age comes from a clock passed along with the data: `analyze` remains a
    pure function.
  - **Verified** with the real binary in the development container: journal present (Info);
    directory removed and no classic log (Warning with the commands); marker 12 days old with
    three packages, one of them duplicated (`SRV003` with the age and two packages, `KERN004`
    unchanged), then everything put back. The end-to-end tests cannot move the root: they
    compare the findings with what the machine itself says. **Not yet seen on a real machine
    with an in-memory journal or with a reboot pending for weeks**: to look at in your first
    report.
  - Tests: 44 new (the reading of `Storage=` and of the files on fake trees: order, hiding,
    links to `/dev/null`, huge file, hostile names, dates at the limits; every verdict and every
    sentence; the packages; the order of the findings in the module; and two end-to-end tests).
    They fail when the code is broken: 146 mutants tried, 146 caught; five had survived the
    first round (a path that was too long and not cut, the packages beyond ten, the reading
    clock, a wrong root) and the tests were tightened. A useless file-type check was removed
    along the way.

- **`--profile server`: two more checks, `SRV004` (are updates waiting?) and `SRV005` (is a
  kernel newer than the running one installed?).** The `server` module now has five, in that
  order; `SRV003` and `SRV005` only appear if there is something to say, `SRV004` only on Debian
  and derivatives.
  - **`SRV004` — pending updates (Debian and derivatives).** `apt list --upgradable` lists what
    is waiting, without being root and without the network (it reads the lists that apt already
    has); `SRV004` counts the packages, and those that come from a repository whose name ends
    in `-security`. The number alone judges nothing: on a machine that updates itself every
    night, an update released this morning is normal. **Warning at 80%** in two cases only: the
    package lists have not been refreshed for 7 days (`update-success-stamp`) — the real number
    may be larger and the daily refresh does not work — or security updates are waiting while
    nothing has been installed or updated for 3 days (the most recent of
    `unattended-upgrades-stamp` and the date of `/var/log/dpkg.log`). Otherwise an **Info** with
    the numbers. If `apt` does not answer, the number is said to be unknown, never zero. The
    commands (refresh, look, install, understand why the automatic task did not do it) are only
    given for the warning. Nothing on Red Hat and derivatives: `dnf` would have to refresh its
    metadata over the network to answer.
  - **`SRV005` — kernel newer than the running one installed.** A kernel is only replaced at the
    next reboot. Debian says so with `/var/run/reboot-required` (`SRV003`, `KERN004`); the other
    families have no marker, so `SRV005` compares the running kernel
    (`/proc/sys/kernel/osrelease`) with the installed kernels (`/boot/vmlinuz-*` and
    `/usr/lib/modules/*/vmlinuz`). Versions are compared as numbers (`6.8.0-9` is older than
    `6.8.0-45`) and only between kernels of the same variant (`generic` with `generic`; Red
    Hat's `el9_4` or `fc40` label is ignored): a machine that has a "lowlatency" kernel next to
    the one it uses has forgotten nothing. Nothing before 7 days since the installation (the
    date of the initrd); then a **Warning at 90%**, with the age and the three steps (look,
    reboot in a maintenance window, check); an **Info** when a live patch is loaded
    (`/sys/kernel/livepatch`), and an Info at 80% when the installation date cannot be found.
    Nothing when the system already has a reboot marker: it is the one that said so.
  - The tools are behind the `Tools` trait as before (one more `apt`, `slow()`: reading the
    package cache can take a few seconds); the file reads are done under the root that the tests
    replace with a fake tree, the age comes from the clock passed along with the data, `analyze`
    remains a pure function.
  - **Verified** with the real binary in the development container: the real `apt` counts 63
    updates, 59 of them security (Info, because `dpkg.log` is a day old); with a fake newer
    kernel in `/boot`: nothing at 2 days, Warning at 10 days with its steps, kernel of another
    variant ignored, older kernel ignored, then `/boot` put back as before. The end-to-end tests
    put a fake `apt` at the head of the `PATH` (the two tests of the module that use it stop by
    themselves on a machine that is not Debian); they cannot move the root, so for `SRV005`
    they only compare the named kernel with the one the machine says.
  - Tests: 50 new (counting the `apt` list and the security repositories, the dates of the two
    marks, every verdict and every sentence at the limits of 3 and 7 days, the versions and
    their variants, the installed kernels on fake trees, the order of the module's findings,
    four end-to-end tests). They fail when the code is broken: 73 mutants tried, 73 caught (one
    had survived: the "at least one security update" threshold was only tested with two, and a
    test was added).
  - **Known limits**: `dpkg.log` changes at the slightest installation, not only a security
    update, hence the text "installed or updated"; a distribution whose variant changes with
    every version (Arch: `arch1-1`, `arch1-2`) is not compared across that change. **Not yet
    seen on a real production machine**: to look at in your first report.

- **Storage: the current state of RAID arrays and of filesystems that have gone read-only.**
  `smartctl` judges one disk at a time and the kernel log says things only once; these two
  findings read what remains true.
  - **`STOR005` — one finding per software RAID (md) array**, read from `/proc/mdstat`. Info
    when the array is whole (a `check` or a `resync` in progress is only information, with its
    progress). Warning while a spare disk is filling up ("recovery 12.6%, about 60 min
    left"), or when the array is complete but a failed disk still appears in it. Error when it
    no longer has redundancy and nothing is rebuilding, or when it has not started (`inactive`).
    The proposed commands go from `mdadm --detail` to `mdadm … --remove failed` and `--add`,
    with `smartctl -a` on the whole disk behind each failed partition. A firmware RAID container
    (`imsm`, `ddf`) is never "started" and has no health of its own: it is not reported, the
    arrays it contains are.
  - **`STOR006` — one finding per filesystem that `/etc/fstab` wants read-write and that the
    kernel serves read-only.** This is what a remount after a disk error (`errors=remount-ro`)
    leaves behind. Error, Critical for `/` (the system can no longer write its logs or its
    state). Confidence 90% and not 100: someone may have remounted it on purpose (a backup,
    maintenance), and the text says so. Only the mounts that fstab lists are looked at, not
    those it writes as `ro`, `noauto` or `bind`, nor those whose medium is read-only by nature
    (`iso9660`, `squashfs`…), nor those that are not on a local disk (`tmpfs`, NFS). It
    complements `LOG006`, which reads the kernel message but only as long as the journal of that
    boot exists and can be read.
  - `STOR005` has not yet been seen on a real md array: the format of `/proc/mdstat` was
    verified against the kernel code and real examples (RAID 1, 5, Intel container), `STOR006`
    was verified on a real read-only mount.

- **Three kernel tables that fill up: `KERN007`, `KERN008` and `NET005`.** The kernel has a few
  fixed-size tables. As long as they have room, nothing shows; when one is full, the next
  program that asks for an entry is refused (`Too many open files in system`, `fork` failing
  with `Resource temporarily unavailable`, a dropped packet), and what breaks (a connection, a
  service restarting, a database) almost never traces back to the table. No tool is run:
  everything is read from `/proc`, under a root that the tests replace with a fake tree.
  - **`KERN007` — open files table** (`kernel` module): `/proc/sys/fs/file-nr` against
    `fs.file-max`.
  - **`KERN008` — table of processes and threads** (`kernel` module): the total from
    `/proc/loadavg` (each thread has its identifier) against the lower of `kernel.pid_max` and
    `kernel.threads-max`, with which of the two is responsible. A threshold of zero is ignored.
  - **`NET005` — connection-tracking table** (`network` module): `nf_conntrack_count` against
    `nf_conntrack_max`. When full, it drops the packets that would open a connection
    (`nf_conntrack: table full, dropping packet`): existing connections continue, new ones time
    out, which looks like an unstable network. No finding when `nf_conntrack` is not loaded (no
    table).
  - **One single rule for the three** (`src/modules/saturation.rs`): **Info** (100%) with the
    figures as long as there is room; **Warning** from 80%; **Error** from 95%, both at 85%
    confidence (the figure is exact, but a counter read once may be a peak: that it is a
    problem remains a strong indication). The comparison is exact, on 128-bit integers (not on
    the rounded percentage, and without overflow: `fs.file-max` is `i64::MAX` on some systems).
    The three findings always exist when the table exists, even at 0%, so that
    `linuxdoctor diff` does not report a finding that only appears under pressure.
  - **The steps** (Warning and Error only) look before touching: who holds the most files (a
    count of `/proc/[0-9]*/fd`) or threads (`ps -eo nlwp`), which protocols and addresses fill
    the tracking table, the timeout of an established TCP connection (5 days by default); then
    the limit raised to double (applied right away and kept in `/etc/sysctl.d`, never beyond
    `i64::MAX`). `kernel.pid_max` goes up at most to what the kernel accepts (4194304) and, if
    it is already there, the step says so without proposing a command.
  - **Known limits**: a single program reaching its own limit (`ulimit -n`, the `TasksMax` of a
    systemd service) is not seen, it would take walking `/proc/*/limits`; in a container,
    `/proc/loadavg` gives the number of tasks of the host machine while `pid_max` may be the
    container's. The warning text states the first.
  - **Verified** with the real binary in the development container: everything at ~0% (Info),
    then `fs.file-max` brought down to 140 and `kernel.threads-max` to 112 for a second:
    `KERN007` (93%) and `KERN008` (84%, limit responsible `kernel.threads-max`) go to Warning
    with their steps, values put back afterwards. The proposed commands were run on the machine
    and they answer. The tracking table was empty (0 entries out of 262144): its Warning was
    only seen on test figures, not on a real table that fills up.
  - Tests: 46 new (the rule and its exact bounds, including huge limits; the reading of the
    three files on fake trees, missing or unreadable pieces; every verdict and every sentence;
    the choice of the limit responsible; the steps and the capped doubling; the order of the
    findings in the two modules; four end-to-end tests, two of them with the real binary, which
    compare what it says with `/proc`). They fail when the code is broken: 39 mutants tried, 39
    caught (two had survived: a limit of 1 was not tested anywhere, cases were added). An
    existing test (`the_profile_lowers_no_finding_of_the_other_modules`) compared all the
    findings of the `kernel` module from one run to the next: the counters of `KERN007` and
    `KERN008` move, so it now only compares their severity.

- **Two network failures that nothing else reports: `NET006` (degraded link aggregate) and
  `NET007` (flapping link).** In both cases the machine "works": an aggregate that has lost a
  card keeps passing through the other, a link that drops comes back within a second. What
  breaks is whatever was passing through at that moment. No tool is run: `/proc/net/bonding`
  and `/sys/class/net`, under a root that the tests replace with a fake tree.
  - **`NET006` — aggregated interface** (`network` module, one finding per aggregate, whether
    its state is good or not, so that `linuxdoctor diff` does not report a finding that only
    appears during a failure): **Error** when no card has a link (nothing passes); **Warning**
    when the aggregate works but has lost its redundancy ("only one link stands between the
    machine and being cut off", with the number of link failures of each card since creation);
    **Warning** at 80% in 802.3ad when all the cards have a link but not in the same LACP
    aggregate (this is what a switch not configured for LACP on those ports gives: a single
    card carries the traffic, and the text says whether no switch answered); **Info** otherwise.
    The steps look before touching (`cat /proc/net/bonding/…`, then `ethtool` and `dmesg` for
    each card without a link) and change nothing.
  - **`NET007` — flapping link** (`network` module): `carrier_changes` of a filtered physical
    card (neither virtual nor Wi-Fi, which loses its link by nature). A single figure says
    nothing (the link comes up at boot, a rebooted switch drops each card once): it takes at
    least **10 changes and one on average every 12 hours** since boot. **Warning** at 80%
    (it is an average rate since boot: an old burst counts too, and the text says so). The
    steps: `dmesg`, `ethtool` and its error counters, Energy-Efficient Ethernet (`--show-eee`
    before `--set-eee … off`), changing the cable or the port to see whether the problem follows
    either, then watching the counter.
  - **Known limits**: the format of `/proc/net/bonding` was taken from the kernel code
    (`bond_procfs.c`) and from published examples, **not seen on a real kernel**: the
    development container does not have the `bonding` driver. The test with the real binary
    therefore mostly checks that it says nothing where there is nothing. Only the kernel's
    aggregates are seen (not `teamd`, nor a bridge, nor Open vSwitch). `carrier_changes` is a
    counter since the interface appeared: there is no way to know when the changes took place,
    `dmesg` says.
  - **Verified** with the real binary in the development container: no aggregate, `eth0` at 2
    changes, so neither `NET006` nor `NET007`, and the output of the network module is the one
    from before. The rest is seen on fake trees.
  - Tests: 51 new (the kernel format, line by line, including missing pieces, hostile names and
    huge files; every state of an aggregate and every sentence; the exact bounds of the
    flapping-link rule; the steps and the names that are not simple words; the order of the
    findings; three end-to-end tests, one of them with the real binary). They fail when the code
    is broken: 105 mutants tried, all caught (13 had survived: the exact bounds — 64 KiB and
    2000 lines read, 256 cards, nine cards against eight named —, the value of a card that says
    nothing (no link) and a zero uptime were not tested anywhere, tests were added; two
    equivalent mutants disappeared when simplifying the code).

## [1.10.0] - 2026-10-17

Machine profiles arrive: `--profile hpc` (four checks specific to compute nodes) and
`--profile server` (automatic security updates). The GPU module details Intel GPUs, and the
header of the reports gives the real number of CPUs of a machine on which some are isolated. A
profile is chosen, it is not guessed: without one, the profiles change neither a severity nor an
exit code. The layout of the JSON report does not change: `profile`
is an added field, absent when no profile was chosen, and `schema_version` stays 1.
The dnf side of `SRV001` has only been seen on fake files, not on a real Fedora or RHEL machine.

### Added

- **Machine profiles: `--profile hpc`** (or `profile = "hpc"` at the top of the configuration
  file). The checks judge a machine "in general"; some measurements mean something else on a
  specific type of machine. A load equal to the number of CPUs is contention on a workstation,
  and a compute node doing its job. A profile says so once, in a single place
  (`src/profile.rs`), instead of each module guessing. For `audit` and `tui` (`diff` has none:
  it reads the one that each report recorded).
  - **Chosen, never guessed.** No detection: two similar machines must not be judged
    differently for a reason that nobody can see. Without a profile, nothing changes, not a
    severity.
  - **A profile only lowers.** Each rule is a ceiling: a finding above it is brought down to the
    ceiling, a finding below it is left as it is, and no rule can raise anything. This is not a
    matter of style: the exit code follows the severities, so a profile that made findings worse
    would make audits that pass today fail, because of a setting. It removes no finding, touches
    neither the evidence nor the confidence, and has nothing to say about a full disk or an
    exposed service (verified with the real binary: same findings, same exit code).
  - **It says what it did, in the finding.** An adjusted finding receives
    `severity_before_profile` and `profile` in its evidence, and a last paragraph of
    explanation with the reason ("Profile hpc: reported as info instead of
    critical. … "). The report also names the profile: first line of the terminal report,
    Markdown and HTML header, banner of the TUI, and a `profile` key at the top of the JSON,
    **absent when no profile was chosen** (added field, `schema_version` stays 1).
  - **Applied to the finished report, before the exit code and before the display
    filter**: `--fail-on` and the default exit code judge the severities that the report shows.
  - **`hpc`** (compute node, where fully busy CPUs are the normal state): `CPU002` (load) and
    `CPU003` (sustained overload, Critical on any other machine) are reported as Info at most;
    the load figures stay in the evidence. **Worth knowing**: under `hpc`, a node that is
    oversubscribed by mistake looks like a node that is working. The profile removes the alarm,
    not the figure.
  - **`diff` warns** when two reports were written with different profiles, including *none*
    against a profile (without this, a finding "improved" between a report without a profile and
    an `hpc` report would be so on paper only): `different_profiles` warning in JSON, before the
    list of changes, without ever altering a change or the exit code.
  - The manual page has a `PROFILES` section (generated from the code, so always up to date) and
    describes the `profile` key of the configuration file; the example configuration file, in the
    README as in the manual page, shows it.
  - Planned next, without promising anything: more checks for the `server` profile
    (see below).
- **The GPU module now gives details on Intel GPUs** (`i915` and `xe` drivers). They were
  recognized but had no measurement at all, unlike AMD and NVIDIA. Direct reading of sysfs,
  without an external tool, in the same `GPU002`.
  - **Frequency**: actual frequency, hardware maximum, and allowed maximum. If the latter is
    lower than what the hardware can reach, the report says so (a ceiling was set by someone or
    something; the program does not know who). A GPU that reports 0 MHz is said to be "idle"
    (asleep in its power-saving state), not "clocked at 0 MHz".
  - **Throttling**: the driver says whether the GPU is held below its target frequency right now
    and why (`pl1`, `pl2`, `pl4`, `thermal`, `ratl`, `prochot`, ...). Throttling due to
    temperature is a **Warning**, even on an integrated GPU that has no temperature measurement,
    with a recommendation about cooling; throttling due to a power limit is explained but remains
    information (reaching its limit under load is not a failure). A cause name that the program
    does not know is shown as the kernel gives it, with no invented explanation.
  - **Discrete cards**: temperature, fan and power limit, through the driver's hwmon chip
    (chosen by its name, not by its position). With `xe`, the package temperature and its
    critical value (kernel 7.0) make it possible to judge the temperature against the card's own
    limit.
  - **What is deliberately not read**: utilization and VRAM (Intel drivers do not give them
    through sysfs), and `cur_freq` of `xe` (the kernel wakes up the GPU to answer it, which a
    read-only audit has no business doing).
  - **A limit to know about**: the paths, units and formats come from the kernel sources and its
    documentation; they have not yet been verified on a real Intel GPU. Each reading is optional:
    a missing or unreadable file leaves the measurement aside, never a guessed value. Only the
    first graphics GT (`gt0`) is read.
  - Tests: 33 new, including fake sysfs trees reproducing both drivers, the old `i915` layout,
    missing or absurd values, and an Intel device entrusted to another driver. They fail
    when the code is broken (21 mutants tried).
- **The GPU module sees the cards that the kernel does not expose in `/sys/class/drm`.**
  It only looked at those cards: a card reserved for a virtual machine (`vfio-pci`), a GPU with
  no driver, or a compute GPU whose driver does not register a graphics card did not appear, and
  a compute server could display "No GPU detected" while containing one. The module now also
  looks for display controllers (PCI class `0x03`) on the PCI bus.
  - **Card under `vfio-pci`**: listed as Info, with a sentence saying that it is reserved for
    passthrough to a virtual machine and that this is expected on a virtualization host. The
    `GPU001` summary counts them ("1 of 3 is bound to vfio-pci").
  - **GPU without a driver**: an NVIDIA, AMD or Intel GPU is a **Warning**, as for a DRM card
    (before, it was invisible). An adapter from another manufacturer found only on the PCI bus
    (typically the video chip of a server's management controller, often left without a driver
    on purpose) is listed as Info, without an alert. The behavior of DRM cards does not change.
  - **What is read** for these cards: the PCIe link, and `nvidia-smi` for the NVIDIA cards that
    the `nvidia` driver handles. Nothing else: without a DRM card, sysfs offers no measurement.
    The `drm_card: false` evidence indicates it.
  - **`nvidia-smi` now only counts the cards it sees.** Without this, a card reserved for
    `vfio-pci` next to a card in use would have made the system look multi-card and removed the
    attribution of processes to the card in use.
  - SR-IOV virtual functions are not counted as GPUs in their own right.
  - Tests: 15 new (fake PCI bus, merging with the DRM cards, analysis, and the complete case of a
    host with a card in use, a reserved card and a management chip). They fail when the code is
    broken (18 mutants tried).
- **A known power limit is displayed even when the consumption is not** ("Power limit:
  190.0 W."), for all manufacturers. Until now, it only appeared in the evidence.
- **The GPU module names the common video chips instead of writing "unknown vendor".** The
  manufacturer is read from the PCI identifier: ASPEED (the video chip of a server's management
  controller), Matrox, VMware, Red Hat (virtio, QXL) and Cirrus Logic. The `GPU001` summary
  counts "1 ASPEED" and the `vendor` evidence says `ASPEED`. It is only a name: the way the
  adapter is judged does not change (no alert for a management chip without a driver, which is
  normal), and an unrecognized manufacturer remains "unknown vendor".
- **A PCIe link narrower than what the card can do is no longer presented as an anomaly to go
  and check on the cable.** The most common case is ordinary: two cards share the motherboard's
  lanes and each runs at x8. The finding now reads the maximum width of the port the card is
  plugged into (new evidence `pcie_port_width_max`) and says so:
  - **the port does not carry more**: "The port it is plugged into allows at most
    x8": this is the machine's layout, not a defect of the card;
  - **the port could carry more**: the text does not attribute it to the port and refers first to
    the motherboard's manual (shared lanes, BIOS setting), then to how the card is seated;
  - **the port says nothing**: the ordinary causes are listed, without accusing any one of them.
  When another card in the machine runs at the same reduced width, the text points it out (cards
  that share lanes often split them equally). A lower speed is explained separately: an idle link
  slows down to save energy, which is normal; and for a card reserved for `vfio-pci`, the text
  says that the idle speed tells nothing about the card, since no driver on this machine
  handles it. No severity changes.
  - **Verified on a real machine** (two cards, each behind a port that announces x8): both ports
    do announce x8, and the report says "The port it is plugged into allows at
    most x8". The width of the port is only read for a device that has a PCIe link of its own:
    the video chip of a management controller, behind a PCIe-to-PCI bridge, has none, and the
    width of that bridge (x1) is that of the bridge's link, not of the chip.
  - **Known limit**: a bifurcated port that would announce its original width
    (x16) while the motherboard shares it has not been seen. The text would fall into the "the
    port could carry more" case, whose wording remains cautious and cites shared lanes first.
  - Tests: 27 new (fake sysfs tree with real symbolic links for the upstream port, each width
    case, cards that share lanes, the speed alone, the card reserved for a virtual machine, the
    named chips, and the complete case of the machine that motivated all this). They
    fail when the code is broken (41 mutants tried, 40 caught; the last one was a redundant
    condition, removed).

- **A profile can add its own checks. First case: `--profile hpc` adds the `hpc` module, with
  the CPU governor check (`HPC001`).** A profile only lowers severities. A check that is wrong
  on one machine and right on another (a workstation is not wrong to leave its CPUs on
  `powersave`) therefore cannot be a rule: it is a module, present only when the profile is
  chosen.
  - **The mechanism** (`src/profile.rs`, `engine::modules_for`): `Profile::modules()` gives the
    modules of the profile, which are not in `all_modules()`. `Context` does not change.
    `--modules` remains exact: `--modules memory --profile hpc` runs only `memory`. Naming the
    module requires the profile: `--modules hpc` alone is refused, before any execution, with
    code 2 and a message that says what to type ("the module 'hpc' is added by the hpc profile:
    run with --profile hpc (or set profile = "hpc" in the configuration file)"), for `audit` as
    for `tui`. The identifiers are known to the command-line parser: completions and the manual
    page list them (the manual page files them under the profile, not under the modules of every
    audit). `diff` has nothing new to know: a module present in only one report is already "not
    compared", and the `different_profiles` warning already exists.
  - **`HPC001` — CPU frequency governor.** It reads `scaling_governor`, `scaling_driver` and,
    when the driver has one, `energy_performance_preference` of each CPU. `powersave` does not
    mean the same thing everywhere, and that is what makes the check delicate: with
    `intel_pstate` and `amd-pstate-epp`, the processor chooses its own frequency and `powersave`
    is only a leaning (judged by the preference: towards performance = Info, towards power
    saving = Warning, `default` or unknown value = Info that says so; without a preference file,
    the frequency follows the load = Warning), whereas with the other drivers (`acpi-cpufreq`,
    `intel_cpufreq`…) it locks the frequency at the minimum (Warning). `performance` is Info;
    `ondemand`, `conservative` and `schedutil` follow the load (Warning); CPUs that do not all
    have the same governor are a Warning. The Warnings come with the commands to switch to
    `performance` right away and at every boot (a `tmpfiles.d` file, no extra package), and
    remind that a tool like tuned may put the old setting back. A machine without a frequency
    interface (a virtual machine) gets an Info saying there was nothing to check, which is not
    the same thing as "the frequency is good". The facts about `powersave` come from the kernel
    documentation (`intel_pstate`, `amd-pstate`).
  - **No judgment goes beyond Warning**, so choosing the profile does not make the default audit
    fail (the exit code follows Errors). The confidence levels follow the project's scale (90
    when the driver and the governor agree, 80 or 78 when an unconfirmed factor remains, 70 when
    the driver is unknown, and a mix is at most as sure as its least sure part).
  - **Not yet verified on a machine with `cpufreq`**: the development container has none. The
    case without an interface was seen with the real binary; the others on fake sysfs trees.
  - Tests: 45 new (reading on fake trees, every branch of the judgment with every driver, the
    mix, the registration of the module and its refusal without a profile with the real binary,
    the manual page, the completions, `diff`). They fail when the code is broken: 49 mutants
    tried, 46 caught the first time; the other 3 produced one more test (the worst CPU type
    decides), one more case (`cpu+1`, which a plain `parse` would accept) and a redundant
    condition removed.

- **`--profile hpc`: new check `HPC002`, the locked-memory limit (RDMA).** The `hpc` module now
  has two: the governor (`HPC001`) then this limit. RDMA (InfiniBand, RoCE) transfers memory
  without the CPU: the kernel keeps it locked in RAM and counts it in `RLIMIT_MEMLOCK`, a few
  MiB by default. An MPI job that registers more fails to register the memory, then stops or
  falls back to a slower transport.
  - **What it reads**: the RDMA devices (`/sys/class/infiniband`, with the link layer of each
    port: InfiniBand, or Ethernet for RoCE) and the `Max locked memory` line of
    `/proc/self/limits` (soft and hard limits), compared with the machine's RAM. The line is
    only read if the unit is `bytes` and each limit is a number or `unlimited`.
  - **What it says**: without an RDMA device, an Info saying that the limit does not matter here
    (a card whose driver is not loaded does not appear in the list). With devices: soft limit
    unlimited or at least equal to the RAM = Info; lower = Warning, confidence 75%, which says
    whether the hard limit lets users raise it themselves or whether root is needed, with the
    commands (`ulimit -l`, a `limits.d` file for logins, `DefaultLimitMEMLOCK` for systemd
    services, then the verification commands). Unreadable limit, or finite with unknown RAM:
    Info that says so, without judging.
  - **Why only 75%**: the limit read is that of the session that launched the audit. Jobs
    launched by a scheduler or by a systemd service have their own; the finding says so in
    each case.
  - **Not yet seen on RDMA hardware**: neither the development container nor the test machine
    has any. The reading is verified on fake sysfs trees (several devices, several ports, any
    filesystem order, hostile names); the `/sys/class/infiniband` path is that of rdma-core. The
    "no device" case was seen with the real binary.
  - Tests: 25 new (23 unit tests for reading and judgment, boundaries included: limit equal to
    the RAM, hard limit equal to the RAM; plus 2 end-to-end, the existing test being replaced by
    three, one per finding and one for the order). They fail when the code is broken: 64 mutants
    tried, 63 caught; the last is equivalent (removing the `?` on the hard-limit column gives the
    same result, because the missing unit fails anyway). A test that was too loose (systemd's
    `printf` command without a final newline passed) was tightened.

- **`--profile hpc`: two more information findings, `HPC003` (automatic NUMA balancing) and
  `HPC004` (SMT).** The `hpc` module now has four. They are Info, never a warning: whether the
  setting helps depends on the jobs, which the node cannot know. They say how the kernel is set
  and what that means depending on the kind of job.
  - **`HPC003`** reads `/proc/sys/kernel/numa_balancing` (a bit field: bit 0 balances between
    nodes, bit 1 is the memory "tiering" mode) and counts the NUMA nodes. Without a switch
    (kernel compiled without it), or with fewer than two nodes, it says so and says that the
    setting changes nothing. With several nodes: *active* = the kernel samples memory through
    page faults and moves it to the node that uses it, which helps jobs not bound to nodes but
    costs time, and which the kernel documentation says to disable for a workload already bound
    to NUMA nodes (`numactl`, MPI or Slurm binding); the commands to disable it (right away,
    then at every boot) come with the finding. *Inactive* = the memory stays on the node where
    the job first touched it. The values 2 (tiering only) and 3 (both) are described
    separately, without a command (writing 0 would also turn off tiering); a value with other
    bits is reported without being interpreted.
  - **`HPC004`** reads `/sys/devices/system/cpu/smt/` (`control`, `active`) and, with the
    `thread_siblings_list` of each CPU, how many logical CPUs share a core ("56 logical CPUs on
    28 cores, 2 threads per core"; and it says so when the cores differ, as on a processor that
    mixes performance and efficiency cores). It distinguishes *active*, *inactive*, *forced
    inactive* (impossible to put back without rebooting) and *no SMT in this processor*. When SMT
    is active and the kernel allows stopping it on the fly, it explains the trade-off (SMT helps
    jobs that wait for memory and can slow down those that compute on all logical CPUs) and gives
    the commands for one thread per core: right away, then the `nosmt` kernel parameter with the
    command that regenerates the boot configuration for the distribution's family
    (`update-grub` or `grub2-mkconfig`, nothing invented for another one).
  - **Verified** with the real binary in the development container (a single node; SMT absent
    from the processor) and on fake sysfs trees for the other cases (two nodes, SMT active,
    forced inactive, cores of different sizes, hostile names). **Not yet seen on a two-node
    machine with SMT active**, yours is one: to look at in the first report.
  - Tests: 32 new (reading the switches, the nodes, SMT and the topology on fake trees; every
    state of every finding, the boundaries — two nodes, more logical CPUs than cores —, the
    precedence of `control` over `active` and then over the topology; and the end-to-end test,
    which compares with the machine's files when it has them). They fail when the code is
    broken: 68 mutants tried, 68 caught.

- **The `server` profile (`--profile server`) and its first check, `SRV001`: are security
  updates installed automatically?** A server that nobody looks at every day is kept up to date
  by a mechanism, not by a person; the check says whether the system's mechanism is in place.
  - **The profile lowers no severity** (the description says so, and a test requires it): there
    is nothing to excuse on a server. It adds the `server` module, which only exists when the
    profile is chosen, like `hpc` for its own. `--modules server` without the profile is
    refused (code 2) with the sentence that says what to run. The choice remains explicit, with
    `--profile server` or `profile = "server"` in the configuration file.
  - **With apt** (Debian, Ubuntu and derivatives): `apt-config dump` (which merges the whole of
    `apt.conf.d`, in the order apt does it), the presence of `unattended-upgrade`, the list of
    allowed origins, and the two timers `apt-daily.timer` and `apt-daily-upgrade.timer`. The
    intervals are read the way apt's script reads them: `0` switches off, `always` or a number
    (with `s`, `m`, `h` or `d`) switches on, and `00` or `0d` *switch on* (the script compares
    the text with `0`, not the number); `APT::Periodic::Enable` at `0` switches off all the
    tasks whatever the other settings say. **With dnf** (Fedora, RHEL and derivatives): dnf 4 or
    dnf 5, `dnf-automatic` installed or not, `apply_updates` and `upgrade_type` of the
    `/etc/dnf/automatic.conf` file (on the package's default values with dnf 5), and the timers.
    Timers that only download or notify do not count as an installation, and the finding says
    which one is active instead.
  - **Honest about what it does not know.** At worst a **Warning at 80%**, never certain: a
    machine kept up to date another way (configuration tool, Landscape, Satellite, maintenance
    window) is fine without this mechanism, and the finding says so in its text. In place: Info
    at 90%. A tool that does not answer (`apt-config`, `systemctl`) gives an Info "could not be
    determined", never a warning. A distribution that is neither Debian nor Red Hat gives an
    Info saying that it was **not** checked. It does not say either whether the last run
    succeeded (it points to the `journalctl` command that does).
  - Each problem has its sentence and its commands (install the package, enable the settings in
    `20auto-upgrades`, allow the security archive, enable the timers — after `unmask` if they
    are masked), and only the ones needed.
  - A new tool in `src/core/command.rs`: `ToolSession::run_ignoring_status`.
    `systemctl is-enabled` answers on its output (`enabled`, `masked`, `not-found`…) and its
    return code means nothing; the existing session discarded any answer from a tool that exited
    with a failure.
  - **Verified** with the real binary in the development container (Ubuntu): without the
    package, then with a fake `unattended-upgrade` package temporarily put in place, and with
    fake `apt-config` and `systemctl` for each case. **The dnf side was only seen on fake files
    and from the documentation** (no Fedora or RHEL machine at hand): to look at in the first
    report on such a machine. Yours is an Ubuntu, so the apt side.
  - Tests: 88 new (reading `apt-config dump` and the dnf file on fake trees, including a huge
    file and hostile values; every problem, its sentences and its steps; the profile, the
    options and the refusal of the module without a profile; and 17 end-to-end tests with the
    real binary and fake tools). They fail when the code is broken: 220 mutants tried, 217
    caught. The other three showed useless code, removed (the special case of the `#` and `;`
    comments of the dnf file, already excluded because the name starts with the mark, and a dnf 5
    branch that could never be used). Several tests that were too loose were tightened along the
    way.
  - Planned next, without promising anything: `SRV002` (persistent journal) and `SRV003`
    (reboot pending for a long time).

### Changed

- The message about a missing driver now cites `amdgpu`, `i915` or `xe`.
- The description of the `hpc` profile (report header, manual page) now also says that it adds
  the `hpc` module.
  It also says, as does the module's sentence in the manual page, that it checks the
  locked-memory limit and that it reports NUMA balancing and SMT.
- The text about a card's PCIe link no longer says "worth checking the physical
  slot/cable": it describes what is measured (`PCIe: 8.0 GT/s PCIe x8 (this card
  supports up to 8.0 GT/s PCIe x16).`), then explains the width and the speed
  separately. The `pcie_link_*` evidence has not changed.

### Fixed

- **The number of CPUs in a report is the machine's, not the process's.**
  It came from `available_parallelism()`, which respects the process's affinity and cgroup
  limits: on a 56-CPU machine on which 24 are isolated for a virtual machine, the header
  announced "32 CPUs" while the `hpc` module saw 56. The number now comes from the kernel's list
  of online CPUs (`/sys/devices/system/cpu/online`, for example `0-55` or `0-27,56-83`), and
  `available_parallelism()` is now only a fallback when the list is unreadable.
  This affects the report header (terminal, Markdown, HTML, interface), the
  `context.cpu_count` field of the JSON and the machine comparison of `diff`; the modules do not
  use it (the CPU module counts its own processors in `/proc/cpuinfo`).
  - Seen with the real binary: confined to a single CPU by `taskset -c 0`, the old one announced
    "1 CPUs", the new one the real number.
  - Tests: 8 new (parsing the list: ranges, gaps, rejected entries including signs and reversed
    lists; the fallback; and `tests/cpu_count.rs`, which launches the real binary confined to
    one CPU and requires the same number as when free). They fail when the code is broken: 12
    mutants tried, 10 caught (two of them only thanks to the end-to-end test). What remains is
    an equivalent one on 64 bits (the arithmetic checked against overflow, which only serves
    32-bit systems) and one indistinguishable here (`possible` in place of `online`, identical on
    this machine).

## [1.9.0] - 2026-10-16

Every output says which version of LinuxDoctor produced it, the TUI can be filtered and
searched, and `diff` warns when it compares reports from different versions. The layout of the
JSON report does not change: `linuxdoctor_version` is an added field, `schema_version` stays 1.

### Added

- **`diff` warns when the two reports do not come from the same version of
  LinuxDoctor.** The checks evolve from one version to the next: a finding that
  appears or disappears may come from the program, not from the machine. The warning
  is given before the changes, like the one for different machines, in all three
  formats (`> ⚠` in Markdown, `caveats` in JSON with `"kind": "different_versions"`
  and the two versions).
  - It triggers if the two recorded versions differ, **and also** if only one of the two
    reports records one: any version that records it is newer than any version that does
    not, so the two necessarily differ (the other is then "not recorded").
  - It says nothing when the versions are equal, nor when neither report records one: there
    is nothing to conclude, and the warning would be displayed on every comparison of old
    reports.
  - It neither adds nor hides any change and does not alter the exit code.
    The versions come from files: they are cleaned in the text and
    escaped in Markdown.
  - Tests: unit tests (detection, rendering of the three formats, hostile text) and
    `tests/version_shown.rs` with the real binary, including the identical exit code with or
    without the warning. They fail when the warning is removed, when it is extended to two
    reports without a version, or when the cleaning is removed.

- **The version of LinuxDoctor is displayed at the head of every output.** First
  line of the terminal report (`LinuxDoctor 1.8.0 — machine`), first line under
  the title of the Markdown report, first fact of the HTML report header,
  header of the TUI and its loading screen, and header of the comparison
  produced by `diff`. In the Markdown and HTML reports it was already there,
  but at the end of the header ("Generated … by LinuxDoctor"); it is now
  the first piece of information, and the "Generated" line only gives the date.
  - **The JSON report records it**: `linuxdoctor_version`, right after
    `schema_version`. This is not a change of layout
    (`schema_version` stays 1): a reader that ignores unknown keys is
    not affected. The checks evolve from one version to the next; a kept report
    can only be fully understood with the version that wrote it.
  - **`diff` shows three versions**: the one that compares (title of the text,
    "Compared with LinuxDoctor …" in Markdown, `linuxdoctor_version` in JSON)
    and the one that wrote each of the two reports (in parentheses in
    the terminal, "Written by" column in Markdown, `before` / `after` in JSON).
    A report from a version that did not record it (1.8.0 and earlier) has none:
    it is presented as "LinuxDoctor version not recorded" (`null` in JSON). This
    version comes from a file, hence from untrusted text: it is cleaned like the rest
    (terminal) and escaped (Markdown).
  - A single source: the `linuxdoctor::VERSION` constant (the one behind
    `--version`).
  - Tests: `tests/version_shown.rs` launches the real binary and checks the version
    at the head of each format, in `diff` (including a report without a version and a
    report whose version contains escape sequences), and that the
    `VERSION` file and `Cargo.toml` agree (a release that only updates one of the two
    fails). Unit tests cover each rendering, the header and the loading screen of
    the TUI. They fail when the display or the cleaning is removed.

- **The TUI can be filtered and searched.** With 13 modules and dozens of findings,
  seeing only what matters meant scrolling through everything.
  - **`f` picks a minimum severity**: everything, warning and above, error and
    above, critical only (the four levels of `--min-severity`).
  - **`/` searches for text**, case-insensitively, in the identifier, title,
    explanation, recommendation, instance and evidence of a finding.
    Enter keeps it, Esc forgets it; while typing, `q`, `r`, `f`, `j` and `k`
    are letters, not commands.
  - **A filtered screen cannot pass for a complete one**: the bottom bar shows
    `Filter: … · N of M findings`, each module displays the number of its retained
    findings (those that have none left are greyed out), and each page recalls how many
    of the module's findings are shown. A module in error or skipped keeps its
    display.
  - **The report is never modified**: the ✓/⚠/✗ of a module still describes the
    whole module and the exit code of `linuxdoctor tui` takes all the
    findings into account, filtered or not.
  - **Sub-items follow the filter**: if a single instance remains, it is
    shown flat, as for a module that only has one. The screen jumps to the first
    module that has a match when the filter changes.
  - **Esc undoes one level at a time**: the submenu, then the filter, then quits.
    Without a filter, nothing changes. The bottom bar is now two lines (the state
    of the display, then the keys).
  - The typed text is limited to 40 characters and refuses control characters,
    since it is displayed again.
  - Tests: `output::tui_filter` (severity, text, length, case) and the TUI without a
    terminal (keys, drawn screen, colors of empty modules, submenus,
    refresh, hostile text under a filter). They fail when the jump to the matching
    module, the severity filter, the check on Ctrl/Alt keys or the role of Esc is removed.

## [1.8.0] - 2026-10-16

A configuration file to keep your options without retyping them, and the
fix for the crash of `audit | head`. The format of the JSON report does not change
(`schema_version` stays 1).

### Added

- **A configuration file, `~/.config/linuxdoctor/config.toml`** (under
  `$XDG_CONFIG_HOME` when it is set), to keep without retyping the
  options that you type every time: `timeout`, `fail_on`, `min_severity`
  (valid for `audit` and `diff`) and `output` (in the `[audit]` and
  `[diff]` sections, because the two commands do not accept the same formats). The
  file is optional, as is each of its lines.
  - **What you type on the command line always wins**, option by
    option: the file only fills in what has not been typed. Typing the default
    value counts as typing (`--output terminal` wins over
    `output = "markdown"`). In the file, the line of a section wins
    over the one at the top.
  - **The words are those of the command line**, read by the same parser
    (`"md"` works like `--output md`): a value or an alias added
    later exists in both places at once.
  - **An error is an error, never a guess.** Unknown key, refused value,
    unreadable file, too big (more than 64 KiB), not UTF-8
    text or not an ordinary file: the program stops
    with code 2, before having run anything, saying which file and which
    line. Only the absence of the default file is normal.
  - **`--config FILE`** reads another file (which must exist) and
    **`--no-config`** ignores the file for one run, including a broken
    file. `man` and `completions` never read the file; `tui` only reads
    `timeout`.
  - **A level coming from the file explains itself**, like `--fail-on`, when it
    gives exit code 1: `fail_on = "warning" in /home/you/.config/…`.
    The default level stays silent.
  - `--modules` is deliberately not configurable: a file that would
    quietly restrict every audit would give healthy-looking reports
    on checks that were never made.
  - The file is treated as untrusted text: read after a `stat` (a named pipe
    would make `open` wait indefinitely), bounded, and the line quoted
    in an error is shortened and stripped of its control characters
    (the error display of the TOML library would have copied the whole
    line).
  - The manual page has a FILES section with the complete example; the README has
    the "The configuration file" section, and a test checks that the README's example
    is exactly the one that the program accepts.
  - New dependency: `toml` 0.9.6 (read-only: `std`, `serde` and `parse`
    features), pinned with its dependencies to remain compilable with
    Rust 1.75 (see the "Toolchain note" of the README).
  - Tests: 34 unit tests (`src/config.rs`) and 19 integration tests with
    the real binary (`tests/config_file.rs`); they fail when the priority is
    reversed, when reading the file is forgotten or when the origin of the level is lost.
    A test also checks that every test that launches the binary isolates it from the real
    configuration file of whoever runs the suite.

### Changed

- `audit --output` and `diff --output` no longer have a default value in
  `clap`: the help no longer shows "[default: terminal]" but says it in its
  text ("Default: terminal"). The behavior is the same; it was necessary to
  distinguish "not typed" from "typed" so that the file only replaces
  what has not been typed.
- The `--fail-on` message on the error output now says where the level
  comes from (`--fail-on warning` or the file's line); with the option typed,
  it is identical to before.

### Fixed

- **`linuxdoctor audit | head` no longer crashes.** When the reader of the output
  disappeared before the write (`| head -1`, a pager quit immediately), the
  four formats of `audit` panicked (message `failed printing to stdout:
  Broken pipe`, exit code 101) because they wrote with `print!`.
  The text is now built and then written with the safe write already
  used by `diff`, `man` and `completions`: a reader that has left is not an
  error. The verdict does not change for all that: the exit code remains that
  of the audit (1 if a finding reaches the `--fail-on` level) and an
  explicit `--fail-on` is still explained on the error output. A real write
  error (full disk) is still reported and gives code 1.
  - Tests: `tests/broken_pipe.rs` closes the pipe before the write (the audits
    are long enough for this to be certain) and checks, with the real
    binary, the absence of a panic for the four formats, the verdict preserved
    (fake almost-full `df`), the `--fail-on` message, and `man`,
    `completions` and `diff`. Three of these tests fail without the fix.

## [1.7.0] - 2026-10-16

Comparison of two reports (`linuxdoctor diff`) and a security fix: text chosen by
the audited machine can no longer act on your terminal. The format of the JSON
report does not change (`schema_version` stays 1).

### Security

- **Text chosen by the audited machine can no longer act on your
  terminal.** Names of processes, virtual machines and containers,
  mount points, user names, tool messages: any of them
  could contain an escape sequence (clear the screen, change the window
  title, rewrite the line above with a carriage return) or a
  bidirectional control that reverses the display order. The Markdown and HTML reports
  passed them on as they were (a `cat report.md` was enough to trigger
  them), and the terminal and the TUI did not filter them
  everywhere. From now on the terminal, Markdown and HTML reports and the TUI replace
  control characters and bidirectional controls with `?`; line
  breaks, indentation, accents and right-to-left scripts are kept, and a real
  complete audit (874 strings) is not modified in any way.
  - A single entry point: `output::common::display_safe` copies the report
    processing **every** string. It destructures `Context`, `ModuleRunResult`,
    `Finding` and `Confidence` without `..`: adding a text field to any of them
    prevents compilation until it is handled, so a renderer cannot
    forget it. The cleaning function is `core::text::printable`.
  - The JSON does not change, deliberately: it already escapes control characters
    (`\u001b`) and remains the faithful record of what was
    observed, which is what `linuxdoctor diff` compares.
  - Tests: one test per renderer (terminal, Markdown, HTML, TUI
    buffer, including after an `r`), a test on the whole report, and
    `tests/hostile_names.rs`, which launches the real binary against a fake `df` whose
    mount point is made of escape sequences, in the four
    formats and in `diff`. Each fails when the call is removed.

### Added

- **Comparison of reports**: `linuxdoctor diff before.json after.json`
  compares two JSON reports (`audit --output json`) and shows what
  changed: findings that **appeared**, were **resolved**, **worsened** or **improved**
  (with the evidence values that moved), the information-only changes
  ("Other changes") being separated so that a new network
  interface does not pass for a regression. The machine's facts (kernel,
  distribution, memory, CPU, reboot) are listed first.
  - **An absence is never good news**: a finding that has disappeared
    is only "resolved" if its module really ran to completion in the
    second report. A module that failed, was skipped or is absent is listed under
    "Not compared" (with the number of findings that could not be rechecked),
    and a module whose commands were interrupted marks the changes
    concerned with a `?`.
  - Warnings at the top when the comparison risks being worthless:
    different machines, probably swapped reports (the second dates from an earlier
    boot), or a report written with `--min-severity`.
  - `--output terminal|json|markdown` (alias `md`); the JSON is a versioned
    document (`schema_version`, `kind: "comparison"`). `-` reads one of the two
    reports from standard input.
  - `--min-severity` (display filter, which counts what it hides) and
    `--fail-on` (exit code, judged on the whole comparison before any
    filter) work as for `audit`. Exit codes: **0** nothing
    appeared or worsened at the requested level (default `error`), **1**
    a finding appeared or worsened at that level or above, **2** the
    comparison could not be made (unreadable file, not a LinuxDoctor
    report, format newer than the program) or usage error.
  - The files read are treated as untrusted: titles, instances,
    evidence, error messages and machine names go through
    `core::text::clean` for the terminal and are escaped for Markdown;
    a hostile file cannot send escape sequences to the
    terminal. Size limited to 64 MiB.
  - The manual page (exit code, examples, description) and the shell
    completions know the new command.
- `core::text::clean`: the cleaning of untrusted text (control
  characters, escape sequences, bidirectional controls, truncation),
  moved out of the Logs module so that `diff` can use it too. The Logs module
  re-exports it, its behavior is unchanged.
- `Severity` is now deserializable (`serde`), which reading
  reports requires.
- Tests: 25 integration tests of the real binary (`tests/diff_command.rs`:
  exit codes, standard input, unreadable or hostile files, three
  formats, re-reading a real `audit` report), 44 unit tests in
  `src/diff/`, 6 in the CLI and the manual page.

## [1.6.0] - 2026-10-15

Two modules (Security, Logs), the Markdown and HTML reports, the `--min-severity` and
`--fail-on` options, the manual page and the shell completions. One change of behavior to
know about: `--modules` now refuses a nonexistent identifier instead of producing an empty
report.

### Added

- **Manual page**: `linuxdoctor man` writes the `linuxdoctor(1)` page (roff format) to
  standard output, with NAME, SYNOPSIS, DESCRIPTION, OPTIONS, COMMANDS (each with its own
  options), MODULES, EXIT CODES, EXAMPLES, SEE ALSO. The options come from the clap definition
  that the parser really uses (via `clap_mangen`) and the list of modules from the
  `all_modules()` registry: the page cannot contradict the program. It is
  deterministic (no date, only the version), and the integration test has it
  re-read by `groff -ww` when installed, without the slightest warning. A module registered
  without a description line in `module_summary()` (`src/manpage.rs`) makes a test fail.
- **Shell completions**: `linuxdoctor completions <bash|zsh|fish|elvish|
  powershell>` writes the completion script (via `clap_complete`). It offers
  the subcommands, the options, the values of `--output`, `--min-severity`
  and `--fail-on`, and the module identifiers for `--modules`.
- **The `.deb` and `.rpm` packages install** the manual page
  (`/usr/share/man/man1/linuxdoctor.1.gz`, `gzip -9n`) and the bash, fish and
  zsh completions (`vendor-completions` on Debian/Ubuntu, `site-functions` on
  Fedora/RHEL/openSUSE). `build-deb.sh` and `build-rpm.sh` generate them with the
  binary they have just compiled; if a generation fails, `Cargo.toml`
  is restored as for the other steps.
- Dependencies: `clap_complete` 4.4.10 and `clap_mangen` 0.2.20 (hence `roff`
  0.2.2), pinned to those versions because they are the last ones to accept
  `clap` 4.4 and a Rust version below 1.85. They only add
  three packages to `Cargo.lock` and change no existing version.

- **Logs module** (`linuxdoctor audit --modules logs`): read-only.
  It reads the systemd journal (`journalctl -o json`), falling back to
  `/var/log/auth.log` or `secure` and to `dmesg`. Four subjects (TUI
  submenus):
  - **Authentication** (`LOG002` to `LOG004`): SSH login failures over the
    last 24 hours by source address and by account name; a password
    login that follows many failures from the same address
    (the signature of a guessed password: Critical from 20 failures,
    Warning from 5); `sudo`, `su` and console failures, and accounts
    refused by `sudo`. A failure counts only once even if sshd logs
    both the refused account and the password attempt.
  - **System errors** (`LOG005`): error messages since boot,
    grouped by service, with the message that each repeats the most.
  - **Kernel messages** (`LOG006`, `LOG007`): disk and
    filesystem errors, filesystem gone read-only,
    corrected or uncorrected memory/PCIe errors, blocked tasks, thermal
    throttling, kernel faults, processor lockups, programs that
    crash. Out-of-memory (OOM) kills stay with the Kernel module.
  - **Journal and log files** (`LOG008`, `LOG009`): does the journal survive
    a reboot, its size against journald's cap, services whose messages
    journald had to drop, `/var/log` files that were never rotated.
  A summary finding `LOG001` opens the module's page and lists what
  needs attention **and what could not be read**: an unreadable journal
  (no permissions, journald absent, container) is never presented
  as a quiet journal, and the command to join the groups
  `adm` and `systemd-journal` is given. A suspected intrusion comes before
  any other finding of the same severity. Text coming from the logs (account names
  chosen by an attacker, program names) is stripped of its control
  characters — terminal escape sequences included —,
  bounded in length, and only enters a suggested command if it is
  a simple word; addresses only enter it if they are real IP
  addresses. The commands are only suggested, never executed.
- `modules::recommend` now also provides the distribution family
  (`Family`, `family_of`) to choose between `apt` and `dnf`; the Security
  module uses it instead of its own copy.
- `core::context::effective_uid()`: effective user identifier read from
  `/proc/self/status`, shared by the Security and Logs modules.

- **Security module** (`linuxdoctor audit --modules security`): read-only,
  usable without root (root adds visibility, and each
  finding says what it could not see). Six subjects (TUI submenus):
  - **Listening services** (`SEC002`, `SEC003`): all the TCP/UDP sockets
    of `/proc/net/*`, reachable from the network or only from the machine,
    with the owning program when possible. A catalog of
    services that should almost never be exposed (Telnet, unencrypted Docker
    API, Redis, Memcached, databases, VNC, SNMP…)
    produces one finding per exposed service, with steps to
    check it, restrict it or filter it.
  - **Firewall** (`SEC004`): ufw, firewalld, nftables or iptables. The
    absence of a firewall is only a warning if a TCP port (other than SSH)
    is really reachable; the finding specifies whether the rules could be
    read.
  - **SSH** (`SEC005`): effective `sshd_config` configuration with
    `Include` and `Match` blocks (root login, empty or allowed
    passwords, protocol 1, host-based trust, weak algorithms…),
    capped at Warning when sshd is not running. The steps put
    the safe action first: install a key before disabling
    passwords, validate with `sshd -t`, keep a second session
    open.
  - **Access control** (`SEC006`): SELinux (enforcing, permissive,
    disabled, and mismatch with `/etc/selinux/config`) and AppArmor (profiles
    loaded and enforced), read in sysfs without an external tool.
  - **Hardening** (`SEC007`): 19 kernel/network settings judged by the
    value actually applied, with the commands to make them
    persistent in `/etc/sysctl.d/` without touching the distribution's
    files.
  - **Accounts and files** (`SEC008`, `SEC009`): additional UID 0 accounts,
    logins without a password, weak hashes (if `/etc/shadow` is
    readable), permissions of `/etc/passwd`, `/etc/shadow`, `sudoers`, of the SSH
    configuration and of `/tmp`.
  A summary finding `SEC001` opens the module's page and lists what
  needs attention; everything that is Warning or above stays on this
  page, the rest is filed by subject. The commands are never
  executed, only suggested.
- `modules::recommend` module: the numbered-steps builder
  (`Steps`) and the `sysctl` commands, extracted from the Memory module to be
  shared.

- **Markdown report**: `linuxdoctor audit --output markdown` (alias `md`)
  produces a complete document — header (machine, date, version), summary
  table per module, then each finding with its severity, confidence,
  evidence, explanation and recommendations (numbered
  steps, commands in `bash` blocks). The tables aligned by
  the modules are rendered as code blocks to keep their columns. Any
  text coming from the machine (host name, process names, error
  messages of the tools) is escaped: it cannot break the layout
  or inject a tag.
- **HTML report**: `linuxdoctor audit --output html` produces a single,
  self-contained page (embedded CSS, no JavaScript, no external file or
  network access), light and dark themes, readable even on a phone,
  with collapsible findings (open from Warning). Severity
  is never indicated by color alone. Dynamic strings are
  escaped and the page carries a strict `Content-Security-Policy`.
- **`--min-severity info|warning|error|critical`** (`audit`): a
  **display** filter that hides the less severe findings. It never hides
  a module in error, skipped or with incomplete data, and all the
  formats state how many findings were hidden (final line in the
  terminal, "Filtered view" banner in Markdown and HTML, `filter` object
  in JSON).
- **`--fail-on info|warning|error|critical|never`** (`audit`): **exit code**
  threshold. Code 1 is returned as soon as a finding reaches the
  threshold; `never` always returns 0. The verdict is based on the
  **complete** report, before the display filter: hiding findings cannot
  turn a failed audit into a successful one. When the option is
  given explicitly, a sentence on the error output explains the failure
  (standard output remains clean JSON/Markdown/HTML).
- **`filter` key in the JSON** (only when `--min-severity` is
  used): `{"min_severity": "...", "hidden_findings": N}`, right after
  `schema_version`. Addition of a field: `schema_version` stays at 1.
- Modules `core::gate` (pass/fail decision), `output::common`
  (elements shared by the document renderers) and `output::markdown` /
  `output::html`.

### Changed

- **`--modules` now refuses an unknown identifier** (exit code 2,
  with the suggestion "a similar value exists: 'memory'"), for `audit` as
  for `tui`. Before, a typo (`--modules memroy`) selected
  no module and produced an empty report with code 0: a "clean"
  result that nobody had checked. A single mistake in a list
  (`memory,logz`) stops the whole run. The identifiers are those of
  `all_modules()`, so a new module is accepted (and completed) as soon as it
  is registered.
- The exit code goes through `core::gate`. Without `--fail-on`, the behavior
  is unchanged: code 1 as soon as an Error or Critical finding exists (and
  for an execution error), code 2 for a usage error.
  `linuxdoctor tui` keeps this default threshold and does not have the new options.
- A module whose tool was interrupted ("incomplete data") is
  presented in Markdown/HTML as "⚠ Incomplete data" and not as "OK",
  as in the terminal.

### Tests

- `tests/docs_commands.rs`: 11 integration tests with the real binary —
  `man` (roff page, all the modules listed, identical output from one run to
  the next, re-reading by `groff -ww` without warning), `completions`
  (bash, zsh, fish; unknown or missing shell = usage error) and the check of
  `--modules` (typo alone or in a list, also for `tui`, and a correct
  identifier that still runs). Plus 17 unit tests
  (`cli.rs`, `manpage.rs`): sections in order, common options
  documented only once, `help` absent, version in the header without a date,
  completion scripts that know every module.
- `tests/logs_module.rs`: 14 integration tests of the Logs module — a
  quiet server (nothing above Info), a server in trouble (all
  the expected findings with the right severity), the order of the pages and the
  numbered steps, the advice depending on the distribution family, hostile
  content (HTML/Markdown tags, terminal escape sequences, names that
  could break a command) through the four
  formats, and the real binary against a fake `journalctl` placed at the head of the
  `PATH`: simulated journal, exit code, unreadable journal reported, journal
  that does not answer (stopped after the time limit and reported as
  incomplete), and a test on the host machine that only checks the presence
  of the findings, never their severity.
- 110 unit tests for the Logs module (parsers for the journal, for
  syslog and for `dmesg`, for SSH/sudo/PAM messages, for the kernel, for
  `journald.conf`, fallback logic between sources, walking of `/var/log`
  without following symbolic links).
- `tests/security_module.rs`: 8 integration tests of the Security module —
  a well-kept server (nothing above Info), a neglected server (all the
  expected findings with the right severity), the order of the pages and the presence
  of numbered steps, the identifiers `SEC001` to `SEC009`, hostile names
  (HTML tags, Markdown, JavaScript) through the Markdown and HTML renderers,
  the four formats, and a test of the real binary on the host machine that only
  checks the presence of the findings, never their severity (it depends on
  the machine).
- 139 unit tests for the Security module (parsers for `/proc/net/*`,
  `sshd_config`, `nft`/`iptables`, `passwd`/`shadow`/`group`, SELinux,
  AppArmor, sysctl settings) on sample texts, including malformed
  inputs.
- `tests/export_and_gate.rs`: 14 end-to-end tests with the real binary
  (Markdown/HTML formats, `md` alias, `--min-severity`, `--fail-on`, exit code
  for each threshold, the display filter never changes the exit
  code, usage errors = code 2).
- Unit tests of the renderers (escaping of hostile content, tags
  allowed in the HTML, structure of tables/code blocks), of
  `core::gate`, of the report filtering and of argument parsing.
- The renderers were also validated with a CommonMark parser, a strict
  HTML5 parser and a headless browser (light, dark, phone
  width).

## 2026-10-14

### Added

- **`schema_version` in the JSON**: `linuxdoctor audit --output json`
  starts with `"schema_version": 1`. Rule: adding a field does not change
  the version (readers ignore unknown keys); removing,
  renaming or changing the meaning of a field increments it. The other fields
  do not move. Constant `output::json::SCHEMA_VERSION`, documented
  in `ARCHITECTURE.md` ("Schema version").
- **GitHub Actions continuous integration** (`.github/workflows/ci.yml`),
  on every push to `main` and every pull request: `cargo fmt
  --check`, `cargo clippy --all-targets -- -D warnings` (stable), then
  `cargo build` and `cargo test` with Rust 1.75.0 (minimum version) and
  stable. Everything is run with `--locked` to respect the pinned versions of
  `Cargo.lock`. The v4 format of `Cargo.lock` (Cargo ≥ 1.78) is
  unreadable by Cargo 1.75: the 1.75 job puts the header back to v3 in
  the CI run only — with 100% "registry" dependencies,
  the content is identical.
- **Memory module completely reworked**: 13 checks (`MEM001` to
  `MEM013`) split into six themes, which are also the TUI submenus:
  - *Used memory*: `MEM007` details the memory used by nature
    (programs' anonymous memory, cache, shared memory, kernel) and the
    main consumers by private memory (RssAnon), grouped by
    program name; `MEM004` (overview) and `MEM003` (critical
    memory) are kept.
  - *Page cache*: `MEM008` (really reclaimable cache, the `drop_caches`
    myth, `vfs_cache_pressure`); `MEM005` (dirty pages).
  - *Shared memory*: `MEM006` — `Shmem`, filling of tmpfs and
    `/dev/shm`, orphaned SysV segments (`nattch = 0`) with the command
    `ipcrm -m` to remove them.
  - *Swap*: `MEM001` (swappiness judged by swap type: zram, SSD,
    spinning disk), `MEM002` (swap activity, most swapped
    programs, swap traffic since boot), `MEM010` (configuration:
    no swap, zram priority, compression ratio, algorithm,
    redundant zswap + zram, `page-cluster`).
  - *Pressure*: `MEM009` — PSI (`/proc/pressure/memory`), OOM kills
    since boot, direct reclaim.
  - *Kernel tuning*: `MEM011` (overcommit and `CommitLimit`),
    `MEM012` (Transparent Huge Pages, reserved but unused hugepages),
    `MEM013` (unreclaimable slab, page tables, ZFS ARC,
    `min_free_kbytes`, balloon).
- **Recommendations in numbered steps**, with the commands on their
  own lines (never executed by the tool), sized for the
  machine: suggested swap file size, `vm.overcommit_ratio`
  leaving a 20% margin, `zfs_arc_max` cap, etc. The TUI shows the
  title "Recommendation:" in bold and the commands in cyan; the terminal output
  indents them under a bold title.
- New data sources, all optional: `/proc/vmstat`,
  `/proc/pressure/memory`, `/proc/swaps`, `/sys/block/zram*`,
  `/proc/<pid>/status`, `/proc/sysvipc/shm`, `df -t tmpfs`, THP
  and `vm.*` files, ZFS `arcstats`. A missing source only removes
  the checks that depend on it. The memory audit stays
  fast (~35 ms, ~60 ms with 2000 processes).
- `MemoryRawData::from_meminfo()`: builds the data from the
  `/proc/meminfo` text alone (useful for tests and examples).
- Module home page: the problems (Warning and above) come
  first, the `MEM004` overview closes the page.

### Changed

- `Cargo.toml` declares `rust-version = "1.75"`: an older toolchain
  stops with a clear message instead of obscure compilation errors.
  The build scripts are not affected (they only
  rewrite the `version = ` line at the start of a line).
- **Formatting and Clippy across the whole project**: `cargo fmt` applied to
  all the code (19 files reformatted, no change of
  behavior) and the 7 remaining Clippy warnings fixed
  (useless `trim()` before `split_whitespace()`, `splitn(2, …)` replaced
  by `split_once`, `format!` without arguments, useless closure in
  `cli.rs`). `cargo clippy --all-targets -- -D warnings` passes without
  warnings; the mention of "Clippy warnings" in the
  "Known limits" section below is therefore settled.
- **Semantics of "Cached" fixed**: the `Cached` line of
  `/proc/meminfo` contains shared memory (`Shmem`); the "file"
  cache is now computed without it, and reclaimable
  memory counts buffers, file cache and reclaimable slab.
- The dirty-page thresholds are computed on "dirtyable" memory
  (free + file cache) and not on total RAM, with three zones:
  background writeback (Info), write throttling
  (Warning), blocking (Error). The `dirty_*_bytes` settings win
  over the ratios. A percentage limit that exceeds 4 GiB on a
  big server is reported as Info with optional caps.
- A swap that is 80% full or more is now a Warning (before: Info
  even at 97%).
- Shared memory attached to SysV segments (PostgreSQL, Oracle…)
  is considered legitimate and no longer enters the percentage
  judgment.
- `src/modules/memory/analyze.rs` is now just a coordinator: the
  logic lives in `used`, `cache`, `shared`, `swap`, `pressure`,
  `tuning`, `kernel` and `format`.

### Fixed

- `tests/hung_tools.rs`: the fake tools also define `docker` and
  `podman` (exit 127). With a slow real `docker`, the test could
  exceed the 1 s limit and fail intermittently.

### Tests

- 4 unit tests for the JSON envelope (`schema_version` present,
  numeric, first field, only addition at the top level) and 2 end-to-end tests
  with the real binary (`tests/json_schema.rs`).
- 219 unit tests for the memory module, including invariants checked on eight scenarios:
  confidence of at least 60%, numbered steps for any result above Info,
  no leftover `{}`, no MiB/GiB units, serializable JSON. 10 integration
  tests (`tests/memory_module.rs`): healthy 64 GB server,
  saturated workstation, badly prioritized zram, orphaned SysV segments, ZFS ARC,
  terminal and JSON rendering. Total: 567 library tests, 7 CLI,
  45 integration (619, all green).
- Verified on a real system: orphaned SysV segment, 900 MB file
  in `/dev/shm`, 3 GB process, real OOM kill, real swap
  (256 MB file) and rendering in a real terminal (TUI under tmux).

### Known limits

- The minimum Rust version (1.75) could not be verified here (the local
  compiler is 1.97); the new code avoids the known later
  APIs (for example `Option::is_none_or`).
- Compatibility with Rust 1.75: not verifiable locally (rustup blocked in
  the development environment), but **verified by continuous
  integration** — the "Tests (Rust 1.75.0)" job went green on
  pull request #1, like the stable, fmt and Clippy jobs.

## 2026-10-07

### Added

- **Maximum time for every external command.** Until now, a `virsh`
  whose daemon no longer answered, a `smartctl` on a disk in
  trouble or a hung `nvidia-smi` froze the whole audit — and the TUI
  with it, without a message. Every command launched through
  `core::command::command()` now has a default limit of **10 s**,
  adjustable with `--timeout <seconds>` (1 to 3600, before or after
  the subcommand). `smartctl`, `nvidia-smi` and `docker/podman stats`
  get double (waking a sleeping disk, initializing the
  driver). Beyond that, the command is killed and the audit continues.
- **Incomplete data is visible, never silent.** A timeout
  is recorded in a new `notes` field of each module's result
  (present in the JSON). The terminal mode shows
  `↳ incomplete data: 'virsh list --all --name' did not finish within
  10s and was stopped` under the module; the TUI shows a yellow banner
  on the module's page, with a reminder of `--timeout`. A module with
  notes gets a ⚠ instead of a ✓: a green tick would claim more
  than the data allows. The notes are attached to the right
  module even when the modules run in parallel (tracking per thread).
- **Per-tool safeguard (`ToolSession`).** The ~9 `virsh` calls made
  for each VM, and the 3 `nvidia-smi` calls, share a session:
  at the first timeout, the following calls are skipped. A stuck
  `libvirtd` costs one limit, not (number of VMs × 9) limits.
- **Modules run in parallel** (`std::thread::scope`, no
  dependency added): a slow module now only delays itself.
  The order of the menu and of the results is unchanged. An error **or a
  panic** in a module is isolated in its `error`; if the system
  refuses a thread, the module runs inline rather than being lost.
- **SMART queries in parallel** (`core::parallel::parallel_map`, 8 at a
  time at most, results in disk order): a server with a dozen
  disks no longer waits for each `smartctl` one after the other.
- Tests: 33 new unit tests (30 library + 3 CLI: time limit, large output
  without deadlock, grandchild keeping the pipe open,
  order of the results, real concurrency and thread cap,
  isolation of a panic, attribution of notes to the right module,
  progress, `--timeout`, terminal/TUI rendering) and 3 end-to-end
  tests (`tests/hung_tools.rs`) that launch the real binary against
  fake `virsh` that hang. Mutation check: without the session
  safeguard, the "mid-run hang" test fails
  (6.1 s instead of 1.2 s).

### Changed

- `core::command::command()` now returns a `Cmd` (same usage:
  `arg`, `args`, `output`, plus `timeout` and `slow`) instead of a
  `std::process::Command`. A command that is too slow returns an
  `ErrorKind::TimedOut` error; "tool missing" remains `NotFound`.
- The progress callback is now
  `on_progress(finished, total, running)`. The TUI's startup/refresh
  screen shows for example
  `10/11 done — waiting for virtualization`: with simultaneous
  modules there is no longer a single "current module".
- The JSON gains a `notes` field per module (compatible addition: the existing
  fields do not move).

### Measurements (honest)

Release binary, same slow fake tools (`virsh`, `smartctl` on 6
disks, `mokutil`, `dmesg`, 1 s each):

| Version | Audit duration |
|---|---|
| before (sequential) | 10.1 s |
| modules in parallel only | 6.1 s |
| + SMART in parallel | **2.0 s** |

With the real tools of this test machine (fast, no physical
disk or GPU), the duration is the same, ~0.1 s: the gain only appears
when tools are really slow, which is precisely the
case that was a problem. The rest of those 2 s is the `firmware` module,
which chains `mokutil` then `dmesg` internally.

### Known limits

- Only the launched process is killed at the deadline, not its possible
  descendants; they never prevent the audit from continuing, however
  (the pipes are abandoned at the deadline).
- A process blocked waiting on uninterruptible I/O (dead NFS
  mount, failing disk) cannot be killed by the kernel before the
  I/O returns: the audit continues without waiting for it, but the process
  may remain in disk sleep until it returns.
- The `config.toml` file described in ARCHITECTURE.md still does not
  exist; `--timeout` is for now the only setting.
- This step was compiled and tested with `rustc` 1.97 (1.75 could not
  be installed in the test environment). The new code only uses
  APIs stable since ≤ 1.75 (`thread::scope`, `spawn_scoped`,
  `thread_local!` with `const`, `recv_timeout`), verified by reading;
  the CI planned for the next step will explicitly compile with 1.75.

## 2026-09-14

### Changed — version management policy revised

Correction of the previous correction: the manual resynchronization
done on 10 September (see below) treated the wrong symptom. Reported
by the user: it is not that their local builds were ahead of what was
delivered here — it is the opposite. Their local `VERSION` stayed
stuck at `0.4.0` despite several runs of `build-deb.sh` with
increment options, whereas it should have reached `1.3.0`.

Verified in depth before concluding: the increment logic
itself works correctly — 4 successive real runs
(`--major`, `--minor`, `--minor`, `--minor`) chain correctly
`0.4.0 → 1.0.0 → 1.1.0 → 1.2.0 → 1.3.0`, confirming that an increment
composes correctly from one run to the next. The most probable cause on the
user's side: `fpm` is not a system package, it is installed via
`gem install --user-install fpm` — if it is not present, every run
fails cleanly at the tool check, with a clear message, **without ever touching `VERSION`**
(deliberate behavior: no increment without a fully successful
build). Confirmed by a dedicated test: a run without `fpm` available
→ clean failure, `VERSION` unchanged, exactly the reported symptom.

**Decision**: `VERSION` (and the `version` field of `Cargo.toml`) are
no longer included in source code deliveries from now on. This file belongs exclusively to the user's
local environment, advanced only by their own successful runs
of `build-deb.sh`/`build-rpm.sh` — making it advance on the delivery side as well
created exactly the opposite of the problem it aimed at: each
new delivery overwrote the user's local progress.
Verified that both scripts start cleanly at `0.1.0` in
the total absence of `VERSION` (the case of a fresh extraction). The entries
of this changelog will now use a date rather than a version number
invented here, for the same reason — that number is no longer
mine to decide.

### Added

- New **firmware** module, placed in the menu right after `kernel`
  and before `virtualization` (virtualization enabled in the BIOS is a
  logical prerequisite of what the latter does) — verified under real
  conditions, not only in the code.
  - **Honest answer to the question asked**: no, there is no
    universal Linux API to read the whole of the BIOS/UEFI
    configuration menu (fan curves, XMP profiles,
    detailed boot order, CSM toggle) — this module does not claim
    to do so. Some manufacturers (Dell, Lenovo) have
    proprietary tools for part of their specific settings; not
    covered here, a much wider and more fragile scope.
  - **What is covered, entirely verified before coding**: firmware
    identity (manufacturer/version/date/revision) via
    `/sys/class/dmi/id/*` — pure sysfs reading, no external tool,
    no root required (confirmed through several independent sources);
    boot mode (UEFI vs Legacy/CSM) and Secure Boot state (via
    `mokutil`, left "undetermined" rather than guessed from the
    raw bytes of the EFI variable when the tool is absent — the
    sources disagreed on the exact offset); virtualization
    extensions (VT-x/AMD-V); IOMMU/VT-d; presence of a TPM.
  - **Virtualization enabled in the BIOS**: the severity only increases
    when `dmesg` explicitly confirms "disabled by bios" — the
    mere absence of the `vmx`/`svm` flag remains ambiguous (CPU without
    real support vs disabled in the BIOS, two cases indistinguishable from
    that single piece of data) and therefore never raises the severity alone,
    it only lowers the confidence accordingly.
  - **IOMMU/VT-d**: cross-checks the requested kernel parameter (`/proc/cmdline`)
    with the state actually active (`/sys/class/iommu/`) — a
    parameter requested but never active signals a block at BIOS
    level, with a direct pointer to the already existing GPU (SR-IOV
    passthrough) and Virtualization (VFIO) modules.
  - New canonical category `Firmware`, added to the enum and to the
    vision list of `PROJECT_CONTEXT.md` (same precedent as for
    GPU).

## [1.3.0] - 2026-09-10

### Note on this version jump (0.4.0 → 1.3.0)

No code change in this entry — resynchronization of
`VERSION`/`Cargo.toml` only. Reported as inconsistent by the
user: `VERSION` stayed at `0.4.0` while they were at
`1.3.0` on their own machine. Cause identified: two distinct
increment mechanisms, not synchronized with each other —
`build-deb.sh`/`build-rpm.sh` increment `VERSION` directly on the
machine where they are run (locally, independently of any
conversation), while each delivery made here increments its
own copy with no visibility on the user's local state.
Resynchronized to `1.3.0` (the reported local state) rather than
continuing on a desynchronized base at `0.4.0`.

## [0.4.0] - 2026-09-10

### Added

- **gpu** module enriched with several additional pieces of information
  explicitly requested — each verified before being coded, with
  a real reliability trap found and honestly integrated rather than
  passed over in silence.
  - **Separate core/memory clocks**, for both manufacturers —
    NVIDIA via `clocks.gr`/`clocks.mem`, AMD via `pp_dpm_sclk`/
    `pp_dpm_mclk` (the line marked with an asterisk indicates the
    active state among all the available DPM states).
  - **PCIe port speed and width** (current + maximum), read
    generically through the standard PCI sysfs files
    (`current_link_speed` etc.) — applicable to any
    manufacturer, not only AMD/NVIDIA. **Reliability trap found and
    documented**: a real GitHub ticket on `amdgpu_top` reports that
    `current_link_speed` can sometimes display the *maximum* value
    rather than a real real-time reading on certain
    kernel/driver combinations — the text produced carries this
    warning rather than claiming a precision that is not
    guaranteed, and this data alone never raises the severity.
  - **Maximum CUDA version supported by the driver** (`GPU001`,
    from the text header of `nvidia-smi` — not a `--query-gpu`
    query field, contrary to what one might expect).
    Explicitly labelled as such and distinguished from the version of the
    CUDA *toolkit* actually installed (`nvcc --version`) — a
    confusion documented as frequent in several independent
    sources found during the research.
  - **Number of CUDA cores — deliberately absent.** Confirmed not exposed
    by `nvidia-smi`, including through `compute_cap` (which gives the
    architecture, not the number of cores, and can moreover make the whole query
    fail on old drivers). It is a fixed hardware characteristic per model;
    adding it would have required a model→specs lookup table that would become
    wrong as soon as a new card is released — refused rather than
    guessed.
  - Small cosmetic fix along the way: the manufacturer's name no longer
    repeats when the GPU description already includes it (e.g. "NVIDIA
    NVIDIA GeForce RTX 4090" → "NVIDIA GeForce RTX 4090").



### Added

- New **gpu** module, placed in the menu right after `numa` (with
  the other hardware resources: memory/cpu/numa/gpu/storage,
  before the services/diagnostic modules) — verified under
  real conditions, not only in the code.
  - Generic detection via `/sys/class/drm/card*` (filtered of the
    connector-type entries like `card0-DP-1`), classification of the manufacturer
    from the `PCI_ID` read in `uevent` (`0x10de` NVIDIA, `0x1002`
    AMD/ATI — distinct from `0x1022`, AMD's own PCI ID for its
    CPUs/chipsets, deliberately not confused with a GPU — `0x8086`
    Intel).
  - **AMD**: entirely through direct sysfs, no external tool —
    `mem_info_vram_total`/`used` (bytes), `gpu_busy_percent`/
    `mem_busy_percent` (%), `hwmon/*/temp1_input` (**millidegrees**),
    `power1_average` (**microwatts**), `fan1_input` (RPM). Each
    path and unit confirmed through the kernel documentation itself and
    several independent real captures (including the Rust library
    `amdgpu-sysfs`), not assumed.
  - **NVIDIA**: a single `nvidia-smi --query-gpu=...
    --format=csv,noheader,nounits` call covering all the NVIDIA cards at
    once, correlated with the DRM entries by normalized PCI address
    (`nvidia-smi` uses an 8-hex-digit domain, the rest of the
    project 4 — dedicated normalization, tested). Case handled explicitly:
    `power.draw` can literally be `"[Not Supported]"` depending on the
    card's power state. Reporting of the processes using the
    GPU (`--query-compute-apps`) only when a single NVIDIA card is
    present — with several cards, no per-process attribution is
    provided rather than risking a wrong correlation.
  - **Severity based on temperature only**: high utilization,
    VRAM and power remain Info (a normal sign of a card that is
    working, not a problem in itself — same reasoning as the resource
    metrics of the virtualization module). For AMD, the
    temperature is compared with the critical threshold *specific to that card*
    (`temp1_crit`, a real piece of data); for NVIDIA, lacking an equally
    direct equivalent, a more conservative generic threshold is used, with
    an explicitly reduced confidence accordingly. Missing driver
    detected separately and always at least a Warning, without ever
    lowering the severity of a card that is otherwise overheating.
  - **Assumed limit**: the `nvidia-smi`/AMD sysfs path could only be
    verified at the parsing level (fixtures based on confirmed real
    formats) — `/sys/class/drm` being a kernel structure, it is
    impossible to simulate it without modifying the production code
    just for the tests, and this sandbox has no real GPU available.

First truly "published" version since the initial scaffold
0.1.0 — until now, every change accumulated under "Unreleased"
without ever getting a version increment, which was
reported as a real problem: `VERSION` stayed frozen at `0.1.0`
despite substantial evolution of the project. From now on,
every delivered change increments `VERSION`/`Cargo.toml` and "publishes"
the corresponding section with a date, instead of letting
it accumulate indefinitely under "Unreleased".

This version groups everything that was built since the initial scaffold
(memory/cpu/numa/storage/systemd + basic TUI): the network, kernel, ntp and
virtualization modules; the deep enrichment of memory, storage (SMART), and
virtualization (VMs/host containers, CPU/NUMA pinning, passthrough/SR-IOV,
stats inside the VMs); the rework of the TUI (submenus, live header,
progress screen, manual refresh); and several fixes for real bugs
(SR-IOV false positive, sensitivity of `virsh` to the locale, blocking
confirmation prompt in the build scripts, default behavior of
`linuxdoctor` without a subcommand).

### Changed

- `linuxdoctor` without a subcommand now opens the TUI by default,
  when stdin **and** stdout are a real terminal (`std::io::IsTerminal`,
  standard library since Rust 1.70, no new dependency) —
  matches the expected usage once the package is installed. Automatic fallback
  to the `audit` behavior (text, as before) whenever
  this is not the case (redirection, pipe, script/cron/CI), so that the existing
  non-interactive uses (`linuxdoctor > report.txt`,
  `linuxdoctor | grep ...`) keep working exactly as
  before rather than failing against a TUI that has nowhere to
  display. `linuxdoctor audit` and `linuxdoctor tui` remain
  available to explicitly force either mode.
  Verified with a real pseudo-terminal (`tmux`): launching without
  arguments does open the TUI, clean exit with `q`; redirection to a
  file and pipe to `grep` do stay in text mode, unchanged.
  Decision logic extracted into a pure, testable function
  separate from the real I/O detection — the same "thin collection +
  testable core" principle as the diagnostic modules.

### Clarified

- `build-rpm.sh` adds a "-1" to the name of the generated `.rpm` file (e.g.
  `linuxdoctor-1.5.2-1.x86_64.rpm`) — reported as abnormal by a
  user. **Verified in depth, it is not a bug**: it is the
  "Release" field of the RPM format, distinct from the "Version" field in the
  NEVRA convention (Name-Epoch:Version-Release.Architecture), set to `1`
  by default by `fpm` in the absence of an explicit `--iteration`. The
  `.deb` format has no such notion, hence the absence of this suffix on the
  `build-deb.sh` side — which explained the confusion. Complete verification
  performed (not just re-read): the 4 version options (1/2/3/4,
  both via CLI flags and via the numbered interactive menu, with a
  real pseudo-terminal) give a strictly identical and correct result
  in both scripts — `VERSION` and `Cargo.toml` never
  contain this suffix, in any tested scenario. Success
  message of `build-rpm.sh` enriched with an explicit note on this, so
  that it never remains ambiguous.

### Fixed

- **Real bug reported by a user**: `VERSION` (and `Cargo.toml`)
  was never updated during builds, without any visible error message.
  Cause found by actually running the scripts (with a fake `fpm` to work around the
  absence of `rubygems.org` in this sandbox) rather than only re-reading
  them: the confirmation prompt `read -p "Construire ? [o/N]"` existed **even** when an
  explicit version flag (`--patch` etc.) had already been passed. In any
  context without an interactive terminal attached to standard input (launched
  from a script, a tool, an automation), `read` receives an immediate EOF
  — and with `set -e` at the top of the script, that killed the script
  instantly, **before even compiling**, without any message,
  leaving `VERSION`/`Cargo.toml` unchanged. Reproduced and confirmed
  precisely before fixing (`bash build-deb.sh --patch < /dev/null`
  → exit code 1, no output).
  - `build-deb.sh` and `build-rpm.sh` now detect whether standard input
    is a real terminal (`[ -t 0 ]`). Without a terminal AND without a
    version flag → clear error message asking for one,
    instead of a hang or a silent death. Without a terminal BUT
    with a flag already provided → automatic confirmation (the flag already
    expresses the intent), with an explicit message saying that this
    happened.
  - New `--yes`/`-y` flag to skip the confirmation explicitly,
    even in an interactive session.
  - Re-verified after the fix, in both scripts, on the four
    scenarios: flag + no terminal (works now), no
    flag + no terminal (fails cleanly with a clear message),
    explicit `--yes`, and the existing rollback in case of `fpm` failure
    (still intact, not affected by this fix).

### Fixed

- **virtualization** module: display precision of storage. A
  small-but-real allocation (e.g. a freshly created qcow2 disk)
  was visually rounded to "0.0 GB" with a single digit after the
  decimal point, indistinguishable from a real read failure — reported as a bug
  by a user. New adaptive-unit formatter (GB → MB →
  KB depending on magnitude) rather than a simple fixed `{:.1} GB`. Investigated
  in depth before fixing: `virsh domblkinfo` with `target`
  (`vda`) vs `source` (full host path) as the identifier actually give the
  **same result** in this version of libvirt (10.0.0,
  tested against a real domain with a real qcow2 disk, `libvirtd`
  daemon launched manually in this sandbox) — so the exact symptom
  reported could not be reproduced identically. Switched to
  `target` anyway for robustness (recommended by the official libvirt
  examples, also works for pool-based storage such as
  `virt-manager` creates by default, unlike
  `source` which may not be a direct file path in that case).

### Added

- **virtualization** module: per-VM detail greatly enriched, verified with
  a real `libvirtd` launched manually in this sandbox (no `/dev/kvm`
  available here, so starting is impossible, but domain definition,
  `domblklist`, `domblkinfo`, `domiflist` all tested against a real
  inactive domain).
  - **CPU pinning + NUMA node integrated per group**: instead of a NUMA
    summary separate from the aggregate, each pinning group shows
    its node directly ("vCPUs 0-1: host 0-3 (NUMA node 0)").
  - **Cross-check with the host's isolated CPUs**: reuses
    `cpu::collect::collect().all_isolated_cpus()` — indicates whether the pinned
    vCPUs fall on CPUs reserved/isolated from the general scheduler,
    not only which ones.
  - **PCI hardware descriptions** (`lspci -s <address>`): each
    passthrough/SR-IOV device now shows which hardware
    it corresponds to, not only its address. Trap handled: a
    valid but absent address gives an empty output with exit code 0,
    not an error — verified empirically.
  - **Guest-internal memory statistics** (`virsh dommemstat`,
    format confirmed through 4 concordant sources): percentage really used
    by the guest operating system, with an explicit warning
    when the "unused" value is 0 (it may be a real zero
    or a balloon driver without periodic collection enabled — the two
    are indistinguishable from that single piece of data).
  - **Approximate CPU usage**: delta between two `virsh dominfo`
    samples taken before/after the rest of the enrichment of
    that VM (not a dedicated pause — the word "approximate" in the
    text honestly reflects a short and variable sampling window, not
    a precise measurement over a fixed duration like the one in the TUI header).
  - **Network interfaces** (`virsh domiflist`, much simpler than
    re-parsing XML — directly gives type/source/model/MAC
    in columns): type, source, model. No invented "speed" for
    paravirtualized NICs (virtio has no fixed throughput) — instead,
    an honest note on what each common model implies.
  - Cost to know about: about 10 additional `virsh`/`lspci` calls
    per VM from now on — significant for a host with several VMs,
    still in the "full scan, not continuous refresh" spirit
    of the rest of the tool.

### Added

- **virtualization** module: per-VM detail enriched further — CPU pinning
  to the effective NUMA nodes, configured NUMA policy, passthrough/SR-IOV
  devices.
  - **Effective NUMA nodes**: derived data, not directly provided
    by `virsh` — cross-checks the vCPU pinning (`virsh vcpupin`) with the
    host's real NUMA topology (`/sys/devices/system/node/*/
    cpulist`, read directly, without going through the module NUMA's full
    pipeline — same principle as `live_stats.rs`). Reuses the
    `parse_cpu_list` already shared between the CPU and NUMA modules rather than
    duplicating a third one.
  - **Configured NUMA policy** (`virsh numatune`): mode and nodeset
    explicitly defined, distinct from the computation above (one is the
    configured policy, the other is where the vCPUs actually run
    once pinned). Honestly stays `None` when nothing is
    configured rather than guessing a default value.
  - **Passthrough/SR-IOV devices** (`virsh dumpxml`): two distinct XML
    forms handled separately, confirmed by the official libvirt
    documentation and real examples — `<hostdev type='pci'>`
    for generic passthrough (GPU, etc.) and
    `<interface type='hostdev'>` specifically for network SR-IOV VFs
    (with the MAC address). Parsed via a small state machine
    targeted at the output format of `virsh dumpxml` — not a general
    XML parser — with a trap handled explicitly: the `<mac>` element
    appears *after* the closing of `<source>` in document order, so it is
    captured pending until the block closes
    rather than at the time of reading the PCI address.
  - PCI addresses accepted in hexadecimal (`0x06`) or decimal (`11`)
    depending on the XML form encountered — both exist in real
    examples of the documentation.

### Added

- TUI: live header, progress screen at startup, manual refresh
  — three related requests, one single coherent rework.
  - **Real-time header**: a second line shows CPU%, Mem%
    (used/total in GB) and disk space of `/` (`%`), refreshed
    automatically about once a second as long as the TUI is
    open — without any user action. Color codes (green/yellow/
    red according to 70%/90% thresholds). CPU% is computed as a delta between
    two reads of `/proc/stat` (standard technique on Linux — a
    single read gives no "instantaneous usage %", only
    cumulative counters since boot), so it shows "…" until a
    second sample is available (~1s after opening).
    New `output/live_stats.rs` module, deliberately separate from the
    diagnostic `Module` pipeline — these are display gauges,
    not findings with evidence/explanation/recommendation, and
    rerunning them entirely at every tick (including the per-disk `smartctl`
    calls) would be both useless and far too slow for a
    once-a-second refresh.
  - **Progress screen**: at launch, a centered gauge shows
    which module is being scanned and how far along we are (N/total) —
    important for a scan with a slower module (`smartctl` per
    disk in Storage, `virsh`/`docker` in Virtualization) which
    could previously give the impression of a frozen terminal.
  - **Manual refresh (`r`)**: reruns the full module pipeline
    without quitting the program, with the same progress screen.
    The current module selection is preserved if it still exists
    in the new data. The "findings from Ns ago" counter in the
    header explicitly distinguishes the freshness of the two types of
    data: the header gauges are always up to date, the findings
    shown date from the last scan/refresh.
  - **Necessary architecture change**: `TuiApp` now owns
    its `Report` directly (instead of borrowing it) — without
    that, it is impossible to replace it during a refresh. This
    changed the signature of several internal methods (they return owned
    `String`s rather than borrowed `&str`) to avoid a
    borrow conflict with `ratatui`'s mutable `ListState`s.
    `core::engine::run_audit()` stays unchanged for the non-interactive
    `audit` command; a new `run_audit_with_progress()` accepts a
    progress callback, used only by the TUI.
  - **Verified with a real pseudo-terminal** (`tmux`, not only the
    headless `TestBackend` rendering): progress screen captured in the middle of a real
    scan, header confirmed live over several seconds (CPU% resolves
    after the second tick, age counter increments), `r` key
    confirmed triggering a real new scan with preservation of
    the selection, clean exit with `q`.

### Fixed

- **Real bug reported by a user**: on a system with a French
  locale, `virsh dominfo` came back with `state: unknown` for
  **all** VMs (including running ones), and the summary
  displayed "0 currently running" despite active VMs. Cause: `virsh`
  translates its field labels via gettext (`State:` becomes
  something else depending on the locale), and the parser looked for the exact
  English string. Fix: new shared utility
  `core::command::command()` which forces `LC_ALL=C`/`LANG=C` on **all**
  subprocess calls of the project (not only `virsh`) — these
  are not just unset variables, they explicitly override the
  inheritance of the parent environment (verified: launching
  `linuxdoctor` itself under `LC_ALL=fr_FR.UTF-8` still produces
  `virsh`/`docker` error messages in English). Exact reproduction of the
  mechanism not confirmed in this sandbox (Ubuntu's minimal `libvirt-l10n`
  package installs no real translation file — verified
  by comparing `virsh` under the C locale and under a manually generated
  `fr_FR.UTF-8`), so honestly treated as "most likely cause,
  fixed by a standard defensive practice" rather than "100%
  confirmed cause".

### Added

- **virtualization** module: per-VM detail enriched.
  - vCPU pinning (`virsh vcpupin`, format confirmed via `virsh help` and
    real captures from the libvirt/Red Hat documentation, not
    guessed) — which host CPUs each vCPU may use, grouped for
    readability ("vCPUs 0-1: host 0-3; vCPUs 2-3: host 4-7").
  - Storage per VM (`virsh domblklist --details` + `domblkinfo`) — per
    disk: configured capacity and space actually allocated on
    the host (the data that matters for a "thin-provisioned" format
    like qcow2). Empty CD-ROM drives are excluded. Correction made along
    the way: I had wrongly assumed a `--bytes` flag
    for `domblkinfo` by analogy with `domblkstat` — verified via
    `virsh help domblkinfo` that this flag does not exist, fixed before
    delivering.

### Added

- **virtualization** module enriched: host-side inventory, in addition to the
  guest-side detection (`VIRT001`, unchanged). Important distinction:
  `VIRT001` answers "what is this machine running in", these new
  checks answer "what does this machine host".
  - `VIRT002`/`VIRT003` (VMs, via `virsh`): summary always present
    (`VIRT002`) + one finding per VM (`VIRT003`, in a dedicated submenu).
    Three-level state, not a simple boolean: `virsh` absent, `virsh`
    present but hypervisor unreachable (no `libvirtd`, or no
    permission — behavior verified empirically: `virsh list --all`
    exits with code 1 and `"failed to connect to the hypervisor"`), or
    available. Per VM: state, vCPUs, configured max memory, memory
    actually used (only if running — otherwise
    `virsh dominfo` reflects the balloon target, not a real usage).
  - `VIRT004`/`VIRT005` (containers, via `docker` then `podman` as a fallback)
    : same summary + per-container detail structure. Uses `.State`
    (simple word: `running`/`exited`) rather than `.Status` (human text)
    to determine the state, with live CPU/memory consumption
    (`docker stats --no-stream`) for running containers.
  - **Verified against real tools, not only fixtures**:
    `virsh` and `docker` really installed in this sandbox
    (`libvirt-clients`, `docker.io` via apt), `dockerd` launched
    manually, a minimal image built from a static busybox
    (import without network, the Docker Hub pull being blocked by the
    network allowlist), two real containers created (one
    running, one stopped). The compiled `linuxdoctor` binary
    ran against this real daemon and reported the real live
    resource statistics. The "tool installed but daemon unreachable" case
    was also confirmed for real for `virsh` and `docker`, with the exact error
    messages captured.
  - Measured cost: +75-110ms on this sandbox (several
    `virsh`/`docker`/`podman` calls, including connection attempts to a
    missing socket) — well within the <2s target, but a real cost
    to know about on a host where the module runs frequently.

### Added

- **virtualization** module: detection of the virtualization
  technology via `systemd-detect-virt`. Important difference from
  the systemd/ntp modules: this tool **works without systemd
  being PID 1** (it probes DMI/CPUID/environment markers
  directly, no D-Bus bus to PID 1) — verified empirically on
  this sandbox before coding, so no `is_available()` restriction.
  Exit-code trap to note: the tool exits with a **non-zero** code
  precisely when nothing is detected (`none`) — verified in its own
  documentation — so standard output is captured independently of the
  exit code, otherwise every bare-metal machine would report a
  false collection error.
  - `VIRT001` (always present, Info — being virtualized is neither good nor
    bad in itself) distinguishes the four cases: bare metal, VM only,
    container only, or nested (container on VM). Falls back to the `hypervisor` CPUID
    flag of `/proc/cpuinfo` if the tool is not installed
    (weaker signal: confirms hardware virtualization without
    saying which).
  - Verified under real conditions on this sandbox: `docker` on `kvm`
    (real nesting, not a fixture) — correctly identified and
    explained.

### Added

- **ntp** module: clock synchronization status and mode of the
  hardware clock (RTC), via `timedatectl show`.
  - `NTP001` (sync status): reads `NTPSynchronized=`, which comes from the
    `STA_UNSYNC` flag of the **kernel** itself (`adjtimex(3)`) — authoritative
    whichever daemon is in charge (systemd-timesyncd, chrony, ntpd),
    since they all update the same kernel state. Confidence
    deliberately reduced (`strong_indication`, not
    `direct_observation`) when this field indicates a problem: a Red Hat
    support ticket confirms it is a known false negative with
    certain chrony/ntpd configs (chrony without `rtcsync`, ntpd with
    `-x`) that do not update this kernel flag — verified before
    coding, not assumed.
  - `NTP002` (RTC mode): `LocalRTC=` — an RTC in local time is not
    a problem in itself (common setting in Windows dual-boot), so it
    stays Info, presented as context to confirm rather than as
    a verdict.
  - Same availability mechanism as the systemd module
    (`/run/systemd/system`) — `timedatectl` is part of systemd's core,
    so it depends on the same condition.

### Added

- **kernel** module enriched: four new checks, always present.
  - `KERN003` (build info): parses `/proc/version` — build user/host,
    compiler, build tag. Trap avoided: compiler strings often contain their own nested
    parentheses (`gcc (Ubuntu 13.2.0-...) 13.2.0`), so the parser counts
    depth rather than naively looking for the first closing
    parenthesis — verified both on this sandbox (custom
    Firecracker kernel) and on an Ubuntu-style `/proc/version` example.
  - `KERN004` (reboot required): `/var/run/reboot-required`
    (Debian/Ubuntu convention). On the other distribution families,
    the absence of the marker is honestly reported as "not
    confirmed", not as "no reboot needed" — this file
    does not exist at all elsewhere.
  - `KERN005` (ASLR status): `kernel.randomize_va_space` — disabled
    (0) is reported as Warning, partial (1) or full (2) stays Info.
  - `KERN006` (notable boot parameters): targeted scan of
    `/proc/cmdline` for `mitigations=off` (Warning — disables the
    Spectre/Meltdown mitigations), `nomodeset`, single/emergency mode.
    Not an exhaustive command-line linter, just a few well-chosen
    signals.

### Added

- **kernel** module: taint status (`/proc/sys/kernel/tainted`, the 20
  bits transcribed from the official kernel documentation —
  https://docs.kernel.org/admin-guide/tainted-kernels.html — not
  assumed) and history of OOM kills (via `dmesg`, degrades
  cleanly if access is denied — `kernel.dmesg_restrict` often
  limits this to root). `KERN001` combines all the active bits into a single
  finding (these are heterogeneous conditions, not a list of
  similar instances like sockets or filesystems).
  Severity at the worst active signal (e.g. a Machine Check Exception or a
  soft lockup outweigh a simple proprietary module loaded, which is
  common and harmless).

### Fixed

- **network** module: `NET002` treated the RX/TX loss rate as a
  reliable signal without taking SR-IOV into account. On an interface with
  active VFs, traffic steered by the hardware to a VF may be
  counted in the physical function's `rx_dropped` without indicating a
  real cable/duplex problem — documented phenomenon (reported even
  by an Intel engineer on i40e). Detection via
  `/sys/class/net/<iface>/device/sriov_numvfs` (standard kernel sysfs
  interface, no pattern matching on the interface name): if
  VFs are active, the severity goes down one level and the confidence
  explicitly goes to "weak indication", with the context in
  the explanation and an adapted recommendation (compare with the traffic
  of the VF interfaces themselves rather than suspecting the cable first).

### Added

- **network** module: per-interface overview, graded error/loss rate
  (with a minimum sample threshold — below 100 packets, a rate
  is not statistically significant, so it is reported as Info rather than
  risking a false alert), default gateway, DNS configuration.
  No external command: everything comes from `/proc/net/dev`,
  `/proc/net/route` (with decoding of the kernel's little-endian hexadecimal
  IPv4 addresses), `/sys/class/net/*` and `/etc/resolv.conf`.
  `NET001`/`NET002` are grouped by interface for the TUI submenu.

### Added

- **storage** module: SMART health per physical device, in a dedicated
  submenu — distinct from the per-mount-point instances
  (`STOR001`/`STOR002`), since SMART is read per device (`/dev/sda`),
  not per mount.
  - `STOR003` (summary, always present): number of candidate devices
    examined (`/sys/block`, filtered of loop/ram/zram/dm/md/optical) and
    how many support SMART. Explicitly distinguishes "smartctl not
    installed", "no device supports SMART" and, if relevant,
    adds a permissions hint (root is generally needed for
    raw device access — detected via `/proc/self/status`, no
    new dependency).
  - `STOR004` (one per device, in the submenu): parses the JSON of
    `smartctl -a --json=c` (`smartmontools` ≥ 7.0), handles separately the
    ATA attributes ("big four": reallocated/pending/
    uncorrectable sectors) and the NVMe health log (`critical_warning`,
    `percentage_used`, `media_errors`). Severity graded on the strongest
    signal found — an overall "PASSED" status does not prevent a
    rise to ERROR if the individual attributes drift, since SMART's
    PASSED/FAILED threshold is often more lax than the
    drift of these attributes taken one by one.

### Added

- TUI: navigation submenus. Modules whose findings carry
  2+ distinct `instance` values (CPU sockets, filesystems,
  NUMA nodes, failed units) now display only their
  global findings at the module level, with a prompt (`▸ N items —
  press Enter for detail`) to reach the per-instance detail. `Enter`
  to go in, `Esc` to go back out; `PgUp`/`PgDn` navigates the
  active list at each level (modules, then instances once inside).
  Below 2 instances, everything stays displayed flat as before —
  going down into a submenu for "a single thing" would have brought
  only friction.
  - Generic mechanism: new `Finding.instance: Option<String>` field
    in the canonical model — the TUI does not know which IDs are "per
    instance" for which module, it comes entirely from the data. The modules concerned
    (`cpu` for `CPU004`, `storage` for
    `STOR001`/`STOR002`, `numa` for `NUMA001`, `systemd` for `SYSD002`)
    just set `.instance(...)` on the finding builder.

### Changed

- TUI: navigation reversed — PgUp/PgDn now change module,
  ↑/↓ (and `j`/`k`, moved along with the arrows) scroll the detail
  panel. Scrolling also goes from 5 lines per press to 1 line,
  better suited to arrow keys (PgUp/PgDn no longer have a scrolling
  role, so there is no need for a big jump).

### Added

- **memory** module: three new checks, always present.
  - `MEM004` (Memory Usage Overview): distinguishes memory really
    used (`MemTotal - MemAvailable`) from reclaimable cache — answers
    directly the classic confusion "why does `free` show so little
    free memory".
  - `MEM005` (Dirty Page / Writeback Pressure): compares the percentage
    of "dirty" pages with the system's **actually configured** thresholds
    (`vm.dirty_ratio`, `vm.dirty_background_ratio` — read, not assumed
    at the default values), with an honest fallback if byte-based tuning
    (`vm.dirty_bytes`) is used instead (avoids a false positive on a
    zero threshold).
  - `MEM006` (Shared Memory Usage): usage of `Shmem` (tmpfs, `/dev/shm`,
    SysV/POSIX segments) — not reclaimable like cache, so monitored
    separately, with concrete leads for resolution (`du -sh /dev/shm`,
    `ipcs -m`, `df -h -t tmpfs`).
  - `MEM002` enriched: cross-checks the configured `vm.swappiness` with the
    observed swap usage — a low swappiness (≤10) that swaps anyway is a
    stronger signal than at the default value.

### Added

- **numa** module: automatic topology comparison mechanism.
  - `NUMA002` (renamed "Memory Balance Across Nodes") is now
    **always** present from 2 nodes — before, it only showed if an
    imbalance was detected, which made its absence ambiguous (same
    lesson as `CPU005`).
  - `NUMA003` (new): **structural** comparison of the topology —
    number of CPUs and memory capacity per node, distinct from usage
    (`NUMA002`). Detects nodes without local memory (pure compute
    nodes, e.g. tied to an accelerator), nodes without CPUs (pure
    memory nodes), and capacity asymmetries (ratio ≥ 2×). Each
    detected imbalance comes with a concrete recommendation
    (`numactl --hardware`, `--cpunodebind`/`--membind`).

- **systemd** module: global system state (`systemctl is-system-running`)
  and one finding per failed unit (`systemctl --failed`). Second
  module to use `is_available()` — checks `/run/systemd/system`
  (the standard marker used by libsystemd's `sd_booted()`), not
  only the presence of the `systemctl` binary (which can be installed
  without systemd being PID 1, as in this development sandbox).
  `SYSD001` is always present, even on a healthy system — same principle as
  `CPU005`.
- **numa** module: one finding per NUMA node (CPUs, memory), detection of
  memory imbalance between nodes (`NUMA002`). First module to use
  `is_available()` — disables itself cleanly on a system without NUMA.
- **cpu** module: complete rework for multi-socket machines.
  `/proc/cpuinfo` is now fully parsed (not only the
  first `model name` line) and grouped by physical socket.
  - `CPU001` (machine overview) and `CPU004` (per-socket detail,
    one finding per socket) replace the old single aggregated finding.
  - `CPU004` indicates, for each socket, the available cores and those
    isolated from the scheduler — not only a machine total.
  - `CPU005` now reads **four** distinct isolation mechanisms:
    `isolcpus=` (`/sys/devices/system/cpu/isolated`), `nohz_full=`
    (`/sys/devices/system/cpu/nohz_full` — separate file, previously
    mentioned in the text but never read), the isolated cgroup v2
    cpuset partitions (`cpuset.cpus.isolated`, found by a bounded walk of
    `/sys/fs/cgroup`), and — added following precise feedback on a real
    case — the restriction of `system.slice` via `AllowedCPUs=`
    (`systemctl set-property --runtime system.slice AllowedCPUs=<cpus>`,
    a common libvirt hook technique to reserve cores for a
    VM at startup: the `cpuset.cpus.effective` of `system.slice` is
    compared with the set of online CPUs, the complement is considered
    reserved).
    `CPU005` is now **always** present, even without isolation
    detected, so as not to suggest that the tool did not check. The
    vCPU pinning at hypervisor level (`virsh vcpupin`) remains out
    of scope: no kernel interface exposes it on the guest side, whatever the
    mechanism checked.
  - `CPU006`: CPUs that are "possible" but not online
    (`/sys/devices/system/cpu/possible` diffed against `/proc/cpuinfo`) —
    relevant on a VM where the hypervisor announces more vCPUs than it
    activates.
- **storage** module: disk space usage (`df -kPT`) and inode usage
  (`df -iPT`), one finding per real filesystem (pseudo-filesystems
  — tmpfs, proc, overlay, etc. — are excluded),
  4 severity levels (< 80% / 80-89% / 90-94% / ≥ 95%).
- `ModuleError::Command`, for modules that run an external command
  rather than reading a file.

### Fixed

- **storage** module: AppImage FUSE mounts (type containing
  `.AppImage`, whatever the application name) are now
  excluded, like the other pseudo-filesystems.
- **cpu** module: `CPU005` only read `/sys/devices/system/cpu/isolated`
  (`isolcpus=`) while claiming in its text to cover `nohz_full=` —
  the latter lives in a separate file, never read. The isolated cgroup v2
  cpuset partitions were not covered at all. Both are
  now read; see "Added" above for the detail.

### Changed

- Display order of the modules: memory, cpu, numa, storage (NUMA right
  after CPU, the two being linked to the processor topology).

## [0.1.0] - 2026-08-04

### Added

- Core engine: `Context` (reading `/proc`, `/sys`, `/etc/os-release`), `Module`
  trait, `engine` with error isolation per module.
- Canonical models: `Severity` (4 levels), `Confidence` (%, reason),
  `Category`, `Finding`.
- **memory** module: `vm.swappiness`, swap pressure (3 levels), critical
  memory.
- **cpu** module: CPU information, load pressure (3 levels),
  sustained overload (1/5/15 min windows).
- Three outputs: terminal (ANSI colors), JSON, interactive TUI (ratatui).
- 35 tests (31 unit + 4 integration), all fixture-driven — no
  test depends on the real state of the system.
- `PROJECT_CONTEXT.md` (vision, principles) and `ARCHITECTURE.md` (canonical
  technical contract).
