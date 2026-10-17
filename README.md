<!-- SPDX-License-Identifier: GPL-3.0-only -->

# LinuxDoctor

Fast, explainable Linux health diagnostics. See `PROJECT_CONTEXT.md` for vision and
principles, `ARCHITECTURE.md` for the technical contract (types, module trait,
severity/confidence scales, layout).

## Status

v1 scaffold, thirteen modules shipping end-to-end:

* **Memory** — the most detailed module, organised in six topics
  (TUI submenu): **Used memory** (breakdown by kind — program memory,
  page cache, shared memory, kernel — with the top consumers by private
  memory, grouped by program name, and a critical low-memory check),
  **Page cache** (what is really reclaimable, the `drop_caches` myth,
  dirty pages judged against this system's actual `vm.dirty_*` settings
  and the memory they apply to, not assumed defaults), **Shared memory**
  (`Shmem`, tmpfs/`/dev/shm` fill levels, orphaned SysV segments with the
  `ipcrm` command to remove them), **Swap** (`vm.swappiness` judged for
  the kind of swap in use — zram, SSD or spinning disk —, swap activity
  with the programs that are swapped out and since-boot swap traffic,
  and the swap configuration: missing swap, zram priority and
  compression, zswap, `page-cluster`), **Pressure** (PSI stall times,
  OOM kills since boot, direct reclaim) and **Kernel tuning**
  (overcommit mode and commit limit, Transparent Huge Pages, idle
  reserved huge pages, slab/page-table growth, ZFS ARC, `min_free_kbytes`).
  Every finding above Info comes with numbered, copy-pasteable steps
  (commands are only suggested, never run), sized to the machine — for
  example the swap file size, or the `vm.overcommit_ratio` that leaves
  20% headroom. Sources beyond `/proc/meminfo` are best-effort: a missing
  one just removes the findings that need it.
* **CPU** — per-socket topology (cores, threads, model), load-average
  pressure, sustained overload, and — per socket — how many of its logical
  CPUs are available versus isolated. Isolation is checked via three
  distinct kernel-visible mechanisms (`isolcpus=`, `nohz_full=`, and
  cgroup v2 isolated cpuset partitions — the last one being how a VM/
  container orchestrator like Kubernetes' CPU Manager typically reserves
  cores at runtime), always reported even when none are found, so the
  absence of isolation is never ambiguous with "wasn't checked". Plus
  machine-wide reporting of offline CPUs (relevant on VMs where the
  hypervisor provisions more possible vCPUs than it activates). Correctly
  handles multi-socket machines: `/proc/cpuinfo` is grouped by physical
  socket rather than collapsed into one aggregate.
* **Storage** — disk space and inode usage per real filesystem (pseudo
  filesystems like tmpfs/proc/overlay/AppImage FUSE mounts are excluded),
  4 severity tiers, plus per-device SMART health (`smartctl` JSON output —
  ATA "big four" attributes and NVMe health log) in its own submenu,
  separate from the filesystem instances.
* **NUMA** — per-node CPU/memory breakdown; automatic cross-node
  comparison on two axes — memory *usage* balance (`NUMA002`) and
  *structural* topology symmetry (`NUMA003`: CPU count, memory capacity,
  memory-less/CPU-less nodes) — each always reported on multi-node systems
  with a concrete recommendation when asymmetry is found. Skips cleanly on
  systems without NUMA support.
* **GPU** — per-card detail (`GPU002`, one per card in its own submenu
  when 2+ are present) plus an always-present inventory summary
  (`GPU001`). AMD entirely via direct sysfs reads (VRAM, busy%,
  temperature, power, fan, core/memory clocks via `pp_dpm_sclk`/
  `pp_dpm_mclk` — no external tool); Intel (`i915` and `xe` drivers)
  likewise via direct sysfs reads: current and maximum frequency (with a
  note when the allowed maximum has been capped below what the hardware
  can reach), whether the GPU is asleep in its power-saving state, and
  whether the driver reports it is being throttled right now and why
  (`pl1`, `thermal`, ...); discrete Intel cards also give temperature,
  fan and power limit through the driver's hwmon chip. Utilization and
  VRAM aren't read for Intel: the drivers don't provide them through
  sysfs. These interfaces are taken from the kernel's own sources and ABI
  documentation and have not yet been checked on real Intel hardware, so
  anything a given kernel doesn't provide is simply left out; NVIDIA via
  one combined
  `nvidia-smi --query-gpu` call covering every NVIDIA card at once
  (core/memory clocks included), plus per-process GPU memory when
  exactly one NVIDIA card is present (skipped with 2+, rather than risk
  misattributing a process to the wrong card), plus the maximum CUDA
  version the installed driver supports (from `nvidia-smi`'s own text
  header — not a `--query-gpu` field — and explicitly labeled as the
  driver's ceiling, not the CUDA Toolkit version an application actually
  uses, which are commonly confused). PCIe link speed/width (current and
  maximum) read generically via PCI sysfs for any vendor, with an honest
  caveat carried in the wording: some kernel/driver combinations report
  the *maximum* speed even during idle/power-saving states rather than a
  true live reading, a documented real-world quirk, so this alone never
  raises severity. CUDA core count is deliberately not included — not
  exposed by `nvidia-smi` at all, and would otherwise need a model→specs
  lookup table that goes stale the moment a new card ships.
  GPUs the kernel exposes no DRM card for are found on the PCI bus
  (display controllers, class `0x03`) rather than missed: a card reserved
  for VM passthrough (`vfio-pci`, reported as expected on a
  virtualization host and counted in the summary), a GPU with no driver
  bound, or a compute GPU whose driver registers no graphics card. Only
  the PCIe link is read for these (plus `nvidia-smi` for NVIDIA cards the
  `nvidia` driver manages). A missing driver is a Warning for NVIDIA, AMD
  and Intel, but only a note for an adapter from another vendor found
  solely on the PCI bus — typically a server's management-controller
  video chip, often left unbound on purpose. SR-IOV virtual functions
  aren't counted as GPUs of their own.
  Severity is driven by temperature — utilization/VRAM/power near their
  limits are normal signs of a card doing real work, not flagged on their
  own — compared against the card's own critical-temperature reading when
  available (AMD, recent Intel), or a more conservative generic threshold
  (with correspondingly lower confidence) for vendors without that exact
  figure. An Intel driver stating outright that heat is throttling the GPU
  is a Warning too, even for an integrated GPU that has no temperature
  reading; throttling by a power limit is explained but stays Info.
* **Systemd** — overall system state, one finding per failed unit. Skips
  cleanly on systems where systemd isn't PID 1 (checks
  `/run/systemd/system`, not just whether `systemctl` is installed).
* **NTP** — clock synchronization status (`timedatectl show`'s
  `NTPSynchronized`, sourced from the kernel's own sync flag, so it's
  authoritative regardless of which daemon manages sync — though with a
  documented false-negative caveat for some chrony/ntpd configs, reflected
  in a deliberately capped confidence) and RTC time mode. Same
  `/run/systemd/system` availability check as Systemd, since `timedatectl`
  is part of systemd core.
* **Virtualization** — two distinct concerns, not conflated. *Guest-side*
  self-detection (`VIRT001`) via `systemd-detect-virt`, which (unlike
  `systemctl`/`timedatectl`) works without systemd as PID 1 — no
  availability gate needed; falls back to the CPUID hypervisor flag in
  `/proc/cpuinfo` when the tool isn't installed. *Host-side* inventory
  when this machine hosts VMs (`VIRT002`/`VIRT003`, via `virsh`/libvirt)
  or containers (`VIRT004`/`VIRT005`, via `docker` or `podman`) — each
  with a three-state availability check (tool absent / tool present but
  backend unreachable / available), one finding per VM or container in
  its own submenu, live resource usage for running ones. Per-VM detail
  covers CPU pinning with the NUMA node resolved per pinning group (not
  just a VM-wide aggregate), cross-referenced against the host's own
  isolated-CPU set, configured NUMA memory policy, per-disk
  capacity/allocation (adaptive GB/MB/KB units, so a small real value
  never looks indistinguishable from "0.0 GB"), passthrough/SR-IOV PCI
  devices identified via `lspci` (not just their bus address), an
  approximate host-observed CPU% and guest-reported internal memory
  usage (`virsh dommemstat`, with an explicit caveat when its `unused`
  field is exactly 0 — that can be a real reading or an unconfigured
  balloon driver, indistinguishable from the data alone), and the VM's
  network interfaces (type/source/model via `virsh domiflist`, with an
  honest note on what each model implies rather than a fabricated link
  speed). Always Info — none of this is inherently good or bad, it's
  inventory.
* **Network** — per-interface overview and error/drop rates (with a
  minimum-sample-size guard so a handful of startup drops on a fresh
  interface can't produce a misleading percentage), default gateway,
  DNS configuration. Zero subprocess calls — `/proc/net/dev`,
  `/proc/net/route`, `/sys/class/net/*`, `/etc/resolv.conf` only.
  Detects active SR-IOV VFs (`sriov_numvfs`) and downgrades the
  error/drop-rate severity and confidence accordingly — on some NIC/
  driver combinations, VF-steered traffic inflates the physical
  function's `rx_dropped` without indicating a real link problem.
* **Security** — strictly read-only, usable without root (root only adds
  visibility, and each finding says what it could not see). Six topics
  (TUI submenu): **Listening services** (every TCP/UDP socket in
  `/proc/net/*`, whether it is reachable from the network or only from this
  machine, and — as root — which program owns it; a catalogue of services
  that should rarely face the network, such as Telnet, the unencrypted
  Docker API, Redis, Memcached or database servers, is flagged with a
  severity that depends on whether a firewall stands in front of it),
  **Firewall** (ufw, firewalld, nftables or iptables; "not detected" is only
  a warning when something is actually reachable, and the finding says
  whether the rules could be read), **SSH** (the effective `sshd_config`
  including `Include` drop-ins and `Match` blocks: root login, password
  and empty-password authentication, SSH protocol 1, host-based trust and
  `.rhosts`, `PermitUserEnvironment`, weak ciphers/MACs/key exchanges, and
  — as Info — X11 forwarding and a high `MaxAuthTries`; capped at Warning
  when sshd is not running),
  **Access control** (SELinux enforcing/permissive/disabled, AppArmor
  profiles and enforcement, read from sysfs without any tool),
  **Hardening** (19 kernel and network settings — SYN cookies, source
  routing, redirects, reverse-path filtering, `kptr_restrict`,
  `ptrace_scope`, protected links/files, unprivileged BPF… — judged against
  the value actually in force, with the `/etc/sysctl.d/` file that makes the
  fix persistent) and **Accounts & files** (extra UID 0 accounts, logins
  without a password, weak password hashes when `/etc/shadow` is readable,
  and permissions of the files that protect the system: `/etc/passwd`,
  `/etc/shadow`, `sudoers`, the SSH configuration, `/tmp`…). Every finding
  above Info comes with numbered steps that put the safe action first
  (for SSH: install a key *before* disabling passwords, validate with
  `sshd -t`, keep a second session open). Commands are only suggested,
  never run.
* **Logs** — strictly read-only. Four topics (TUI submenu):
  **Authentication** (failed SSH logins over the last 24 hours by source
  address and account name; a password login that follows many failures
  from the same address — the signature of a guessed password, Critical
  from 20 failures; failed `sudo`, `su` and console logins, and accounts
  refused by `sudo`), **System errors** (error-level messages since boot,
  grouped by service, with the message each one repeats most),
  **Kernel messages** (disk and filesystem errors, a filesystem that
  switched to read-only, corrected and uncorrected memory or PCIe errors,
  tasks stuck on I/O, thermal throttling, kernel faults, CPU lockups and
  crashing programs; out-of-memory kills stay with the Kernel module) and
  **Journal & log files** (does the journal survive a reboot, its size
  against journald's own cap, services whose messages journald had to
  drop, logs in `/var/log` that are never rotated). The source is the
  systemd journal (`journalctl -o json`), with fallbacks to `auth.log` /
  `secure` and to `dmesg`. Without root the journal shows only your own
  entries and the classic files are usually unreadable: the overview then
  lists every log it could not read, and the group to join, instead of
  reporting a clean result it could not verify. Text that comes from logs
  — including account names an attacker chose — is stripped of terminal
  control characters, and only enters a suggested command when it is a
  plain word. Every problem comes with numbered steps, the safest first
  (confirm it was you, cut access, then look for what an intruder leaves);
  commands are only suggested, never run.
* **Kernel** — taint status (all 20 bits, transcribed from the kernel's
  own documentation, not guessed) and OOM-kill history via `dmesg`
  (degrades cleanly when unreadable — `kernel.dmesg_restrict` commonly
  limits it to root); plus build info (`/proc/version`, with a
  paren-depth-aware parser so nested compiler-version parens don't get
  truncated), reboot-required detection (Debian/Ubuntu's
  `/var/run/reboot-required` — absence on other distros is reported as
  "not confirmed", not "clean", since the file is distro-specific),
  ASLR status, and a small set of notable boot parameters
  (`mitigations=off` and similar).
* **Firmware** — what's readable of BIOS/UEFI from userspace, which is a
  real but bounded subset: there's no universal Linux API for the full
  Setup-menu contents (fan curves, memory timings/XMP, detailed boot
  order), so this module doesn't attempt those. What it does cover:
  firmware identity (vendor/version/date/revision via
  `/sys/class/dmi/id/*` — plain sysfs, no root needed, no external
  tool); boot mode (UEFI vs. Legacy/CSM) and Secure Boot state (via
  `mokutil`, left unknown rather than guessed from raw EFI-variable
  bytes when it isn't installed — sources disagreed on the exact byte
  offset); hardware virtualization extensions (VT-x/AMD-V — skipped
  entirely on non-x86 architectures, where the vocabulary doesn't
  apply; severity only escalates when `dmesg` directly confirms "disabled
  by bios", since the flag's mere absence can't distinguish that from
  genuinely unsupported hardware); IOMMU/VT-d (kernel parameter
  requested vs. actually active via `/sys/class/iommu/` — a mismatch
  flags BIOS-level blocking of PCI passthrough, cross-referencing
  directly with the GPU and Virtualization modules' SR-IOV/VFIO
  findings); and TPM presence.

The core, `Module` trait, engine, and three output modes (terminal, JSON,
interactive TUI) are built and tested. Adding the next module means only
writing `collect.rs` + `analyze.rs` under `src/modules/<name>/`, then adding
one line to `all_modules()` in `src/modules/mod.rs` and one line describing
the module in `module_summary()` (`src/manpage.rs` — a test fails until it
exists). Nothing else changes — all three output modes, `--modules`, the shell
completions and the manual page pick it up automatically.

**Scope note on CPU isolation:** hypervisor-level vCPU pinning (`virsh
vcpupin`, libvirt `<cputune>`) is a host-side concept with no kernel
interface exposing it to a guest — it genuinely can't be read from inside
the system LinuxDoctor audits, by this or any other in-guest tool. What
CPU005 reports is every kernel-visible isolation mechanism this tool
checks: `isolcpus=`, `nohz_full=`, cgroup v2 isolated cpuset partitions
(the mechanism a VM/container orchestrator like Kubernetes' CPU Manager
typically uses), and `system.slice` being restricted via `AllowedCPUs=`
(a common libvirt-hook technique: `systemctl set-property --runtime
system.slice AllowedCPUs=<cpus>` on VM start, reserving the complement for
`machine.slice`, reversed on VM stop). CPU005 is always reported, even
when nothing is isolated, specifically so its absence never reads as "the
tool didn't check" — if none of these four show anything but cores are
still expected to be reserved, that reservation is almost certainly
happening at the host level.

## Getting set up

```bash
mkdir -p ~/Projects
unzip linuxdoctor.zip -d ~/Projects/linuxdoctor
cd ~/Projects/linuxdoctor
cargo build
cargo test
```

If you're versioning this with git, the `.gitignore` already excludes `target/`
and generated packages (`*.deb`, `*.rpm`):

```bash
git init
git add .
git commit -m "Initial scaffold: core engine, 10 modules (memory/cpu/numa/gpu/storage/systemd/ntp/network/kernel/virtualization), terminal/json/tui output"
```

## Packaging

Two scripts build native packages via [fpm](https://fpm.readthedocs.io/) —
`build-deb.sh` (Debian/Ubuntu) and `build-rpm.sh` (Fedora/RHEL/Rocky/AlmaLinux/
openSUSE). Both follow the same flow: pick a version bump (interactively or
via a flag), compile in release mode, stage the binary + docs, then package.
`VERSION` and `Cargo.toml` are only updated after a fully successful build —
a failed compile or a failed `fpm` step leaves the repo untouched. A brief
confirmation prompt runs before building, unless a version flag was already
given without a real terminal attached to stdin (a script/CI context — the
flag itself is treated as confirmation) or `--yes`/`-y` is passed explicitly.
Running with no version flag and no interactive terminal available fails
immediately with a clear message, rather than hanging or dying silently.
The generated `.rpm` filename includes a `-1` suffix after the version
(e.g. `linuxdoctor-1.2.3-1.x86_64.rpm`) — that's the RPM "Release" field,
distinct from "Version" in RPM's NEVRA naming convention, defaulted to 1
by `fpm`. `.deb` has no equivalent concept, hence no such suffix there.
Neither `VERSION` nor `Cargo.toml` ever contain it.

```bash
./build-deb.sh --patch   # or --minor / --major / --no-version-change
./build-rpm.sh --patch
./build-deb.sh --patch --yes   # skip the confirmation prompt
./build-deb.sh --clean   # remove build artifacts and generated .deb files
```

Both packages also install the manual page (`man linuxdoctor`) and the shell
completions for bash, zsh and fish. The scripts generate them with the binary
they have just compiled (see "Manual page and shell completions" below), so
they always match that version's options.

Before first use, edit `MAINTAINER` and `URL` at the top of each script —
they're placeholders. Both scripts check for their required tools (`fpm`,
`cargo`, and `dpkg-deb` or `rpmbuild` respectively) and tell you what's
missing and how to install it if something's not found — check that
message carefully: on a silent "no version bump happened", the far more
likely cause is a failed tool check (e.g. `fpm` isn't actually installed —
it needs `gem install --user-install fpm`, not a distro package) than a
bug in the version arithmetic itself, since a bump is only ever written
after a build fully succeeds.

**`VERSION` is deliberately not part of this source drop.** It's yours to
own locally: each successful `build-deb.sh`/`build-rpm.sh` run advances it
on your machine, tracking your own release history across as many builds
as you do between updates from here. If `VERSION` (and `Cargo.toml`'s
matching `version` field) were included and refreshed with every source
update instead, extracting a new drop over your existing project would
silently roll your local version back to whatever this drop last set,
undoing your own build history — so neither file ships here, and this
project's own version tracking isn't touched between drops. If `VERSION`
is missing entirely (a fresh checkout with no local build yet), both
scripts default `CURRENT_VERSION` to `0.1.0` and bump from there.

**On dependencies (`requirements.txt`):** this doesn't apply here the way it
does for a Python project like planche-contact — Rust has no separate
runtime dependency list to install. `Cargo.lock` already pins every
dependency's exact version and is committed to the repo; that's the
equivalent artifact. Nothing else to add.

## Runtime dependencies

Everything ships in the single binary except `df` (Storage — always
present on Linux) and `systemctl` (Systemd — only queried when systemd is
actually PID 1). Fully optional external tools, each degrading cleanly
with an explicit explanation rather than silence when absent: `smartctl`
(from `smartmontools`) for per-device disk health — `STOR003` just reports
that SMART couldn't be checked; `dmesg` for OOM-kill history — commonly
root-restricted; `virsh` (from `libvirt-clients`) for VM inventory, and
`docker`/`podman` for container inventory — both report a specific reason
(not installed vs. installed but its daemon/hypervisor is unreachable)
when unavailable. SMART queries and some `virsh`/`docker` operations
typically need root; run as root/sudo for full detail everywhere.
Network needs nothing extra at all — `/proc/net/*`, `/sys/class/net/*`,
and `/etc/resolv.conf` cover it with zero subprocess calls. Security reads
files first (`/proc/net/*`, `/etc/ssh/sshd_config*`, `/sys/kernel/security/lsm`,
`/proc/sys/*`, `/etc/passwd`, file permissions) and only calls `systemctl`,
`nft` and `iptables` — each optional — to know whether a firewall is active
and what its rules do. Without root it still reports exposure and
configuration, but cannot name the program behind another user's socket,
read `/etc/shadow` or list the firewall rules, and says so.
Logs prefers `journalctl` (systemd) and falls back to `/var/log/auth.log` or
`/var/log/secure` and to `dmesg`; to read the whole journal without `sudo`,
join the `adm` and `systemd-journal` groups
(`sudo usermod -aG adm,systemd-journal $USER`, then log in again).

## Quickstart

```bash
cargo build --release
./target/release/linuxdoctor              # no subcommand: TUI in a real
                                           # terminal, plain audit otherwise
./target/release/linuxdoctor audit
./target/release/linuxdoctor audit --output json   # starts with "schema_version": 1, then "linuxdoctor_version"
./target/release/linuxdoctor audit --output markdown > report.md   # a document to read/share
./target/release/linuxdoctor audit --output html > report.html     # one self-contained page
./target/release/linuxdoctor audit --min-severity warning          # show Warning and above only
./target/release/linuxdoctor audit --fail-on warning               # exit 1 on any Warning or worse
./target/release/linuxdoctor audit --profile hpc                   # a compute node: busy CPUs are normal
./target/release/linuxdoctor audit --modules memory
./target/release/linuxdoctor audit --modules security   # exposure, firewall, SSH, hardening
./target/release/linuxdoctor audit --modules logs       # logins, errors, kernel messages, journal
./target/release/linuxdoctor tui              # interactive terminal UI, explicitly
./target/release/linuxdoctor diff before.json after.json   # what changed between two reports
./target/release/linuxdoctor audit --timeout 30   # allow slow tools 30 s each
./target/release/linuxdoctor --no-config audit    # for once, ignore ~/.config/linuxdoctor/config.toml
./target/release/linuxdoctor man > linuxdoctor.1  # the manual page (see below)
./target/release/linuxdoctor completions bash     # shell completion script
```

### Reports, filtering and exit codes

`--output` picks the format: `terminal` (default), `json`, `markdown` (alias `md`) or
`html`. The Markdown and HTML reports are complete documents meant to be saved and
shared — a ticket, a wiki page, an email attachment, a file you keep next to the
machine's backups. The HTML one is a single self-contained page (no JavaScript, no
external file, no network access; light and dark themes; readable on a phone), and
both formats include every finding, Info ones too.

Every report says **which version of LinuxDoctor wrote it, at the very top** — the first
line of the terminal report, the first line under the title in Markdown, the first fact
of the HTML header — and so do the interactive UI (header and loading screen) and the
comparison made by `diff`. The JSON report records it as `linuxdoctor_version`, right
after `schema_version`: checks are added and thresholds move between versions, so a
saved report is only fully understood with the version that wrote it. `diff` shows the
version of each report it compares (reports from versions that did not record it are shown
as "version not recorded"), and warns when the two were not written by the same version.

```bash
linuxdoctor audit --output html > "report-$(hostname)-$(date +%F).html"
linuxdoctor audit --output markdown --min-severity warning > problems.md
```

Two options, kept separate on purpose:

- **`--min-severity info|warning|error|critical`** only changes **what is shown**. It
  never hides a module that failed, was skipped or returned incomplete data, and every
  format says how many findings it hid (a closing line in the terminal, a banner in
  Markdown/HTML, a top-level `filter` object in JSON). A filtered report cannot pass
  for a complete one.
- **`--fail-on info|warning|error|critical|never`** decides **the exit status**.

| Exit status | Meaning |
|---|---|
| 0 | The audit ran and nothing reached the `--fail-on` level |
| 1 | A finding reached the level (default `error`: Error and Critical), **or** the audit itself could not run |
| 2 | Command-line usage error (a mistyped option value, or a `--modules` id that does not exist), or a configuration file that cannot be used |

Without `--fail-on` the behaviour is exactly what it has always been (exit 1 on Error
or Critical). With it, a short explanation goes to **stderr**, so `--output json >
report.json` stays clean. Things worth knowing, for scripts and CI:

- `--fail-on` always judges the **whole** report, before `--min-severity` filters the
  display: hiding findings can never make a failing audit pass.
- A module that could not run is reported as such but is **not** a finding, so it does
  not change the exit status; check the report's `error` fields if that matters to you.
- `linuxdoctor tui` keeps the default threshold and has neither option (it reads
  `timeout` and `profile` from the configuration file, see below).
- A reader that goes away early (`linuxdoctor audit | head -1`) is not an error and does
  not change the verdict: the exit status is still the audit's own.
- Names chosen by the audited machine (a process, a virtual machine, a mount point, a
  user...) can contain terminal escape sequences. The terminal, Markdown, HTML and TUI
  reports replace control characters and right-to-left overrides with `?`, so a hostile
  name cannot clear your screen or rewrite what is printed above it, even when you read a
  saved report with `cat`. The JSON report keeps the name exactly as observed (JSON
  escapes it, so it is safe to read as text).

```bash
# Nightly job: keep a dated report, fail the job on any Warning or worse
linuxdoctor audit --output html --fail-on warning > "/var/reports/$(date +%F).html" \
  || echo "LinuxDoctor found something, see the report" >&2
```

### Profiles

The checks judge a machine in general, and some readings mean something else on a
particular kind of machine. A load average at the number of CPUs is contention on a
desktop; on a compute node it is the node doing its job. A **profile** tells LinuxDoctor
what kind of machine this is:

```bash
linuxdoctor audit --profile hpc
```

or `profile = "hpc"` at the top of the [configuration file](#the-configuration-file).
What a profile does is deliberately narrow:

- **You choose it; it is never guessed from the machine.** With no profile, every finding
  keeps the severity its check gave it.
- **It only lowers.** A profile caps the severity of readings that are normal for that
  kind of machine. It never raises one, so it cannot make an audit that passes today
  fail, and it never removes a finding or touches the evidence.
- **It says what it did.** An adjusted finding carries the reason in its explanation and
  `severity_before_profile` / `profile` in its evidence, so nobody has to wonder why it
  is Info. The report names the profile it was written with (the first line of the
  terminal report, the Markdown and HTML headers, the interactive UI, and a top-level
  `profile` key in JSON, which is absent when none was chosen).
- **It applies before the exit status.** `--fail-on` and the default exit status judge the
  severities the report shows, so under `hpc` a busy node no longer makes the audit fail.
  Everything else still does: a full disk or an exposed service is reported and fails
  exactly as without a profile.

| Profile | For | What it changes |
|---|---|---|
| `hpc` | A compute node, where fully used CPUs are the normal state | `CPU002` (load average pressure) and `CPU003` (sustained overload) are reported as Info at most; the load figures stay in the evidence. Adds the `hpc` module: `HPC001` checks that the CPU frequency governor does not hold the CPUs back, `HPC002` that the locked-memory limit does not starve RDMA |

One thing to keep in mind: under `hpc`, a node that is oversubscribed *by mistake* looks
the same as one that is working. The profile removes the alarm, not the number.

A profile can also **add a module** of its own: a check that is right on one kind of
machine and noise on another (a desktop is not wrong for leaving its CPUs on `powersave`),
which lowering a severity cannot express. Such a module is part of the audit only when
the profile is chosen, appears in the report like any other module, and `--modules` names
it only together with the profile: `--modules hpc` on its own is refused with a message
that says to add `--profile hpc`. Choosing other modules stays exact: `--modules memory
--profile hpc` runs memory and nothing else.

**What `HPC001` says.** It reads the governor of every CPU and judges it for a compute node,
telling apart the drivers that choose the frequency themselves (`intel_pstate`,
`amd-pstate-epp`, where `powersave` is only a bias, read together with the
energy/performance preference) from the generic ones (`acpi-cpufreq`, `intel_cpufreq`,
where `powersave` holds the lowest frequency). `performance` is fine; `powersave` on a
generic driver, a governor that follows the load (`ondemand`, `conservative`,
`schedutil`), an efficiency-leaning preference, or CPUs that do not all use the same
governor are a Warning, with the commands to set `performance` now and at every boot. A
machine that exposes no frequency scaling (a virtual machine, say) gets an Info that
says there was nothing to check.

**What `HPC002` says.** RDMA (InfiniBand, RoCE) transfers memory without the CPU, so the
kernel keeps that memory locked in RAM, and counts it against the process's
`RLIMIT_MEMLOCK`, a few MiB by default. An MPI job that registers more fails to register
memory and either stops or falls back to a slower transport. The finding lists the RDMA
devices (`/sys/class/infiniband`) and reads the soft and hard limits of its own process
(`/proc/self/limits`). With no RDMA device it is an Info that says the limit does not
matter here (a card whose driver is not loaded is not listed). With devices, an unlimited
soft limit, or one at least the size of the RAM, is an Info; anything lower is a Warning
(75%), which says whether users can raise the limit themselves (hard limit) and comes
with the commands for logins (`limits.d`) and for systemd services
(`DefaultLimitMEMLOCK`). The confidence stops at 75% because the limit read is the one of
the session that ran the audit: jobs started by a scheduler or a systemd service have
limits of their own, and the finding says so.

`linuxdoctor diff` has no `--profile`; it reads the profile each report recorded, and warns
when the two differ.

### Comparing two reports

Keep the JSON report of an audit, change something (or wait), audit again, and ask what
moved:

```bash
linuxdoctor audit --output json > before.json
# ... update the kernel, edit sshd_config, add a disk, wait a week ...
linuxdoctor audit --output json > after.json
linuxdoctor diff before.json after.json
```

The result is a summary line, then **Got worse** (findings that appeared or became more
serious, worst first, with the evidence values that moved), **Got better** (resolved or
less serious), and **Other changes** (informational findings that appeared or disappeared:
a new network interface is not a regression). Machine changes (kernel, distribution,
memory, a reboot) are listed first. `--output markdown` writes the same thing as a
document for a ticket or a change review; `--output json` is for scripts. `-` reads one of
the two reports from standard input:

```bash
linuxdoctor audit --output json | linuxdoctor diff last-week.json -
```

Two things the comparison refuses to do, because they would make a bad result look good:

- **A finding that is gone is only "resolved" if its module really ran again.** If the
  module failed, was skipped, or was left out with `--modules`, the module is listed under
  **Not compared** (with how many findings could not be re-checked) instead of being
  counted as an improvement. A module whose tools were cut short is flagged `?` and listed
  under **Incomplete data**.
- **It says when the comparison may not mean much**: the reports come from different
  machines, they look reversed (the second was taken at an earlier boot), one was
  written with `--min-severity`, they were written by different versions of LinuxDoctor
  (checks are added between versions, so a finding can appear or disappear because the
  program changed, not the machine), or with different [profiles](#profiles) (a finding
  that got better under `hpc` got better on paper only).

`--min-severity` and `--fail-on` work as for `audit`: the first only hides changes (and
says how many), the second decides the exit status, judged on the whole comparison.

| Exit status | Meaning |
|---|---|
| 0 | No finding appeared or got worse to the `--fail-on` level (default `error`) |
| 1 | A finding appeared, or got worse, and is now at that level or above |
| 2 | The reports could not be compared: unreadable file, not a LinuxDoctor report, or written by a newer version; also a usage error |

A finding that is in both reports at the same severity is not a regression, however
serious (use `audit --fail-on` for that), and modules that were not compared do not change
the status. The text in the files is treated as untrusted: control characters are removed
before anything reaches your terminal.

```bash
# After a change: fail the pipeline if anything Warning or worse appeared
linuxdoctor diff before.json after.json --fail-on warning --output markdown > review.md
```

### The configuration file

If you always type the same options, write them down once in
`~/.config/linuxdoctor/config.toml` (under `$XDG_CONFIG_HOME` when that is set to an
absolute path). The file is optional, and every line of it is optional:

```toml
# ~/.config/linuxdoctor/config.toml
# Every line is optional. An option typed on the command line always wins
# over this file.

# Longest an external tool may run, in seconds (--timeout).
timeout = 20

# Exit with status 1 from this severity up, for audit and diff (--fail-on):
# info, warning, error, critical or never.
fail_on = "warning"

# Only show findings from this severity up (--min-severity).
min_severity = "warning"

# The kind of machine, for audit and tui (--profile): hpc. A profile only
# lowers findings that are normal for that kind of machine; without one,
# every finding keeps the severity its check gave it.
profile = "hpc"

[audit]
# terminal, json, markdown or html (--output).
output = "markdown"

[diff]
# terminal, json or markdown (--output).
output = "markdown"
# A section can change the lines above for its own command.
fail_on = "error"
```

```bash
mkdir -p ~/.config/linuxdoctor && editor ~/.config/linuxdoctor/config.toml
```

- **What you type always wins.** The file only fills in what you did not type, option by
  option: with the file above, `linuxdoctor audit --output json` prints JSON and still
  uses the file's `fail_on` and `min_severity`. Typing the default value counts as
  typing something: `--output terminal` beats `output = "markdown"`.
- **The words are the ones of the command line**, read by the same parser, so `"md"`
  works wherever `--output md` does. The top-level `timeout`, `fail_on` and
  `min_severity` apply to `audit` and `diff` (`timeout` to every command), and the
  top-level `profile` to `audit` and `tui`; the
  `[audit]` and `[diff]` sections hold `output` — it cannot be set at the top, because
  the two commands do not accept the same formats (`diff` has no `html`) — and may
  repeat the other two for their own command.
- **A mistake is an error, never a guess.** An unknown key, a value the option would not
  accept or a file that cannot be read stops the program with exit status **2**, before
  anything is run, and says which file and which line. `--no-config` ignores the file
  for one run (the way out of a broken file); `--config FILE` reads another one, which
  must exist (one file per CI job, for instance).
- **A level from the file explains itself**, like `--fail-on` does, when it makes the
  exit status 1: `fail_on = "warning" in /home/you/.config/linuxdoctor/config.toml`.
- `--modules` cannot be set in the file on purpose: a file that quietly narrowed every
  audit would produce clean-looking reports of checks that were never made.
- `man` and `completions` never read the file, so a broken file cannot stop you from
  printing them; `tui` reads only `timeout` and `profile`.
- The file is untrusted text like any other: it must be a regular file of at most
  64 KiB, and whatever is quoted from it in an error message has its control characters
  replaced.

### Manual page and shell completions

The `.deb` and `.rpm` packages install the manual page and the completions for
you. From a source build (`cargo build`, `cargo install`) the program prints both
itself, so they always match the options of the version you run:

```bash
linuxdoctor man > linuxdoctor.1 && man ./linuxdoctor.1          # read it without installing

linuxdoctor completions bash > ~/.local/share/bash-completion/completions/linuxdoctor
linuxdoctor completions fish > ~/.config/fish/completions/linuxdoctor.fish
mkdir -p ~/.zfunc && linuxdoctor completions zsh > ~/.zfunc/_linuxdoctor
#   zsh: put  fpath+=~/.zfunc  before  compinit  in ~/.zshrc
```

Completion offers the commands, the options, the values of `--output`,
`--min-severity` and `--fail-on`, and the module ids for `--modules` (`elvish` and
`powershell` scripts are available too). `--modules` itself rejects an id that does
not exist — `--modules memroy` is a usage error that suggests `memory`, not an empty
report that exits 0.

### Speed and slow tools

Modules run **concurrently** (one thread each, standard library only), and the
per-disk `smartctl` queries inside Storage run several at a time, so a slow tool
delays only its own module instead of the whole audit. Every external command also
has a time limit — 10 seconds by default, `--timeout <seconds>` to change it
(`smartctl`, `nvidia-smi` and `docker stats` get twice that, since waking a sleeping
disk or initializing a driver can legitimately take a few seconds). A command that
exceeds it is stopped, and the module is reported as having **incomplete data**
(a ⚠ instead of a ✓, with the stopped command named) rather than silently showing
less. A wedged `libvirtd` or NVIDIA driver costs one time limit, not one per call.

Running `linuxdoctor` with no subcommand opens the interactive TUI when both
stdin and stdout are a real terminal (`std::io::IsTerminal`, standard
library, no extra dependency) — the expected experience once installed and
run directly. It falls back to `audit`'s plain-text behavior when they
aren't (piped, redirected, or run from a script/cron/CI), so existing
non-interactive uses like `linuxdoctor > report.txt` or
`linuxdoctor | grep ...` keep working exactly as before. `linuxdoctor audit`
and `linuxdoctor tui` remain available to force either mode explicitly
regardless of the terminal.

In the TUI: PgUp/PgDn to select a module (or, once drilled in, an item
within its submenu), ↑/↓ (or j/k) to scroll a long finding, Enter to open
a module's submenu when one is available (2+ items — a small "›" marks
which modules have one), Esc to back out of a submenu, r to re-scan
everything (same progress screen as startup, current module selection
preserved), q or Esc to quit. **f** cycles a minimum severity (everything →
warning and above → error and above → critical only, the same four levels as
`--min-severity`) and **/** searches: type a word (case does not matter; it is
looked for in a finding's id, title, explanation, recommendation, instance and
evidence), Enter keeps it, Esc forgets it. While a filter is on, each module in
the list shows how many of its findings get through and the ones left with none
are greyed out; the screen jumps to the first module that has a match; the bottom
bar says `Filter: … · N of M findings`, so a filtered screen cannot pass for a
complete one. Esc undoes one level at a time — the submenu, then the filter, then
it quits. The filter only changes what is drawn: a module's ✓/⚠/✗ still describes
the whole module, and the exit code is still computed from every finding. The header shows a continuously-updating
CPU/memory/disk-usage line (roughly once a second, no action needed) and
how old the displayed findings are — separate freshness stories, since
the gauges are cheap `/proc` reads but re-scanning the full module
pipeline (SMART, virsh, docker...) is not something to do automatically
every second. The TUI needs a real terminal (it won't run over a piped
stdout or in an environment with no TTY) — `linuxdoctor audit` always
works regardless.

## Tests

```bash
cargo test               # 1166 lib unit tests + 92 CLI unit tests + 188 integration tests
cargo run --example demo_severity      # visually check WARNING/ERROR/CRITICAL
                                        # rendering using synthetic low-memory data
cargo run --example demo_tui_snapshot  # headless "screenshot" of the TUI (no real
                                        # terminal needed — uses ratatui's TestBackend)
```

## Toolchain note

This was built and tested against `rustc`/`cargo` 1.75 (Ubuntu 24.04's apt package).
Five dependencies are pinned for that MSRV:

* `clap` at `4.4.18` — newer `clap_builder` releases declare `edition2024` in their
  own manifest, which requires Cargo ≥ 1.85 just to parse.
* `clap_complete` at `4.4.10` and `clap_mangen` at `0.2.20` (which brings `roff`
  0.2.2) — the last releases that accept `clap` 4.4; the 4.5/0.3 series need it
  newer and a Rust of 1.85.
* `unicode-segmentation` (a transitive dependency of `ratatui`) pinned to `1.11.0`
  in `Cargo.lock` for the same reason.
* `toml` at `0.9.6`, with only the `std`, `serde` and `parse` features (it reads the
  configuration file, it never writes TOML): later 0.9 releases need Rust 1.76. Its
  own dependencies are held in `Cargo.lock` at the last releases that build on 1.75
  (`toml_parser` 1.0.2, `serde_spanned` 1.0.1, `toml_datetime` 0.7.1, `winnow` 0.7.15).
  To choose versions for 1.75 yourself, `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
  cargo add ...` does it from a newer Cargo.

`Cargo.toml` declares `rust-version = "1.75"`, and the GitHub Actions workflow
(`.github/workflows/ci.yml`) builds and tests on exactly 1.75.0 as well as on
stable, then checks formatting and Clippy (`-D warnings`) on stable. Always build
with `--locked` so those pins are respected.

If you're on a newer toolchain (1.85+), both are safe to unpin — `cargo update`
will pick up current versions without any code changes.

## Layout

```
linuxdoctor/
├── .gitignore
├── .github/workflows/ci.yml   # CI: fmt, clippy, tests on Rust 1.75 + stable
├── LICENSE                    # GPL-3.0 full text
├── VERSION                  # single source of truth for the version number
├── CHANGELOG.md              # Keep a Changelog format (in French)
├── CONTRIBUTING.md            # how to report bugs, add a module, code style
├── build-deb.sh                 # .deb packaging (fpm)
├── build-rpm.sh                  # .rpm packaging (fpm)
├── Cargo.toml
├── Cargo.lock
├── README.md
├── PROJECT_CONTEXT.md
├── ARCHITECTURE.md
│
└── src/
    ├── main.rs                # bin entry point
    ├── cli.rs                 # argument parsing (audit / tui / diff / completions / man, --output,
    │                          #   --min-severity, --fail-on, --modules checked against the registry)
    ├── config.rs              # the optional configuration file (~/.config/linuxdoctor/config.toml)
    ├── manpage.rs             # the manual page printed by `linuxdoctor man`
    ├── profile.rs             # machine profiles (--profile): severity caps for a kind of machine
    ├── lib.rs                 # library root (also used by examples/ and tests/)
    │
    ├── core/
    │   ├── command.rs           # Command builder forcing LC_ALL=C and a time
    │   │                        # limit — every collector that shells out uses this
    │   ├── context.rs         # Context — reads /proc, /sys, /etc/os-release once
    │   ├── engine.rs           # runs modules concurrently, isolates failures
    │   ├── gate.rs               # pass/fail decision behind the exit status (--fail-on)
    │   ├── parallel.rs          # ordered parallel map (per-disk SMART queries)
    │   ├── text.rs               # clean(), printable(): control characters out of untrusted text
    │   └── error.rs
    │
    ├── diff/
    │   ├── report.rs            # reads a JSON report file (lenient, size-capped)
    │   ├── compare.rs            # pure: two reports -> what changed (and what could not be compared)
    │   └── render.rs              # terminal, Markdown and JSON output of a comparison
    │
    ├── models/
    │   ├── severity.rs        # Severity (4 levels — see ARCHITECTURE.md)
    │   ├── confidence.rs       # Confidence (%, reason)
    │   ├── category.rs          # Category
    │   └── finding.rs            # Finding + FindingBuilder
    │
    ├── modules/
    │   ├── mod.rs              # the Module trait + all_modules()
    │   ├── recommend.rs        # numbered-steps builder (Steps), sysctl snippets and the
    │   │                       #   distribution family, shared by modules that write advice
    │   ├── memory/              # collect.rs (I/O) + analyze.rs + one file per topic (used, cache,
    │   │                        #   shared, swap, pressure, tuning, kernel) + format.rs
    │   ├── cpu/                  # per-socket topology, load, isolated/offline CPUs
    │   ├── numa/                  # per-node topology, cross-node imbalance
    │   ├── gpu/                     # AMD and Intel sysfs, NVIDIA via nvidia-smi
    │   ├── hpc/                       # added by --profile hpc, not in all_modules(): CPU governor, locked memory
    │   ├── storage/                # filesystems (df) + per-device SMART (smartctl)
    │   ├── systemd/                  # system state, failed units
    │   ├── ntp/                        # clock sync, RTC mode
    │   ├── network/                    # interfaces, gateway, DNS (zero subprocess calls)
    │   ├── security/                   # collect.rs (I/O) + one pure file per topic (listeners,
    │   │                               #   firewall, ssh, access, accounts) + analyze.rs
    │   ├── logs/                       # collect.rs (I/O) + journal.rs (parsers) + one pure file
    │   │                               #   per topic (auth, errors, kernel, health) + analyze.rs
    │   ├── kernel/                       # taint status, OOM history (dmesg)
    │   └── virtualization/                 # systemd-detect-virt, no PID1 gate
    │
    └── output/
        ├── common.rs            # what the document renderers share (dates, layout of
        │                        #   explanations/recommendations, filter notice)
        ├── terminal.rs          # text + ANSI colors
        ├── json.rs                # JSON
        ├── markdown.rs             # Markdown report
        ├── html.rs                   # self-contained HTML report
        ├── tui.rs                  # interactive UI (ratatui)
        ├── tui_filter.rs             # what the TUI shows: minimum severity + search text
        └── live_stats.rs             # TUI header gauges (CPU/mem/disk %)

tests/       # fixture-driven integration tests, one file per module,
             # plus hung_tools.rs (real binary vs. fake tools that hang),
             # json_schema.rs and export_and_gate.rs (real binary: report
             # formats, --min-severity, --fail-on and the exit status);
             # security_module.rs and logs_module.rs also run the real binary
             # (logs_module.rs against a fake journalctl); docs_commands.rs runs
             # it for `man`, `completions` and the --modules check; diff_command.rs
             # runs it for `diff` (exit status, formats, unreadable and hostile files);
             # version_shown.rs checks the version at the top of every output;
             # config_file.rs runs it with real configuration files (the command line
             # wins, exit status 2 for a bad file) and checks that every test that
             # starts the binary keeps it away from the reader's own file;
             # hostile_names.rs runs it against escape sequences in names, every format;
             # profile_option.rs runs the real CPU module and the real binary with profiles;
             # hpc_module.rs runs the binary for the module the hpc profile adds
examples/    # demo_severity.rs, demo_tui_snapshot.rs — not part of the shipping tool
```

## License

GPL-3.0-only. See [LICENSE](LICENSE).

LinuxDoctor is developed by Gilles MAGNEVILLE. Gilles is not a professional
developer — this project has been built with the assistance of Claude.ai.
