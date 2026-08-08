<!-- SPDX-License-Identifier: GPL-3.0-only -->

# LinuxDoctor

Fast, explainable Linux health diagnostics. See `PROJECT_CONTEXT.md` for vision and
principles, `ARCHITECTURE.md` for the technical contract (types, module trait,
severity/confidence scales, layout).

## Status

v1 scaffold, six modules shipping end-to-end:

* **Memory** — usage overview (used vs reclaimable cache vs available,
  answering "why does `free` show so little free RAM"), `vm.swappiness`,
  swap pressure (cross-referenced against swappiness), critical
  low-memory detection, dirty-page/writeback pressure (compared against
  this system's actual configured `vm.dirty_ratio` /
  `vm.dirty_background_ratio`, not assumed defaults), and shared memory
  (tmpfs/shm) usage — each concerning finding paired with a concrete
  resolution.
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
* **Systemd** — overall system state, one finding per failed unit. Skips
  cleanly on systems where systemd isn't PID 1 (checks
  `/run/systemd/system`, not just whether `systemctl` is installed).
* **Network** — per-interface overview and error/drop rates (with a
  minimum-sample-size guard so a handful of startup drops on a fresh
  interface can't produce a misleading percentage), default gateway,
  DNS configuration. Zero subprocess calls — `/proc/net/dev`,
  `/proc/net/route`, `/sys/class/net/*`, `/etc/resolv.conf` only.

The core, `Module` trait, engine, and three output modes (terminal, JSON,
interactive TUI) are built and tested. Adding the next module means only
writing `collect.rs` + `analyze.rs` under `src/modules/<name>/`, then adding
one line to `all_modules()` in `src/modules/mod.rs`. Nothing else changes —
all three output modes pick it up automatically.

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
git commit -m "Initial scaffold: core engine, 6 modules (memory/cpu/numa/storage/systemd/network), terminal/json/tui output"
```

## Packaging

Two scripts build native packages via [fpm](https://fpm.readthedocs.io/) —
`build-deb.sh` (Debian/Ubuntu) and `build-rpm.sh` (Fedora/RHEL/Rocky/AlmaLinux/
openSUSE). Both follow the same flow: pick a version bump (interactively or
via a flag), compile in release mode, stage the binary + docs, then package.
`VERSION` and `Cargo.toml` are only updated after a fully successful build —
a failed compile or a failed `fpm` step leaves the repo untouched.

```bash
./build-deb.sh --patch   # or --minor / --major / --no-version-change
./build-rpm.sh --patch
./build-deb.sh --clean   # remove build artifacts and generated .deb files
```

Before first use, edit `MAINTAINER` and `URL` at the top of each script —
they're placeholders. Both scripts check for their required tools (`fpm`,
`cargo`, and `dpkg-deb` or `rpmbuild` respectively) and tell you what's
missing and how to install it if something's not found.

**On dependencies (`requirements.txt`):** this doesn't apply here the way it
does for a Python project like planche-contact — Rust has no separate
runtime dependency list to install. `Cargo.lock` already pins every
dependency's exact version and is committed to the repo; that's the
equivalent artifact. Nothing else to add.

## Runtime dependencies

Everything ships in the single binary except `df` (Storage — always
present on Linux) and `systemctl` (Systemd — only queried when systemd is
actually PID 1). One truly optional external tool: `smartctl` (from
`smartmontools`) for per-device disk health. Without it, the Storage
module still works normally — `STOR003` just reports that SMART couldn't
be checked, rather than silently having no disk-health data with no
explanation. SMART queries also typically need root (raw device access);
run as root/sudo for full per-device detail. Network needs nothing extra
at all — `/proc/net/*`, `/sys/class/net/*`, and `/etc/resolv.conf` cover
it with zero subprocess calls.

## Quickstart

```bash
cargo build --release
./target/release/linuxdoctor audit
./target/release/linuxdoctor audit --output json
./target/release/linuxdoctor audit --modules memory
./target/release/linuxdoctor tui              # interactive terminal UI
```

In the TUI: PgUp/PgDn to select a module (or, once drilled in, an item
within its submenu), ↑/↓ (or j/k) to scroll a long finding, Enter to open
a module's submenu when one is available (2+ items — a small "›" marks
which modules have one), Esc to back out of a submenu, q or Esc to quit.
The TUI needs a real terminal (it won't run over a piped stdout or in an
environment with no TTY) — `linuxdoctor audit` always works regardless.

## Tests

```bash
cargo test               # 147 unit tests + 19 integration tests
cargo run --example demo_severity      # visually check WARNING/ERROR/CRITICAL
                                        # rendering using synthetic low-memory data
cargo run --example demo_tui_snapshot  # headless "screenshot" of the TUI (no real
                                        # terminal needed — uses ratatui's TestBackend)
```

## Toolchain note

This was built and tested against `rustc`/`cargo` 1.75 (Ubuntu 24.04's apt package).
Two dependencies are pinned for that MSRV:

* `clap` at `4.4.18` — newer `clap_builder` releases declare `edition2024` in their
  own manifest, which requires Cargo ≥ 1.85 just to parse.
* `unicode-segmentation` (a transitive dependency of `ratatui`) pinned to `1.11.0`
  in `Cargo.lock` for the same reason.

If you're on a newer toolchain (1.85+), both are safe to unpin — `cargo update`
will pick up current versions without any code changes.

## Layout

```
linuxdoctor/
├── .gitignore
├── VERSION                  # single source of truth for the version number
├── CHANGELOG.md              # Keep a Changelog format
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
    ├── cli.rs                 # argument parsing (audit / tui)
    ├── lib.rs                 # library root (also used by examples/ and tests/)
    │
    ├── core/
    │   ├── context.rs         # Context — reads /proc, /sys, /etc/os-release once
    │   ├── engine.rs           # runs modules, isolates per-module failures
    │   └── error.rs
    │
    ├── models/
    │   ├── severity.rs        # Severity (4 levels — see ARCHITECTURE.md)
    │   ├── confidence.rs       # Confidence (%, reason)
    │   ├── category.rs          # Category
    │   └── finding.rs            # Finding + FindingBuilder
    │
    ├── modules/
    │   ├── mod.rs              # the Module trait + all_modules()
    │   ├── memory/              # collect.rs (I/O) + analyze.rs (pure logic) + tests
    │   ├── cpu/                  # per-socket topology, load, isolated/offline CPUs
    │   ├── numa/                  # per-node topology, cross-node imbalance
    │   ├── storage/                # filesystems (df) + per-device SMART (smartctl)
    │   ├── systemd/                  # system state, failed units
    │   └── network/                    # interfaces, gateway, DNS (zero subprocess calls)
    │
    └── output/
        ├── terminal.rs          # text + ANSI colors
        ├── json.rs                # JSON
        └── tui.rs                  # interactive UI (ratatui)

tests/       # fixture-driven integration tests, one file per module
examples/    # demo_severity.rs, demo_tui_snapshot.rs — not part of the shipping tool
```
