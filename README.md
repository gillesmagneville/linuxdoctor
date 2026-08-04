<!-- SPDX-License-Identifier: GPL-3.0-only -->

# LinuxDoctor

Fast, explainable Linux health diagnostics. See `PROJECT_CONTEXT.md` for vision and
principles, `ARCHITECTURE.md` for the technical contract (types, module trait,
severity/confidence scales, layout).

## Status

v1 scaffold, three modules shipping end-to-end:

* **Memory** — `vm.swappiness`, swap pressure, critical low-memory detection.
* **CPU** — core count / model, load-average pressure, sustained overload
  (1/5/15-minute load windows all exceeding available CPUs).
* **Storage** — disk space and inode usage per real filesystem (pseudo
  filesystems like tmpfs/proc/overlay are excluded), 4 severity tiers.

The core, `Module` trait, engine, and three output modes (terminal, JSON,
interactive TUI) are built and tested. Adding the next module means only
writing `collect.rs` + `analyze.rs` under `src/modules/<name>/`, then adding
one line to `all_modules()` in `src/modules/mod.rs`. Nothing else changes —
all three output modes pick it up automatically.

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
git commit -m "Initial scaffold: core engine, memory + cpu modules, terminal/json/tui output"
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

## Quickstart

```bash
cargo build --release
./target/release/linuxdoctor audit
./target/release/linuxdoctor audit --output json
./target/release/linuxdoctor audit --modules memory
./target/release/linuxdoctor tui              # interactive terminal UI
```

In the TUI: ↑/↓ (or j/k) to select a module, PgUp/PgDn to scroll a long finding,
q or Esc to quit. The TUI needs a real terminal (it won't run over a piped
stdout or in an environment with no TTY) — `linuxdoctor audit` always works
regardless.

## Tests

```bash
cargo test               # 44 unit tests + 6 integration tests
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
    │   ├── cpu/                  # same shape as memory/
    │   └── storage/                # same shape, one finding per real filesystem
    │
    └── output/
        ├── terminal.rs          # text + ANSI colors
        ├── json.rs                # JSON
        └── tui.rs                  # interactive UI (ratatui)

tests/       # fixture-driven integration tests, one file per module
examples/    # demo_severity.rs, demo_tui_snapshot.rs — not part of the shipping tool
```
