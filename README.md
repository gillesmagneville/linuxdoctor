# LinuxDoctor

Fast, explainable Linux health diagnostics. See `PROJECT_CONTEXT.md` for vision and
principles, `ARCHITECTURE.md` for the technical contract (types, module trait,
severity/confidence scales, layout).

## Status

v1 scaffold, two modules shipping end-to-end:

* **Memory** — `vm.swappiness`, swap pressure, critical low-memory detection.
* **CPU** — core count / model, load-average pressure, sustained overload
  (1/5/15-minute load windows all exceeding available CPUs).

The core, `Module` trait, engine, and three output modes (terminal, JSON,
interactive TUI) are built and tested. Adding the next module (Storage is a
reasonable candidate next) means only writing `collect.rs` + `analyze.rs` under
`src/modules/<name>/`, then adding one line to `all_modules()` in
`src/modules/mod.rs`. Nothing else changes — all three output modes pick it up
automatically.

## Getting set up

```bash
mkdir -p ~/Projects
unzip linuxdoctor.zip -d ~/Projects/linuxdoctor
cd ~/Projects/linuxdoctor
cargo build
cargo test
```

If you're versioning this with git, the `.gitignore` already excludes `target/`:

```bash
git init
git add .
git commit -m "Initial scaffold: core engine, memory + cpu modules, terminal/json/tui output"
```

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
cargo test               # 31 unit tests + 4 integration tests
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
src/
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
│   └── cpu/                  # same shape as memory/
│
└── output/
    ├── terminal.rs          # text + ANSI colors
    ├── json.rs                # JSON
    └── tui.rs                  # interactive UI (ratatui)

tests/       # fixture-driven integration tests, one file per module
examples/    # demo_severity.rs, demo_tui_snapshot.rs — not part of the shipping tool
```
