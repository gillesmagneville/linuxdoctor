# LinuxDoctor

Fast, explainable Linux health diagnostics. See `PROJECT_CONTEXT.md` for vision and
principles, `ARCHITECTURE.md` for the technical contract (types, module trait,
severity/confidence scales, layout).

## Status

v1 scaffold. One module ships end-to-end: **Memory** (`vm.swappiness`, swap
pressure, critical low-memory detection). The core, `Module` trait, engine, and
three output modes (terminal, JSON, interactive TUI) are built and tested —
adding the next module (CPU is the natural next candidate) means only writing
`collect.rs` + `analyze.rs` under `src/modules/cpu/`, then registering it in
`src/modules/mod.rs::all_modules()`. Nothing else needs to change — all three
output modes automatically pick it up.

## Quickstart

```bash
cargo build --release
./target/release/linuxdoctor audit
./target/release/linuxdoctor audit --output json
./target/release/linuxdoctor audit --modules memory
./target/release/linuxdoctor tui              # interactive terminal UI
```

In the TUI: ↑/↓ (or j/k) to select a module, PgUp/PgDn to scroll a long finding,
q or Esc to quit.

## Tests

```bash
cargo test               # 19 unit tests + 2 integration tests
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
├── main.rs / cli.rs      # bin entry point + argument parsing
├── lib.rs                # library root (also used by examples/ and tests/)
├── core/                 # Context, Module-running engine, error types
├── models/                # Severity, Confidence, Category, Finding
├── modules/
│   └── memory/            # collect.rs (I/O) + analyze.rs (pure logic) + tests
└── output/                 # terminal.rs, json.rs, tui.rs — formatting only

tests/                      # fixture-driven integration tests
examples/                   # demo_severity.rs, demo_tui_snapshot.rs — not part
                             # of the shipping tool
```
