<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to LinuxDoctor

Thank you for your interest in this project! This document explains how to
report a problem, suggest an improvement, or contribute code.

## Reporting a bug

Open an issue stating:

- the distribution and the kernel version (`uname -r`, `/etc/os-release`)
- the exact command used (`linuxdoctor audit`, `linuxdoctor tui`, ...)
- the observed behavior vs the expected one
- if possible, the output of `linuxdoctor audit --output json`

## Suggesting an improvement

Open an issue describing the need before writing any code, especially for a
new diagnostic module — it is easier to discuss thresholds and severity
before than after.

## Contributing code

1. Fork the repository and create a branch from `main`.
2. Check that everything passes before opening a pull request:

   ```bash
   cargo build --locked
   cargo test --locked
   cargo fmt --check
   cargo clippy --locked --all-targets -- -D warnings
   ```

   These four commands are exactly those of the continuous integration
   (`.github/workflows/ci.yml`), which also runs them with Rust 1.75, the
   minimum supported version. So do not use an API newer than 1.75 (for
   example `Option::is_none_or`, stabilized in 1.82).

3. A test that launches the real binary must isolate it from the
   configuration file of whoever runs the tests, otherwise a
   `fail_on = "never"` in their `~/.config/linuxdoctor/config.toml` would
   change the suite's mind: `.env("XDG_CONFIG_HOME", "/nonexistent")` (or
   `--no-config`) on every `Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))`.
   A test (`tests/config_file.rs`) fails if a file in `tests/` forgets it.

4. Describe in the pull request what changes and why.

## Adding a new diagnostic module

This is the most common kind of contribution, and the architecture is
designed so that it only involves touching a single folder. For a module
`<name>`:

1. Create `src/modules/<name>/{mod.rs, collect.rs, analyze.rs}`, following
   exactly the pattern of `src/modules/memory/` or `src/modules/cpu/`:
   - `collect.rs` — reading only (I/O). No interpretation.
   - `analyze.rs` — pure functions `RawData -> Vec<Finding>`, testable
     without touching the filesystem.
2. Add a line in `all_modules()` (`src/modules/mod.rs`).
3. Add a module description line in `module_summary()`
   (`src/manpage.rs`): it is what appears in the MODULES section of
   `man linuxdoctor`, and a test fails as long as it is missing.
4. Nothing else should change — neither the engine, nor `Context`, nor the
   terminal/JSON/TUI outputs; `--modules`, the shell completion and the
   manual page know the new module automatically.

See `ARCHITECTURE.md` for the exact contract (types, severity, confidence).

Mind the JSON format: `linuxdoctor diff` reads back the reports that
`audit --output json` writes. Adding a field breaks nothing; renaming or
removing a field of a finding, a module or the context (`id`, `title`,
`severity`, `evidence`, `instance`, `module_id`, `error`, `skipped`, `notes`,
`hostname`…) changes `schema_version` and must come with an update of
`src/diff/report.rs` (an integration test reads back a real report to remind
you of it).

### Running external commands

Always go through `core::command::command()`, never through
`std::process::Command`: it forces the `C` locale **and** applies a time
limit (10 s by default, adjustable with `--timeout`).

- A tool that may be slow even when healthy (waking up a disk,
  initializing a driver): add `.slow()` (double the timeout).
- Several calls to the same tool (for example one command per VM): use a
  `ToolSession` — at the first timeout, the following calls are skipped
  instead of each waiting for its own limit.
- One command per independent item (a disk, a card):
  `core::parallel::parallel_map` runs them in parallel, results in order.
- A command stopped because of a timeout is automatically recorded in the
  module's `notes` ("incomplete data"); there is nothing more to do on the
  module side. Simply treat the error like any other "the tool gave no
  data".

### Rules for every `Finding`

- Every diagnosis must be backed by observable evidence (`evidence`), not a
  guess.
- Confidence must never exceed what the evidence really justifies (see the
  scale in `ARCHITECTURE.md`).
- The explanation text must teach something, not just repeat the raw
  data — see "Explain instead of dumping data" in `PROJECT_CONTEXT.md`.
- Avoid an alarmist tone. "This is not necessarily a problem" is often the
  right sentence.

## Code style

- `cargo fmt` before opening a pull request.
- Stable Rust only, no nightly features.
- A module must never call another module directly — only through the shared
  read-only `Context`.
- Any new dependency must be justified (see "Dependency Philosophy" in
  `ARCHITECTURE.md`) — the standard library is always preferred when
  reasonable.

## Documentation

If your change alters observable behavior (new module, new CLI option, new
output format), update `CHANGELOG.md` in the same pull request, under
`[Unreleased]`.

The documentation of this project is in English only: the audience is system
engineers and advanced support staff, who work in English. Please write
`README.md`, `ARCHITECTURE.md`, `PROJECT_CONTEXT.md`, `CHANGELOG.md` and this
file in English. The same goes for the code and its comments, and for the help text,
messages and comments of the packaging scripts (`build-deb.sh`, `build-rpm.sh`).

## Questions

For any question that does not fit the cases above, simply open an issue.

## License

By contributing, you agree that your contributions will be released under the
same license as the project (GPL-3.0-only).
