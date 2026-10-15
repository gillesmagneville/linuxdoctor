<!-- SPDX-License-Identifier: GPL-3.0-only -->

# LinuxDoctor Architecture

This document is the canonical technical contract for LinuxDoctor. Where
`PROJECT_CONTEXT.md` describes vision and principles, this document defines the
exact types, signatures, and rules that code must follow. If the two ever seem to
disagree, this document wins for anything concrete (enum values, struct shapes,
trait signatures).

## Overview

> **Collect → Analyze → Report**

The application is a lightweight core plus a set of independent diagnostic modules.

```
               +----------------+
               | CLI Interface  |
               +--------+-------+
                        |
                        v
               +----------------+
               | Core Engine    |
               +--------+-------+
                        |
                        v
              Diagnostic Modules
                        |
                        v
               +----------------+
               | Output Engine  |
               +----------------+
```

The Core Engine contains no Linux-specific logic. Its job is only to:

* build the shared `Context`
* discover and run modules
* isolate module failures
* collect `Finding`s
* hand results to the Output Engine

---

# Project Layout (v1)

The original design spread each concern (`modules/`, `rules/`, `collectors/`) into
separate top-level trees before a single real diagnostic existed. That's the right
shape at "thousands of rules" scale, but premature at zero. v1 collapses collection
and analysis into each module's own folder, and defers the split until real
duplication across modules justifies it.

```
linuxdoctor/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── cli.rs
│   │
│   ├── core/
│   │   ├── mod.rs
│   │   ├── command.rs         # Command builder forcing LC_ALL=C/LANG=C and a
│   │   │                      # hard time limit — every collector that shells out
│   │   │                      # uses this, not std::process::Command
│   │   ├── context.rs        # shared, read-only system facts
│   │   ├── engine.rs         # concurrent orchestration, failure isolation
│   │   ├── gate.rs           # pass/fail decision behind the exit status (--fail-on)
│   │   ├── parallel.rs       # ordered parallel map for per-device work (SMART)
│   │   └── error.rs
│   │
│   ├── models/
│   │   ├── mod.rs
│   │   ├── severity.rs       # canonical Severity enum
│   │   ├── confidence.rs     # canonical Confidence scale
│   │   ├── category.rs       # canonical Category enum
│   │   └── finding.rs        # canonical Finding struct
│   │
│   ├── modules/
│   │   ├── mod.rs            # the Module trait + all_modules()
│   │   ├── recommend.rs      # shared by modules: the numbered `Steps` builder, sysctl
│   │   │                     # command snippets and the distribution family (`Family`,
│   │   │                     # `family_of`) used to pick `apt` or `dnf` commands
│   │   ├── memory/           # richest module: see "Memory module layout" below
│   │   ├── cpu/
│   │   ├── numa/
│   │   ├── gpu/
│   │   ├── storage/
│   │   ├── systemd/
│   │   ├── ntp/
│   │   ├── network/
│   │   ├── security/         # see "Security module layout" below
│   │   ├── logs/             # see "Logs module layout" below
│   │   ├── kernel/
│   │   ├── firmware/
│   │   └── virtualization/
│   │       # each module folder has the same shape:
│   │       │   mod.rs        # implements Module, wires collect()+analyze()
│   │       │   collect.rs    # thin I/O: reads /proc, /sys, or shells out
│   │       │                 # (df, systemctl, smartctl, dmesg, timedatectl,
│   │       │                 #  systemd-detect-virt), parses to RawData
│   │       └── analyze.rs    # pure functions: RawData -> Vec<Finding>
│   │
│   └── output/
│       ├── mod.rs
│       ├── common.rs         # RenderMeta, date formatting, recommendation/explanation
│       │                     # layout shared by the document renderers
│       ├── terminal.rs       # text + ANSI colors
│       ├── json.rs           # JSON (+ schema_version)
│       ├── markdown.rs       # Markdown report — see "Markdown Renderer" below
│       ├── html.rs           # self-contained HTML report — see "HTML Renderer" below
│       ├── tui.rs            # interactive UI (ratatui) — see "Output Engine"
│       └── live_stats.rs     # TUI header gauges (CPU/mem/disk %) — see "Output Engine"
│
└── tests/
    # one fixture-driven integration test file per module, e.g.
    ├── memory_module.rs
    ├── cpu_module.rs
    ├── numa_module.rs
    ├── gpu_module.rs
    ├── storage_module.rs
    ├── systemd_module.rs
    ├── ntp_module.rs
    ├── network_module.rs
    ├── security_module.rs
    ├── logs_module.rs
    ├── kernel_module.rs
    ├── firmware_module.rs
    └── virtualization_module.rs
    # (one per module, same fixture-driven pattern)
```

As more modules are added, if `collect.rs` logic starts repeating across modules
(e.g. a shared "read and parse a `/proc` key: value file" helper), promote that into
`src/collectors/proc.rs` shared utility — but only once at least two modules need it.
Same rule for a future `rules/` split: promote when duplication is observed, not in
advance of it.

The **future** full-scale layout (separate `modules/`, `rules/`, `collectors/`,
`outputs/`, a module loader, plugin support) remains the long-term target described
at the end of this document, and nothing in v1 forecloses growing into it.

---

# Execution Flow

```
CLI
 ↓
Load configuration
 ↓
Build Context           (facts gathered once, read-only from here on)
 ↓
Select modules to run
 ↓
For each module:
   is_available(ctx)?  → skip if not applicable to this system
   run(ctx)            → internally: collect() then analyze()
   on error            → isolate, record, continue
 ↓
Aggregate Findings into a Report
 ↓
Exit-status gate (--fail-on) evaluated on the whole report
 ↓
Display filter (--min-severity)
 ↓
Output Formatter (terminal | json | markdown | html | tui)
 ↓
Exit code: 1 if a finding reached the --fail-on level (default: Error)
```

---

# Core Components

## CLI

Parses arguments, selects modules, selects output format, applies the display filter
(`--min-severity`) and the exit-status threshold (`--fail-on`), sets verbosity.
Contains no diagnostic logic.

`audit` options: `--modules`, `--output terminal|json|markdown|html`,
`--min-severity info|warning|error|critical`, `--fail-on info|warning|error|critical|never`
(and the global `--timeout`). The order in `main.rs` matters and is tested: run the
audit → **decide pass/fail on the whole report** → apply the display filter → render.

## Core Engine

Orchestrates execution, builds `Context`, runs the selected modules concurrently,
isolates per-module failures, aggregates `Finding`s into a `Report`. The engine never
interprets system data itself — that is always a module's job. See "Parallel
Execution" and "Error Handling" below.

## Context

`Context` is built once, at startup, from directly observable system facts, and is
immutable (read-only) for the lifetime of the run. Modules receive `&Context` and
cannot mutate it.

```rust
pub struct Context {
    pub hostname: String,
    pub kernel_version: String,
    pub distro: Option<String>,
    pub architecture: String,
    pub cpu_count: usize,
    pub mem_total_kb: u64,
    pub boot_time_unix: u64,
}
```

**v1 rule on cross-module facts:** modules do **not** read each other's findings or
raw data. Every module gets the same static `Context` and otherwise collects its own
data independently. This keeps parallel execution trivial (no dependency graph to
schedule) and keeps modules genuinely independent, per the Module Independence rule
below.

If a future module genuinely needs another module's output (e.g. a Performance
module correlating CPU and Storage findings), that will be modeled as an explicit,
documented dependency resolved by the engine between execution phases — not as
modules calling each other directly, and not implemented until a real module needs
it.

---

# Diagnostic Modules

Every module implements one trait. The trait exposes a single entry point so it stays
object-safe (`Box<dyn Module>`), but every implementation is expected to internally
separate collection (I/O) from analysis (pure logic) — see "Testing Strategy" below
for why this split matters more than the trait shape itself.

```rust
pub trait Module: Send + Sync {
    /// Stable identifier, e.g. "memory"
    fn id(&self) -> &'static str;

    fn category(&self) -> Category;

    /// Whether this module applies to the current system.
    /// Default: always available.
    fn is_available(&self, _ctx: &Context) -> bool { true }

    /// Collect + analyze in one call. Implementations should keep the
    /// collection step (I/O) and analysis step (pure logic) as separate,
    /// independently testable functions internally.
    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError>;
}
```

`report()` is deliberately **not** part of this trait. A module producing its own
rendering would contradict "Output formatters never perform diagnostics" — modules
only ever return `Finding`s; only the Output Engine decides how they're displayed.

---

# Collectors

Collectors retrieve information and do not interpret it. In v1 each module owns its
own thin collection function (e.g. `modules::memory::collect::collect()`), reading
from `/proc` and `/sys` directly wherever possible, and shelling out only when there's
no direct kernel interface for the fact needed. Every subprocess call uses
`core::command::command()`, never `std::process::Command` directly — it forces
`LC_ALL=C`/`LANG=C` so a translated CLI tool (confirmed real-world case: `virsh
dominfo` on a French-locale desktop translates its field labels via gettext, silently
breaking a parser hardcoded to the English "State:" string) can't produce a
locale-dependent parsing failure. Every external command also has a
**time limit** (next paragraph). Network is a clean example of the
former: `/proc/net/dev`, `/proc/net/route`, `/sys/class/net/*`, and `/etc/resolv.conf`
cover its needs with zero subprocess calls. Currently shelling out: `df` (Storage —
space and inode usage), `systemctl` (Systemd — system state, failed units), `smartctl`
(Storage — per-device SMART health, JSON output), `dmesg` (Kernel — OOM-kill history,
best-effort since it's commonly root-restricted), `timedatectl` (NTP — clock sync
status; part of systemd core, so gated by the same availability check as Systemd),
`systemd-detect-virt` (Virtualization, guest-side self-detection — notably does *not*
need systemd as PID 1, unlike `systemctl`/`timedatectl`, since it probes DMI/CPUID
directly rather than talking to PID 1 over D-Bus — verified empirically, not assumed,
so this module has no availability gate), `virsh` (Virtualization, host-side VM
inventory via libvirt — also shells out to `lspci` per passthrough device found, to
identify the hardware behind a bare PCI address), `docker`/`podman`
(Virtualization, host-side container inventory — tried in that order, first one whose
daemon is actually reachable wins), `nvidia-smi` (GPU — reuses the same `lspci`
lookup as Virtualization for the PCI description; AMD's own equivalent needs no
external tool at all, reading `/sys/class/drm/card*/device/*` and its `hwmon`
subdirectory directly), and `mokutil` (Firmware — Secure Boot state; the rest of
Firmware's checks are plain sysfs reads with no external tool at all).
**Time limit.** `core::command::command()` returns a `Cmd` whose `output()` stops the
child and returns an `ErrorKind::TimedOut` error if it runs longer than the limit — 10
seconds by default, changeable with `--timeout <seconds>`. Tools that may legitimately
take a few seconds on a healthy machine (`smartctl` waking a sleeping disk,
`nvidia-smi` initializing the driver, `docker stats` over many containers) call
`.slow()` for twice the allowance. Several calls to the *same* tool that should give
up together (the nine-or-so per-VM `virsh` calls, the three `nvidia-smi` calls) go
through a `ToolSession`: after the first timeout the tool is considered hung and the
remaining calls are skipped, so a wedged daemon costs one limit, not one per call.
Both pipes are drained on their own threads (no stdout/stderr deadlock on large
output), the child is killed — not waited on forever — because a process stuck in
uninterruptible I/O cannot be reaped, and a grandchild that keeps the pipe open cannot
hold the audit past the deadline.
`lsblk`, `journalctl`, `ethtool` remain plausible future
collectors for modules not
yet built (or, for `ethtool`, already pointed to in a *recommendation* string without
the tool itself calling it) — not things already wired in. Shared collection logic
gets promoted to `src/collectors/` once duplicated by a second module.

---

# Analysis (formerly "Rule Engine")

Analysis converts collected facts into `Finding`s. In v1 this is **plain Rust** —
an `analyze()` function per module, deterministic, with no hidden heuristics, e.g.:

```rust
pub fn analyze(data: &MemoryRawData, ctx: &Context) -> Vec<Finding> { ... }
```

A generic declarative rule interpreter (rules expressed as data — TOML/YAML rule
packs evaluated by a shared engine) is real future value once there are enough
modules that pattern duplication across `analyze()` functions becomes visible, but
building that interpreter before a single real diagnostic exists would be solving a
problem that doesn't exist yet. It stays in Future Vision until then.

---

# Findings

```rust
pub struct Finding {
    pub id: String,               // e.g. "MEM002"
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<(String, String)>,   // key/value observed facts
    pub explanation: String,
    pub recommendation: Option<String>,
    pub instance: Option<String>,          // see below
}
```

`instance` names the specific sub-item a finding is about — a socket ("socket 0"), a
filesystem ("/"), a NUMA node ("node0"), a failed unit ("nginx.service"), a disk
("/dev/sda") — when a module's finding applies to one specific thing rather than the
module as a whole. Findings sharing the same `instance` string are grouped together
by output modes that support drilling into detail (the TUI's submenus — see "Output
Engine" below). `None` means the finding is global to the module and always shown at
its top level. This is what lets the TUI decide which modules get a submenu without
any hardcoded knowledge of which check IDs happen to be per-instance for which
module — it's driven entirely by this field, set by whichever module produces the
finding (e.g. CPU's per-socket `CPU004`, Storage's per-filesystem `STOR001`/`STOR002`
and per-device `STOR004`, NUMA's per-node `NUMA001`, Systemd's per-unit `SYSD002`,
Network's per-interface `NET001`/`NET002`).

Example (abridged; recommendations are numbered steps, commands on their own
lines — they are suggestions and are never executed):

```
MEM002 — Swap Activity
WARNING · Confidence: 85% (strong indication)

Evidence
  swap_used_percent:   49.9
  mem_available_pct:   5.5
  vm.swappiness:       60
  swapped_program_1:   chrome (PID 2100): 2.0 GB

Explanation
  The system is actively swapping while relatively little RAM remains free.
  This commonly indicates memory pressure, though it is not necessarily a
  problem on its own — worth investigating if performance feels degraded.

  4.0 GB of 8.0 GB of swap is in use (49.9%).

Recommendation:
  1. See which programs are in swap (chrome has the most):
      grep -H VmSwap /proc/[0-9]*/status 2>/dev/null | sort -k2 -n -r | head
  2. Check whether the machine is swapping right now: ...
      vmstat 1 5
  3. Reduce the demand for memory: ...
```

A per-instance example, for contrast:

```
STOR001 — Filesystem Usage — /data
instance: "/data"
```

Both `STOR001` and `STOR002` (space and inode usage) for the same mount point use the
identical `instance` string, so they group into the same submenu entry.

---

# Severity (canonical)

Four levels, reflecting operational impact:

```
INFO       Purely informational. No action implied.
WARNING    Worth attention. Not necessarily a problem on its own.
ERROR      Likely degraded operation. Investigation recommended.
CRITICAL   Severe, likely user-visible impact. Prompt action recommended.
```

A fifth "NOTICE" tier (INFO < NOTICE < WARNING) was considered and deliberately
dropped: with dozens (eventually thousands) of rules written by different authors
over time, a fuzzy middle tier between "purely informational" and "worth attention"
is a common source of inconsistent classification. Four levels keeps the boundary
each rule has to reason about unambiguous. The "not necessarily a problem" framing
from `PROJECT_CONTEXT.md`'s output principles belongs in the *explanation* text, not
in a separate severity tier — severity says how much it matters; the explanation
says how worried to be.

---

# Confidence (canonical)

Confidence is a percentage plus a short reason, and must never exceed what the
evidence actually shows.

```
100%   Direct, unambiguous observation
90-95% Multiple correlated observations
75-89% Strong indication, one contributing factor unconfirmed
60-74% Weak indication, plausible alternative explanations exist
<60%   Not reported as a Finding — collect more evidence instead
```

```rust
pub struct Confidence {
    pub percent: u8,
    pub reason: String,
}
```

---

# Output Engine

Supported now: Terminal, JSON, Markdown, HTML, interactive TUI.

Output formatters only render `Finding`s — they never compute severity, confidence,
or evidence themselves.

Non-interactive renderers receive the report plus a `RenderMeta`
(`output/common.rs`): the tool version, the generation time (passed in, never read
inside a renderer, so output is deterministic and testable) and, when `--min-severity`
removed findings, a `FilterInfo { min_severity, hidden }`. Every renderer states a
filter when there is one — a filtered report must never pass for a complete one.

## Severity filter and exit status

Two independent options on `audit`, deliberately kept apart:

- `--min-severity <level>` is a **display filter**. `Report::retain_at_or_above` drops
  findings below the level from the output. It never hides module errors, skipped
  modules or "incomplete data" notes, and the renderers say how many findings it hid
  (terminal: a closing line; Markdown/HTML: a banner; JSON: a top-level `filter`
  object).
- `--fail-on <level|never>` is the **gate**. `core::gate::evaluate` counts findings at
  or above the level and the process exits with status 1 if there is any. It looks at
  the **whole report, before the display filter**: hiding findings can never turn a
  failing audit into a passing one (`display_filter_never_changes_the_exit_status` in
  `tests/export_and_gate.rs`, plus a mutation check that fails if the order is swapped).

Without `--fail-on` the threshold is `error`, which is what the exit status always was
(Error and Critical fail), so existing scripts are unaffected; that default gate stays
silent. An explicit `--fail-on` explains itself on stderr
(`N finding(s) at WARNING or above (--fail-on warning); exiting with status 1`) and
keeps stdout clean, so `--output json > report.json` stays parseable.

| Status | Meaning |
|---|---|
| 0 | The audit ran and no finding reached the threshold |
| 1 | A finding reached the threshold, **or** the audit itself could not run (unchanged) |
| 2 | Command-line usage error (from the argument parser) |

A module that fails to run (`error` in the JSON, `✗ ... (error: ...)` in the terminal)
does not count as a finding; check for it separately in CI if it matters.
`tui` keeps the default gate and has neither option.

## Terminal Renderer

Compact per-module status line, followed by full detail for anything above INFO:

```
✓ memory
⚠ cpu
✓ numa
✗ storage
- systemd (skipped)
```

## JSON Renderer

Serializes the full `Report` — a `schema_version` first, then `context` once, then
`results` grouped by module (`module_id`, that module's `findings`, `error`/`skipped`
for modules that didn't run cleanly, and `notes` for modules whose data may be
incomplete):

```json
{
  "schema_version": 1,
  "context": { "hostname": "web01", "kernel_version": "6.8.0-31-generic", "...": "..." },
  "results": [
    {
      "module_id": "memory",
      "findings": [
        {
          "id": "MEM002",
          "title": "Swap Activity",
          "category": "memory",
          "severity": "warning",
          "confidence": { "percent": 85, "reason": "strong indication" },
          "evidence": [["swap_used_kb", "4200000"], ["mem_available_pct", "4.1"]],
          "explanation": "...",
          "recommendation": "...",
          "instance": null
        }
      ],
      "error": null,
      "skipped": false,
      "notes": []
    },
    {
      "module_id": "systemd",
      "findings": [],
      "error": null,
      "skipped": true,
      "notes": []
    }
  ]
}
```

### Schema version

`schema_version` (an integer, `output::json::SCHEMA_VERSION`, currently `1`) names the
layout of the document so scripts and stored reports can tell what they are reading.
It is added by a small wrapper in `output/json.rs`, not by `Report` itself, so
in-memory code and the other renderers never see it.

- **Adding** a field (a new key in a finding, a new note, a new top-level section)
  does **not** change the version: readers must ignore keys they do not know. (Example:
  the optional top-level `filter` object below was added without a bump.)
- **Removing**, renaming or re-typing a field, or changing what a value means
  (for example the unit of an evidence value), **bumps** it by one, with a
  `### Changé` entry in `CHANGELOG.md`.
- Evidence keys and finding ids are part of the contract in the same way: a finding's
  `id` keeps its meaning forever; a retired id is not reused.

Tests: unit tests in `output/json.rs` and the end-to-end `tests/json_schema.rs` (real
binary) pin the envelope — `schema_version` is the first key and, on an unfiltered
report, the only addition to the report's top level.

When `--min-severity` was used, the document also carries (right after
`schema_version`) a `filter` object, absent otherwise:

```json
"filter": { "min_severity": "warning", "hidden_findings": 12 }
```

## Markdown Renderer

`--output markdown` (alias `md`) prints a complete document: title and machine facts, a
summary table (one row per module with counts per severity; skipped and failed modules
are dashed, a module with cut-short tools says "Incomplete data"), then one section per
module with its findings (all of them, Info included — it is a report, not a terminal
screen). Each finding shows severity, confidence, evidence as a list of code spans, the
explanation, and the recommendation.

Layout rules (`output/common.rs` parses what modules write):

- **Explanations**: unindented lines are prose; indented lines are tables or lists that
  modules align with spaces, so each indented group becomes a fenced code block (aligned
  columns survive).
- **Recommendations**: `1. text` steps with commands indented four spaces underneath
  become a numbered list with ```` ```bash ```` blocks; a single line stays a paragraph;
  anything else multi-line is fenced as text.
- **Untrusted text** (host name, instance names, process names, tool error messages):
  prose has its Markdown punctuation backslash-escaped (backslash, `*`, `_`, `[`, `]`, `<`,
  a leading `#` or `>`), values go in code
  spans whose delimiter is longer than any backtick run inside, fences grow the same
  way, table cells escape `|`. Tests check that no `<` survives unescaped.

## HTML Renderer

`--output html` prints one self-contained page: inline CSS, light and dark themes
(`prefers-color-scheme`), responsive down to phone width, no JavaScript, no external
file, no network. Findings are `<details>` blocks: Warning and above are open, Info is
collapsed. Severity is shown as a symbol plus a word, never colour alone. Summary
columns shorten on narrow screens and tables scroll inside their own container, so the
page itself never scrolls sideways.

Security: every dynamic string goes through `esc()` (`& < > " '`); module ids are
slugged before they are used in ids and links; and the page carries a
`Content-Security-Policy` (`default-src 'none'; style-src 'unsafe-inline'`) so that
even a missed escape could not run a script. `hostile_content_cannot_inject_markup_or_script`
feeds an attack string into every field and checks that the only tags in the output are
the renderer's own.

Both document renderers are verified, beyond unit tests, by parsing real output with an
independent parser (a CommonMark parser for Markdown, a strict HTML5 parser for HTML)
and by looking at the HTML in a headless browser (light, dark, phone width).

## Interactive TUI

The third output mode, built on `ratatui`. Consumes the same `Report` as the other
two — no diagnostic logic lives here either. Its extra behavior:

- **Submenus.** Modules whose findings include 2+ distinct `Finding.instance` values
  get a real, navigable submenu (`Enter` to drill in, `Esc` to back out, `PgUp`/`PgDn`
  to move through whichever list — modules or, once drilled in, that module's
  instances — is currently focused; `↑`/`↓` scroll the detail pane). Below 2
  instances, a module's findings are shown flat, exactly as Terminal/JSON always do.
- **Live header.** A second header line shows CPU/memory/root-disk usage,
  refreshed roughly once a second for as long as the TUI stays open, via
  `output::live_stats` — cheap `/proc` reads plus one `df` call, deliberately not
  routed through the Memory/Storage modules' full collect+analyze pipelines (which
  include per-device `smartctl` calls far too slow for a once-a-second tick). CPU
  usage needs two `/proc/stat` samples to compute a delta, so it shows a placeholder
  until the second tick.
- **Startup/refresh progress screen.** `TuiApp` owns its `Report` (not a borrow —
  this is what makes replacing it on refresh possible at all) and is constructed
  only *after* an initial scan that runs behind a progress gauge
  (`core::engine::run_audit_with_progress`, which takes an `on_progress(done,
  total, pending)` callback the TUI uses to redraw each time a module finishes — the
  label names the modules still running, since they run concurrently). The `r` key
  re-runs the same scan behind the same screen and swaps the result in via
  `TuiApp::replace_report`, preserving the current module selection when it still
  exists in the new report. This exists specifically so a module with a slow
  collector (SMART, virsh, docker) never makes the terminal look frozen.

See `src/output/tui.rs` for the implementation and `Finding.instance` above for the
submenu mechanism this is built on.

---

# Module Independence

Modules communicate only through the initial, read-only `Context` — never by calling
each other directly.

```
Forbidden:   CPU module  →  calls  →  Storage module
Allowed:     CPU  →  Context  ←  Storage      (both read the same starting facts)
```

---

# Parallel Execution

Because v1 modules never depend on each other's output (see Context, above),
execution is embarrassingly parallel — no dependency graph or scheduler is needed.
`core::engine::run_modules` starts every selected module on its own thread with
`std::thread::scope` (stdlib, zero dependencies) and returns the results **in menu
order**, whichever finishes first. An async runtime (`tokio`) is deliberately not used:
the work is short-lived blocking I/O (`/proc` reads, subprocess calls), not
high-concurrency networking, and pulling in a runtime for that would violate the
"every dependency must justify its existence" principle.

- **Progress.** `on_progress(done, total, pending)` is called on the *calling* thread
  (never from a worker, so the callback needs no `Send`): once at the start, then each
  time a module finishes, with the ids of the modules still running. The TUI shows
  "10/11 done — waiting for virtualization" instead of a single "current" module,
  because with concurrent modules there is no single current one.
- **Isolation.** A module's returned error *and* a panic inside it (`catch_unwind`)
  both become that module's `error`; the others are unaffected. If the OS refuses a
  thread, that module runs inline on the calling thread instead of being lost.
- **Inside a module.** Work that is one slow command per independent item uses
  `core::parallel::parallel_map` — currently `smartctl` per disk, at most 8 at once,
  results in input order. A server with a dozen disks no longer pays for them one
  after another.
- **What does not change.** Output is identical to a sequential run apart from elapsed
  time: same modules, same order, same findings.

---

# Error Handling

A collector or module failure never stops the run. Example: SMART unavailable →
the Storage module continues, SMART findings are simply absent, and the failure is
recorded (not silently dropped) so the user can see what didn't run and why.

Three distinct things can be recorded, and the output tells them apart:

| Recorded as | Meaning | Example |
|---|---|---|
| a `Finding` | something about the *system* | "swap pressure is high" |
| `error` | the *module* could not run | a required file was unreadable; a module panicked |
| `notes` | the module ran, but **its data may be incomplete** | `'smartctl -a /dev/sda' did not finish within 20s and was stopped` |

`notes` exists because a timed-out command used to be indistinguishable from "tool
absent": the finding it would have produced is simply missing, and a green check would
claim more than the data supports. A module with notes is therefore shown with a
warning symbol (never a clean ✓) in the terminal and TUI, the notes are listed under
it (a yellow banner on the module's page in the TUI), and they are present in the JSON
as `"notes": [...]`. They are collected per thread — each module runs on its own
thread — so a note is always attributed to the module whose command was stopped.

---

# Configuration

```
~/.config/linuxdoctor/config.toml
```

```toml
output = "terminal"
parallel = true
colors = true
timeout = 10
```

The configuration file is not implemented yet. Today the only runtime setting is the
command-line flag `--timeout <seconds>` (default 10), which overrides the per-command
time limit described under Collectors.

---

## Memory module layout

The memory module is the largest one, so it is split by topic instead of living in a
single `analyze.rs`. Each topic file exposes pure functions
`fn(&MemoryRawData, &Context) -> Option<Finding>` (or a `Vec`) and has its own
unit tests.

| File | Findings | Topic (TUI submenu) |
|---|---|---|
| `collect.rs` | — (all I/O and parsers; `MemoryRawData::from_meminfo()` builds the data from `/proc/meminfo` text alone) | — |
| `used.rs` | `MEM004` overview, `MEM007` used memory + top consumers, `MEM003` critically low | Used memory |
| `cache.rs` | `MEM008` page cache, `MEM005` dirty pages | Page cache |
| `shared.rs` | `MEM006` shared memory, tmpfs, SysV segments | Shared memory |
| `swap.rs` | `MEM001` swappiness, `MEM002` swap activity, `MEM010` swap configuration (zram/zswap) | Swap |
| `pressure.rs` | `MEM009` PSI, OOM kills, direct reclaim | Pressure |
| `tuning.rs` | `MEM011` overcommit, `MEM012` huge pages | Kernel tuning |
| `kernel.rs` | `MEM013` slab, page tables, ZFS ARC, `min_free_kbytes` | Kernel tuning |
| `format.rs` | shared helpers: sizes, process grouping, swap command snippets; re-exports the numbered `Steps` builder and sysctl snippets, which now live in `modules::recommend` so other modules can use them | — |
| `analyze.rs` | coordinator: runs every topic, assigns `instance`, orders the result | — |

Rules the coordinator enforces (and tests check on eight scenarios):

- Every finding gets `instance = Some(topic)` so the TUI shows one submenu per topic —
  except `MEM004` and anything at Warning or above, which stay on the module's top
  page so problems are visible immediately. The overview closes that page.
- Findings are sorted: top page first, then by topic, then by descending severity.
- Confidence is at least 60%; every finding at Warning or above carries a numbered
  recommendation; no template placeholders leak into text.
- `MemoryRawData` has eleven required headline fields (the original contract) plus
  best-effort extras (`detail`, `vm`, `swap_devices`, `pressure`, `vmstat`,
  `processes`, `tmpfs_mounts`, `sysv_shm`, `zfs_arc`). Every extra defaults to
  "absent", and a topic that needs a missing source returns no finding rather than
  guessing. This keeps old fixtures valid (`..Default::default()`).

## Security module layout

The security module follows the same discipline as memory: `collect.rs` is the only file
that does I/O, and every topic file holds pure parsing and analysis that is tested against
literal fixtures. It is strictly read-only and works without root: root only adds
visibility, and every finding says what it could not see (the program behind another
user's socket, the firewall rules, `/etc/shadow`).

| File | Findings | Topic (TUI submenu) |
|---|---|---|
| `collect.rs` | — (all I/O: `/proc/net/*`, socket owners via `/proc/*/fd` within a 3 s budget, `systemctl`/`nft`/`iptables` through `core::command`, `sshd_config` with `Include` expansion, sysfs/`/proc/sys` reads, `stat` of sensitive files) | — |
| `listeners.rs` | `SEC002` listening services overview, `SEC003` one finding per exposed risky service (catalogue of ports with a severity and a reason) | Listening services |
| `firewall.rs` | `SEC004` firewall (ufw, firewalld, nftables, iptables; active / not detected / unknown) | Firewall |
| `ssh.rs` | `SEC005` effective `sshd_config` (drop-ins, `Match` blocks, weak algorithms) | SSH |
| `access.rs` | `SEC006` SELinux / AppArmor, `SEC007` kernel and network hardening (19 checks) | Access control, Hardening |
| `accounts.rs` | `SEC008` accounts (extra UID 0, empty or weak passwords), `SEC009` permissions of sensitive files | Accounts & files |
| `analyze.rs` | `SEC001` overview; coordinator: runs every topic, assigns `instance`, orders the result | — |

Rules the coordinator enforces (and `tests/security_module.rs` checks on a well-kept and a
neglected server built from fixtures):

- `SEC001` leads the module's top page and lists what needs attention. Anything at Warning
  or above stays on that page, worst first; everything else goes to its topic's submenu.
- Context changes what is reported, and how sure the module is. A risky service only
  becomes a finding when it is reachable from the network (a service bound to loopback
  only is listed in `SEC002` but gets no `SEC003`); its severity comes from the catalogue entry, and its confidence from the
  firewall (89% with no firewall verified, 80% when that could not be verified without
  root, 70% when a firewall is active, because individual rules are not evaluated). "No
  firewall" is only a Warning when a non-SSH TCP port is reachable from the network. SSH
  findings are capped at Warning when sshd is not running.
- Confidence reflects what could be verified: a conclusion drawn without root, or from
  rules that could not be listed, gets a lower confidence than one drawn from direct
  observation.
- Every finding at Warning or above carries numbered steps, safest action first (install an
  SSH key before disabling passwords, `sshd -t` before reloading, a second session kept
  open). Configuration changes go in drop-in files (`/etc/ssh/sshd_config.d/`,
  `/etc/sysctl.d/`) so the distribution's own files are never edited. Commands are only
  suggested, never run.
- Text that comes from the machine (program names, user names, configuration values) is
  data: it reaches the renderers unmodified and is escaped there, which the integration
  tests check through the Markdown and HTML renderers with hostile names.

## Logs module layout

Same discipline again: `collect.rs` is the only file that does I/O, and everything else is
pure parsing and analysis tested against literal fixtures. The one subtlety is *what to use
when a source is missing*: that decision is `collect::assemble()`, a pure function of
everything that was read, so it is tested without a journal.

| File | Findings | Topic (TUI submenu) |
|---|---|---|
| `collect.rs` | — (`journalctl -o json` queries run in parallel through `core::parallel`, `auth.log`/`secure` tail, `dmesg`, the journal directory and `journald.conf`, a bounded walk of `/var/log`; `assemble()` picks the sources and lists what could not be read) | — |
| `journal.rs` | — (parsers: journal JSON, classic syslog lines, `dmesg`, all into one `Entry` shape) | — |
| `text.rs` | — (`clean`, `is_safe_word`, `normalize`, `human_size`, `table`) | — |
| `auth.rs` | `LOG002` SSH login activity, `LOG003` one finding per login that follows many failures from the same address, `LOG004` failed `sudo`/`su`/console logins | Authentication |
| `errors.rs` | `LOG005` error-level messages since boot, grouped by service | System errors |
| `kernel.rs` | `LOG006` storage and hardware errors, `LOG007` crashes and lockups | Kernel messages |
| `health.rs` | `LOG008` the journal (persistence, size, dropped messages), `LOG009` log files in `/var/log` | Journal & log files |
| `analyze.rs` | `LOG001` overview; coordinator: runs every topic, assigns `instance`, orders the result | — |

Rules the coordinator enforces (and `tests/logs_module.rs` checks on a quiet and a troubled
server built from fixtures, and on the real binary against a fake `journalctl`):

- `LOG001` leads the top page, lists what needs attention and — above all — what **could not
  be read**. A log that was not read is a `Gap` (with the group to join when that would fix
  it), never an empty list: an unreadable journal must not look like a quiet one. A journal
  that answers every query with nothing is treated as unavailable, because a running
  journald always holds at least the kernel's boot messages.
- Authentication is judged over the last 24 hours (`auth::WINDOW_HOURS`), errors and kernel
  messages over the current boot. A failed SSH attempt is counted once even though sshd logs
  both the rejected account and the password attempt (same address and port). Login order
  matters: a login is "suspicious" only for failures from its own address *before* it.
- A suspected break-in outranks everything else at equal severity (`ORDER` in `analyze.rs`).
  Thresholds are named constants (`SOURCE_FLOOD`, `TOTAL_FLOOD`, `SUSPICIOUS_AFTER`,
  `BREAK_IN_AFTER`, `NOISY_SERVICE`, ...), each with a comment saying why that number.
- **Log content is untrusted.** Account names are chosen by whoever connects, program names
  by any local user. Every message passes through `text::clean` on the way in (control
  characters, including terminal escape sequences and direction overrides, become `?`;
  length is bounded), and a name only enters a suggested command when `text::is_safe_word`
  accepts it — otherwise a placeholder such as `<account>` is shown. Addresses go into
  commands only when they parse as IP addresses.
- Every finding at Warning or above carries numbered steps, safest first (confirm it was
  you, cut access, look for what an intruder leaves, then block). Commands are only
  suggested, never run; the module never rotates, vacuums or truncates anything.
- Out-of-memory kills are the Kernel module's (`KERN` findings) and are not repeated here.

---

# Testing Strategy

Three levels:

**Unit tests** — every `analyze()` function, tested as a pure function against
constructed `RawData` fixtures (no filesystem access). Every parser (e.g.
`parse_meminfo(text: &str)`) tested against literal fixture strings, including
malformed/partial input.

**Integration tests** — one test per module, still fixture-driven, exercising the
full `collect → analyze` path with an injected fixture instead of live `/proc`.

**End-to-end tests** — run against real systems (Ubuntu, Debian, Fedora, Arch,
Rocky, AlmaLinux). Not part of `cargo test`; run on real or containerized targets.
(`tests/hung_tools.rs`, `tests/json_schema.rs`, `tests/export_and_gate.rs`, one test of
`tests/security_module.rs` and `tests/logs_module.rs` are the exception: they run the real
binary inside `cargo test`, but against fake tools (`logs_module.rs` puts a fake
`journalctl` first on `PATH`, so a journal can be simulated on any host) or only the memory,
security or logs module, so they need no particular distribution. Each of those modules
always reports at least its Info overview, which is what makes their expectations
deterministic on any host: the host-run security and logs tests only assert which findings
exist, never their severity, because that depends on the machine it runs on.)

**Continuous integration** — `.github/workflows/ci.yml` runs on every push to `main`
and every pull request: `cargo fmt --check`, `cargo clippy --all-targets -- -D
warnings` (stable), and `cargo build` + `cargo test` on both Rust 1.75.0 (the
minimum supported version, also declared as `rust-version` in `Cargo.toml`) and
stable. Every job uses `--locked`, because `Cargo.lock` pins dependencies for the old
toolchain (see README "Toolchain note"). Cargo 1.75 cannot read lockfile format v4
(Cargo 1.78+), so the 1.75 leg rewrites the header to v3 inside the CI run — with
registry-only dependencies the content is identical. The same commands are what a
contributor runs locally before a pull request.

The reason `collect()` and `analyze()` must be separate functions, not just separate
mental steps inside one method, is entirely for this: `analyze()` needs to be
callable in a unit test with zero I/O.

---

# Dependency Philosophy

Prefer the standard library. Add a dependency only when it clearly earns its keep:

* `thiserror` — exhaustive, low-boilerplate error types
* `serde` / `serde_json` — JSON output; hand-rolled serialization is a maintenance
  and correctness risk for no real benefit here
* `clap` (derive) — CLI parsing; the UX surface (module selection, output format,
  verbosity, filtering) grows quickly enough that hand-rolled parsing stops paying
  off almost immediately

Avoided on purpose: an async runtime (see Parallel Execution), a system-info crate
like `sysinfo` (reading `/proc`/`/sys` directly is barely more code and keeps every
fact's provenance visible, which matches the "transparency" and "evidence-based"
values directly), a terminal-color crate (a handful of ANSI codes by hand is simpler
than a dependency for this).

---

# Performance Targets

* Startup: < 100 ms
* Typical audit: < 2 seconds
* Memory: < 100 MB
* Zero background services

---

# Security Principles

LinuxDoctor is read-only. It never modifies configuration, restarts services, opens
listening sockets, sends telemetry, or uploads data. No internet connection is
required.

---

# Plugin System (Future, not v1)

Future external modules (`gpu`, `postgres`, `mysql`, `zfs`, `ceph`, ...) following
the same `Module` trait. Not implemented in v1, but the trait and `Finding`/`Context`
types are kept `serde`-friendly on purpose, so a future plugin boundary — whether
`libloading` + a pinned-compiler ABI, or a `wasmtime` sandbox — doesn't require
reshaping the core types later. Which mechanism to use is an open question deferred
until there's a real plugin to build.

---

# Design Principles

* Single Responsibility Principle
* Composition over inheritance
* Read-only diagnostics
* Deterministic behavior
* Explicit data flow
* Minimal shared state
* Modular by default
* Testability first

---

# Long-Term Goal

The architecture should let LinuxDoctor grow from a handful of diagnostics to
several thousand rules without changing the Core Engine. New functionality should
almost always mean adding a new module or a new check within a module — not
modifying the engine, `Context`, or the `Module` trait.
