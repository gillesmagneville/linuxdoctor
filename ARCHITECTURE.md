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
│   ├── cli.rs                 # clap definition (audit / tui / diff / completions / man)
│   ├── config.rs              # the optional config.toml — see "Configuration"
│   ├── manpage.rs             # `linuxdoctor man`: the page, generated — see
│   │                          # "Manual Page and Shell Completions"
│   ├── profile.rs             # machine profiles (--profile): what kind of machine is
│   │                          # being audited — see "Profiles"
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
│   │   ├── text.rs           # `clean` and `printable`: control characters out of untrusted text
│   │   └── error.rs
│   │
│   ├── models/
│   │   ├── mod.rs
│   │   ├── severity.rs       # canonical Severity enum
│   │   ├── confidence.rs     # canonical Confidence scale
│   │   ├── category.rs       # canonical Category enum
│   │   └── finding.rs        # canonical Finding struct
│   │
│   ├── diff/                 # `linuxdoctor diff` — see "Report Diff" below
│   │   ├── report.rs         # reads a JSON report file, leniently
│   │   ├── compare.rs        # pure: two reports -> Comparison
│   │   └── render.rs         # Comparison -> terminal / Markdown / JSON
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
│   │   ├── hpc/              # added by --profile hpc, not in all_modules() — see "Profiles"
│   │   ├── server/           # added by --profile server, not in all_modules() — see "Profiles"
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
│       │                     # layout shared by the document renderers, and
│       │                     # `display_safe` (see "Text from the audited machine")
│       ├── terminal.rs       # text + ANSI colors
│       ├── json.rs           # JSON (+ schema_version)
│       ├── markdown.rs       # Markdown report — see "Markdown Renderer" below
│       ├── html.rs           # self-contained HTML report — see "HTML Renderer" below
│       ├── tui.rs            # interactive UI (ratatui) — see "Output Engine"
│       ├── tui_filter.rs     # what the TUI shows: minimum severity + search text
│       └── live_stats.rs     # TUI header gauges (CPU/mem/disk %) — see "Output Engine"
│
└── tests/
    # one fixture-driven integration test file per module, e.g.
    ├── memory_module.rs
    ├── cpu_module.rs
    ├── cpu_count.rs          # the CPU count is the machine's, even when the audit is confined to one CPU
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
    ├── virtualization_module.rs
    # (one per module, same fixture-driven pattern)
    ├── docs_commands.rs      # the real binary: man, completions, --modules check
    ├── diff_command.rs       # the real binary: diff, its exit status and its formats
    ├── profile_option.rs     # profiles: the real CPU module and the real binary
    ├── hpc_module.rs         # the module the hpc profile adds, with the real binary
    ├── server_module.rs      # the module the server profile adds, with fake apt-config and systemctl
    └── hostile_names.rs      # the real binary against escape sequences in names, every format
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
Aggregate Findings into a Report, applying the profile (--profile) if one was chosen
                                                    (only ever lowers severities)
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

`diff <BEFORE> <AFTER>` takes the same `--min-severity` and `--fail-on`, and
`--output terminal|json|markdown`; see "Report Diff".

Every one of these options, and `--timeout`, can also come from the configuration file;
what is typed wins (see "Configuration"). `--config FILE` and `--no-config`, both global,
choose which file is read.

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

`cpu_count` is the number of CPUs the kernel has **online** (`/sys/devices/system/cpu/online`),
not the number the audit may run on: `available_parallelism()` honours the process's
CPU affinity and cgroup limits, so on a machine that sets some CPUs aside (a virtual machine
pinned to its own cores) it would report fewer CPUs than the machine has. It remains the
fallback when the list cannot be read (`tests/cpu_count.rs` runs the real binary confined to
one CPU and requires the same count).

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

Every output says which version of LinuxDoctor produced it, up front, from one constant
(`linuxdoctor::VERSION`, which is `CARGO_PKG_VERSION` and so what `--version` prints): the
first line of the terminal report, the first line under the title in Markdown, the first
fact of the HTML header (and its `generator` meta tag and footer), the second key of the
JSON document, the TUI header and its loading screen, and the header of a comparison.
`tests/version_shown.rs` checks each with the real binary, and that `VERSION` and
`Cargo.toml` agree.

Non-interactive renderers receive the report plus a `RenderMeta`
(`output/common.rs`): the tool version, the generation time (passed in, never read
inside a renderer, so output is deterministic and testable) and, when `--min-severity`
removed findings, a `FilterInfo { min_severity, hidden }`. Every renderer states a
filter when there is one — a filtered report must never pass for a complete one.

## Text from the audited machine

A report is full of strings the audited machine chose: process names, virtual machine and
container names, unit and interface names, mount points, user names, messages from tools.
Any of them can carry a terminal escape sequence (clear the screen, retitle the window,
overwrite the line above with a carriage return) or a right-to-left override that
reorders what is displayed. The rule is one sentence: **no renderer other than JSON emits
a control character that came from the machine.**

* `core::text::printable` is the one function that does it. It keeps text as it is — line
  breaks, indentation, accents, right-to-left scripts — and replaces what could act on a
  terminal with `?`: every control character (ESC, BEL, backspace, NUL, DEL, the C1 range,
  a carriage return that does not end a line) and the bidirectional overrides and
  isolates. A tab becomes a space. It returns the input without copying when there is
  nothing to change, which is almost always: a full real audit (874 strings) is unchanged.
* `output::common::display_safe(&Report) -> Report` applies it to **every** string of a
  report. It takes `Context`, `ModuleRunResult`, `Finding` and `Confidence` apart without
  `..`, so adding a text field to any of them stops it from compiling until the new field
  is handled: a renderer cannot forget a field, and a new field cannot be forgotten.
* The terminal, Markdown and HTML renderers call it on entry; the TUI calls the in-place
  `make_display_safe` when it receives a report (`TuiApp::new` and `replace_report`), so
  nothing it draws — lists, details, search, the header — can show raw text. Markdown and
  HTML still escape their own markup (below): that is a different problem, and a file
  that is read with `cat` needs both.
* **JSON is the exception, on purpose.** `serde_json` escapes control characters
  (`\u001b`), so the output is safe to read as text, and it is the record of what was
  observed: altering names in it would make a stored report lie, and `linuxdoctor diff`
  compares reports by those names.
* `linuxdoctor diff` reads files rather than the machine, and uses `core::text::clean`
  (single line, bounded length) for the strings of a comparison; see "Report Diff".

Tests: `core::text` (the rules), `output::common` (a report with hostile text in every
field comes out clean, an ordinary one comes out identical, the original keeps its
bytes), one test per renderer including the TUI's screen buffer, and
`tests/hostile_names.rs`, which runs the real binary against a fake `df` whose mount point
is made of escape sequences and checks every format. Each of these fails when the call is
removed (checked by hand when it was written).

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

The report is written to standard output with `write_stdout` (not `print!`, which panics
when the reader has gone away): a closed pipe (`audit | head`) is not an error and the
status stays the audit's verdict; any other write failure is reported and exits 1.
`tui` keeps the default gate and has neither option (it has `--profile`, below).

## Terminal Renderer

The first line names the program, its version and the machine
(`LinuxDoctor 1.10.0 — web01`); then a compact per-module status line, followed by full
detail for anything above INFO:

```
✓ memory
⚠ cpu
✓ numa
✗ storage
- systemd (skipped)
```

## JSON Renderer

Serializes the full `Report` — a `schema_version` first, then the `linuxdoctor_version`
that wrote it, then the `profile` it was written with (only when one was chosen), then
`context` once, then
`results` grouped by module (`module_id`, that module's `findings`, `error`/`skipped`
for modules that didn't run cleanly, and `notes` for modules whose data may be
incomplete):

```json
{
  "schema_version": 1,
  "linuxdoctor_version": "1.10.0",
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
report written without a profile, the two version keys are the only additions to the
report's top level.

`linuxdoctor_version` (a string, `linuxdoctor::VERSION`) is **not** part of the layout —
`schema_version` is — but a record of where the findings came from: checks are added and
thresholds move between versions, so a stored report is only fully understood with the
version that wrote it. It was added without a bump, as the rule allows; reports written
before it (1.8.0 and earlier) simply lack the key, and `diff` says "version not recorded"
for them.

`profile` (a string, `"hpc"`) is present only when the audit was run with a profile, and
absent otherwise, so a report written without one is exactly what it always was. It was
added without a bump, as the rule allows. See "Profiles".

When `--min-severity` was used, the document also carries (right after the version keys
and the profile) a `filter` object, absent otherwise:

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

## Report Diff

`linuxdoctor diff before.json after.json` compares two JSON reports (`audit --output
json`) and says what changed: findings that **appeared**, were **resolved**, got
**worse** or got **better**. It is the only command that reads reports instead of the
machine, so it touches no system file and runs no tool. It lives in `src/diff/`, in three
files that follow the project's collect / analyze / report split:

| File | Role |
|---|---|
| `report.rs` | **Reads** a report file. Lenient on purpose: it declares only the fields the comparison needs and ignores every other key (the JSON contract says readers must), a missing `schema_version` reads as 0, and a `schema_version` newer than `output::json::SCHEMA_VERSION` is refused *before* the rest of the document is interpreted, since its shape cannot be trusted. The size is capped (64 MiB) and `-` reads standard input. |
| `compare.rs` | **Pure**: two parsed reports in, a `Comparison` out. No I/O, so every rule below is a plain unit test. |
| `render.rs` | **Lays out** a `Comparison`: terminal text, Markdown, or a versioned JSON document. |

### What is compared

Findings are matched by `(module id, finding id, instance)`. When one key has several
findings on a side, they are paired one to one if they are the only ones, else by equal
title, then by position, so a group never reports a change that is not there. A pair whose
severity differs is **worse** or **better** (and carries which evidence values moved); a
finding on one side only is **new** or **resolved**. Informational findings that appear or
disappear are inventory changes, not problems, and are listed apart ("Other changes") so a
new network interface does not look like a regression.

### The rule that matters: absence is not good news

A finding missing from the later report only counts as *resolved* if the module that would
have reported it **ran to the end** in that report. If the module failed, was skipped, was
not run (`--modules` left it out), or is absent from one of the files, it is listed under
**Not compared**, with what each side said and how many findings could not be re-checked —
never as a quiet improvement. The mirror case holds too: a finding new in the later report
is not trusted as new when the earlier report's module failed. Smaller cases get a flag
instead: a module whose commands were cut short (`notes` in the report) may simply not have
seen a finding, so a *resolved* or *new* one on that side is marked `?` (`doubt` in JSON)
and the notes are printed under "Incomplete data". This is the diff-side form of the
project's principle that unchecked is never presented as clean.

Caveats are stated before the changes: the two reports describe different machines (host
name or architecture differ), the second looks older than the first (a boot time that went
backwards, so the arguments are probably reversed), or either was written with
`--min-severity` (so nothing below the stricter floor exists on either side, and the
comparison says it only compared findings at or above it), or they were not written by the
same version of LinuxDoctor. That last one matters because checks are added and thresholds
move between versions: a finding that appears or disappears may come from the program, not
from the machine. Two recorded versions that differ raise it; so does one recorded version
next to a report that records none (every version that records the field is newer than every
one that does not, so the two certainly differ); two reports that both record none say
nothing, since there is nothing to conclude — a warning there would only be noise on every
comparison of old reports. The same goes for the profile (`Caveat::DifferentProfiles`): a
profile lowers some severities, so a finding that "got better" between a report written
without a profile and one written with `hpc` got better on paper only. Unlike a version,
"no profile" is a value (it is also what every report from before profiles looks like), so
`none` against `hpc` raises the caveat and two reports without one say nothing. A caveat
never adds or hides a change and never moves the exit status (the versions and profiles
come from files and are cleaned like the host names). Changed machine facts (kernel, distribution, memory, CPUs, a reboot) are listed
under "Machine changes".

### Exit status and options

| Status | Meaning |
|---|---|
| 0 | No finding appeared or got worse to the `--fail-on` level (default `error`) |
| 1 | A finding appeared, or got worse, and is now at the level or above |
| 2 | The comparison could not be made: a file is unreadable, is not a report, or comes from a newer format; also a usage error |

`2` differs from `1` on purpose: a script must be able to tell "something got worse" from
"I could not look". A finding that is in both reports at the same severity is never a
regression, however serious (that is what `audit --fail-on` is for), and modules that were
not compared are listed but do not change the status, as a module that fails to run does
not for `audit`. As for `audit`, `--fail-on` is judged on the **whole comparison before**
`--min-severity` hides anything (`retain_at_or_above` runs after `regressions`), and only
an explicit `--fail-on` explains itself on stderr. `--min-severity` keeps a change if the
finding reached the level in either report, and never hides "Not compared" or "Incomplete
data".

### Reports are untrusted input

A comparison reads files that may have been written elsewhere, so every string taken from
them is hostile until proven otherwise: finding titles, instance names, evidence, error
messages, file names, the host name. The terminal output passes all of it through
`core::text::clean` (control characters, escape sequences and bidirectional overrides become
`?`, long text is cut with `…`); the Markdown output also escapes it the way the audit's
Markdown report does (`escape_text`, `code_span`, `|` in table cells); the JSON output
escapes it by construction. `tests/diff_command.rs` feeds a report full of escape sequences
and markup to the real binary and checks all three outputs.

### Which versions are involved

A comparison involves three: the version that made it (the title of the terminal text,
"Compared with LinuxDoctor …" in Markdown, top-level `linuxdoctor_version` in JSON) and
the versions that wrote the two reports (in parentheses after each report in the terminal
text, a "Written by" column in Markdown, `before.linuxdoctor_version` /
`after.linuxdoctor_version` in JSON — `null` for a report from a version that did not
record it, shown as "LinuxDoctor version not recorded"). The versions of the reports come
from files and are untrusted text like the rest: cleaned for the terminal, escaped for
Markdown. When they differ, the comparison also says so as a caveat (below).

### JSON output

`--output json` prints a document of its own, versioned the same way as the audit report
(`render::COMPARISON_SCHEMA_VERSION`, currently `1`, first key; adding a key never bumps
it):

```json
{
  "schema_version": 1,
  "kind": "comparison",
  "linuxdoctor_version": "1.10.0",
  "before": { "report": "before.json", "linuxdoctor_version": null,
              "machine": { "hostname": "web01", "...": "..." } },
  "after":  { "report": "after.json", "linuxdoctor_version": "1.10.0",
              "machine": { "...": "..." } },
  "machine_changes": [ { "fact": "kernel", "before": "6.8.0-31", "after": "6.8.0-40" } ],
  "rebooted": true,
  "caveats": [ { "kind": "different_machines", "before": "web01", "after": "db02" } ],
  "floor": "info",
  "summary": { "worse": 2, "better": 1, "other": 0, "unchanged": 14, "not_compared": 1 },
  "changes": [
    { "section": "worse", "kind": "worse", "module_id": "security", "id": "SEC005",
      "instance": "sshd", "title": "...", "before": "warning", "after": "error",
      "evidence": [ { "key": "permit_root_login", "before": "no", "after": "yes" } ] }
  ],
  "incomplete": [ { "module_id": "storage", "side": "after", "notes": ["..."] } ],
  "not_compared": [ { "module_id": "network", "before": { "state": "ran" },
      "after": { "state": "failed", "error": "..." },
      "findings_before": 3, "findings_after": 0 } ],
  "skipped_in_both": ["numa"],
  "hidden": 0
}
```

`caveats[].kind` is `different_machines`, `reports_look_reversed`, `filtered`,
`different_versions` (`before` / `after` are the two versions, `null` for a report that does
not record one) or `different_profiles` (`before` / `after` are the two profiles, `null` for
a report written without one); a reader should ignore a caveat kind it does not know, as it ignores a key.
`kind` of a change is `new`, `resolved`, `worse` or `better`; `section` is where the change is listed
(`worse`, `better`, `other`); `before` / `after` are the severities (`null` on the side
where the finding does not exist); `doubt` (`"before"` or `"after"`) appears on a change that
incomplete data makes uncertain; `hidden_below` appears with `hidden` when `--min-severity`
was used.

## Interactive TUI

The third output mode, built on `ratatui`. Consumes the same `Report` as the other
two — no diagnostic logic lives here either. Its extra behavior:

- **Submenus.** Modules whose findings include 2+ distinct `Finding.instance` values
  get a real, navigable submenu (`Enter` to drill in, `Esc` to back out, `PgUp`/`PgDn`
  to move through whichever list — modules or, once drilled in, that module's
  instances — is currently focused; `↑`/`↓` scroll the detail pane). Below 2
  instances, a module's findings are shown flat, exactly as Terminal/JSON always do.
- **Version.** The first header line starts with `LinuxDoctor <version>`, and so does the
  loading screen.
- **Filter and search** (`f`, `/`; `output::tui_filter::ViewFilter`). A *view* over the
  report, never a change to it: `TuiApp` keeps the `Report` whole and a `ViewFilter`
  beside it, and every place that draws findings asks the filter first
  (`visible_findings`). Two narrowings combined with "and": a minimum severity (the four
  levels of `--min-severity`) and a text matched without regard to case against a
  finding's id, title, explanation, recommendation, instance and evidence — the text as
  typed, not split into words. Rules worth knowing:
  - *The report is untouched.* A module's ✓/⚠/✗ is still computed from all its findings,
    and the exit code of `linuxdoctor tui` from all of them: hiding a finding on screen
    cannot hide it from the exit status. The bottom bar always says what the screen is
    (`All N findings shown`, `Filter: … · M of N findings`, or the text being typed), and
    each filtered page starts with `Filter: … — x of y findings of this module shown`.
  - *Sub-items follow the filter.* A module's instances are those of the findings that pass
    it (`instances_of(visible_findings(..))`), so a filter that leaves one instance shows
    it flat — the same "fewer than 2 instances" rule as before, not a special case. A
    filter change leaves any open submenu.
  - *The selection only moves when the filter changes.* `settle_selection` runs after a
    filter change or a refresh and, if the selected module has nothing to show, selects
    the first that has; with no match anywhere the selection stays and the page says
    "Nothing in this module matches the filter". `PgUp`/`PgDn` are not narrowed, so a
    failed or skipped module (which has no findings to match) stays reachable.
  - *Typing mode.* After `/`, letters are text — `q`, `r`, `f`, `j` and `k` included — and
    only keys that cannot be text act: Enter keeps the text, Esc forgets it (the severity
    stays), Backspace edits, the arrows and `PgUp`/`PgDn` still work. Control/Alt
    combinations are ignored. The text is limited to 40 characters and refuses control
    characters, because it is drawn back; it is typed, not read from the audited machine,
    so the hostile-text cleaning does not apply to it. Outside typing mode, Esc undoes one
    level at a time: submenu, then filter, then quit.
  - *Testable without a terminal.* Key handling is `handle_key(app, key) -> KeyAction`
    (`Nothing`, `Quit`, `Rescan`), separate from the event loop.
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

# Profiles

```
linuxdoctor audit --profile hpc          profile = "hpc"      (top level of config.toml)
```

The checks are written for a machine in general, and some readings mean something else on a
particular kind of machine: a load average at the number of CPUs is contention on a
desktop and a compute node doing its job. A **profile** says what kind of machine is being
audited, once, in one place (`src/profile.rs`), instead of every module guessing. Today
there are two, `hpc` and `server`. A profile does two things, and only these: it **lowers
severities** (rules 2 to 5 below; `server` lowers none), and it may **add modules** (the end
of this section).

Five rules, each with the test that holds it:

1. **Chosen, never detected.** `--profile`, or `profile` in the configuration file; the
   command line wins. Nothing looks at the machine to pick one: two similar machines must
   not be judged differently for a reason nobody can see. With no profile, `profile::apply`
   is not called and every severity is the one the module gave
   (`without_a_profile_no_report_mentions_one`).
2. **A profile only lowers.** A `Rule { id, cap, reason }` is a *cap*: a finding with that
   id and a severity above `cap` is reported at `cap`; one at or below it is left alone, and
   no rule can raise anything (`no_rule_ever_raises_a_severity`). This is not a style
   choice. The exit status follows the severities, so a profile that made findings worse
   would make audits that pass today fail, on the strength of a setting.
3. **A profile never looks away.** It removes no finding, changes no evidence it was given
   and no confidence, and has nothing to say about a full disk or an exposed service:
   `a_real_problem_is_still_reported_and_still_fails_under_a_profile` runs the real binary
   on a nearly full file system with and without `--profile hpc` and requires the same
   findings and the same exit status.
4. **It says what it did, in the finding.** An adjusted finding gets two evidence lines,
   `severity_before_profile` and `profile`, and a closing paragraph in its explanation
   ("Profile hpc: reported as info instead of critical. …" followed by the reason). Anybody
   reading a report can tell an adjusted finding from an untouched one, and see what it
   would have been. The report itself records the profile (JSON `profile` right after
   `linuxdoctor_version`; a dim `· profile hpc` on the first line of the terminal report;
   a "Profile" line in Markdown and HTML; the TUI header).
5. **It is applied to the finished report, before the gate and before the display filter.**
   The profile is a parameter of the functions that build a report
   (`core::engine::run_audit`, `run_audit_with_progress`, and `audit_of` underneath), which
   call `profile::apply` on the result: there is no step for a caller to forget, and a
   report cannot record a profile it did not apply. The exit status, every renderer and
   `diff` all work from the same severities (`the_profile_is_applied_before_the_gate_can_look_at_the_report`
   with a fake module, `a_busy_node_fails_the_audit_without_a_profile_and_passes_with_hpc`
   with the real CPU module). `--fail-on` therefore judges the severities the report shows.

`diff` compares what the reports say, so it has no `--profile`; it reads the profile each
report recorded and, when the two differ (including *none* against one), says so as a
caveat (see "Report Diff").

### The `hpc` profile

| Finding | Cap | Why |
|---|---|---|
| `CPU002` Load Average Pressure | info | The CPUs of a compute node are meant to be busy: a load at or above the CPU count is a node running jobs. |
| `CPU003` Sustained CPU Overload | info | The same, over every window. |

The load figures stay in the evidence. `CPU003` is a Critical finding on any other machine:
under `hpc` a node with a load of nine on four CPUs passes the default gate. That is the
point of the profile, and also what to remember when choosing it: **a node that is
oversubscribed by mistake looks the same as one that is working.** The profile removes the
alarm, not the number.

`hpc` also adds a module, `hpc` (`src/modules/hpc/`):

| Finding | What it judges |
|---|---|
| `HPC001` CPU Frequency Governor | The `scaling_governor` of every online CPU with a frequency policy, read with its `scaling_driver` and, where there is one, its `energy_performance_preference`. `performance` is Info. `powersave` means two different things: under `intel_pstate` and `amd-pstate-epp` the processor picks its own frequency and `powersave` only biases it (judged by the preference: performance-leaning is Info, efficiency-leaning a Warning, unknown or `default` an Info that says so; with no preference file, the load drives it: Warning), under every other driver it holds the lowest frequency (Warning, 90%). `ondemand`, `conservative` and `schedutil` follow the load (Warning). CPUs that do not share one governor are a Warning. No policy at all (a virtual machine) is an Info that says there was nothing to check. The facts behind the `powersave` split are in the kernel's `intel_pstate` and `amd-pstate` documentation. |
| `HPC002` Locked Memory Limit | The RDMA devices (`/sys/class/infiniband/<device>/ports/<n>/link_layer`) and the `Max locked memory` line of `/proc/self/limits`, compared with the RAM of the node (`Context::mem_total_kb`). RDMA pins the memory it transfers, and the kernel charges that to `RLIMIT_MEMLOCK`; the default is a few MiB. No device: Info that says the limit does not matter here. Devices and no readable limit: Info that says so. Soft limit unlimited, or at least the RAM: Info. Lower: Warning, 75% (strong indication: the limit read is the audit session's own, not that of the jobs), with the hard limit deciding whether the text says users can raise it or that it takes root. A finite limit with the RAM unknown is not judged. Recommendation: `ulimit -l`, `limits.d` for logins, `DefaultLimitMEMLOCK` for systemd services, then the commands that check. |
| `HPC003` Automatic NUMA Balancing | `/proc/sys/kernel/numa_balancing` (a bit field: bit 0 balances between nodes, bit 1 is memory tiering) and the number of `node<N>` directories of `/sys/devices/system/node`. Always Info: whether balancing helps depends on whether the jobs are bound to NUMA nodes, which the node cannot tell. No switch (kernel built without it): Info that says so. Fewer than two nodes: Info that says the setting changes nothing. Two or more: off, on (with a conditional recommendation for bound jobs: the kernel documentation says to disable it for them), memory tiering (2) and both (3) are described apart; a value with other bits is reported, not interpreted. |
| `HPC004` SMT (Hyper-Threading) | `smt/control` and `smt/active` under `/sys/devices/system/cpu`, and the `topology/thread_siblings_list` of each CPU (the same list read from `n` CPUs is one core of `n` threads, so the cores and the threads per core come out even when a processor mixes performance and efficiency cores). Always Info. `control` decides (`on`, `off`, `forceoff`, `notsupported`); when it is missing or `notimplemented`, `active` then the topology do. On with a `control` file that is `on`: the trade-off and the commands for one thread per core (now, then the `nosmt` kernel parameter and the boot-configuration command of the distribution family). |

### The `server` profile

`server` lowers nothing (`rules(Profile::Server)` is empty, and its description says so): a
load that is too high, a full disk or an exposed service is as wrong on a server as
anywhere, and the general audit already judges it. The profile exists for its module,
`server` (`src/modules/server/`, category `Security`), whose checks would be noise on a
desktop — a desktop shows its updates to the person using it:

| Finding | What it judges |
|---|---|
| `SRV001` Automatic Security Updates | Whether the system's own mechanism for installing security updates unattended is set up. It is chosen by the family of the distribution (`family_of(Context.distro)`): Debian-like reads **apt**, Red Hat-like reads **dnf**, anything else gets an Info that says the check was not made. **apt**: the settings come from `apt-config dump`, which merges `/etc/apt/apt.conf.d/` as apt does (keys compared without regard to case, because apt's are not), and are read as `/usr/lib/apt/apt.systemd.daily` reads them: `APT::Periodic::Enable` is a number and only 0 turns the jobs off; an interval is off when absent or exactly `0`, on when `always` or a number with an optional `s`, `m`, `h` or `d` suffix (the script compares the *text* with `0`, so `0d` runs every time and is "on" here too), invalid otherwise. Required: `/usr/bin/unattended-upgrade` exists; `Unattended-Upgrade` and `Update-Package-Lists` are on; at least one entry in `Unattended-Upgrade::Allowed-Origins::` or `Origins-Pattern::` (not reported while the package is missing: the file with the list is the package's own); `apt-daily.timer` (refreshes the lists) and `apt-daily-upgrade.timer` (runs `unattended-upgrade`) are enabled. **dnf**: dnf 5 if `/usr/bin/dnf5` exists, else dnf 4. Installed means `/usr/bin/dnf-automatic` (4) or the packaged defaults `/usr/share/dnf5/dnf5-plugins/automatic.conf` (5). `apply_updates` and `upgrade_type` are read from the `[commands]` section of `/etc/dnf/automatic.conf`, over the defaults with dnf 5; booleans as dnf reads them (`1`, `yes`, `true`, `enabled` and their opposites, in any case). It installs when `dnf-automatic-install.timer` is enabled (dnf 4 only; it ignores `apply_updates`), or when the timer that follows the file (`dnf-automatic.timer`, `dnf5-automatic.timer`) is enabled and `apply_updates` is true. The download-only and notify-only timers are named when they are the ones that are on. A timer is **enabled** when `systemctl is-enabled` says `enabled` or `enabled-runtime`: the persistent intent, readable without a running systemd. **Verdict**: everything in place is an Info (90%, `correlated`) with no recommendation; anything missing is a Warning (80%, `strong_indication`) that lists every fault and gives the numbered steps for them; a reading that failed (no `apt-config`, a timer systemd did not answer about) with no fault in what could be read is an Info (100%) that says what could not be told — a failed reading is never a Warning. It stops at 80% because the machine may be patched another way (a configuration-management tool, Landscape, Satellite, a maintenance window), which nothing here can see; the explanation says so. It does not say whether the last run worked. |

The tools are behind a trait (`collect::Tools`) so that `collect_from` is tested with fake
answers, and the real ones are two `ToolSession`s (`apt-config`, `systemctl`): one hung
`systemctl` costs one time limit, not one per unit. `systemctl is-enabled` answers
`disabled` with exit status 1, so the module uses `ToolSession::run_ignoring_status`, which
returns the output whatever the status. The end-to-end test (`tests/server_module.rs`) puts
fake `apt-config` and `systemctl` first on `PATH`.

### Modules a profile adds

A lowering rule cannot say "this is wrong here and right elsewhere": that is a check, and
it would be noise on a machine it does not suit (a desktop left on `powersave` is
fine). So a profile may add modules, with these rules:

* **`Profile::modules()`** returns them. They are **not** in `all_modules()`; the engine
  builds the list for a run with `engine::modules_for(profile)` (the general modules, then
  the profile's), so a run without the profile cannot contain one
  (`a_profile_adds_its_modules_after_the_ones_every_audit_has`,
  `a_full_audit_has_no_hpc_module_without_the_profile`).
* **`Context` does not change.** A module reads what it needs itself, like any other.
* **`--modules` stays exact.** `--modules memory --profile hpc` runs memory only; naming the
  module needs the profile (`profile::module_needing_profile`), and asking for it without
  the profile stops with status 2 and a message that says what to type, before anything
  runs, for `audit` and `tui` alike (`asking_for_the_module_without_the_profile_is_refused_in_words_that_say_what_to_do`).
  The ids are known to the parser, so they are completed and listed in the manual page
  (`modules_accepts_the_ids_a_profile_adds_and_completions_offer_them`).
* **Ids are unique** across both lists (`a_module_a_profile_adds_never_takes_the_id_of_one_every_audit_has`).
* **`diff` needs nothing new.** A module present in one report only is already "not
  compared: not run", and the `different_profiles` caveat is already there.
* **Rule 2 does not apply to what the module finds**, since the module is the profile's own:
  its findings can be a Warning. They stay at Warning at most unless the failure is
  certain, so choosing a profile does not make the default exit status fail.

### Adding a profile or a rule

A rule must name a finding some module really produces (`the_rules_name_findings_the_cpu_module_really_produces`
guards the `hpc` ones), give a reason a reader can disagree with, and only lower. A profile
that needs a check the general audit does not make (what a server should have, for
instance) adds a module (above); it does not change `Context`. The module needs a line in
`module_summary()` (`src/manpage.rs`; a test fails until it exists) and its id must not
collide with an existing one. The word that chooses a profile lives in two places,
`Profile::name` and `cli::ProfileArg`, and a test walks both lists to keep them the same.

---

# Configuration

```
$XDG_CONFIG_HOME/linuxdoctor/config.toml      (~/.config/linuxdoctor/config.toml when unset)
```

An optional file holding the options a person would otherwise type every time. The
README ("The configuration file") shows it and `config::EXAMPLE` is the text a test
keeps identical in the README and the manual page.

| Key | Where | Same as |
|---|---|---|
| `timeout` | top level | `--timeout` (every command) |
| `profile` | top level only | `--profile` (`audit` and `tui`) |
| `fail_on`, `min_severity` | top level, or inside `[audit]` / `[diff]` | `--fail-on`, `--min-severity` |
| `output` | `[audit]` or `[diff]` only | `--output` (each command has its own formats) |

`src/config.rs` lives in the binary crate, next to `cli.rs`, because the words it accepts
are those of the `clap` enums. The design in five rules:

1. **The command line always wins.** The option structs in `cli.rs` hold `Option`s with no
   `clap` default, so "typed" can be told from "not typed" (`--output terminal` is a
   choice; nothing typed is not). `Settings::resolve` then applies, per option: typed >
   the command's section > the top-level line > the built-in default. A pure function,
   with the precedence tests next to it.
2. **One parser per word.** A value is read by `ValueEnum::from_str`, the very function
   behind the option it stands for, and the list of accepted words in an error comes from
   `value_variants()`. A new value or alias is available in the file and on the command
   line at once; a unit test walks every variant to keep it so.
3. **A mistake is an error, never a guess.** `deny_unknown_fields` everywhere, repeated
   keys refused by the parser, a missing `--config` file refused, and any of it ends the
   run with status 2 (`CONFIG_UNUSABLE`, the status of a usage error) before anything is
   collected. Only a *missing default file* is normal. `--no-config` is the way out.
4. **`--modules` is not configurable.** A file that quietly narrowed every audit would
   produce clean-looking reports of checks nobody made — the failure the module-id
   validation of `--modules` was written to prevent.
5. **The exit status explains where it came from.** `fail_on` is the one setting whose
   effect is not visible in the output, so a level chosen by the file carries
   `Origin::ConfigFile` and the stderr line that explains an exit of 1 quotes it
   (`fail_on = "warning" in <path>`) instead of `--fail-on warning`. The default gate
   stays silent, as before.

The file is untrusted text. It is looked at with `stat` before it is opened (a named pipe
would block `open`), must be a regular file of at most 64 KiB and valid UTF-8, and the
error message is built by `describe_error` — message, line number, and the offending line
cut to 100 characters and passed through `core::text::clean` — rather than taken from the
parser's own rendering, which quotes the whole line. `man` and `completions` do not read
the file at all; `tui` reads only `timeout` and `profile`.

`toml` is used with its `std`, `serde` and `parse` features only (reading, no writing),
pinned for Rust 1.75 (see the README "Toolchain note").

**Rule for tests:** a test that starts the real binary must keep it away from the
reader's own configuration file — `.env("XDG_CONFIG_HOME", "/nonexistent")` or
`--no-config`. `tests/config_file.rs` checks every file in `tests/` for it, so a person
with `fail_on = "never"` in their own file does not see the suite change its mind.

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
| `text.rs` | — (`is_safe_word`, `normalize`, `human_size`, `table`; `clean` now lives in `core::text` and is re-exported) | — |
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
(`tests/hung_tools.rs`, `tests/json_schema.rs`, `tests/export_and_gate.rs`,
`tests/docs_commands.rs` (it only prints generated text), one test of
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

# Manual Page and Shell Completions

`linuxdoctor man` and `linuxdoctor completions <shell>` print the manual page and the
completion scripts. Both are **generated at run time from the same `clap::Command` the
parser uses** (`cli::definition()`), never written by hand, so an option added to
`cli.rs` appears in `--help`, in the completion scripts and in the manual page at once.
Packaging (`build-deb.sh`, `build-rpm.sh`) runs the freshly built binary to produce the
files it installs, which is also why the page carries the version that was built.

`src/manpage.rs` assembles the page from `clap_mangen`'s section renderers plus a few
sections clap cannot know (description, exit status, examples, see also):

* **Commands** are rendered one by one, each with its own options. The options every
  command shares (`--timeout`, which is `global`, and the generated `-h`/`-V`) are hidden
  from those per-command renderings and appear once, under OPTIONS. The generated `help`
  command is left out.
* **Modules** are listed from the registry (`all_modules()`) with a one-line summary from
  `module_summary()`. The summary lives next to the page, not in the `Module` trait, so
  adding a module does not touch the trait; the unit test `every_registered_module_has_a_summary`
  fails until the line exists, and a module without one is still listed by id.
* **Deterministic output**: no date, no host name, so packaging the same source twice gives
  identical bytes. `clap_mangen` emits a two-line apostrophe preamble per rendered piece;
  the page keeps the first and drops the rest (`Page::piece`).
* **Fail loudly on layout drift**: reusing the body of a `clap_mangen` section means
  stripping its `.SH` heading. The crate is pinned to an exact version and the unit tests
  render the page, so a changed layout stops the build instead of printing a doubled heading.

`--modules` takes its accepted values from the same registry (`cli::module_ids()`, a clap
`PossibleValuesParser`). That is what lets shells complete module ids, and it closes a quiet
failure: an unknown id used to select no module and produce an empty report with exit
status 0.

`tests/docs_commands.rs` runs the real binary, and — when `groff` is installed — feeds the
page to `groff -man -ww` and requires no warning at all.

---

# Dependency Philosophy

Prefer the standard library. Add a dependency only when it clearly earns its keep:

* `thiserror` — exhaustive, low-boilerplate error types
* `serde` / `serde_json` — JSON output; hand-rolled serialization is a maintenance
  and correctness risk for no real benefit here
* `clap` (derive) — CLI parsing; the UX surface (module selection, output format,
  verbosity, filtering) grows quickly enough that hand-rolled parsing stops paying
  off almost immediately
* `clap_complete` / `clap_mangen` — shell completions and the manual page, generated from
  the same definition as the parser so they cannot drift from it (a hand-written copy would,
  the first time an option changed). They add only `roff` to the dependency tree.
  Pinned to the last releases that accept `clap` 4.4 on Rust 1.75 (README "Toolchain note").

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

What the audited machine and the files it is compared with can say is untrusted: it is
neutralised before any renderer but JSON shows it (see "Text from the audited machine"),
and Markdown and HTML escape their own markup on top of that.

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
