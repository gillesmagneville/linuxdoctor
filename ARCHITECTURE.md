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
│   │   ├── context.rs        # shared, read-only system facts
│   │   ├── engine.rs         # orchestration, failure isolation
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
│   │   ├── memory/
│   │   ├── cpu/
│   │   ├── numa/
│   │   ├── storage/
│   │   ├── systemd/
│   │   ├── ntp/
│   │   ├── network/
│   │   ├── kernel/
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
│       ├── terminal.rs       # text + ANSI colors
│       ├── json.rs           # JSON
│       └── tui.rs            # interactive UI (ratatui) — see "Output Engine"
│
└── tests/
    # one fixture-driven integration test file per module, e.g.
    ├── memory_module.rs
    ├── cpu_module.rs
    ├── numa_module.rs
    ├── storage_module.rs
    ├── systemd_module.rs
    ├── ntp_module.rs
    ├── network_module.rs
    ├── kernel_module.rs
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
Output Formatter (terminal | json | tui)
 ↓
Exit code reflects highest severity found
```

---

# Core Components

## CLI

Parses arguments, selects modules, selects output format, sets verbosity. Contains
no diagnostic logic.

## Core Engine

Orchestrates execution, builds `Context`, isolates per-module failures, aggregates
`Finding`s into a `Report`. The engine never interprets system data itself — that is
always a module's job.

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
no direct kernel interface for the fact needed. Network is a clean example of the
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
inventory via libvirt) and `docker`/`podman` (Virtualization, host-side container
inventory — tried in that order, first one whose daemon is actually reachable wins).
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

Example:

```
MEM002 — Swap Activity
WARNING · Confidence: 85% (strong indication)

Evidence
  Swap used:     4.2 GB
  Free RAM:      420 MB (4.1% of total)

Explanation
  The system is actively swapping while very little RAM remains free.
  This commonly indicates memory pressure, not necessarily a problem
  on its own, but worth investigating if performance feels degraded.

Recommendation
  Identify high-memory processes (ps, smem) and consider whether
  more RAM or lower memory usage is needed.
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

Supported now: Terminal, JSON, interactive TUI.
Future: HTML, Markdown.

Output formatters only render `Finding`s — they never compute severity, confidence,
or evidence themselves.

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

Serializes the full `Report` — `context` once, then `results` grouped by module
(`module_id`, that module's `findings`, and `error`/`skipped` for modules that didn't
run cleanly):

```json
{
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
      "skipped": false
    },
    {
      "module_id": "systemd",
      "findings": [],
      "error": null,
      "skipped": true
    }
  ]
}
```

## Interactive TUI

The third output mode, built on `ratatui`. Consumes the same `Report` as the other
two — no diagnostic logic lives here either. Its one piece of extra behavior:
modules whose findings include 2+ distinct `Finding.instance` values get a real,
navigable submenu (`Enter` to drill in, `Esc` to back out, `PgUp`/`PgDn` to move
through whichever list — modules or, once drilled in, that module's instances —
is currently focused; `↑`/`↓` scroll the detail pane). Below 2 instances, a module's
findings are shown flat, exactly as Terminal/JSON always do. See `src/output/tui.rs`
for the implementation and `Finding.instance` above for the mechanism this is built
on.

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
execution is embarrassingly parallel — no dependency graph or scheduler is needed
yet. Use `std::thread::scope` (stdlib, zero dependencies) once there are enough
modules for parallelism to matter; an async runtime (`tokio`) is deliberately not
used, since the actual work is short-lived blocking I/O (`/proc` reads, occasional
subprocess calls), not high-concurrency networking — pulling in an async runtime for
that would violate the "every dependency must justify its existence" principle.

---

# Error Handling

A collector or module failure never stops the run. Example: SMART unavailable →
the Storage module continues, SMART findings are simply absent, and the failure is
recorded (not silently dropped) so the user can see what didn't run and why.

---

# Configuration

```
~/.config/linuxdoctor/config.toml
```

```toml
output = "terminal"
parallel = true
colors = true
timeout = 5
```

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
Rocky, AlmaLinux). Not part of `cargo test`; run in CI on real or containerized
targets.

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
