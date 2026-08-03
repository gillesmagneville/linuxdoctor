# PROJECT_CONTEXT.md

# LinuxDoctor

**LinuxDoctor** is an open-source Linux diagnostic and auditing tool written in **Rust**.

Its goal is to provide a fast, reliable and understandable health assessment of a Linux
system by collecting system information, detecting configuration issues, identifying
common performance bottlenecks, and explaining their potential impact.

LinuxDoctor is intended for:

* Linux system administrators
* DevOps engineers
* HPC administrators
* Power users
* Developers
* Technical support engineers

It is designed to work on a **single Linux machine** without requiring external
infrastructure.

> **Note on this document:** PROJECT_CONTEXT.md defines *why* the project exists and
> *what* it values. It intentionally does not restate exact type definitions, enum
> values, or trait signatures — those live once, canonically, in `ARCHITECTURE.md`,
> so the two documents cannot silently drift apart again.

---

# Vision

Most Linux diagnostic tools expose raw data.

LinuxDoctor aims to answer a more useful question:

> **"Is my Linux system healthy, and if not, why?"**

Rather than replacing existing tools such as:

* top
* htop
* vmstat
* iostat
* journalctl
* lscpu
* lsblk
* smartctl

LinuxDoctor combines information from many sources and provides a coherent diagnosis.

---

# Project Philosophy

LinuxDoctor follows five principles.

## 1. Explain instead of dumping data

Bad:

```
vm.swappiness = 60
```

Good:

```
vm.swappiness = 60

Default kernel value.

For a desktop with large amounts of RAM,
a lower value is often preferred.

No action required unless swap activity is high.
```

---

## 2. Read-only by default

LinuxDoctor never modifies the system.

It:

* reads
* analyzes
* reports

It never:

* edits configuration
* changes kernel parameters
* restarts services
* installs packages

Future versions may generate suggested commands but never execute them automatically.

---

## 3. Evidence-based diagnostics

Every finding must be supported by observable facts. Never guess.

Each finding includes collected evidence, a plain-language explanation, a confidence
level, and possible actions. The exact `Finding` structure and the confidence scale
are defined in `ARCHITECTURE.md`.

---

## 4. Modular architecture

Every subsystem is independent:

```
CPU
Memory
Storage
Network
Security
Systemd
Filesystems
Kernel
Virtualization
Containers
```

Modules can be added, removed, or extended without touching the core engine or other
modules. The exact module contract is defined in `ARCHITECTURE.md`.

---

## 5. Fast

Typical execution time should remain below:

* 2 seconds on modern hardware
* 5 seconds on older systems

Long-running tests must always be optional.

---

# Project Scope

LinuxDoctor focuses on:

* system diagnostics
* configuration auditing
* health reporting
* performance analysis
* best-practice detection

LinuxDoctor is **not**:

* a monitoring daemon
* a metrics database
* a Prometheus exporter
* an IDS
* an antivirus
* a configuration management tool
* a benchmark suite

---

# Target Platforms

Primary target: Linux.

Supported architectures:

* x86_64
* ARM64

Supported distributions:

* Debian
* Ubuntu
* Fedora
* RHEL
* Rocky
* AlmaLinux
* openSUSE
* Arch Linux

Support for additional distributions should require minimal platform-specific code.

---

# User Experience

Running LinuxDoctor should be simple.

```
linuxdoctor
```

or

```
linuxdoctor audit
```

The output should be readable by humans.

Machine-readable formats should also be available:

* JSON (v1)
* YAML (future)
* HTML report (future)

---

# Diagnostic Categories

Examples:

* CPU
* Memory
* NUMA
* Kernel
* Scheduler
* Storage
* SMART
* Filesystems
* Network
* DNS
* NTP
* SSH
* TLS
* Systemd
* Logs
* Containers
* Virtualization
* Security
* Performance

Each category can eventually contain dozens of checks. Not every category needs a
module in v1 — see `ARCHITECTURE.md` for what ships first.

---

# Severity and Confidence

Findings carry a severity (reflecting operational impact) and a confidence level
(reflecting how strongly the evidence supports the finding). Neither is ever
alarmist by default, and confidence never exceeds what the evidence actually shows.

The exact severity levels and confidence scale are defined once, in
`ARCHITECTURE.md`, and used identically everywhere in the codebase.

---

# Explain Every Recommendation

Recommendations must answer three questions:

## What was detected?

## Why does it matter?

## What can the administrator do?

Recommendations should avoid alarmist language.

---

# Extensibility

Every diagnostic module exposes a common interface so new modules can be added
without changing the core engine. See `ARCHITECTURE.md` for the trait definition.

---

# Performance Goals

* Memory usage: < 100 MB
* Typical runtime: < 2 seconds
* Zero background processes
* No telemetry
* No cloud dependency

---

# Coding Principles

* Rust stable only — no nightly features
* Prefer safe Rust
* Prefer the standard library; add a dependency only when it clearly earns its place
* Zero-copy where practical
* Strong typing, exhaustive error handling
* Unsafe code avoided whenever possible

---

# Output Principles

Output should be concise, actionable, and educational.

Good:

```
Swap usage detected.

Current usage:
2.1 GB

This is not necessarily a problem.

High swap usage combined with sustained disk I/O may indicate memory pressure.
```

Bad:

```
Swap = 2.1 GB
```

---

# Future Vision

Future versions may include:

* HTML reports
* Trend comparison
* Configuration snapshots
* Interactive TUI
* Plugin system
* Remote auditing over SSH
* Declarative rule packs
* Enterprise profiles
* HPC / Desktop / Server profiles

None of these are required for LinuxDoctor to be useful. v1 is deliberately narrow:
a small core, a handful of real modules, terminal and JSON output.

---

# Non-Goals

LinuxDoctor will never attempt to become:

* another monitoring platform
* another SIEM
* another configuration manager
* another orchestration tool

It should remain a lightweight diagnostic utility.

---

# Project Values

LinuxDoctor values:

* correctness
* clarity
* speed
* reliability
* transparency
* educational output
* portability

Above all:

**Every warning must teach something useful to the user.**
