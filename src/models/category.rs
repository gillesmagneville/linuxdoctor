use serde::Serialize;
use std::fmt;

/// Every diagnostic category named in PROJECT_CONTEXT.md. Not every variant
/// has a shipping module yet (v1 ships `Memory` only) — the enum exists up
/// front so `Finding.category` has a stable, exhaustive type from day one.
// Most variants have no shipping module yet (v1 ships `Memory` only) and so
// are intentionally unconstructed for now — see PROJECT_CONTEXT.md
// "Diagnostic Categories".
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Cpu,
    Memory,
    Numa,
    Kernel,
    Scheduler,
    Storage,
    Smart,
    Filesystem,
    Network,
    Dns,
    Ntp,
    Ssh,
    Tls,
    Systemd,
    Logs,
    Containers,
    Virtualization,
    Security,
    Performance,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
