// SPDX-License-Identifier: GPL-3.0-only

use thiserror::Error;

// Context::detect() currently degrades gracefully per-field rather than
// failing outright, so this variant has no caller yet. Kept for the day a
// context fact becomes mandatory (e.g. a required module dependency).
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("failed to build system context: {0}")]
    ContextError(String),
}

/// Error surfaced by a module's `run()`. Per ARCHITECTURE.md "Error
/// Handling", a module error is isolated by the engine and never stops
/// other modules from running.
#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {what}: {reason}")]
    Parse { what: String, reason: String },
}
