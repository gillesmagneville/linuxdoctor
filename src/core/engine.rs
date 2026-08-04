// SPDX-License-Identifier: GPL-3.0-only

use serde::Serialize;

use crate::core::context::Context;
use crate::core::error::CoreError;
use crate::models::Finding;
use crate::modules::all_modules;

/// One module's outcome: either the findings it produced, or a note that it
/// failed / was skipped. Kept separate from `Finding` so a collector failure
/// is visible in output rather than silently disappearing.
#[derive(Serialize)]
pub struct ModuleRunResult {
    pub module_id: &'static str,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    pub skipped: bool,
}

#[derive(Serialize)]
pub struct Report {
    pub context: Context,
    pub results: Vec<ModuleRunResult>,
}

impl Report {
    pub fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.results.iter().flat_map(|r| r.findings.iter())
    }

    pub fn highest_severity(&self) -> Option<crate::models::Severity> {
        self.all_findings().map(|f| f.severity).max()
    }
}

/// Run every registered module, isolating failures per ARCHITECTURE.md
/// "Error Handling": one module failing never stops the others.
///
/// v1 runs modules sequentially. Modules don't depend on each other's
/// output (see ARCHITECTURE.md "Context"), so switching this loop to
/// `std::thread::scope` later is a pure performance change, not a
/// correctness one — not worth doing yet with a single module.
pub fn run_audit(selected_ids: Option<&[String]>) -> Result<Report, CoreError> {
    let context = Context::detect()?;
    let modules = all_modules();

    let mut results = Vec::new();
    for module in &modules {
        if let Some(ids) = selected_ids {
            if !ids.iter().any(|id| id == module.id()) {
                continue;
            }
        }

        if !module.is_available(&context) {
            results.push(ModuleRunResult {
                module_id: module.id(),
                findings: Vec::new(),
                error: None,
                skipped: true,
            });
            continue;
        }

        match module.run(&context) {
            Ok(findings) => results.push(ModuleRunResult {
                module_id: module.id(),
                findings,
                error: None,
                skipped: false,
            }),
            Err(e) => results.push(ModuleRunResult {
                module_id: module.id(),
                findings: Vec::new(),
                error: Some(e.to_string()),
                skipped: false,
            }),
        }
    }

    Ok(Report { context, results })
}
