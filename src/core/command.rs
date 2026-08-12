// SPDX-License-Identifier: GPL-3.0-only

use std::process::Command;

/// Build a `Command` with the locale forced to `C` (POSIX/English).
///
/// Every collector that shells out to a human-oriented CLI tool and
/// parses its text output needs this. Confirmed against a real report:
/// `virsh dominfo` on a French-locale desktop returned `state: unknown`
/// for every VM, because `virsh` translates its field labels via
/// gettext (e.g. `State:` becomes something else entirely) and the
/// parser was matching the English string. This sandbox's own libvirt
/// package ships no French translation data at all (`libvirt-l10n`
/// installs empty), so the exact mismatch couldn't be reproduced
/// here — but the fix doesn't depend on reproducing it: forcing the C
/// locale eliminates the entire category for any gettext-based tool,
/// regardless of which language triggered it.
///
/// `smartctl --json`, `timedatectl show`, `docker ... --format`, and
/// `systemd-detect-virt` all use structured/machine-readable output
/// modes that don't translate their keys, so they were never actually
/// at risk — but every caller here uses this helper anyway, on the
/// principle that "doesn't currently need it" is a fragile thing to
/// rely on as these tools evolve.
pub fn command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("LC_ALL", "C").env("LANG", "C");
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_runs_and_reports_c_locale_to_the_child() {
        // `env` itself is locale-agnostic, but this confirms the env vars
        // are actually being set on the spawned process, not just present
        // on our own.
        let output = command("sh")
            .args(["-c", "echo $LC_ALL $LANG"])
            .output()
            .expect("sh should be available in any test environment");
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(text.trim(), "C C");
    }
}
