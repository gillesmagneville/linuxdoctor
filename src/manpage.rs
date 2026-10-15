// SPDX-License-Identifier: GPL-3.0-only

//! The manual page printed by `linuxdoctor man`.
//!
//! Everything that describes an option comes from the same clap definition
//! the parser uses (through `clap_mangen`), and the list of modules comes
//! from the module registry, so the page cannot disagree with the program.
//! What clap cannot know -- the overview, the exit statuses, the examples --
//! is written here, and the tests below tie it to the real behaviour.
//!
//! The page is deterministic: no date and no build host, only the program
//! version, so packaging the same source twice gives byte-identical files.

use std::io::{self, Write};

use clap::Command;
use clap_mangen::roff::{bold, roman, Roff};
use clap_mangen::Man;

/// What each module is for, in one line. A module id without an entry is
/// still listed (by id only) rather than breaking the page; the test
/// `every_registered_module_has_a_summary` makes sure that never ships.
fn module_summary(id: &str) -> Option<&'static str> {
    Some(match id {
        "memory" => {
            "Memory use, page cache, shared memory, swap, memory pressure and kernel memory tuning."
        }
        "cpu" => "CPU topology, load, sustained overload and CPU isolation.",
        "numa" => "NUMA nodes: per-node CPU and memory, usage balance and topology symmetry.",
        "gpu" => "AMD and NVIDIA graphics cards: temperature, memory, clocks and PCIe link.",
        "storage" => "Disk space and inodes per filesystem, and the SMART health of each disk.",
        "systemd" => "Overall systemd state and failed units.",
        "ntp" => "Clock synchronization and real-time clock mode.",
        "network" => "Interfaces, error and drop rates, default gateway and DNS configuration.",
        "security" => {
            "Listening services, firewall, SSH configuration, SELinux and AppArmor, kernel \
             hardening, accounts and permissions of sensitive files."
        }
        "logs" => {
            "Failed logins, system errors, kernel messages, and the health of the journal \
             and of the log files."
        }
        "kernel" => "Kernel taint status, out-of-memory kills, build information, pending reboot and boot parameters.",
        "firmware" => {
            "BIOS/UEFI identity, boot mode, Secure Boot, virtualization extensions, IOMMU and TPM."
        }
        "virtualization" => {
            "Whether this machine is a virtual machine, and the virtual machines and containers \
             it hosts."
        }
        _ => return None,
    })
}

/// The two lines every `roff` writer starts its output with (they define how
/// an apostrophe is typeset). Each piece of the page is rendered separately,
/// so the pair is kept once, at the top, and dropped from the rest.
const PREAMBLE: &[u8] = b".ie \\n(.g .ds Aq \\(aq\n.el .ds Aq '\n";

/// The page being assembled, piece by piece.
#[derive(Default)]
struct Page {
    bytes: Vec<u8>,
}

impl Page {
    /// Appends a piece of ready-made roff, without its repeated preamble.
    fn piece(&mut self, piece: &[u8]) {
        let piece = if self.bytes.is_empty() {
            piece
        } else {
            piece.strip_prefix(PREAMBLE).unwrap_or(piece)
        };
        self.bytes.extend_from_slice(piece);
    }

    /// Appends what `fill` writes on a fresh [`Roff`].
    fn roff(&mut self, fill: impl FnOnce(&mut Roff)) -> io::Result<()> {
        let mut roff = Roff::new();
        fill(&mut roff);
        let mut piece = Vec::new();
        roff.to_writer(&mut piece)?;
        self.piece(&piece);
        Ok(())
    }

    /// Appends one of `clap_mangen`'s section renderers whole.
    fn rendered(
        &mut self,
        render: impl FnOnce(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut piece = Vec::new();
        render(&mut piece)?;
        self.piece(&piece);
        Ok(())
    }

    /// Appends the body of one of `clap_mangen`'s section renderers: the
    /// renderer starts with its own `.SH` heading, which this page replaces
    /// with its own wording or merges under a subsection. The crate is
    /// pinned to an exact version in Cargo.toml and the unit tests render
    /// the page, so a change in its output cannot slip in unnoticed; if it
    /// does differ, this fails loudly instead of printing a doubled heading.
    fn section_body(
        &mut self,
        render: impl FnOnce(&mut dyn Write) -> io::Result<()>,
        heading: &str,
    ) -> io::Result<()> {
        let mut piece = Vec::new();
        render(&mut piece)?;
        let piece = piece.strip_prefix(PREAMBLE).unwrap_or(&piece);
        let marker = format!(".SH {heading}\n");
        match piece.strip_prefix(marker.as_bytes()) {
            Some(body) => {
                self.piece(body);
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected manual page layout: no `{heading}` heading"),
            )),
        }
    }
}

/// Renders the whole page. `root` is the program's clap definition and
/// `module_ids` the ids of every registered module, in the order the
/// program runs them.
pub fn render(root: &Command, module_ids: &[&str]) -> io::Result<Vec<u8>> {
    // Building the command fills in what clap works out itself (the full
    // name of each subcommand, the generated help flag, the version).
    let mut root = root.clone();
    root.build();
    let top = Man::new(root.clone()).title("LINUXDOCTOR");
    // `help` is generated by clap and says nothing the page does not.
    let commands: Vec<&Command> = root
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();

    let mut page = Page::default();
    page.rendered(|w| top.render_title(w))?;
    page.rendered(|w| top.render_name_section(w))?;

    // SYNOPSIS: the program, then one line per command.
    page.roff(|r| {
        r.control("SH", ["SYNOPSIS"]);
    })?;
    page.section_body(|w| top.render_synopsis_section(w), "SYNOPSIS")?;
    for command in &commands {
        page.roff(|r| {
            r.control("br", []);
        })?;
        let man = Man::new(without_inherited_options(command));
        page.section_body(|w| man.render_synopsis_section(w), "SYNOPSIS")?;
    }

    write_description(&mut page)?;

    // OPTIONS: the ones every command shares, once.
    page.rendered(|w| top.render_options_section(w))?;

    // COMMANDS: each with its own options, the shared ones left out.
    page.roff(|r| {
        r.control("SH", ["COMMANDS"]);
    })?;
    for command in &commands {
        let about = command.get_long_about().or_else(|| command.get_about());
        page.roff(|r| {
            r.control("SS", [command.get_name()]);
            if let Some(about) = about {
                r.text([roman(about.to_string())]);
            }
            r.control("PP", []);
        })?;
        let man = Man::new(without_inherited_options(command));
        page.section_body(|w| man.render_synopsis_section(w), "SYNOPSIS")?;
        if has_own_options(command) {
            page.section_body(|w| man.render_options_section(w), "OPTIONS")?;
        }
    }

    write_modules(&mut page, module_ids)?;
    write_exit_status(&mut page)?;
    write_examples(&mut page)?;
    write_closing(&mut page)?;
    Ok(page.bytes)
}

/// A copy of `command` without the options every command shares (the ones
/// declared `global`, and the generated help and version flags), which the
/// page documents once, under OPTIONS, instead of under every command.
fn without_inherited_options(command: &Command) -> Command {
    command.clone().mut_args(|arg| {
        let hidden = arg.is_global_set()
            || arg.is_hide_set()
            || arg.get_id() == "help"
            || arg.get_id() == "version";
        arg.hide(hidden)
    })
}

fn has_own_options(command: &Command) -> bool {
    command.get_arguments().any(|a| {
        !a.is_global_set() && !a.is_hide_set() && a.get_id() != "help" && a.get_id() != "version"
    })
}

fn paragraph(roff: &mut Roff, text: &str) {
    roff.control("PP", []);
    roff.text([roman(text)]);
}

fn write_description(page: &mut Page) -> io::Result<()> {
    page.roff(|r| {
        r.control("SH", ["DESCRIPTION"]);
        r.text([
            bold("linuxdoctor"),
            roman(
                " audits a Linux machine and explains what it finds. It reads the kernel's own \
                 files (/proc and /sys), configuration files and the output of standard tools, \
                 and reports each finding with a severity, a confidence level, the evidence \
                 behind it, an explanation and, for anything above Info, numbered steps to \
                 fix it.",
            ),
        ]);
        paragraph(
            r,
            "The audit is strictly read-only: it never changes the system, and the commands it \
             suggests are only printed, never run. Run it as root for full detail; without \
             root, each finding says what it could not see, and a source that could not be \
             read is reported as such rather than as a clean result.",
        );
        paragraph(
            r,
            "Severities, from least to most serious, are Info, Warning, Error and Critical. \
             Info findings describe the machine and are not problems.",
        );
        paragraph(
            r,
            "To see what changed on a machine, keep the JSON report of an audit (audit --output \
             json) and compare it with a later one (diff): the comparison lists the findings \
             that appeared, the ones that were resolved and the ones that got worse or better. \
             A finding only counts as resolved when the module that would have reported it ran \
             to the end in the later report; a module that failed, was skipped or was not run \
             there is listed as not compared instead.",
        );
        paragraph(
            r,
            "Without a command, linuxdoctor opens the interactive interface (tui) when both \
             standard input and standard output are a terminal, and prints a plain-text audit \
             otherwise, so that redirections and pipes keep working.",
        );
    })
}

fn write_modules(page: &mut Page, module_ids: &[&str]) -> io::Result<()> {
    page.roff(|r| {
        r.control("SH", ["MODULES"]);
        r.text([
            roman("The audit is made of independent modules, which run concurrently. "),
            roman("Select some of them with "),
            bold("--modules"),
            roman(" (a comma-separated list of the ids below); without it, all of them run."),
        ]);
        for id in module_ids {
            // 16 columns: wide enough for the longest id, so every
            // description starts at the same place.
            r.control("TP", ["16"]);
            r.text([bold(*id)]);
            if let Some(summary) = module_summary(id) {
                r.text([roman(summary)]);
            }
        }
    })
}

fn write_exit_status(page: &mut Page) -> io::Result<()> {
    page.roff(|r| {
        r.control("SH", ["EXIT STATUS"]);
        for (status, meaning) in [
            (
                "0",
                "audit: the audit ran and no finding reached the --fail-on level. diff: no \
                 finding appeared or got worse to the --fail-on level. The manual page or the \
                 completion script was printed.",
            ),
            (
                "1",
                "audit: a finding reached the --fail-on level (by default error: Error and \
                 Critical findings), or the audit itself could not run, or the output could not \
                 be written. diff: a finding appeared, or got worse, and is now at the --fail-on \
                 level or above.",
            ),
            (
                "2",
                "Command-line usage error, including an unknown module id. diff: a report could \
                 not be read, is not a LinuxDoctor report, or was written by a newer version; \
                 nothing was compared.",
            ),
        ] {
            r.control("TP", []);
            r.text([bold(status)]);
            r.text([roman(meaning)]);
        }
        paragraph(
            r,
            "--fail-on always judges the whole report (or, for diff, the whole comparison), \
             before --min-severity filters what is displayed: hiding findings never turns a \
             failing audit into a passing one. A module that could not run is reported as such \
             but is not a finding, so it does not change the exit status; likewise, diff lists \
             the modules it could not compare without failing because of them. A finding that \
             was already there in both reports is not a regression, however serious: that is \
             what audit --fail-on is for.",
        );
    })
}

fn write_examples(page: &mut Page) -> io::Result<()> {
    page.roff(|r| {
        r.control("SH", ["EXAMPLES"]);
        for (command, what) in [
            (
                "linuxdoctor audit --modules security,logs",
                "Check only the Security and Logs modules.",
            ),
            (
                "linuxdoctor audit --output html > report.html",
                "Write a single self-contained HTML page to keep or share.",
            ),
            (
                "linuxdoctor audit --min-severity warning",
                "Show only Warning findings and worse.",
            ),
            (
                "linuxdoctor audit --fail-on warning --output json > report.json",
                "For scripts and CI: exit with status 1 on any Warning or worse, and keep the \
                 full JSON report.",
            ),
            (
                "linuxdoctor audit --output json > before.json",
                "Keep a report to compare with later (the same command, after a change, writes \
                 after.json).",
            ),
            (
                "linuxdoctor diff before.json after.json",
                "Show what appeared, was resolved, got worse or got better between the two.",
            ),
            (
                "linuxdoctor diff before.json after.json --fail-on warning --output markdown",
                "For a change review: a Markdown comparison, and exit status 1 if a Warning or \
                 worse appeared or got worse.",
            ),
            (
                "linuxdoctor audit --output json | linuxdoctor diff before.json -",
                "Compare a saved report with a fresh audit, without writing the fresh one to a file.",
            ),
            (
                "linuxdoctor audit --timeout 30",
                "Allow each external tool 30 seconds instead of the default 10.",
            ),
            (
                "source <(linuxdoctor completions bash)",
                "Enable bash completion in the current shell (put the line in ~/.bashrc to keep it).",
            ),
        ] {
            r.control("TP", []);
            r.text([bold(command)]);
            r.text([roman(what)]);
        }
    })
}

fn write_closing(page: &mut Page) -> io::Result<()> {
    page.roff(|r| {
        r.control("SH", ["SEE ALSO"]);
        r.text([roman(
            "The tools it uses when they are installed: journalctl(1), systemctl(1), \
             timedatectl(1), dmesg(1), smartctl(8), nvidia-smi(1), virsh(1), docker(1), \
             podman(1), nft(8), iptables(8).",
        )]);
        r.control("SH", ["REPORTING BUGS"]);
        r.text([roman(format!(
            "Project page and issue tracker: {}",
            env!("CARGO_PKG_REPOSITORY")
        ))]);
        r.control("SH", ["LICENSE"]);
        r.text([roman(
            "GNU General Public License, version 3 only (GPL-3.0-only).",
        )]);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli;

    /// The text of `page` from the line `from` up to the line `to`.
    fn section<'a>(page: &'a str, from: &str, to: &str) -> &'a str {
        let start = page.find(from).unwrap_or_else(|| panic!("{from} missing"));
        let len = page[start..]
            .find(to)
            .unwrap_or_else(|| panic!("{to} missing"));
        &page[start..start + len]
    }

    fn page() -> String {
        let ids: Vec<&str> = linuxdoctor::modules::all_modules()
            .iter()
            .map(|m| m.id())
            .collect();
        let bytes = render(&cli::definition(), &ids).expect("the page renders");
        String::from_utf8(bytes).expect("the page is UTF-8")
    }

    #[test]
    fn every_registered_module_has_a_summary() {
        for module in linuxdoctor::modules::all_modules() {
            assert!(
                module_summary(module.id()).is_some(),
                "module `{}` is registered but has no line in the manual page \
                 (add it to module_summary in src/manpage.rs)",
                module.id()
            );
        }
    }

    #[test]
    fn every_module_is_listed_in_the_page() {
        let page = page();
        for module in linuxdoctor::modules::all_modules() {
            assert!(
                page.contains(&format!("\\fB{}\\fR\n", module.id())),
                "{} missing from the MODULES section",
                module.id()
            );
        }
    }

    #[test]
    fn has_the_standard_sections_in_order() {
        let page = page();
        let mut at = 0;
        for heading in [
            ".SH NAME",
            ".SH SYNOPSIS",
            ".SH DESCRIPTION",
            ".SH OPTIONS",
            ".SH COMMANDS",
            ".SH MODULES",
            ".SH \"EXIT STATUS\"",
            ".SH EXAMPLES",
            ".SH \"SEE ALSO\"",
            ".SH \"REPORTING BUGS\"",
            ".SH LICENSE",
        ] {
            let found = page[at..]
                .find(heading)
                .unwrap_or_else(|| panic!("{heading} missing or out of order"));
            at += found + heading.len();
        }
    }

    #[test]
    fn documents_every_visible_command_and_its_options() {
        let page = page();
        for command in ["audit", "tui", "diff", "completions", "man"] {
            assert!(page.contains(&format!(".SS {command}\n")), "{command}");
        }
        for option in [
            "modules",
            "output",
            "min\\-severity",
            "fail\\-on",
            "timeout",
        ] {
            assert!(page.contains(option), "--{option} is not in the page");
        }
        // The values of --output come straight from the enum.
        for value in ["terminal", "json", "markdown", "html"] {
            assert!(page.contains(value), "{value}");
        }
    }

    #[test]
    fn global_options_are_documented_once_not_under_every_command() {
        let page = page();
        let commands = section(&page, ".SH COMMANDS", ".SH MODULES");
        assert!(
            !commands.contains("\\-\\-timeout"),
            "--timeout is shared by every command and belongs under OPTIONS only:\n{commands}"
        );
        assert!(
            !commands.contains("\\-\\-help"),
            "the generated help flag must not be repeated under each command:\n{commands}"
        );
        let options = section(&page, ".SH OPTIONS", ".SH COMMANDS");
        assert!(options.contains("\\-\\-timeout"), "{options}");
    }

    #[test]
    fn the_generated_help_command_is_not_listed() {
        assert!(!page().contains(".SS help"));
    }

    #[test]
    fn carries_the_program_version_and_no_date() {
        let page = page();
        let th = page
            .lines()
            .find(|l| l.starts_with(".TH "))
            .expect("a .TH line");
        // Title, section, an empty date (so the bytes do not depend on when
        // the page was built), then the program and its version.
        assert!(
            th.starts_with(&format!(
                ".TH LINUXDOCTOR 1  \"linuxdoctor {}\"",
                env!("CARGO_PKG_VERSION")
            )),
            "{th}"
        );
    }

    #[test]
    fn exit_statuses_match_the_documented_contract() {
        let page = page();
        let exit = &page[page.find(".SH \"EXIT STATUS\"").unwrap()..];
        for status in ["\\fB0\\fR", "\\fB1\\fR", "\\fB2\\fR"] {
            assert!(exit.contains(status), "{status}");
        }
        // The comparison has its own meaning for 1 and 2.
        assert!(exit.contains("diff:"), "{exit}");
    }

    #[test]
    fn the_examples_show_how_to_compare_two_reports() {
        let page = page();
        let examples = &page[page.find(".SH EXAMPLES").unwrap()..];
        assert!(
            examples.contains("linuxdoctor diff before.json after.json"),
            "{examples}"
        );
    }

    #[test]
    fn rendering_twice_gives_identical_bytes() {
        assert_eq!(page(), page());
    }

    #[test]
    fn a_module_without_a_summary_is_still_listed() {
        let bytes = render(&cli::definition(), &["brand-new"]).unwrap();
        let page = String::from_utf8(bytes).unwrap();
        assert!(page.contains("\\fBbrand\\-new\\fR\n"), "{page}");
    }
}
