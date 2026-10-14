// SPDX-License-Identifier: GPL-3.0-only

//! The recommendation layout shared by every module: numbered steps with
//! copy-pasteable commands on their own indented lines. No I/O.

/// Builds the multi-line, numbered recommendation text:
///
/// ```text
/// 1. Find what is using the memory:
///     ps -eo pid,user,rss,comm --sort=-rss | head -15
/// 2. ...
/// ```
///
/// Commands sit on their own indented lines so they can be copied as they
/// are; the prose never contains a command that is not shown this way.
/// Every command is a *suggestion for the administrator to run* —
/// LinuxDoctor never executes any of them.
#[derive(Default)]
pub struct Steps {
    steps: Vec<(String, Vec<String>)>,
}

impl Steps {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn step(mut self, text: impl Into<String>, commands: &[&str]) -> Self {
        self.steps.push((
            text.into(),
            commands.iter().map(|c| c.to_string()).collect(),
        ));
        self
    }

    pub fn step_owned(mut self, text: impl Into<String>, commands: Vec<String>) -> Self {
        self.steps.push((text.into(), commands));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn build(&self) -> String {
        let mut out = String::new();
        for (i, (text, commands)) in self.steps.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!("{}. {}", i + 1, text));
            for command in commands {
                out.push_str(&format!("\n    {command}"));
            }
        }
        out
    }
}

/// Commands that make a sysctl change immediate and persistent.
pub fn sysctl_commands(setting: &str, file: &str) -> Vec<String> {
    vec![
        format!("sudo sysctl {setting}"),
        format!(
            "echo '{}' | sudo tee /etc/sysctl.d/{file}",
            setting.replacen('=', " = ", 1)
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_are_numbered_with_commands_on_their_own_lines() {
        let text = Steps::new()
            .step("Find the consumers:", &["ps aux", "smem -tk"])
            .step("Restart the leaker.", &[])
            .build();
        assert_eq!(
            text,
            "1. Find the consumers:\n    ps aux\n    smem -tk\n2. Restart the leaker."
        );
    }

    #[test]
    fn sysctl_commands_apply_now_and_persist() {
        let cmds = sysctl_commands("vm.swappiness=10", "99-swappiness.conf");
        assert_eq!(cmds[0], "sudo sysctl vm.swappiness=10");
        assert_eq!(
            cmds[1],
            "echo 'vm.swappiness = 10' | sudo tee /etc/sysctl.d/99-swappiness.conf"
        );
    }

    #[test]
    fn empty_steps_report_empty() {
        assert!(Steps::new().is_empty());
        assert_eq!(Steps::new().build(), "");
    }
}
