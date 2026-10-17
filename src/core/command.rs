// SPDX-License-Identifier: GPL-3.0-only

use std::cell::RefCell;
use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// How long one external command may run before it is stopped, unless the
/// user changes it with `--timeout`. Ten seconds is far above what any
/// tool called here needs on a healthy machine (`df`, `lspci` and
/// `systemctl` answer in milliseconds), and still short enough that a
/// wedged daemon or a hung disk costs one visible pause rather than a
/// frozen terminal.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Factor applied by [`Cmd::slow`]: tools that may have to wake a
/// sleeping disk (`smartctl`) or initialize a driver (`nvidia-smi`) get
/// twice the normal allowance.
const SLOW_FACTOR: u32 = 2;

/// Extra time granted after the deadline for the reader threads to hand
/// over output the child already wrote. Keeps a command that finished
/// right at the deadline from losing its output.
const READER_GRACE: Duration = Duration::from_millis(250);

/// How long to wait for the OS to reap a child after `kill()`. A process
/// stuck in uninterruptible I/O (a dead NFS mount, a failing disk) cannot
/// be killed until the I/O returns, so waiting for it forever would
/// recreate the exact hang this module exists to prevent.
const REAP_GRACE: Duration = Duration::from_millis(200);

static DEFAULT_TIMEOUT: AtomicU64 = AtomicU64::new(DEFAULT_TIMEOUT_SECS);

/// Changes the per-command timeout for every command started afterwards.
/// Called once at startup from `--timeout`. A value of zero is raised to
/// one second: a zero timeout would stop every command before it could
/// answer, which is never what anyone means.
pub fn set_default_timeout(timeout: Duration) {
    DEFAULT_TIMEOUT.store(timeout.as_secs().max(1), Ordering::Relaxed);
}

/// The timeout currently applied to ordinary commands.
pub fn default_timeout() -> Duration {
    Duration::from_secs(DEFAULT_TIMEOUT.load(Ordering::Relaxed))
}

thread_local! {
    /// Commands stopped for exceeding their timeout, on this thread, since
    /// the last [`take_timeouts`]. Thread-local on purpose: the engine runs
    /// each module on its own thread, so "which module's command timed
    /// out" is answered by "which thread", without passing a context
    /// object through every collector.
    static TIMED_OUT: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Drains and returns the human-readable description of every command
/// stopped for exceeding its timeout on the current thread. The engine
/// calls this after each module so the report can say "this module's data
/// is incomplete" instead of silently showing less.
pub fn take_timeouts() -> Vec<String> {
    TIMED_OUT.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

fn record_timeout(description: String) {
    TIMED_OUT.with(|t| t.borrow_mut().push(description));
}

/// Adds already-collected timeout descriptions to the current thread's
/// list. Used by `core::parallel` to hand a worker thread's notes back to
/// the thread that owns the module run.
pub(crate) fn record_timeouts(descriptions: Vec<String>) {
    TIMED_OUT.with(|t| t.borrow_mut().extend(descriptions));
}

/// A subprocess with the locale forced to `C` *and* a hard time limit.
///
/// It deliberately mirrors the small part of `std::process::Command` the
/// collectors use (`arg`, `args`, `output`), so every call site written
/// as `command("tool").args([...]).output()` gets the timeout without
/// changing. `output()` returns `io::Result<Output>` exactly as before; a
/// command stopped for running too long surfaces as an
/// `ErrorKind::TimedOut` error, which every collector already treats like
/// any other "this tool didn't give me data" failure.
pub struct Cmd {
    inner: Command,
    description: String,
    timeout: Duration,
}

impl Cmd {
    pub fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.description.push(' ');
        self.description.push_str(&arg.as_ref().to_string_lossy());
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        for a in args {
            self.arg(a);
        }
        self
    }

    /// Overrides the time limit for this one command.
    pub fn timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = timeout;
        self
    }

    /// Doubles the allowance for tools that may legitimately take a few
    /// seconds on a healthy system (waking a sleeping disk, initializing
    /// a GPU driver). Scales with `--timeout` rather than ignoring it.
    pub fn slow(&mut self) -> &mut Self {
        self.timeout = default_timeout() * SLOW_FACTOR;
        self
    }

    /// Runs the command to completion or until the time limit, whichever
    /// comes first, capturing stdout and stderr like `Command::output`
    /// (stdin is closed). On timeout the child is killed, the command is
    /// recorded for [`take_timeouts`], and an `ErrorKind::TimedOut` error
    /// is returned.
    pub fn output(&mut self) -> io::Result<Output> {
        match run_with_timeout(&mut self.inner, self.timeout) {
            Ok(output) => Ok(output),
            Err(RunError::Io(e)) => Err(e),
            Err(RunError::TimedOut) => {
                let message = format!(
                    "'{}' did not finish within {} and was stopped",
                    self.description,
                    format_limit(self.timeout)
                );
                record_timeout(message.clone());
                Err(io::Error::new(io::ErrorKind::TimedOut, message))
            }
        }
    }
}

/// Build a command with the locale forced to `C` (POSIX/English) and the
/// default time limit.
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
pub fn command(program: &str) -> Cmd {
    let mut inner = Command::new(program);
    inner.env("LC_ALL", "C").env("LANG", "C");
    Cmd {
        inner,
        description: program.to_string(),
        timeout: default_timeout(),
    }
}

/// Several calls to the *same* tool that give up together: once one of
/// them times out, the tool is considered hung and every later call is
/// skipped instead of waiting out its own time limit.
///
/// Without this, a wedged `libvirtd` would cost `virsh`'s nine
/// per-VM calls × the number of VMs × the time limit; a wedged NVIDIA
/// driver would cost three limits in a row. With it, the damage is one
/// limit, noted once in the report.
pub struct ToolSession {
    program: &'static str,
    slow: bool,
    timeout: Option<Duration>,
    hung: bool,
}

impl ToolSession {
    pub fn new(program: &'static str) -> Self {
        ToolSession {
            program,
            slow: false,
            timeout: None,
            hung: false,
        }
    }

    /// Gives every call in this session the longer allowance of
    /// [`Cmd::slow`].
    pub fn slow(mut self) -> Self {
        self.slow = true;
        self
    }

    /// Fixes the time limit for every call in this session, instead of the
    /// global default.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// True once any call has timed out.
    pub fn is_hung(&self) -> bool {
        self.hung
    }

    /// Runs the tool and returns its stdout as text if it started, finished
    /// in time and exited with status 0. Anything else — not installed,
    /// non-zero exit, timeout, or an earlier timeout in this session —
    /// returns `None`.
    pub fn run(&mut self, args: &[&str]) -> Option<String> {
        let output = self.start(args)?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Like [`run`](Self::run), but the exit status does not matter: for a
    /// tool that answers with it, such as `systemctl is-enabled`, which exits
    /// with 1 to say `disabled`. `None` only when the tool did not start or
    /// finish in time, or an earlier call timed out.
    pub fn run_ignoring_status(&mut self, args: &[&str]) -> Option<String> {
        let output = self.start(args)?;
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Starts the tool and waits for it, remembering a timeout.
    fn start(&mut self, args: &[&str]) -> Option<Output> {
        if self.hung {
            return None;
        }
        let mut cmd = command(self.program);
        cmd.args(args);
        if self.slow {
            cmd.slow();
        }
        if let Some(timeout) = self.timeout {
            cmd.timeout(timeout);
        }
        match cmd.output() {
            Ok(output) => Some(output),
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut {
                    self.hung = true;
                }
                None
            }
        }
    }
}

/// "10s" for whole seconds, "300ms" below one second (only reachable
/// through `.timeout()` — `--timeout` is whole seconds).
fn format_limit(d: Duration) -> String {
    if d >= Duration::from_secs(1) {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

enum RunError {
    Io(io::Error),
    TimedOut,
}

/// Reads one pipe to the end on its own thread and sends the bytes over a
/// channel. A thread per pipe (rather than reading stdout then stderr in
/// turn) is what prevents the classic deadlock where the child fills the
/// stderr pipe while we are still blocked reading stdout.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// Waits for `child` until `deadline`, polling with a short, growing
/// sleep so fast commands (most of them: `df`, `lspci`) are collected
/// within a millisecond or two without a busy loop for slow ones.
fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    let mut pause = Duration::from_millis(1);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(Duration::from_millis(20));
    }
}

fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<Output, RunError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(RunError::Io)?;

    let stdout_rx = drain(child.stdout.take());
    let stderr_rx = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;

    let status = match wait_until(&mut child, deadline) {
        Ok(Some(status)) => status,
        Ok(None) => {
            // Over time: stop it, give the OS a moment to reap it, and
            // move on without waiting for the reader threads — a
            // grandchild process may still hold the pipes open, and the
            // threads end by themselves when it finally exits.
            let _ = child.kill();
            let _ = wait_until(&mut child, Instant::now() + REAP_GRACE);
            return Err(RunError::TimedOut);
        }
        Err(e) => {
            let _ = child.kill();
            return Err(RunError::Io(e));
        }
    };

    // The child has exited; its output is normally already in the pipe.
    // Bound the wait anyway: a background process it left behind could
    // keep the pipe open indefinitely.
    let patience = deadline
        .saturating_duration_since(Instant::now())
        .max(READER_GRACE);
    let stdout = stdout_rx
        .recv_timeout(patience)
        .map_err(|_| RunError::TimedOut)?;
    let stderr = stderr_rx
        .recv_timeout(patience)
        .map_err(|_| RunError::TimedOut)?;

    Ok(Output {
        status,
        stdout,
        stderr,
    })
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

    #[test]
    fn captures_stdout_stderr_and_exit_status() {
        let output = command("sh")
            .args(["-c", "echo out; echo err >&2; exit 3"])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&output.stderr).trim(), "err");
        assert_eq!(output.status.code(), Some(3));
    }

    #[test]
    fn missing_program_is_still_not_found() {
        // Collectors distinguish "tool not installed" from other
        // failures by this error kind — it must survive the wrapper.
        let err = command("linuxdoctor-no-such-program-xyz")
            .output()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(take_timeouts().is_empty());
    }

    #[test]
    fn output_larger_than_the_pipe_buffer_does_not_deadlock() {
        // A pipe holds ~64 KiB; this is five times that on stdout and
        // stderr at once, which deadlocks any implementation that reads
        // the two pipes one after the other.
        let output = command("sh")
            .args([
                "-c",
                "head -c 300000 /dev/zero | tr '\\0' x; head -c 300000 /dev/zero | tr '\\0' y >&2",
            ])
            .timeout(Duration::from_secs(20))
            .output()
            .unwrap();
        assert_eq!(output.stdout.len(), 300_000);
        assert_eq!(output.stderr.len(), 300_000);
    }

    #[test]
    fn slow_command_is_stopped_and_recorded() {
        let started = Instant::now();
        let err = command("sleep")
            .arg("30")
            .timeout(Duration::from_millis(300))
            .output()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );

        let notes = take_timeouts();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("sleep 30"), "{notes:?}");
        assert!(notes[0].contains("was stopped"), "{notes:?}");
        // Drained: a second call sees nothing.
        assert!(take_timeouts().is_empty());
    }

    #[test]
    fn grandchild_holding_the_pipe_does_not_block_the_timeout() {
        // `sh` stays alive as the parent of `sleep` here (the trailing
        // `echo` prevents the shell from exec-ing sleep directly), and
        // after the shell is killed the orphaned `sleep` still holds the
        // stdout pipe open for three more seconds. The call must come
        // back at the deadline, not when the pipe finally closes.
        let started = Instant::now();
        let err = command("sh")
            .args(["-c", "sleep 3; echo done"])
            .timeout(Duration::from_millis(300))
            .output()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
        let _ = take_timeouts();
    }

    #[test]
    fn exited_command_with_a_lingering_background_process_is_bounded() {
        // The shell exits immediately but leaves a background `sleep`
        // holding the pipes: the call must give up at the deadline
        // instead of waiting for the pipes to close.
        let started = Instant::now();
        let result = command("sh")
            .args(["-c", "sleep 3 & echo started"])
            .timeout(Duration::from_millis(300))
            .output();
        assert!(started.elapsed() < Duration::from_secs(2));
        // Either outcome is acceptable as long as it is prompt; what
        // matters is that it is not a multi-second hang.
        if let Err(e) = result {
            assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        }
        let _ = take_timeouts();
    }

    #[test]
    fn fast_command_is_not_penalized_by_polling() {
        let started = Instant::now();
        for _ in 0..20 {
            command("true").output().unwrap();
        }
        // Twenty process launches; polling overhead per call is a few
        // milliseconds at worst. A generous bound still catches a
        // regression to fixed 100 ms-style sleeps.
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn slow_doubles_the_default_allowance() {
        let mut cmd = command("true");
        cmd.slow();
        assert_eq!(cmd.timeout, default_timeout() * 2);
    }
    #[test]
    fn session_returns_stdout_on_success_and_none_on_failure() {
        let mut sh = ToolSession::new("sh");
        assert_eq!(sh.run(&["-c", "echo hello"]).as_deref(), Some("hello\n"));
        assert_eq!(sh.run(&["-c", "exit 1"]), None);
        assert!(!sh.is_hung(), "a plain failure is not a hang");
        assert_eq!(
            ToolSession::new("linuxdoctor-no-such-program-xyz").run(&[]),
            None
        );
    }

    #[test]
    fn session_can_ignore_the_exit_status_when_the_tool_answers_with_it() {
        let mut sh = ToolSession::new("sh");
        assert_eq!(
            sh.run_ignoring_status(&["-c", "echo disabled; exit 1"])
                .as_deref(),
            Some("disabled\n")
        );
        assert_eq!(
            sh.run_ignoring_status(&["-c", "echo enabled"]).as_deref(),
            Some("enabled\n")
        );
        assert_eq!(
            sh.run_ignoring_status(&["-c", "exit 3"]).as_deref(),
            Some("")
        );
        assert!(!sh.is_hung());
        assert_eq!(
            ToolSession::new("linuxdoctor-no-such-program-xyz").run_ignoring_status(&[]),
            None
        );
    }

    #[test]
    fn a_timeout_stops_the_calls_that_ignore_the_status_too() {
        let mut session = ToolSession::new("sleep").with_timeout(Duration::from_millis(200));
        let started = Instant::now();
        assert_eq!(session.run_ignoring_status(&["30"]), None);
        assert!(session.is_hung());
        assert_eq!(session.run_ignoring_status(&["30"]), None);
        assert_eq!(session.run(&["30"]), None);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(take_timeouts().len(), 1);
    }

    #[test]
    fn session_stops_calling_a_tool_after_its_first_timeout() {
        // Three 30-second sleeps against a 200 ms limit: only the first is
        // actually run (and stopped); the others are skipped outright, so
        // the whole thing costs one limit, and the report gets one note.
        let mut session = ToolSession::new("sleep").with_timeout(Duration::from_millis(200));
        let started = Instant::now();
        assert_eq!(session.run(&["30"]), None);
        assert!(session.is_hung());
        assert_eq!(session.run(&["30"]), None);
        assert_eq!(session.run(&["30"]), None);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(take_timeouts().len(), 1);
    }
}
