use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::process::Command;
use tracing::{field::Empty, Instrument};

use crate::redact::redact_command_line_with_visible;
use crate::ToolOutput;

/// Default timeout for tool execution (2 minutes).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Typed marker attached to the `anyhow::Error` chain when
/// [`CommandBuilder::execute`] fails at `Command::spawn` time. Callers that
/// need to distinguish "binary genuinely absent" from "transient OS refusal"
/// downcast the error via [`spawn_error_kind`] instead of string-matching
/// the human-readable message — the wording is asserted in `executor::tests`
/// but the typed variant is the authoritative signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnErrorKind {
    /// Raw `io::ErrorKind` from the failed `spawn()` call. `NotFound`
    /// means ENOENT and is the only kind that warrants long-term caching
    /// as "tool unavailable"; everything else is transient.
    pub io_kind: std::io::ErrorKind,
}

impl SpawnErrorKind {
    /// True iff the kernel returned ENOENT — i.e. the binary is genuinely
    /// absent from the worker's PATH. Safe to cache and prune on.
    pub fn is_not_found(self) -> bool {
        self.io_kind == std::io::ErrorKind::NotFound
    }
}

impl std::fmt::Display for SpawnErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spawn error kind: {:?}", self.io_kind)
    }
}

impl std::error::Error for SpawnErrorKind {}

/// Return the [`SpawnErrorKind`] attached to an `anyhow::Error` by
/// [`CommandBuilder::execute`], if any.
///
/// Consumers of tool-dispatch errors (worker classifier, runner pruning
/// check) should prefer this over string-matching. The string wording is
/// preserved for backward compatibility with in-flight rollouts.
///
/// Uses `anyhow::Error::downcast_ref` — which walks every attached
/// context and the root cause — rather than `err.chain()`, which only
/// exposes the source chain via `std::error::Error::source()` and misses
/// values attached with `.context(...)`.
pub fn spawn_error_kind(err: &anyhow::Error) -> Option<SpawnErrorKind> {
    err.downcast_ref::<SpawnErrorKind>().copied()
}

/// Map a program name to a prioritized list of candidate executables that
/// satisfy the same role. Used to recover when an image ships a broken or
/// missing symlink for the canonical name (e.g. the Kali pipx install of
/// NetExec creates `/usr/local/bin/NetExec` but the lowercase
/// `/usr/local/bin/netexec` symlink is sometimes broken/self-referential).
///
/// First candidate that resolves on PATH (or is an absolute path that
/// exists) wins. Returns `None` to mean "use the program as-is".
fn resolve_program_alias(program: &str) -> Option<&'static [&'static str]> {
    match program {
        // NetExec a.k.a. nxc a.k.a. legacy crackmapexec.
        "netexec" | "nxc" | "NetExec" => Some(&[
            "netexec",
            "nxc",
            "NetExec",
            "/opt/pipx/venvs/netexec/bin/NetExec",
            "/opt/pipx/venvs/netexec/bin/netexec",
            "crackmapexec",
        ]),
        _ => None,
    }
}

/// Return the first candidate that is resolvable (either an absolute path
/// that exists, or a bare name that `which`-resolves on PATH).
fn first_resolvable<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    use std::path::Path;
    for cand in candidates {
        if cand.contains('/') {
            // Absolute or relative path — check existence directly so we
            // sidestep broken symlinks (readlink returns Ok for those).
            if Path::new(cand).exists() {
                return Some(cand);
            }
            continue;
        }
        // Bare name — walk $PATH and check that each candidate resolves to
        // a file that actually exists. `metadata()` follows symlinks, so a
        // self-referential symlink returns Err and we skip it.
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in path_var.split(':') {
                if dir.is_empty() {
                    continue;
                }
                let full = Path::new(dir).join(cand);
                if std::fs::metadata(&full).is_ok() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// Builder for constructing and executing subprocess commands with timeout support.
pub struct CommandBuilder {
    program: String,
    args: Vec<String>,
    env_vars: Vec<(String, String)>,
    timeout: Duration,
    stdin_data: Option<String>,
    cwd: Option<std::path::PathBuf>,
    visible_indices: HashSet<usize>,
}

impl CommandBuilder {
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: Vec::new(),
            env_vars: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            stdin_data: None,
            cwd: None,
            visible_indices: HashSet::new(),
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Only add the arg if the condition is true.
    pub fn arg_if(self, condition: bool, arg: impl Into<String>) -> Self {
        if condition {
            self.arg(arg)
        } else {
            self
        }
    }

    /// Add a flag and its value as two separate args (e.g., `-p 445`).
    pub fn flag(self, flag: &str, value: impl Into<String>) -> Self {
        self.arg(flag).arg(value)
    }

    /// Add a flag and its value, declaring that the value is NOT a secret.
    ///
    /// [`crate::redact::redact_command_line`] masks the argument after any
    /// credential-bearing flag by default, including the ones that are only
    /// sometimes secret (`-p`, `-H`, `-w`). A call site that knows its value is
    /// benign — an nmap port spec, an ldapsearch URI, hashcat's workload
    /// profile — uses this instead of [`CommandBuilder::flag`] so the value
    /// stays readable in logs and traces. Everything else stays fail-closed.
    pub fn flag_visible(mut self, flag: &str, value: impl Into<String>) -> Self {
        self.args.push(flag.to_string());
        self.visible_indices.insert(self.args.len());
        self.args.push(value.into());
        self
    }

    /// Add a flag and value only if the value is Some.
    pub fn flag_opt(self, flag: &str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.flag(flag, v),
            None => self,
        }
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn timeout_secs(self, secs: u64) -> Self {
        self.timeout(Duration::from_secs(secs))
    }

    /// Write `data` to the child's stdin.
    ///
    /// Without this, the child's stdin is `/dev/null`. Tools that prompt then
    /// read EOF and exit instead of blocking until the timeout expires — a
    /// worker has no interactive input to give them.
    pub fn stdin(mut self, data: impl Into<String>) -> Self {
        self.stdin_data = Some(data.into());
        self
    }

    pub fn current_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Test accessor for the positional/flag arg vector. Used by unit tests
    /// (in this crate and downstream callers) to assert on the constructed
    /// command line without actually spawning the binary — e.g., that
    /// `-k -no-pass` is present when a Kerberos ccache is supplied.
    ///
    /// Exposed (rather than `#[cfg(test)]`-gated) so the ares-cli worker
    /// crate can write the Bug-B contract test that walks the resolver's
    /// `tool_consumes_ticket_path` allowlist.
    #[doc(hidden)]
    pub fn args_for_test(&self) -> &[String] {
        &self.args
    }

    /// Test accessor for the environment-variable list. Used to assert that
    /// tools wire `KRB5CCNAME` into the child process when the caller
    /// supplies a `ticket_path` — Bug B silent-drop guard.
    #[doc(hidden)]
    pub fn env_vars_for_test(&self) -> &[(String, String)] {
        &self.env_vars
    }

    /// The command line with every secret masked, safe for logs, span
    /// attributes, and error messages surfaced to the LLM.
    ///
    /// Honours the indices recorded by [`CommandBuilder::flag_visible`];
    /// everything else goes through the fail-closed rules in
    /// [`crate::redact`].
    pub(crate) fn redacted_command_line(&self) -> String {
        redact_command_line_with_visible(&self.program, &self.args, &self.visible_indices)
    }

    pub async fn execute(self) -> Result<ToolOutput> {
        #[cfg(test)]
        {
            if let Some(output) = mock::take_next() {
                return Ok(output);
            }
        }

        let redacted_cmd = self.redacted_command_line();
        tracing::debug!(cmd = %redacted_cmd, timeout = ?self.timeout, "executing tool command");

        // Global cap on concurrent subprocess spawns. Held for the full
        // spawn+wait lifetime; released when this function returns.
        let _tool_permit = crate::concurrency::acquire_tool_permit().await;

        // Resolve aliases like `netexec` -> `NetExec` when the canonical
        // name isn't resolvable on PATH (broken symlink, etc.).
        let resolved_program: String = match resolve_program_alias(&self.program) {
            Some(candidates) => match first_resolvable(candidates) {
                Some(found) => found.to_string(),
                None => self.program.clone(),
            },
            None => self.program.clone(),
        };
        if resolved_program != self.program {
            tracing::debug!(
                requested = %self.program,
                resolved = %resolved_program,
                "resolved program alias"
            );
        }

        let otel_name = format!("exec.{resolved_program}");
        let span = tracing::info_span!(
            "exec.command",
            otel.name = %otel_name,
            otel.kind = "client",
            otel.status_code = Empty,
            otel.status_message = Empty,
            "process.executable.name" = %resolved_program,
            "process.command_line" = %redacted_cmd,
            "process.command_args.count" = self.args.len(),
            "process.exit_code" = Empty,
            "tool.timed_out" = Empty,
            "tool.duration_ms" = Empty,
        );

        self.spawn_and_wait(resolved_program, redacted_cmd, span.clone())
            .instrument(span)
            .await
    }

    /// Time the spawn+wait, record the span's deferred fields on every exit
    /// path, and hand the result back to [`CommandBuilder::execute`].
    async fn spawn_and_wait(
        self,
        resolved_program: String,
        redacted_cmd: String,
        span: tracing::Span,
    ) -> Result<ToolOutput> {
        let started = Instant::now();
        let outcome = self.run_child(&resolved_program, &redacted_cmd).await;
        span.record("tool.duration_ms", started.elapsed().as_millis() as u64);
        span.record("tool.timed_out", outcome.timed_out);

        match &outcome.result {
            Ok(output) => {
                if let Some(code) = output.exit_code {
                    span.record("process.exit_code", code);
                }
                if output.success {
                    span.record("otel.status_code", "OK");
                } else {
                    span.record("otel.status_code", "ERROR");
                    span.record(
                        "otel.status_message",
                        format!("exited with {:?}", output.exit_code).as_str(),
                    );
                }
            }
            Err(e) => {
                span.record("otel.status_code", "ERROR");
                span.record("otel.status_message", format!("{e:#}").as_str());
            }
        }

        outcome.result
    }

    async fn run_child(self, resolved_program: &str, redacted_cmd: &str) -> ExecOutcome {
        let mut cmd = Command::new(resolved_program);
        cmd.args(&self.args);

        if let Some(ref dir) = self.cwd {
            cmd.current_dir(dir);
        }

        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        if self.stdin_data.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // Send SIGKILL when the `Child` is dropped. Required for the
        // timeout-abort path below to actually terminate the OS process
        // (tokio's default is to leave the child running on drop).
        cmd.kill_on_drop(true);

        // Only ENOENT (binary genuinely absent from PATH) uses the permanent
        // "failed to spawn ... is it installed?" wording that downstream code
        // caches on. Every other spawn error — EAGAIN (fork resource
        // pressure), ENOMEM, EMFILE (fd exhaustion), EACCES (transient
        // AppArmor/SELinux denial), I/O errors reading /proc — is transient
        // and must NOT poison the tool for the worker's lifetime or prune it
        // from the LLM's tool set. The executor is the single source of truth
        // for this distinction; upstream classifiers prefer the typed
        // [`SpawnErrorKind`] attached below and fall back to string matching
        // for backward compatibility with in-flight rollouts.
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let io_kind = e.kind();
                let msg = if io_kind == std::io::ErrorKind::NotFound {
                    format!("failed to spawn '{}' — is it installed?", self.program)
                } else {
                    format!(
                        "transient spawn error for '{}' ({io_kind:?}): {e}",
                        self.program
                    )
                };
                // Attach the typed marker before the human-readable context so
                // `spawn_error_kind()` on the returned error can recover the
                // discriminator without ever inspecting the message string.
                return ExecOutcome::failed(
                    anyhow::Error::new(e)
                        .context(SpawnErrorKind { io_kind })
                        .context(msg),
                );
            }
        };

        if let Some(data) = &self.stdin_data {
            use tokio::io::AsyncWriteExt;
            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(data.as_bytes()).await {
                    return ExecOutcome::failed(
                        anyhow::Error::new(e).context("failed to write stdin"),
                    );
                }
                drop(stdin);
            }
        }

        // Move the child into a task so we can cancel the wait on timeout.
        // On timeout we must `handle.abort()` — merely dropping a `JoinHandle`
        // detaches the task and the child continues to run. Aborting drops
        // the task's owned `Child`, and the `kill_on_drop(true)` above then
        // sends SIGKILL to the OS process.
        let timeout = self.timeout;
        let handle = tokio::spawn(async move { child.wait_with_output().await });
        let abort = handle.abort_handle();

        let join_result = tokio::time::timeout(timeout, handle).await;

        match join_result {
            Ok(Ok(Ok(output))) => {
                let stdout = sanitize_tool_output(&output.stdout);
                let stderr = sanitize_tool_output(&output.stderr);
                let exit_code = output.status.code();
                let success = output.status.success();

                tracing::debug!(
                    exit_code = ?exit_code,
                    stdout_len = stdout.len(),
                    stderr_len = stderr.len(),
                    "command completed"
                );

                ExecOutcome::completed(ToolOutput {
                    stdout,
                    stderr,
                    exit_code,
                    success,
                })
            }
            Ok(Ok(Err(e))) => ExecOutcome::failed(anyhow::anyhow!("command execution failed: {e}")),
            Ok(Err(e)) => ExecOutcome::failed(anyhow::anyhow!("task join error: {e}")),
            Err(_) => {
                abort.abort();
                ExecOutcome::timed_out(anyhow::anyhow!(
                    "command timed out after {timeout:?}: {redacted_cmd}"
                ))
            }
        }
    }
}

/// Result of one spawn+wait, carrying the timeout discriminator the span needs
/// but the `anyhow` chain does not express.
struct ExecOutcome {
    result: Result<ToolOutput>,
    timed_out: bool,
}

impl ExecOutcome {
    fn completed(output: ToolOutput) -> Self {
        Self {
            result: Ok(output),
            timed_out: false,
        }
    }

    fn failed(err: anyhow::Error) -> Self {
        Self {
            result: Err(err),
            timed_out: false,
        }
    }

    fn timed_out(err: anyhow::Error) -> Self {
        Self {
            result: Err(err),
            timed_out: true,
        }
    }
}

/// Convert raw bytes to a clean UTF-8 string safe for JSON serialization.
/// Strips null bytes and C0 control characters (except newline, tab, carriage return)
/// that would cause OpenAI-compatible APIs to reject the payload.
fn sanitize_tool_output(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| {
            // Keep printable chars, newline, tab, carriage return
            // Strip null bytes and other C0 controls that break JSON parsers
            *c >= ' ' || *c == '\n' || *c == '\t' || *c == '\r'
        })
        .collect()
}

/// Convenience: run a simple command with default timeout.
pub async fn run(program: &str, args: &[&str]) -> Result<ToolOutput> {
    CommandBuilder::new(program)
        .args(args.iter().map(|s| s.to_string()))
        .execute()
        .await
}

/// Mock executor for testing tool wrapper functions without spawning subprocesses.
///
/// In test mode, push `ToolOutput` values onto the thread-local queue.
/// Each `CommandBuilder::execute()` call pops the next response (or falls through
/// to real execution if the queue is empty).
#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    thread_local! {
        static RESPONSES: RefCell<VecDeque<ToolOutput>> = const { RefCell::new(VecDeque::new()) };
    }

    /// Push a single mock response onto the queue.
    pub fn push(output: ToolOutput) {
        RESPONSES.with(|r| r.borrow_mut().push_back(output));
    }

    /// Pop the next response, or `None` to fall through to real execution.
    pub(super) fn take_next() -> Option<ToolOutput> {
        RESPONSES.with(|r| r.borrow_mut().pop_front())
    }

    /// Create a default success output.
    pub fn success() -> ToolOutput {
        ToolOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        }
    }

    /// Create a success output with custom stdout.
    pub fn success_with_stdout(stdout: impl Into<String>) -> ToolOutput {
        ToolOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_tool_output ─────────────────────────────────────────────────

    #[test]
    fn sanitize_valid_utf8_passthrough() {
        let input = b"hello world";
        assert_eq!(sanitize_tool_output(input), "hello world");
    }

    #[test]
    fn sanitize_strips_null_bytes() {
        let input = b"hel\x00lo";
        assert_eq!(sanitize_tool_output(input), "hello");
    }

    #[test]
    fn sanitize_strips_c0_control_chars() {
        // \x01 (SOH), \x07 (BEL), \x1b (ESC) are C0 controls that must be stripped
        let input = b"he\x01ll\x07o\x1b";
        assert_eq!(sanitize_tool_output(input), "hello");
    }

    #[test]
    fn sanitize_preserves_newline_tab_cr() {
        let input = b"line1\nline2\ttabbed\r\nwindows";
        assert_eq!(
            sanitize_tool_output(input),
            "line1\nline2\ttabbed\r\nwindows"
        );
    }

    #[test]
    fn sanitize_empty_input() {
        assert_eq!(sanitize_tool_output(b""), "");
    }

    #[test]
    fn sanitize_lossy_utf8() {
        // 0xff is not valid UTF-8; from_utf8_lossy replaces it with U+FFFD.
        // U+FFFD (0xFFFD) is >= ' ', so it should be kept.
        let input = b"ok\xff!";
        let result = sanitize_tool_output(input);
        assert!(result.starts_with("ok"));
        assert!(result.ends_with('!'));
        // Replacement char is present somewhere between them
        assert!(result.contains('\u{FFFD}'));
    }

    #[test]
    fn sanitize_mixed_control_and_printable() {
        // BEL (\x07) stripped, space and printable kept, newline kept
        let input = b"alert\x07\nsafe text";
        assert_eq!(sanitize_tool_output(input), "alert\nsafe text");
    }

    // ── CommandBuilder builder API ───────────────────────────────────────────

    #[test]
    fn builder_new_does_not_panic() {
        let _b = CommandBuilder::new("echo");
    }

    #[test]
    fn builder_arg_chains() {
        let _b = CommandBuilder::new("echo").arg("hello").arg("world");
    }

    #[test]
    fn builder_args_chains() {
        let _b = CommandBuilder::new("ls").args(["-l", "-a"]);
    }

    #[test]
    fn builder_arg_if_true_adds_arg() {
        // We can't inspect private fields, but we verify it returns Self (compiles & doesn't panic).
        let _b = CommandBuilder::new("cmd").arg_if(true, "--verbose");
    }

    #[test]
    fn builder_arg_if_false_skips_arg() {
        let _b = CommandBuilder::new("cmd").arg_if(false, "--verbose");
    }

    #[test]
    fn builder_flag_chains() {
        let _b = CommandBuilder::new("nmap").flag("-p", "445");
    }

    #[test]
    fn builder_flag_opt_some_chains() {
        let _b = CommandBuilder::new("cmd").flag_opt("-u", Some("admin"));
    }

    #[test]
    fn builder_flag_opt_none_skips() {
        let _b = CommandBuilder::new("cmd").flag_opt("-u", Option::<String>::None);
    }

    #[test]
    fn builder_env_chains() {
        let _b = CommandBuilder::new("cmd").env("MY_VAR", "value");
    }

    #[test]
    fn builder_timeout_secs_chains() {
        let _b = CommandBuilder::new("cmd").timeout_secs(30);
    }

    #[test]
    fn builder_stdin_chains() {
        let _b = CommandBuilder::new("cmd").stdin("input data");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdin_defaults_to_null_so_a_reader_gets_eof_instead_of_blocking() {
        use std::time::Instant;

        let start = Instant::now();
        let out = CommandBuilder::new("cat")
            .timeout(Duration::from_secs(10))
            .execute()
            .await
            .expect("cat with a null stdin must exit on EOF, not hang");

        assert!(out.success, "cat should exit 0 on immediate EOF: {out:?}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cat blocked on stdin instead of seeing EOF: {:?}",
            start.elapsed()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supplied_stdin_data_still_reaches_the_child() {
        let out = CommandBuilder::new("cat")
            .stdin("hello from stdin\n")
            .timeout(Duration::from_secs(10))
            .execute()
            .await
            .expect("supplied stdin data must still be piped to the child");

        assert_eq!(out.stdout, "hello from stdin\n");
    }

    #[test]
    fn builder_full_chain_does_not_panic() {
        let _b = CommandBuilder::new("netexec")
            .arg("smb")
            .args(["192.168.58.10", "-u", "admin"])
            .flag("-p", "Password1")
            .flag_opt("--domain", Some("contoso.local"))
            .flag_opt("--extra", Option::<String>::None)
            .arg_if(true, "--shares")
            .arg_if(false, "--sam")
            .env("KRB5CCNAME", "/tmp/ticket.ccache")
            .timeout_secs(60)
            .stdin("y\n");
    }

    // ── timeout kills the child process ─────────────────────────────────────
    //
    // Regression guard for the OOM cause where a hung tool's `Child` was
    // detached (via dropping the `JoinHandle`) instead of aborted, leaking
    // the OS process. Verifies end-to-end that timeout → abort → SIGKILL.

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_child_process() {
        use std::time::{Duration, Instant};

        // sh writes its PID to a temp file, then `exec sleep 30` replaces
        // the shell process with sleep — same PID, so the file tells us
        // exactly which OS process to check for aliveness after timeout.
        let pid_file = tempfile::NamedTempFile::new().unwrap();
        let script = format!("echo $$ > {} && exec sleep 30", pid_file.path().display());

        let start = Instant::now();
        let result = CommandBuilder::new("sh")
            .arg("-c")
            .arg(&script)
            .timeout(Duration::from_millis(500))
            .execute()
            .await;
        let elapsed = start.elapsed();

        // Must time out, not wait 30s.
        assert!(result.is_err(), "expected timeout error, got {result:?}");
        assert!(
            elapsed < Duration::from_secs(3),
            "execute() didn't return promptly on timeout: {elapsed:?}"
        );

        // Give the runtime a moment to drop the aborted task and let the
        // OS deliver SIGKILL + reap. 200ms is generous; the abort chain is
        // synchronous up to the kernel signal.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Read the PID sh wrote before exec'ing sleep.
        let pid_str = std::fs::read_to_string(pid_file.path())
            .expect("child never wrote its PID — script didn't run at all");
        let pid: i32 = pid_str
            .trim()
            .parse()
            .expect("PID file contained non-integer");

        // `kill -0 <pid>` returns 0 if the process exists and we can signal
        // it, non-zero (ESRCH) if it's gone. This is the actual assertion
        // the whole fix hinges on.
        let alive = std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .expect("failed to invoke `kill -0`")
            .success();

        assert!(
            !alive,
            "child pid {pid} is still alive after timeout — abort/kill path is broken"
        );
    }

    // ── ENOENT wording contract ──────────────────────────────────────────────
    //
    // Three separate call sites in three separate crates key off the exact
    // phrasing this code emits when `Command::spawn()` returns
    // `io::ErrorKind::NotFound`:
    //
    //   1. `ares-cli/src/worker/tool_executor.rs::is_tool_unavailable_error`
    //      requires both "failed to spawn" AND "is it installed?".
    //   2. `ares-llm/src/agent_loop/runner.rs`'s pruning check uses the same
    //      pair as a string-fallback alongside the typed `ToolFailureKind`.
    //   3. Log-grep patterns in `.claude/skills/ares-debug/SKILL.md` (Step 3.5)
    //      match on this phrase to identify the tool-pruning cascade.
    //
    // If the wording drifts, the classifier silently stops firing and one
    // ENOENT quietly stops nuking recon primitives — but transient spawn
    // errors also stop being distinguishable. Lock the wording here.

    #[tokio::test]
    async fn spawn_of_missing_binary_uses_enoent_wording() {
        let result = CommandBuilder::new("definitely-not-a-real-binary-xyz-9999")
            .execute()
            .await;

        let err = result.expect_err("spawn of a non-existent binary must fail");
        let msg = format!("{err:#}");

        assert!(
            msg.contains("failed to spawn"),
            "ENOENT wording missing 'failed to spawn': {msg}"
        );
        assert!(
            msg.contains("is it installed?"),
            "ENOENT wording missing 'is it installed?': {msg}"
        );
        assert!(
            msg.contains("definitely-not-a-real-binary-xyz-9999"),
            "ENOENT wording must include the program name: {msg}"
        );
        assert!(
            !msg.contains("transient spawn error"),
            "ENOENT must NOT be classified as transient: {msg}"
        );
    }

    #[tokio::test]
    async fn spawn_of_missing_binary_attaches_typed_kind() {
        // The typed SpawnErrorKind is the authoritative classifier signal
        // for downstream callers. If this ever fails, the string wording
        // above is the ONLY thing keeping the worker cache honest — and
        // the whole point of the enum was to stop relying on string
        // matching. So both the wording AND the typed kind must pass.
        let err = CommandBuilder::new("still-not-a-real-binary-xyz-5555")
            .execute()
            .await
            .expect_err("spawn of a non-existent binary must fail");

        let kind = spawn_error_kind(&err)
            .expect("SpawnErrorKind must be attached to the anyhow chain on spawn failure");
        assert_eq!(
            kind.io_kind,
            std::io::ErrorKind::NotFound,
            "ENOENT must be reported as NotFound, got {:?}",
            kind.io_kind
        );
        assert!(
            kind.is_not_found(),
            "SpawnErrorKind::is_not_found() must be true for ENOENT"
        );
    }

    #[tokio::test]
    async fn spawn_of_missing_binary_is_not_labeled_transient() {
        // Belt-and-suspenders: the transient branch is exercised only for
        // non-NotFound `io::ErrorKind`s, which are hard to synthesise
        // portably (EAGAIN needs fork exhaustion). But we CAN assert the
        // negative: an ENOENT must never be labelled transient, or the
        // worker cache stops poisoning genuinely-missing binaries and the
        // LLM burns steps re-calling them every task.
        let err = CommandBuilder::new("another-definitely-fake-binary-abc-1234")
            .execute()
            .await
            .expect_err("spawn must fail");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("is it installed?") && !msg.contains("transient"),
            "ENOENT must land in the permanent branch: {msg}"
        );
    }
}
