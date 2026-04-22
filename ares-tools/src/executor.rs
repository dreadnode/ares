use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

use crate::ToolOutput;

/// Default timeout for tool execution (2 minutes).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Builder for constructing and executing subprocess commands with timeout support.
pub struct CommandBuilder {
    program: String,
    args: Vec<String>,
    env_vars: Vec<(String, String)>,
    timeout: Duration,
    stdin_data: Option<String>,
}

impl CommandBuilder {
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: Vec::new(),
            env_vars: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            stdin_data: None,
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

    pub fn stdin(mut self, data: impl Into<String>) -> Self {
        self.stdin_data = Some(data.into());
        self
    }

    pub async fn execute(self) -> Result<ToolOutput> {
        #[cfg(test)]
        {
            if let Some(output) = mock::take_next() {
                return Ok(output);
            }
        }

        let display_cmd = format!("{} {}", self.program, self.args.join(" "));
        tracing::debug!(cmd = %display_cmd, timeout = ?self.timeout, "executing tool command");

        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);

        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        if self.stdin_data.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn '{}' — is it installed?", self.program))?;

        if let Some(data) = &self.stdin_data {
            use tokio::io::AsyncWriteExt;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data.as_bytes()).await?;
                drop(stdin);
            }
        }

        // Spawn the wait on a task so we can abort on timeout. Aborting the
        // task drops the `Child`, which sends SIGKILL on Unix.
        let timeout = self.timeout;
        let handle = tokio::spawn(async move { child.wait_with_output().await });

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

                Ok(ToolOutput {
                    stdout,
                    stderr,
                    exit_code,
                    success,
                })
            }
            Ok(Ok(Err(e))) => Err(anyhow::anyhow!("command execution failed: {e}")),
            Ok(Err(e)) => Err(anyhow::anyhow!("task join error: {e}")),
            Err(_) => Err(anyhow::anyhow!(
                "command timed out after {:?}: {}",
                timeout,
                display_cmd
            )),
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
}
