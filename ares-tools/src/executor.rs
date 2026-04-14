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
