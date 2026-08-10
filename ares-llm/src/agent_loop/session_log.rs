//! Append-only JSONL session log.
//!
//! Each agent loop invocation writes one record per turn (user prompt,
//! assistant turn, tool result, terminal outcome) to
//! `{dir}/{op_id}/{task_id}.jsonl`. The log is the source of truth for
//! crash recovery and replay; the in-memory `Vec<ChatMessage>` is a cache.
//!
//! All write paths are best-effort: a failed disk write logs a warning
//! but does not abort the agent loop. The session log is observability,
//! not a hard requirement for correctness.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;
use tracing::warn;

use super::config::SessionLogConfig;
use crate::provider::{ChatMessage, ContentPart, Role, TokenUsage};

/// A single line in the session log.
#[derive(Debug, Serialize)]
pub struct SessionLogEntry<'a> {
    /// RFC3339 timestamp.
    pub ts: String,
    /// Operation ID (top-level Redis namespace).
    pub op_id: &'a str,
    /// Task ID within the operation.
    pub task_id: &'a str,
    /// Owning team (`red` | `blue`) — lets the ingester tag rows for analysis.
    pub team: &'a str,
    /// Agent role (recon, lateral, ...).
    pub role: &'a str,
    /// Step counter (0 for boot/start, increments per LLM iteration).
    pub step: u32,
    /// Model identifier.
    pub model: &'a str,
    /// Event kind: `system_prompt`, `user`, `assistant`, `tool_result`,
    /// `usage`, `compaction`, `outcome`.
    pub kind: &'a str,
    /// Free-form structured payload.
    pub data: serde_json::Value,
}

/// Best-effort append-only writer for one task's session log.
pub struct SessionLog {
    path: PathBuf,
    op_id: String,
    task_id: String,
    team: String,
    role: String,
    model: String,
    enabled: bool,
}

impl SessionLog {
    /// Build a writer rooted at `config.dir/op_id/task_id.jsonl`. When the
    /// config has no directory the writer is a no-op.
    pub fn open(
        config: &SessionLogConfig,
        op_id: &str,
        task_id: &str,
        role: &str,
        model: &str,
    ) -> Self {
        // Config can override the op_id (blue benchmark files its transcript
        // under the replayed operation) and always carries the owning team.
        let op_id = config.op_id.as_deref().unwrap_or(op_id);
        let team = config.team.as_str();
        let Some(root) = config.dir.as_ref() else {
            return Self::disabled(op_id, task_id, team, role, model);
        };
        let mut path = root.clone();
        path.push(sanitize(op_id));
        if let Err(e) = fs::create_dir_all(&path) {
            warn!(error = %e, dir = %path.display(), "failed to create session log dir");
            return Self::disabled(op_id, task_id, team, role, model);
        }
        path.push(format!("{}.jsonl", sanitize(task_id)));
        Self {
            path,
            op_id: op_id.to_string(),
            task_id: task_id.to_string(),
            team: team.to_string(),
            role: role.to_string(),
            model: model.to_string(),
            enabled: true,
        }
    }

    fn disabled(op_id: &str, task_id: &str, team: &str, role: &str, model: &str) -> Self {
        Self {
            path: PathBuf::new(),
            op_id: op_id.to_string(),
            task_id: task_id.to_string(),
            team: team.to_string(),
            role: role.to_string(),
            model: model.to_string(),
            enabled: false,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_entry(&self, kind: &str, step: u32, data: serde_json::Value) {
        if !self.enabled {
            return;
        }
        let entry = SessionLogEntry {
            ts: Utc::now().to_rfc3339(),
            op_id: &self.op_id,
            task_id: &self.task_id,
            team: &self.team,
            role: &self.role,
            step,
            model: &self.model,
            kind,
            data,
        };
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to serialize session log entry");
                return;
            }
        };
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, path = %self.path.display(), "failed to open session log");
                return;
            }
        };
        if let Err(e) = writeln!(file, "{line}") {
            warn!(error = %e, path = %self.path.display(), "failed to append session log");
            return;
        }
        // fsync is too expensive for hot-path turns; rely on append + OS
        // buffering. On a hard crash we may lose the trailing few lines,
        // which is the standard JSONL trade-off.
        let _ = file.flush();
    }

    /// Boot record written at loop start.
    pub fn record_start(&self, system_prompt: &str, task_prompt: &str, tools: &[String]) {
        self.write_entry(
            "start",
            0,
            serde_json::json!({
                "system_prompt": system_prompt,
                "task_prompt": task_prompt,
                "tools": tools,
            }),
        );
    }

    /// One agent message (user / assistant / tool result).
    pub fn record_message(&self, step: u32, msg: &ChatMessage) {
        let kind = match msg.role {
            Role::User => {
                if has_tool_result(msg) {
                    "tool_result"
                } else {
                    "user"
                }
            }
            Role::Assistant => "assistant",
            Role::Tool => "tool_result",
            Role::System => "system",
        };
        let data = serde_json::to_value(msg).unwrap_or(serde_json::Value::Null);
        self.write_entry(kind, step, data);
    }

    /// Per-call token usage.
    pub fn record_usage(&self, step: u32, usage: &TokenUsage) {
        self.write_entry(
            "usage",
            step,
            serde_json::json!({
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_creation_input_tokens": usage.cache_creation_input_tokens,
                "cache_read_input_tokens": usage.cache_read_input_tokens,
            }),
        );
    }

    /// A compaction event.
    pub fn record_compaction(&self, step: u32, kind: &str, before: u32, after: u32) {
        self.write_entry(
            "compaction",
            step,
            serde_json::json!({
                "kind": kind,
                "tokens_before": before,
                "tokens_after": after,
            }),
        );
    }

    /// Terminal outcome.
    pub fn record_outcome(&self, step: u32, reason: &str, detail: serde_json::Value) {
        self.write_entry(
            "outcome",
            step,
            serde_json::json!({
                "reason": reason,
                "detail": detail,
            }),
        );
    }
}

fn has_tool_result(msg: &ChatMessage) -> bool {
    msg.parts
        .as_ref()
        .map(|p| {
            p.iter()
                .any(|p| matches!(p, ContentPart::ToolResult { .. }))
        })
        .unwrap_or(false)
}

/// Replace any character outside `[A-Za-z0-9._-]` with `_` so caller-supplied
/// IDs are safe path segments (and not e.g. `..` or `/`).
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// Replay the messages from a previous session log, reconstructing the
/// `Vec<ChatMessage>` portion. Returns the messages in order. Lines that
/// cannot be parsed are skipped with a warning.
pub fn replay_messages(path: &Path) -> std::io::Result<Vec<ChatMessage>> {
    use std::io::{BufRead, BufReader};
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "skipping unparsable session log line");
                continue;
            }
        };
        let kind = value.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        if !matches!(kind, "user" | "assistant" | "tool_result" | "system") {
            continue;
        }
        if let Some(data) = value.get("data") {
            if let Ok(msg) = serde_json::from_value::<ChatMessage>(data.clone()) {
                out.push(msg);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sanitize_strips_path_separators() {
        assert_eq!(sanitize("op-123"), "op-123");
        assert_eq!(sanitize("../etc/passwd"), ".._etc_passwd");
        assert_eq!(sanitize(""), "_");
        assert_eq!(sanitize("a/b\\c"), "a_b_c");
    }

    #[test]
    fn disabled_when_no_dir() {
        let cfg = SessionLogConfig::default();
        let log = SessionLog::open(&cfg, "op", "task", "recon", "model");
        assert!(!log.enabled());
        // No-op writes should not panic.
        log.record_start("sys", "task", &[]);
        log.record_outcome(0, "EndTurn", serde_json::json!({}));
    }

    #[test]
    fn writes_jsonl_lines() {
        let dir = tempdir().unwrap();
        let cfg = SessionLogConfig {
            dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let log = SessionLog::open(&cfg, "op-1", "t-1", "recon", "claude-sonnet-4-6");
        assert!(log.enabled());
        log.record_start("system", "do recon", &["nmap_scan".into()]);
        log.record_message(1, &ChatMessage::text(Role::User, "go"));
        log.record_message(1, &ChatMessage::text(Role::Assistant, "ok"));
        log.record_message(2, &ChatMessage::tool_result("c1", "open ports: 22, 80"));
        log.record_usage(
            1,
            &TokenUsage {
                input_tokens: 100,
                output_tokens: 20,
                ..Default::default()
            },
        );
        log.record_outcome(2, "EndTurn", serde_json::json!({"content": "done"}));

        let path = log.path().to_path_buf();
        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 6);
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["op_id"], "op-1");
            assert_eq!(v["task_id"], "t-1");
            assert_eq!(v["role"], "recon");
            assert_eq!(v["model"], "claude-sonnet-4-6");
            assert!(v.get("ts").is_some());
        }
        // Replay roundtrips just the message-shaped lines.
        let replayed = replay_messages(&path).unwrap();
        assert_eq!(replayed.len(), 3);
        assert_eq!(replayed[0].role, Role::User);
        assert_eq!(replayed[1].role, Role::Assistant);
        assert_eq!(replayed[2].role, Role::User);
    }

    #[test]
    fn record_compaction_writes_event() {
        let dir = tempdir().unwrap();
        let cfg = SessionLogConfig {
            dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let log = SessionLog::open(&cfg, "op-c", "t-c", "recon", "model");
        log.record_compaction(7, "proactive", 60_000, 30_000);

        let raw = std::fs::read_to_string(log.path()).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(v["kind"], "compaction");
        assert_eq!(v["step"], 7);
        assert_eq!(v["data"]["kind"], "proactive");
        assert_eq!(v["data"]["tokens_before"], 60_000);
        assert_eq!(v["data"]["tokens_after"], 30_000);
    }

    #[test]
    fn replay_skips_non_message_kinds() {
        let dir = tempdir().unwrap();
        let cfg = SessionLogConfig {
            dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let log = SessionLog::open(&cfg, "op-r", "t-r", "recon", "m");
        log.record_start("sys", "task", &[]);
        log.record_message(1, &ChatMessage::text(Role::User, "hello"));
        log.record_usage(
            1,
            &TokenUsage {
                input_tokens: 1,
                output_tokens: 2,
                ..Default::default()
            },
        );
        log.record_compaction(2, "reactive", 100, 50);
        log.record_outcome(2, "EndTurn", serde_json::json!({}));

        let replayed = replay_messages(log.path()).unwrap();
        // Only the single user message is a replayable kind.
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].role, Role::User);
    }

    #[test]
    fn replay_skips_unparsable_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("session.jsonl");
        // Mix valid + invalid lines + a record with unknown kind.
        let mut f = std::fs::File::create(&path).unwrap();
        use std::io::Write;
        writeln!(f, "{{not json}}").unwrap();
        writeln!(f).unwrap();
        writeln!(
            f,
            r#"{{"ts":"t","op_id":"o","task_id":"t","role":"r","step":0,"model":"m","kind":"unknown","data":{{}}}}"#
        )
        .unwrap();
        // A real user message
        let msg = ChatMessage::text(Role::User, "real");
        let entry = serde_json::json!({
            "ts":"t","op_id":"o","task_id":"t","role":"r","step":1,"model":"m",
            "kind":"user","data": serde_json::to_value(&msg).unwrap()
        });
        writeln!(f, "{entry}").unwrap();
        drop(f);

        let replayed = replay_messages(&path).unwrap();
        assert_eq!(replayed.len(), 1);
    }

    #[test]
    fn sanitize_collapses_empty_to_underscore() {
        assert_eq!(sanitize(""), "_");
        assert_eq!(sanitize("//"), "__");
    }
}
