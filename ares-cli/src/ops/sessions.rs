use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use ares_llm::{replay_messages, ChatMessage, ContentPart, Role, SessionLogConfig};

use crate::cli::SessionsCommands;

pub(crate) async fn run_sessions(cmd: SessionsCommands) -> Result<()> {
    match cmd {
        SessionsCommands::List { operation_id } => sessions_list(operation_id),
        SessionsCommands::Show {
            operation_id,
            task_id,
            pretty,
        } => sessions_show(&operation_id, &task_id, pretty),
        SessionsCommands::Replay {
            operation_id,
            task_id,
            json,
        } => sessions_replay(&operation_id, &task_id, json),
    }
}

fn session_root() -> Result<PathBuf> {
    SessionLogConfig::default_root()
        .ok_or_else(|| anyhow!("session log root unset (set ARES_SESSION_LOG_DIR or HOME)"))
}

fn sessions_list(operation_id: Option<String>) -> Result<()> {
    let root = session_root()?;
    if !root.exists() {
        println!("No session logs at {}", root.display());
        return Ok(());
    }

    match operation_id {
        None => list_operation_ids(&root),
        Some(op_id) => list_task_ids(&root, &op_id),
    }
}

fn list_operation_ids(root: &Path) -> Result<()> {
    let mut entries: Vec<String> = std::fs::read_dir(root)
        .with_context(|| format!("reading session log root {}", root.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    entries.sort();
    if entries.is_empty() {
        println!("No session logs at {}", root.display());
        return Ok(());
    }
    println!("Operations with session logs ({}):", root.display());
    for op_id in entries {
        println!("  {op_id}");
    }
    Ok(())
}

fn list_task_ids(root: &Path, op_id: &str) -> Result<()> {
    let dir = root.join(op_id);
    if !dir.exists() {
        return Err(anyhow!(
            "no session logs for operation {op_id} at {}",
            dir.display()
        ));
    }
    let mut entries: Vec<(String, u64)> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".jsonl")?.to_string();
            let size = e.metadata().ok()?.len();
            Some((stem, size))
        })
        .collect();
    entries.sort();
    if entries.is_empty() {
        println!("No session logs for operation {op_id}");
        return Ok(());
    }
    println!("Tasks for {op_id}:");
    for (task_id, size) in entries {
        println!("  {task_id}  ({size} bytes)");
    }
    Ok(())
}

fn sessions_show(op_id: &str, task_id: &str, pretty: bool) -> Result<()> {
    let path = session_path(op_id, task_id)?;
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading session log {}", path.display()))?;
    if !pretty {
        print!("{raw}");
        return Ok(());
    }
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => {
                let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
                let step = v.get("step").and_then(|s| s.as_u64()).unwrap_or(0);
                let ts = v.get("ts").and_then(|t| t.as_str()).unwrap_or("?");
                println!("[{ts}] step={step} kind={kind}");
                if let Some(data) = v.get("data") {
                    let pretty_data =
                        serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string());
                    for ln in pretty_data.lines() {
                        println!("    {ln}");
                    }
                }
            }
            Err(_) => println!("[unparsable] {line}"),
        }
    }
    Ok(())
}

fn sessions_replay(op_id: &str, task_id: &str, json: bool) -> Result<()> {
    let path = session_path(op_id, task_id)?;
    let messages = replay_messages(&path)
        .with_context(|| format!("replaying session log {}", path.display()))?;
    if json {
        let out = serde_json::to_string_pretty(&messages)?;
        println!("{out}");
        return Ok(());
    }
    if messages.is_empty() {
        println!("No replayable messages in {}", path.display());
        return Ok(());
    }
    for (i, msg) in messages.iter().enumerate() {
        print_message(i, msg);
    }
    Ok(())
}

fn session_path(op_id: &str, task_id: &str) -> Result<PathBuf> {
    let root = session_root()?;
    let mut path = root.join(op_id);
    path.push(format!("{task_id}.jsonl"));
    if !path.exists() {
        return Err(anyhow!("no session log at {}", path.display()));
    }
    Ok(path)
}

fn print_message(index: usize, msg: &ChatMessage) {
    let role = match msg.role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    };
    println!("--- [{index}] {role} ---");
    if let Some(text) = msg.content.as_deref() {
        println!("{text}");
    }
    if let Some(parts) = msg.parts.as_ref() {
        for part in parts {
            match part {
                ContentPart::Text { text } => println!("{text}"),
                ContentPart::ToolResult {
                    tool_use_id,
                    content,
                } => println!("<tool_result id={tool_use_id}>\n{content}"),
                ContentPart::ToolUse { id, name, input } => {
                    let pretty =
                        serde_json::to_string_pretty(input).unwrap_or_else(|_| input.to_string());
                    println!("<tool_use id={id} name={name}>\n{pretty}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_llm::SessionLog;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Serializes tests that mutate `ARES_SESSION_LOG_DIR` so the parallel
    /// scheduler does not interleave them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_root<F: FnOnce(&Path) -> Result<()>>(f: F) -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let prev_dir = std::env::var_os("ARES_SESSION_LOG_DIR");
        std::env::set_var("ARES_SESSION_LOG_DIR", dir.path());
        let result = f(dir.path());
        match prev_dir {
            Some(v) => std::env::set_var("ARES_SESSION_LOG_DIR", v),
            None => std::env::remove_var("ARES_SESSION_LOG_DIR"),
        }
        result
    }

    fn write_session(root: &Path, op_id: &str, task_id: &str) {
        let cfg = SessionLogConfig {
            dir: Some(root.to_path_buf()),
            ..Default::default()
        };
        let log = SessionLog::open(&cfg, op_id, task_id, "recon", "test-model");
        log.record_start("sys", "task", &[]);
        log.record_message(1, &ChatMessage::text(Role::User, "hello"));
        log.record_message(1, &ChatMessage::text(Role::Assistant, "hi"));
        log.record_outcome(1, "EndTurn", serde_json::json!({}));
    }

    #[test]
    fn list_operations_finds_jsonl_dirs() {
        with_root(|root| {
            write_session(root, "op-aaa", "task-1");
            write_session(root, "op-bbb", "task-2");
            sessions_list(None)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn list_tasks_for_operation_errors_when_missing() {
        with_root(|_root| {
            let err = sessions_list(Some("nope".into())).unwrap_err();
            assert!(err.to_string().contains("nope"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn replay_returns_user_and_assistant_messages() {
        with_root(|root| {
            write_session(root, "op-x", "task-x");
            // exercise both replay and show paths
            sessions_replay("op-x", "task-x", false)?;
            sessions_replay("op-x", "task-x", true)?;
            sessions_show("op-x", "task-x", true)?;
            sessions_show("op-x", "task-x", false)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn show_missing_session_errors() {
        with_root(|_root| {
            let err = sessions_show("op-missing", "task", false).unwrap_err();
            assert!(err.to_string().contains("no session log"));
            Ok(())
        })
        .unwrap();
    }
}
