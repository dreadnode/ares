use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::TaskStatusRecord;

use crate::redis_conn::{connect_redis, resolve_operation_id};

pub(crate) async fn ops_tasks(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    task_status: String,
    role: Option<String>,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let task_keys = {
        let mut all_keys = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("ares:task_status:*")
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await?;
            all_keys.extend(keys);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        all_keys
    };

    let mut found_tasks: Vec<(String, TaskStatusRecord)> = Vec::new();

    for key in &task_keys {
        let raw: Option<String> = conn.get(key).await?;
        let Some(json_str) = raw else { continue };

        let data: TaskStatusRecord = match serde_json::from_str(&json_str) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if data.operation_id != op_id {
            continue;
        }
        if let Some(ref role_filter) = role {
            if data.role.as_deref() != Some(role_filter.as_str()) {
                continue;
            }
        }
        if task_status != "all" && data.status != task_status {
            continue;
        }

        found_tasks.push((key.clone(), data));
    }

    if found_tasks.is_empty() {
        println!("No {task_status} tasks found for operation {op_id}");
        return Ok(());
    }

    found_tasks.sort_by(|a, b| {
        let a_time =
            a.1.started_at
                .as_deref()
                .or(a.1.ended_at.as_deref())
                .unwrap_or("");
        let b_time =
            b.1.started_at
                .as_deref()
                .or(b.1.ended_at.as_deref())
                .unwrap_or("");
        a_time.cmp(b_time)
    });

    for (key, data) in &found_tasks {
        println!("{key}");
        let display = serde_json::json!({
            "status": data.status,
            "started_at": data.started_at,
            "ended_at": data.ended_at,
            "pod": data.pod_name,
            "role": data.role,
            "task_type": data.task_type,
            "error": data.error,
            "payload": data.payload,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&display).unwrap_or_default()
        );
    }

    Ok(())
}
