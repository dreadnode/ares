//! Red team playbook integration — Redis-backed detection query generation.

use std::collections::HashMap;

use serde_json::Value;

use crate::ToolOutput;

/// Load a red team operation's state from Redis and generate a detection
/// playbook with prioritized LogQL queries.
///
/// Parameters:
/// - `operation_id` (optional): Specific op ID. If omitted, finds latest.
/// - `redis_url` (optional): Redis URL override.
pub async fn get_attack_playbook(args: &Value) -> anyhow::Result<ToolOutput> {
    let operation_id = args.get("operation_id").and_then(Value::as_str);
    let redis_url = args
        .get("redis_url")
        .and_then(Value::as_str)
        .unwrap_or("redis://127.0.0.1:6379");

    let redis_url = std::env::var("ARES_REDIS_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| redis_url.to_string());

    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            return Ok(ToolOutput {
                stdout: String::new(),
                stderr: format!("Failed to connect to Redis: {e}"),
                exit_code: Some(1),
                success: false,
            })
        }
    };
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            return Ok(ToolOutput {
                stdout: String::new(),
                stderr: format!("Redis connection failed: {e}"),
                exit_code: Some(1),
                success: false,
            })
        }
    };

    // Find operation ID
    let op_id = if let Some(id) = operation_id {
        id.to_string()
    } else {
        // Scan for latest operation
        match find_latest_operation(&mut conn).await {
            Some(id) => id,
            None => {
                return Ok(ToolOutput {
                    stdout: "No red team operations found in Redis.".into(),
                    stderr: String::new(),
                    exit_code: Some(0),
                    success: true,
                })
            }
        }
    };

    // Load red team state: credentials, techniques, targets
    let meta_key = format!("ares:op:{op_id}:meta");
    let meta_exists: bool = redis::AsyncCommands::exists(&mut conn, &meta_key)
        .await
        .unwrap_or(false);
    if !meta_exists {
        return Ok(ToolOutput {
            stdout: format!("Operation {op_id} not found in Redis."),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let (creds, hosts, loot, meta) = load_op_collections(&mut conn, &op_id).await;

    // Build playbook
    let mut lines = Vec::new();
    lines.push(format!(
        "=== Detection Playbook for Operation {op_id} ===\n"
    ));

    if let Some(started) = meta.get("started_at") {
        lines.push(format!("Operation started: {started}"));
    }
    if let Some(domain) = meta.get("domain") {
        lines.push(format!("Target domain: {domain}"));
    }

    // Extract usernames and IPs from credentials for targeted queries
    let mut target_users = Vec::new();
    let mut target_ips = Vec::new();
    for cred in &creds {
        if let Ok(cred_json) = serde_json::from_str::<Value>(cred) {
            if let Some(user) = cred_json.get("username").and_then(|u| u.as_str()) {
                if !target_users.contains(&user.to_string()) {
                    target_users.push(user.to_string());
                }
            }
            if let Some(ip) = cred_json.get("ip").and_then(|i| i.as_str()) {
                if !target_ips.contains(&ip.to_string()) {
                    target_ips.push(ip.to_string());
                }
            }
        }
    }

    // Extract techniques from loot
    let mut techniques_used = Vec::new();
    for item in &loot {
        if let Ok(loot_json) = serde_json::from_str::<Value>(item) {
            if let Some(technique) = loot_json.get("technique").and_then(|t| t.as_str()) {
                if !techniques_used.contains(&technique.to_string()) {
                    techniques_used.push(technique.to_string());
                }
            }
        }
    }

    // Priority queries based on what the red team actually did
    lines.push("\n--- Priority Detection Queries ---".to_string());

    let mut query_count = 0;
    let technique_queries: Vec<(&str, &str, &str)> = vec![
        ("T1003.006", "detect_dcsync", "DCSync replication attack"),
        ("T1003", "detect_secretsdump", "Credential dumping"),
        ("T1558.003", "detect_kerberoasting", "Kerberoasting"),
        ("T1558.004", "detect_asrep_roasting", "AS-REP Roasting"),
        ("T1558.001", "detect_golden_ticket", "Golden ticket usage"),
        ("T1550.002", "detect_pass_the_hash", "Pass-the-Hash"),
        ("T1021", "detect_lateral_movement", "Lateral movement"),
        ("T1110", "detect_brute_force", "Brute force / spray"),
        (
            "T1649",
            "detect_adcs_exploitation",
            "ADCS certificate abuse",
        ),
    ];

    for (tech_id, query_name, description) in &technique_queries {
        if techniques_used.iter().any(|t| t.starts_with(tech_id)) || query_count < 5 {
            let priority = if techniques_used.iter().any(|t| t.starts_with(tech_id)) {
                "HIGH (confirmed red team technique)"
            } else {
                "MEDIUM (recommended baseline)"
            };
            lines.push(format!(
                "  [{priority}] {query_name} — {description} ({tech_id})"
            ));
            query_count += 1;
        }
    }

    // IOC targets
    if !target_users.is_empty() {
        lines.push(format!(
            "\n--- Compromised Accounts ({}) ---",
            target_users.len()
        ));
        for user in target_users.iter().take(20) {
            lines.push(format!("  {user}"));
        }
    }

    if !target_ips.is_empty() {
        lines.push(format!("\n--- Target IPs ({}) ---", target_ips.len()));
        for ip in target_ips.iter().take(20) {
            lines.push(format!("  {ip}"));
        }
    }

    if !hosts.is_empty() {
        lines.push(format!("\n--- Discovered Hosts ({}) ---", hosts.len()));
        let mut sorted_hosts: Vec<&String> = hosts.iter().collect();
        sorted_hosts.sort();
        for host in sorted_hosts.iter().take(20) {
            lines.push(format!("  {host}"));
        }
    }

    if !techniques_used.is_empty() {
        lines.push(format!(
            "\n--- Techniques Used ({}) ---",
            techniques_used.len()
        ));
        for tech in &techniques_used {
            lines.push(format!("  {tech}"));
        }
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Get detection queries specific to a MITRE technique, optionally informed
/// by red team operation state.
///
/// Parameters:
/// - `technique_id` (required)
/// - `operation_id` (optional)
/// - `redis_url` (optional)
pub async fn get_detection_queries_for_technique(args: &Value) -> anyhow::Result<ToolOutput> {
    let technique_id = crate::args::required_str(args, "technique_id")?;

    // Normalize
    let normalized = if technique_id.starts_with('t') || technique_id.starts_with('T') {
        let mut s = technique_id.to_string();
        s.replace_range(0..1, "T");
        s
    } else {
        technique_id.to_string()
    };

    // Static technique → detection template mapping
    let technique_to_queries: HashMap<&str, Vec<(&str, &str)>> = {
        let mut m = HashMap::new();
        m.insert(
            "T1003",
            vec![
                ("detect_secretsdump", "Credential dumping via secretsdump"),
                ("detect_dcsync", "DCSync replication attack"),
                ("detect_lsa_secrets_access", "LSA secrets registry access"),
            ],
        );
        m.insert(
            "T1003.006",
            vec![
                ("detect_dcsync", "DCSync replication attack"),
                (
                    "detect_dcsync_replication",
                    "DCSync via RPC replication calls",
                ),
            ],
        );
        m.insert(
            "T1558.003",
            vec![(
                "detect_kerberoasting",
                "Kerberoasting TGS requests with RC4",
            )],
        );
        m.insert(
            "T1558.004",
            vec![
                ("detect_asrep_roasting", "AS-REP Roasting pre-auth disabled"),
                ("detect_asrep_roasting_bulk", "Bulk AS-REP Roasting"),
            ],
        );
        m.insert(
            "T1558.001",
            vec![("detect_golden_ticket", "Golden ticket anomalous TGT")],
        );
        m.insert(
            "T1550.002",
            vec![("detect_pass_the_hash", "Pass-the-Hash NTLM authentication")],
        );
        m.insert(
            "T1021",
            vec![
                ("detect_lateral_movement", "Remote service lateral movement"),
                ("detect_smb_file_access", "SMB share access"),
            ],
        );
        m.insert(
            "T1021.002",
            vec![
                ("detect_smb_file_access", "SMB/admin share access"),
                ("detect_lateral_movement", "SMB lateral movement"),
            ],
        );
        m.insert(
            "T1110",
            vec![
                ("detect_brute_force", "Password brute force"),
                ("detect_password_spray", "Password spray"),
            ],
        );
        m.insert(
            "T1078",
            vec![("detect_lateral_movement", "Anomalous logon patterns")],
        );
        m.insert(
            "T1649",
            vec![
                ("detect_adcs_exploitation", "ADCS exploitation"),
                ("detect_certipy_enumeration", "Certipy enumeration"),
                ("detect_esc1_attack", "ESC1 template abuse"),
            ],
        );
        m.insert(
            "T1134",
            vec![
                ("detect_s4u_delegation", "S4U delegation abuse"),
                ("detect_delegation_abuse", "Kerberos delegation abuse"),
            ],
        );
        m
    };

    // Try exact match, then parent technique
    let queries = technique_to_queries.get(normalized.as_str()).or_else(|| {
        normalized
            .split('.')
            .next()
            .and_then(|parent| technique_to_queries.get(parent))
    });

    let mut lines = vec![format!("Detection queries for {normalized}:\n")];

    match queries {
        Some(query_list) => {
            for (name, desc) in query_list {
                lines.push(format!("  run_detection_query(\"{name}\") — {desc}"));
            }
        }
        None => {
            lines.push("  No specific detection templates for this technique.".to_string());
            lines.push(
                "  Try using suggest_techniques or list_detection_templates to find relevant queries."
                    .to_string(),
            );
        }
    }

    // If an operation ID is provided, add context from the playbook
    if args.get("operation_id").is_some() {
        lines.push("\nFetching operation context...".to_string());
        let playbook_result = get_attack_playbook(args).await?;
        if playbook_result.success && !playbook_result.stdout.is_empty() {
            lines.push(String::new());
            lines.push("--- Operation Context ---".to_string());
            // Extract just the relevant IOC lines
            for line in playbook_result.stdout.lines() {
                if line.contains("Compromised")
                    || line.contains("Target IP")
                    || line.starts_with("  ")
                {
                    lines.push(line.to_string());
                }
            }
        }
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Load credentials, hosts, loot, and metadata for an operation from Redis.
///
/// Credentials are stored as a HASH (dedup_key → JSON), hosts as a LIST,
/// loot as a LIST, and metadata as a HASH.
async fn load_op_collections(
    conn: &mut impl redis::AsyncCommands,
    op_id: &str,
) -> (
    Vec<String>,
    std::collections::HashSet<String>,
    Vec<String>,
    HashMap<String, String>,
) {
    // Credentials — stored as HASH (dedup_key -> JSON)
    let creds_key = format!("ares:op:{op_id}:credentials");
    let creds_map: HashMap<String, String> = redis::AsyncCommands::hgetall(conn, &creds_key)
        .await
        .unwrap_or_default();
    let creds: Vec<String> = creds_map.into_values().collect();

    // Hosts — stored as LIST (JSON per entry)
    let hosts_key = format!("ares:op:{op_id}:hosts");
    let hosts_list: Vec<String> = redis::AsyncCommands::lrange(conn, &hosts_key, 0, -1)
        .await
        .unwrap_or_default();
    let hosts: std::collections::HashSet<String> = hosts_list.into_iter().collect();

    // Loot/techniques
    let loot_key = format!("ares:op:{op_id}:loot");
    let loot: Vec<String> = redis::AsyncCommands::lrange(conn, &loot_key, 0, -1)
        .await
        .unwrap_or_default();

    // Operation metadata
    let meta_key = format!("ares:op:{op_id}:meta");
    let meta: HashMap<String, String> = redis::AsyncCommands::hgetall(conn, &meta_key)
        .await
        .unwrap_or_default();

    (creds, hosts, loot, meta)
}

/// Find the latest operation ID in Redis by scanning `ares:op:*:meta` keys.
async fn find_latest_operation(conn: &mut redis::aio::MultiplexedConnection) -> Option<String> {
    let mut cursor: u64 = 0;
    let mut latest_id: Option<String> = None;

    loop {
        let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("ares:op:*:meta")
            .arg("COUNT")
            .arg(100)
            .query_async(conn)
            .await
            .ok()?;

        for key in keys {
            // Extract op ID from "ares:op:{id}:meta"
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() >= 3 {
                let id = parts[2].to_string();
                // Pick latest alphabetically (UUIDs sort chronologically for v7,
                // otherwise just pick the last one found)
                latest_id = Some(match latest_id {
                    Some(prev) if prev > id => prev,
                    _ => id,
                });
            }
        }

        cursor = new_cursor;
        if cursor == 0 {
            break;
        }
    }

    latest_id
}

#[cfg(test)]
mod tests {
    use super::super::mitre_db::{lookup_technique, suggest_techniques};
    use serde_json::json;

    #[test]
    fn lookup_known_technique() {
        let args = json!({"technique_id": "T1003"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("OS Credential Dumping"));
        assert!(result.stdout.contains("Credential Access"));
    }

    #[test]
    fn lookup_subtechnique() {
        let args = json!({"technique_id": "T1003.001"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("LSASS Memory"));
    }

    #[test]
    fn lookup_unknown_falls_back_to_parent() {
        let args = json!({"technique_id": "T1003.999"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("OS Credential Dumping"));
        assert!(result.stdout.contains("parent technique"));
    }

    #[test]
    fn lookup_completely_unknown() {
        let args = json!({"technique_id": "T9999"});
        let result = lookup_technique(&args).unwrap();
        assert!(!result.success);
        assert!(result.stderr.contains("not found"));
    }

    #[test]
    fn lookup_case_insensitive() {
        let args = json!({"technique_id": "t1003"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("OS Credential Dumping"));
    }

    #[test]
    fn suggest_credential_access() {
        let args = json!({"evidence_type": "credential_access"});
        let result = suggest_techniques(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("T1003"));
        assert!(result.stdout.contains("T1558"));
    }

    #[test]
    fn suggest_lateral_movement() {
        let args = json!({"evidence_type": "lateral_movement"});
        let result = suggest_techniques(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("T1021"));
        assert!(result.stdout.contains("T1550"));
    }

    #[test]
    fn suggest_with_hyphens() {
        let args = json!({"evidence_type": "lateral-movement"});
        let result = suggest_techniques(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("T1021"));
    }

    #[test]
    fn suggest_unknown_type() {
        let args = json!({"evidence_type": "nonexistent"});
        let result = suggest_techniques(&args).unwrap();
        assert!(!result.success);
        assert!(result.stderr.contains("Unknown evidence type"));
        assert!(result.stderr.contains("Available types"));
    }

    #[test]
    fn missing_required_arg() {
        let args = json!({});
        let result = lookup_technique(&args);
        assert!(result.is_err());
    }

    // -- load_op_collections tests (mock Redis) --

    use super::load_op_collections;
    use ares_core::state::mock_redis::MockRedisConnection;
    use redis::AsyncCommands;

    #[tokio::test]
    async fn load_op_collections_empty() {
        let mut conn = MockRedisConnection::new();
        let (creds, hosts, loot, meta) = load_op_collections(&mut conn, "op-test").await;
        assert!(creds.is_empty());
        assert!(hosts.is_empty());
        assert!(loot.is_empty());
        assert!(meta.is_empty());
    }

    #[tokio::test]
    async fn load_op_collections_reads_credentials_as_hash() {
        let mut conn = MockRedisConnection::new();
        let key = "ares:op:op-test:credentials";
        let cred_json = json!({
            "username": "admin",
            "password": "P@ssw0rd!",  // pragma: allowlist secret
            "domain": "contoso.local"
        })
        .to_string();
        conn.hset::<_, _, _, ()>(key, "cred:contoso.local:admin:abc123", &cred_json)
            .await
            .unwrap();

        let (creds, _, _, _) = load_op_collections(&mut conn, "op-test").await;
        assert_eq!(creds.len(), 1);
        assert!(creds[0].contains("admin"));
    }

    #[tokio::test]
    async fn load_op_collections_reads_hosts_as_list() {
        let mut conn = MockRedisConnection::new();
        let key = "ares:op:op-test:hosts";
        let host_json = json!({
            "ip": "192.168.58.10",
            "hostname": "dc01.contoso.local"
        })
        .to_string();
        conn.rpush::<_, _, ()>(key, &host_json).await.unwrap();

        let (_, hosts, _, _) = load_op_collections(&mut conn, "op-test").await;
        assert_eq!(hosts.len(), 1);
        assert!(hosts.iter().next().unwrap().contains("192.168.58.10"));
    }

    #[tokio::test]
    async fn load_op_collections_reads_meta_as_hash() {
        let mut conn = MockRedisConnection::new();
        let key = "ares:op:op-test:meta";
        conn.hset::<_, _, _, ()>(key, "target_domain", "contoso.local")
            .await
            .unwrap();
        conn.hset::<_, _, _, ()>(key, "started_at", "2025-01-28T12:00:00Z")
            .await
            .unwrap();

        let (_, _, _, meta) = load_op_collections(&mut conn, "op-test").await;
        assert_eq!(meta.get("target_domain").unwrap(), "contoso.local");
        assert_eq!(meta.get("started_at").unwrap(), "2025-01-28T12:00:00Z");
    }

    #[tokio::test]
    async fn load_op_collections_multiple_credentials_deduped_by_hash_field() {
        let mut conn = MockRedisConnection::new();
        let key = "ares:op:op-test:credentials";
        let cred1 = json!({"username": "alice", "domain": "contoso.local"}).to_string();
        let cred2 = json!({"username": "bob", "domain": "contoso.local"}).to_string();
        conn.hset::<_, _, _, ()>(key, "cred:contoso.local:alice:aaa", &cred1)
            .await
            .unwrap();
        conn.hset::<_, _, _, ()>(key, "cred:contoso.local:bob:bbb", &cred2)
            .await
            .unwrap();
        // Duplicate field — should overwrite, not duplicate
        conn.hset::<_, _, _, ()>(key, "cred:contoso.local:alice:aaa", &cred1)
            .await
            .unwrap();

        let (creds, _, _, _) = load_op_collections(&mut conn, "op-test").await;
        assert_eq!(creds.len(), 2);
    }
}
