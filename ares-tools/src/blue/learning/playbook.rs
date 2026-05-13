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

    let body = build_playbook_text(&op_id, &creds, &hosts, &loot, &meta);

    Ok(ToolOutput {
        stdout: body,
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// MITRE technique → (`run_detection_query` template name, description) pairs
/// used by the playbook builder. Order matters: the first five entries are
/// the recommended baseline that always appear, even when the operation
/// loot doesn't tag the technique.
fn playbook_technique_queries() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
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
    ]
}

/// Extract distinct usernames and IPs from a list of credential JSON strings.
/// Returns `(usernames, ips)` in first-seen order with deduplication.
/// Malformed JSON entries are silently skipped.
pub(crate) fn extract_users_and_ips_from_creds(creds: &[String]) -> (Vec<String>, Vec<String>) {
    let mut users = Vec::new();
    let mut ips = Vec::new();
    for cred in creds {
        let Ok(cred_json) = serde_json::from_str::<Value>(cred) else {
            continue;
        };
        if let Some(user) = cred_json.get("username").and_then(|u| u.as_str()) {
            if !users.contains(&user.to_string()) {
                users.push(user.to_string());
            }
        }
        if let Some(ip) = cred_json.get("ip").and_then(|i| i.as_str()) {
            if !ips.contains(&ip.to_string()) {
                ips.push(ip.to_string());
            }
        }
    }
    (users, ips)
}

/// Extract distinct MITRE technique IDs from a list of loot JSON strings.
/// Malformed JSON entries are silently skipped.
pub(crate) fn extract_techniques_from_loot(loot: &[String]) -> Vec<String> {
    let mut techniques = Vec::new();
    for item in loot {
        let Ok(loot_json) = serde_json::from_str::<Value>(item) else {
            continue;
        };
        if let Some(technique) = loot_json.get("technique").and_then(|t| t.as_str()) {
            if !techniques.contains(&technique.to_string()) {
                techniques.push(technique.to_string());
            }
        }
    }
    techniques
}

/// Build the human-readable detection playbook text from already-loaded
/// red-team operation state. Pure — no Redis, no IO.
///
/// `creds`, `loot` are raw JSON strings as returned by Redis (HGETALL /
/// LRANGE); `hosts` is a deduped string set of hostnames; `meta` is the
/// operation's metadata hash.
pub(crate) fn build_playbook_text(
    op_id: &str,
    creds: &[String],
    hosts: &std::collections::HashSet<String>,
    loot: &[String],
    meta: &HashMap<String, String>,
) -> String {
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

    let (target_users, target_ips) = extract_users_and_ips_from_creds(creds);
    let techniques_used = extract_techniques_from_loot(loot);

    // Priority queries based on what the red team actually did
    lines.push("\n--- Priority Detection Queries ---".to_string());

    let mut query_count = 0;
    let technique_queries = playbook_technique_queries();
    for (tech_id, query_name, description) in &technique_queries {
        let confirmed = techniques_used.iter().any(|t| t.starts_with(tech_id));
        if confirmed || query_count < 5 {
            let priority = if confirmed {
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

    lines.join("\n")
}

/// Normalize a MITRE technique ID to the standard `T####[.###]` form (just
/// uppercases the leading `t` if present). Used by the detection-template
/// lookup path; non-alpha input passes through unchanged.
pub(crate) fn normalize_technique_id(technique_id: &str) -> String {
    if technique_id.starts_with('t') || technique_id.starts_with('T') {
        let mut s = technique_id.to_string();
        s.replace_range(0..1, "T");
        s
    } else {
        technique_id.to_string()
    }
}

/// Build the static MITRE → detection-template lookup table the playbook
/// uses for `get_detection_queries_for_technique`. Pulled out so the
/// lookup logic (exact match → parent-technique fallback) can be unit
/// tested without round-tripping through the full async tool fn.
pub(crate) fn detection_templates_for_technique(
    technique_id: &str,
) -> Vec<(&'static str, &'static str)> {
    let normalized = normalize_technique_id(technique_id);
    let table: HashMap<&'static str, Vec<(&'static str, &'static str)>> = {
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

    if let Some(v) = table.get(normalized.as_str()) {
        return v.clone();
    }
    // Parent fallback.
    if let Some(parent) = normalized.split('.').next() {
        if let Some(v) = table.get(parent) {
            return v.clone();
        }
    }
    Vec::new()
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
    let normalized = normalize_technique_id(technique_id);
    let queries = detection_templates_for_technique(&normalized);

    let mut lines = vec![format!("Detection queries for {normalized}:\n")];
    if queries.is_empty() {
        lines.push("  No specific detection templates for this technique.".to_string());
        lines.push(
            "  Try using suggest_techniques or list_detection_templates to find relevant queries."
                .to_string(),
        );
    } else {
        for (name, desc) in &queries {
            lines.push(format!("  run_detection_query(\"{name}\") — {desc}"));
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

    // ── tests for build_playbook_text + extracted helpers ───────────────

    use super::{
        build_playbook_text, detection_templates_for_technique, extract_techniques_from_loot,
        extract_users_and_ips_from_creds, normalize_technique_id,
    };
    use std::collections::{HashMap, HashSet};

    fn cred_json(user: &str, ip: &str) -> String {
        json!({ "username": user, "ip": ip }).to_string()
    }

    // --- extract_users_and_ips_from_creds --------------------------------

    #[test]
    fn extract_users_ips_basic() {
        let creds = vec![
            cred_json("alice", "192.168.58.10"),
            cred_json("bob", "192.168.58.20"),
        ];
        let (users, ips) = extract_users_and_ips_from_creds(&creds);
        assert_eq!(users, vec!["alice", "bob"]);
        assert_eq!(ips, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn extract_users_ips_dedupes_in_order() {
        let creds = vec![
            cred_json("alice", "192.168.58.10"),
            cred_json("alice", "192.168.58.10"),
            cred_json("alice", "192.168.58.20"),
        ];
        let (users, ips) = extract_users_and_ips_from_creds(&creds);
        assert_eq!(users, vec!["alice"]);
        assert_eq!(ips, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn extract_users_ips_skips_malformed_json() {
        let creds = vec![
            "not valid json".to_string(),
            cred_json("alice", "192.168.58.10"),
        ];
        let (users, ips) = extract_users_and_ips_from_creds(&creds);
        assert_eq!(users, vec!["alice"]);
        assert_eq!(ips, vec!["192.168.58.10"]);
    }

    #[test]
    fn extract_users_ips_handles_missing_fields() {
        let creds = vec![
            json!({"password": "P@ss"}).to_string(),
            json!({"username": "alice"}).to_string(),
            json!({"ip": "192.168.58.10"}).to_string(),
        ];
        let (users, ips) = extract_users_and_ips_from_creds(&creds);
        assert_eq!(users, vec!["alice"]);
        assert_eq!(ips, vec!["192.168.58.10"]);
    }

    // --- extract_techniques_from_loot ------------------------------------

    #[test]
    fn extract_techniques_dedupes_and_preserves_order() {
        let loot = vec![
            json!({"technique": "T1003"}).to_string(),
            json!({"technique": "T1558.003"}).to_string(),
            json!({"technique": "T1003"}).to_string(),
        ];
        assert_eq!(
            extract_techniques_from_loot(&loot),
            vec!["T1003", "T1558.003"]
        );
    }

    #[test]
    fn extract_techniques_skips_malformed_and_missing() {
        let loot = vec![
            "{not json".to_string(),
            json!({"summary": "no technique field"}).to_string(),
            json!({"technique": "T1110"}).to_string(),
        ];
        assert_eq!(extract_techniques_from_loot(&loot), vec!["T1110"]);
    }

    // --- normalize_technique_id ------------------------------------------

    #[test]
    fn normalize_lowercases_leading_t() {
        assert_eq!(normalize_technique_id("t1003"), "T1003");
        assert_eq!(normalize_technique_id("T1003"), "T1003");
        assert_eq!(normalize_technique_id("t1558.003"), "T1558.003");
    }

    #[test]
    fn normalize_passes_through_unknown_prefix() {
        // Non-`t` input is returned unchanged.
        assert_eq!(normalize_technique_id("1003"), "1003");
        assert_eq!(normalize_technique_id(""), "");
    }

    // --- detection_templates_for_technique -------------------------------

    #[test]
    fn detection_templates_exact_match() {
        let v = detection_templates_for_technique("T1558.003");
        assert!(v.iter().any(|(n, _)| *n == "detect_kerberoasting"));
    }

    #[test]
    fn detection_templates_normalizes_lowercase_t() {
        let v = detection_templates_for_technique("t1558.003");
        assert!(v.iter().any(|(n, _)| *n == "detect_kerberoasting"));
    }

    #[test]
    fn detection_templates_parent_fallback() {
        // T1003.999 doesn't exist — fall back to T1003.
        let v = detection_templates_for_technique("T1003.999");
        assert!(v.iter().any(|(n, _)| *n == "detect_secretsdump"));
    }

    #[test]
    fn detection_templates_unknown_returns_empty() {
        assert!(detection_templates_for_technique("T9999").is_empty());
    }

    #[test]
    fn detection_templates_subtechnique_takes_precedence_over_parent() {
        // T1003.006 has its own entry — should not fall back to T1003.
        let v = detection_templates_for_technique("T1003.006");
        assert!(v.iter().any(|(n, _)| *n == "detect_dcsync_replication"));
        // T1003 has detect_lsa_secrets_access; T1003.006 does not.
        assert!(!v.iter().any(|(n, _)| *n == "detect_lsa_secrets_access"));
    }

    // --- build_playbook_text ---------------------------------------------

    fn empty_state() -> (
        Vec<String>,
        HashSet<String>,
        Vec<String>,
        HashMap<String, String>,
    ) {
        (Vec::new(), HashSet::new(), Vec::new(), HashMap::new())
    }

    #[test]
    fn playbook_text_header_includes_op_id() {
        let (c, h, l, m) = empty_state();
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        assert!(text.contains("=== Detection Playbook for Operation op-abc ==="));
    }

    #[test]
    fn playbook_text_emits_baseline_queries_when_no_loot() {
        let (c, h, l, m) = empty_state();
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        // First five technique_queries become MEDIUM baseline regardless.
        let medium_count = text.matches("MEDIUM (recommended baseline)").count();
        assert_eq!(medium_count, 5);
        assert!(text.contains("detect_dcsync"));
        assert!(text.contains("detect_secretsdump"));
    }

    #[test]
    fn playbook_text_promotes_confirmed_techniques_to_high() {
        let (mut c, h, mut l, m) = empty_state();
        // ADCS exploitation is the 9th in the list; without confirmation
        // it stays out of the baseline-5 cut.
        l.push(json!({"technique": "T1649.001"}).to_string());
        c.push(cred_json("alice", "192.168.58.10"));
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        assert!(text.contains("[HIGH (confirmed red team technique)] detect_adcs_exploitation"));
    }

    #[test]
    fn playbook_text_emits_meta_lines_when_present() {
        let (c, h, l, mut m) = empty_state();
        m.insert("started_at".into(), "2025-01-28T12:00:00Z".into());
        m.insert("domain".into(), "contoso.local".into());
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        assert!(text.contains("Operation started: 2025-01-28T12:00:00Z"));
        assert!(text.contains("Target domain: contoso.local"));
    }

    #[test]
    fn playbook_text_lists_compromised_accounts_when_creds_present() {
        let (mut c, h, l, m) = empty_state();
        c.push(cred_json("alice", "192.168.58.10"));
        c.push(cred_json("bob", "192.168.58.20"));
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        assert!(text.contains("--- Compromised Accounts (2) ---"));
        assert!(text.contains("  alice"));
        assert!(text.contains("  bob"));
        assert!(text.contains("--- Target IPs (2) ---"));
    }

    #[test]
    fn playbook_text_caps_users_at_twenty() {
        let (mut c, h, l, m) = empty_state();
        for i in 0..25 {
            c.push(cred_json(
                &format!("user{i:02}"),
                &format!("192.168.58.{}", i + 1),
            ));
        }
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        // Header should show 25, but the rendered list takes only 20.
        assert!(text.contains("--- Compromised Accounts (25) ---"));
        let user_lines = text.lines().filter(|l| l.starts_with("  user")).count();
        assert_eq!(user_lines, 20);
    }

    #[test]
    fn playbook_text_lists_hosts_sorted() {
        let (c, mut h, l, m) = empty_state();
        h.insert("web01.contoso.local".into());
        h.insert("dc01.contoso.local".into());
        h.insert("sql01.contoso.local".into());
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        let host_section_pos = text.find("--- Discovered Hosts (3)").unwrap();
        let section = &text[host_section_pos..];
        let dc_pos = section.find("dc01").unwrap();
        let sql_pos = section.find("sql01").unwrap();
        let web_pos = section.find("web01").unwrap();
        assert!(dc_pos < sql_pos && sql_pos < web_pos);
    }

    #[test]
    fn playbook_text_lists_techniques_when_loot_has_them() {
        let (c, h, mut l, m) = empty_state();
        l.push(json!({"technique": "T1003"}).to_string());
        l.push(json!({"technique": "T1558.003"}).to_string());
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        assert!(text.contains("--- Techniques Used (2) ---"));
        assert!(text.contains("  T1003"));
        assert!(text.contains("  T1558.003"));
    }

    #[test]
    fn playbook_text_omits_empty_sections() {
        let (c, h, l, m) = empty_state();
        let text = build_playbook_text("op-abc", &c, &h, &l, &m);
        assert!(!text.contains("--- Compromised Accounts"));
        assert!(!text.contains("--- Target IPs"));
        assert!(!text.contains("--- Discovered Hosts"));
        assert!(!text.contains("--- Techniques Used"));
    }
}
