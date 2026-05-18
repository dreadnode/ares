use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use redis::AsyncCommands;
use tracing::{info, warn};

use crate::redis_conn::connect_redis;

/// Environment variable names to capture for blue team investigations.
#[cfg(feature = "blue")]
pub(crate) const BLUE_ENV_VAR_NAMES: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GRAFANA_SERVICE_ACCOUNT_TOKEN",
    "GRAFANA_URL",
    "LOKI_URL",
    "LOKI_AUTH_TOKEN",
    "PROMETHEUS_URL",
    "DREADNODE_API_KEY",
    "DREADNODE_SERVER_URL",
    "DREADNODE_ORGANIZATION",
    "DREADNODE_WORKSPACE",
    "DREADNODE_PROJECT",
    "ARES_MODEL",
    "ARES_ORCHESTRATOR_MODEL",
];

/// Environment variable names to capture and pass to the orchestrator.
pub(crate) const OPS_ENV_VAR_NAMES: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DREADNODE_API_KEY",
    "DREADNODE_API_TOKEN",
    "DREADNODE_SERVER_URL",
    "DREADNODE_SERVER",
    "DREADNODE_ORGANIZATION",
    "DREADNODE_WORKSPACE",
    "DREADNODE_PROJECT",
    "GRAFANA_SERVICE_ACCOUNT_TOKEN",
    "GRAFANA_URL",
    "ARES_MODEL",
    "ARES_ORCHESTRATOR_MODEL",
    "ARES_WORKER_MODEL",
    "ARES_AGENT_RECON_MODEL",
    "ARES_AGENT_CREDENTIAL_ACCESS_MODEL",
    "ARES_AGENT_CRACKER_MODEL",
    "ARES_AGENT_ACL_MODEL",
    "ARES_AGENT_PRIVESC_MODEL",
    "ARES_AGENT_LATERAL_MODEL",
    "ARES_AGENT_COERCION_MODEL",
];

/// Collect environment variables that are set, returning a map of name->value.
pub(crate) fn collect_env_vars(names: &[&str]) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for name in names {
        if let Ok(val) = std::env::var(name) {
            if !val.is_empty() {
                result.insert(name.to_string(), val);
            }
        }
    }
    result
}

/// Resolve the effective model from --model flag or environment variables.
pub(crate) fn resolve_model(model: &Option<String>) -> Option<String> {
    model
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("ARES_ORCHESTRATOR_MODEL").ok())
        .or_else(|| std::env::var("ARES_MODEL").ok())
        .filter(|s| !s.is_empty())
}

pub(crate) struct OpsSubmitParams {
    pub redis_url: Option<String>,
    pub target: String,
    pub domain: String,
    pub ips: Vec<String>,
    pub operation_id: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ntlm_hash: Option<String>,
    pub resume: bool,
    pub model: Option<String>,
    pub max_steps: u32,
    pub env: Option<String>,
    pub pin_active: bool,
}

pub(crate) async fn ops_submit(p: OpsSubmitParams) -> Result<String> {
    let OpsSubmitParams {
        redis_url,
        target,
        domain,
        ips,
        operation_id,
        username,
        password,
        ntlm_hash,
        resume,
        model,
        max_steps,
        env,
        pin_active,
    } = p;

    if ips.is_empty() {
        anyhow::bail!(
            "No target IPs specified. Use --ips or --resolve-targets to provide target IPs."
        );
    }

    // Generate operation ID if not provided
    let op_id =
        operation_id.unwrap_or_else(|| format!("op-{}", Utc::now().format("%Y%m%d-%H%M%S")));

    // Build initial credential if username provided
    let initial_cred = username.as_ref().map(|uname| {
        let mut cred = serde_json::Map::new();
        cred.insert(
            "username".to_string(),
            serde_json::Value::String(uname.clone()),
        );
        cred.insert(
            "domain".to_string(),
            serde_json::Value::String(domain.clone()),
        );
        if let Some(ref pw) = password {
            cred.insert(
                "password".to_string(),
                serde_json::Value::String(pw.clone()),
            );
        }
        if let Some(ref hash) = ntlm_hash {
            cred.insert(
                "ntlm_hash".to_string(),
                serde_json::Value::String(hash.clone()),
            );
        }
        serde_json::Value::Object(cred)
    });

    info!("Submitting operation: {op_id}");
    info!("Target: {target} ({domain})");
    info!("IPs: {}", ips.join(", "));

    // Collect environment variables
    let env_vars = collect_env_vars(OPS_ENV_VAR_NAMES);
    if !env_vars.is_empty() {
        let mut keys: Vec<&str> = env_vars.keys().map(|s| s.as_str()).collect();
        keys.sort();
        info!("Submitting with env vars: {}", keys.join(", "));
    } else {
        warn!("No env vars found to submit with operation request");
    }

    // Resolve model
    let effective_model = resolve_model(&model);
    if let Some(ref m) = effective_model {
        if m.starts_with("gpt-") && std::env::var("OPENAI_API_KEY").is_err() {
            anyhow::bail!(
                "OPENAI_API_KEY is required for OpenAI models. Set it in the environment \
                 before submitting the operation."
            );
        }
    }
    if effective_model.is_none() {
        anyhow::bail!(
            "No model specified. Provide --model or set \
             ARES_ORCHESTRATOR_MODEL/ARES_MODEL in the environment."
        );
    }

    let now = Utc::now();

    let request = serde_json::json!({
        "operation_id": op_id,
        "target_domain": domain,
        "target_ips": ips,
        "target_environment": env,
        "initial_credential": initial_cred,
        "resume_from_checkpoint": resume,
        "model": effective_model,
        "max_steps": max_steps,
        "checkpoint_interval": 60,
        "report_dir": null,
        "submitted_at": now.to_rfc3339(),
    });

    let mut conn = connect_redis(redis_url).await?;

    // Pin this operation as the active one (workers will prefer it)
    if pin_active {
        info!("Pinning active operation: {op_id}");
        let _: () = conn.set("ares:operation:active", &op_id).await?;
    }

    // Store env_vars separately to avoid exposing secrets in the main queue
    if !env_vars.is_empty() {
        let env_vars_key = format!("ares:op:{op_id}:env_vars");
        let env_json = serde_json::to_string(&env_vars)?;
        let _: () = conn.set(&env_vars_key, &env_json).await?;
        let _: () = conn.expire(&env_vars_key, 3600).await?; // 1 hour TTL
    }

    let request_json = serde_json::to_string(&request)?;
    let _: () = conn.rpush("ares:operations", &request_json).await?;

    info!("Operation submitted: {op_id}");
    println!("{op_id}");

    Ok(op_id)
}

pub(crate) async fn follow_operation(
    redis_url: Option<String>,
    op_id: &str,
    interval_secs: u64,
) -> Result<()> {
    use ares_core::state::RedisStateReader;

    println!("\nFollowing operation {op_id} (poll every {interval_secs}s, Ctrl+C to stop)...\n");

    let mut conn = crate::redis_conn::connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(op_id.to_string());

    let mut prev_creds: usize = 0;
    let mut prev_hosts: usize = 0;
    let mut prev_vulns: usize = 0;
    let mut prev_da = false;
    let mut prev_gt = false;
    let mut started = false;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        let now = chrono::Utc::now().format("%H:%M:%S");

        // Check if operation has been picked up
        let is_running = reader.is_running(&mut conn).await.unwrap_or(false);
        if !started && is_running {
            started = true;
            println!("[{now}] Operation started");
        }

        // Read current state
        let Ok(meta) = reader.get_meta(&mut conn).await else {
            continue; // operation not yet initialized
        };

        let creds = reader
            .get_credentials(&mut conn)
            .await
            .map(|c| c.len())
            .unwrap_or(0);
        let hosts = reader
            .get_hosts(&mut conn)
            .await
            .map(|h| h.len())
            .unwrap_or(0);
        let vulns = reader
            .get_vulnerabilities(&mut conn)
            .await
            .map(|v| v.len())
            .unwrap_or(0);

        // Print milestones
        if meta.has_domain_admin && !prev_da {
            println!("[{now}] *** DOMAIN ADMIN ACHIEVED ***");
            prev_da = true;
        }
        if meta.has_golden_ticket && !prev_gt {
            println!("[{now}] *** GOLDEN TICKET OBTAINED ***");
            prev_gt = true;
        }

        // Print count changes
        if creds != prev_creds || hosts != prev_hosts || vulns != prev_vulns {
            println!(
                "[{now}] credentials: {} (+{})  hosts: {} (+{})  vulns: {} (+{})",
                creds,
                creds.saturating_sub(prev_creds),
                hosts,
                hosts.saturating_sub(prev_hosts),
                vulns,
                vulns.saturating_sub(prev_vulns),
            );
            prev_creds = creds;
            prev_hosts = hosts;
            prev_vulns = vulns;
        }

        // Check for completion
        if meta.completed_at.is_some() {
            println!("[{now}] Operation completed");
            break;
        }
        if started && !is_running {
            println!("[{now}] Operation stopped");
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Env-var tests are bundled into a single `#[test]` function so they run
    /// serially within the binary — the test runner parallelises across `#[test]`
    /// boundaries, and `collect_env_vars`/`resolve_model` both read process-wide
    /// state. Mirrors the pattern in `orchestrator/config.rs`.
    #[test]
    fn env_var_helpers() {
        // Use throwaway names that no other test or runtime path reads, so the
        // serial assertion holds regardless of what else is in flight.
        const NAME_A: &str = "ARES_TEST_SUBMIT_COLLECT_A_9c1a";
        const NAME_B: &str = "ARES_TEST_SUBMIT_COLLECT_B_9c1a";
        const NAME_C: &str = "ARES_TEST_SUBMIT_COLLECT_C_9c1a";

        // --- collect_env_vars ---
        std::env::remove_var(NAME_A);
        std::env::remove_var(NAME_B);
        std::env::remove_var(NAME_C);

        // All unset → empty map.
        let got = collect_env_vars(&[NAME_A, NAME_B, NAME_C]);
        assert!(got.is_empty(), "expected empty, got {got:?}");

        // Set + empty → only set+nonempty entries appear.
        std::env::set_var(NAME_A, "alpha");
        std::env::set_var(NAME_B, "");
        let got = collect_env_vars(&[NAME_A, NAME_B, NAME_C]);
        assert_eq!(got.len(), 1);
        assert_eq!(got.get(NAME_A).map(String::as_str), Some("alpha"));

        std::env::remove_var(NAME_A);
        std::env::remove_var(NAME_B);

        // --- resolve_model ---
        const ORCH: &str = "ARES_ORCHESTRATOR_MODEL";
        const LEGACY: &str = "ARES_MODEL";
        // Snapshot + clear so we don't trample a developer-set var.
        let prev_orch = std::env::var(ORCH).ok();
        let prev_legacy = std::env::var(LEGACY).ok();
        std::env::remove_var(ORCH);
        std::env::remove_var(LEGACY);

        // No flag, no env → None.
        assert_eq!(resolve_model(&None), None);
        // Empty flag, no env → None (empty strings are filtered out).
        assert_eq!(resolve_model(&Some(String::new())), None);
        // Explicit flag wins over everything.
        std::env::set_var(ORCH, "gpt-orch");
        std::env::set_var(LEGACY, "gpt-legacy");
        assert_eq!(
            resolve_model(&Some("gpt-explicit".to_string())),
            Some("gpt-explicit".to_string())
        );
        // No flag → ARES_ORCHESTRATOR_MODEL beats ARES_MODEL.
        assert_eq!(resolve_model(&None), Some("gpt-orch".to_string()));
        // Only legacy set.
        std::env::remove_var(ORCH);
        assert_eq!(resolve_model(&None), Some("gpt-legacy".to_string()));
        // Empty env vars are still treated as set by `std::env::var`, but the
        // trailing filter strips them out.
        std::env::set_var(LEGACY, "");
        assert_eq!(resolve_model(&None), None);

        // Restore.
        std::env::remove_var(ORCH);
        std::env::remove_var(LEGACY);
        if let Some(v) = prev_orch {
            std::env::set_var(ORCH, v);
        }
        if let Some(v) = prev_legacy {
            std::env::set_var(LEGACY, v);
        }
    }
}
