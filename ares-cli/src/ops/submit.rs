use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use redis::AsyncCommands;
use tracing::{info, warn};

use crate::redis_conn::connect_redis;

/// Environment variable names to capture for blue team investigations.
pub(crate) const BLUE_ENV_VAR_NAMES: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GRAFANA_SERVICE_ACCOUNT_TOKEN",
    "GRAFANA_API_KEY",
    "GRAFANA_URL",
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn ops_submit(
    redis_url: Option<String>,
    target: String,
    domain: String,
    ips: Vec<String>,
    operation_id: Option<String>,
    username: Option<String>,
    password: Option<String>,
    ntlm_hash: Option<String>,
    resume: bool,
    model: Option<String>,
    max_steps: u32,
    env: Option<String>,
) -> Result<()> {
    if ips.is_empty() {
        anyhow::bail!("No target IPs specified. Use --ips to provide target IPs.");
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

    // Build operation request (matches Python orchestrator_client.py format)
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

    // Stored separately to avoid exposing secrets in the main queue
    if !env_vars.is_empty() {
        let env_vars_key = format!("ares:op:{op_id}:env_vars");
        let env_json = serde_json::to_string(&env_vars)?;
        let _: () = conn.set(&env_vars_key, &env_json).await?;
        let _: () = conn.expire(&env_vars_key, 3600).await?; // 1 hour TTL
    }

    // Push operation request to queue (matches Python: RPUSH to ares:operations)
    let request_json = serde_json::to_string(&request)?;
    let _: () = conn.rpush("ares:operations", &request_json).await?;

    info!("Operation submitted: {op_id}");
    println!("{op_id}");

    Ok(())
}
