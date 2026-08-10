use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use tracing::info;

use ares_core::models::{
    Credential, ForceInterRealmForgeRequest, Hash, Host, TrustInfo, VulnerabilityInfo,
};
use ares_core::state::{self, RedisStateReader};

use crate::redis_conn::connect_redis;

pub(crate) async fn ops_inject_credential(
    redis_url: Option<String>,
    operation_id: String,
    username: String,
    password: String,
    domain: String,
    source: String,
    is_admin: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let cred = Credential {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.clone(),
        password: password.clone(),
        domain: domain.clone(),
        source,
        discovered_at: Some(Utc::now()),
        is_admin,
        parent_id: None,
        attack_step: 0,
    };

    let added = reader.add_credential(&mut conn, &cred).await?;

    if added {
        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        info!(
            "Injected credential: {}\\{}:{} ({n} subscribers notified)",
            domain, username, password
        );
    } else {
        info!("Credential already exists: {}\\{}", domain, username);
    }

    Ok(())
}

pub(crate) struct OpsForceInterRealmForgeParams {
    pub redis_url: Option<String>,
    pub operation_id: String,
    pub source: String,
    pub target: String,
    pub trust_key: String,
    pub aes_key: Option<String>,
    pub source_sid: Option<String>,
    pub target_sid: Option<String>,
    pub target_dc_ip: Option<String>,
    pub target_dc_fqdn: Option<String>,
}

/// Queue an operator escape-hatch inter-realm forge request.
///
/// This CLI runs out-of-process from the orchestrator, so it cannot dispatch
/// the forge itself. It RPUSHes a [`ForceInterRealmForgeRequest`] onto
/// `ares:op:{id}:force_forge_requests`, which `auto_trust_follow` drains each
/// tick and hands to `dispatch_create_inter_realm_ticket` — bypassing the
/// SID-filter check and trust_follow dedup that suppress the auto path. Watch
/// the orchestrator log for `ARES_TICKET_PATH` to confirm the ccache landed.
pub(crate) async fn ops_force_inter_realm_forge(
    params: OpsForceInterRealmForgeParams,
) -> Result<()> {
    let OpsForceInterRealmForgeParams {
        redis_url,
        operation_id,
        source,
        target,
        trust_key,
        aes_key,
        source_sid,
        target_sid,
        target_dc_ip,
        target_dc_fqdn,
    } = params;

    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());
    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let request = ForceInterRealmForgeRequest {
        source_domain: source.clone(),
        target_domain: target.clone(),
        trust_key,
        aes_key,
        source_sid,
        target_sid,
        target_dc_ip,
        target_dc_fqdn,
    };
    let payload = serde_json::to_string(&request)?;
    let key = state::build_key(&operation_id, state::KEY_FORCE_FORGE_REQUESTS);
    let _: i64 = redis::cmd("RPUSH")
        .arg(&key)
        .arg(&payload)
        .query_async(&mut conn)
        .await?;
    let n = state::publish_state_update(&mut conn, &operation_id)
        .await
        .unwrap_or(0);
    info!(
        "Queued force-inter-realm-forge {source} -> {target} for {operation_id} \
         (orchestrator dispatches on next trust tick; {n} subscribers notified)"
    );
    println!(
        "Queued inter-realm forge request: {source} -> {target}\n\
         Watch the orchestrator log for ARES_TICKET_PATH to confirm the ccache."
    );
    Ok(())
}

pub(crate) struct OpsInjectVulnerabilityParams {
    pub redis_url: Option<String>,
    pub operation_id: String,
    pub vuln_type: String,
    pub target_ip: String,
    pub target_hostname: String,
    pub target_spn: String,
    pub account_name: String,
    pub domain: String,
    pub details_json: String,
}

pub(crate) async fn ops_inject_vulnerability(p: OpsInjectVulnerabilityParams) -> Result<()> {
    let OpsInjectVulnerabilityParams {
        redis_url,
        operation_id,
        vuln_type,
        target_ip,
        target_hostname,
        target_spn,
        account_name,
        domain,
        details_json,
    } = p;

    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let extra_details: HashMap<String, serde_json::Value> =
        serde_json::from_str(&details_json).unwrap_or_default();

    let mut vuln_details = HashMap::new();
    vuln_details.insert(
        "target_ip".to_string(),
        serde_json::Value::String(target_ip.clone()),
    );
    vuln_details.insert(
        "target_hostname".to_string(),
        serde_json::Value::String(target_hostname),
    );
    vuln_details.insert("domain".to_string(), serde_json::Value::String(domain));
    if !target_spn.is_empty() {
        vuln_details.insert(
            "target_spn".to_string(),
            serde_json::Value::String(target_spn),
        );
    }
    if !account_name.is_empty() {
        vuln_details.insert(
            "account_name".to_string(),
            serde_json::Value::String(account_name.clone()),
        );
    }
    vuln_details.extend(extra_details);

    let vuln_id = format!(
        "{}_{}_{}",
        vuln_type,
        target_ip,
        if account_name.is_empty() {
            "manual"
        } else {
            &account_name
        }
    );

    let vuln = VulnerabilityInfo {
        vuln_id,
        vuln_type: vuln_type.clone(),
        target: target_ip.clone(),
        discovered_by: "manual-inject".to_string(),
        discovered_at: Utc::now(),
        details: vuln_details,
        recommended_agent: String::new(),
        priority: 99, // Default priority; config lookup would go here
    };

    let added = reader.add_vulnerability(&mut conn, &vuln).await?;
    if added {
        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        info!(
            "Injected vulnerability: {vuln_type} on {target_ip} (priority={}, {n} subscribers notified)",
            vuln.priority
        );
    } else {
        info!("Vulnerability already exists");
    }

    Ok(())
}

pub(crate) async fn ops_inject_host(
    redis_url: Option<String>,
    operation_id: String,
    ip: String,
    hostname: String,
    dc: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let mut host = Host {
        ip: ip.clone(),
        hostname: hostname.clone(),
        os: String::new(),
        roles: Vec::new(),
        services: Vec::new(),
        is_dc: dc,
        owned: false,
    };
    if !host.is_dc {
        host.is_dc = host.detect_dc();
    }

    reader.add_host(&mut conn, &host).await?;
    info!("Injected host: {hostname} / {ip} (dc={dc})");

    // Also add the domain if hostname has a domain part
    let domain = if hostname.contains('.') {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() > 1 {
            let domain = parts[1..].join(".");
            let added = reader.add_domain(&mut conn, &domain).await?;
            if added {
                info!("Added domain from hostname: {domain}");
            }
            Some(domain)
        } else {
            None
        }
    } else {
        None
    };

    // Register DC in domain_controllers map so the orchestrator can route
    // trust key extraction and cross-domain attacks to this DC.
    if host.is_dc {
        if let Some(domain) = domain {
            let dc_key = format!(
                "{}:{}:{}",
                state::KEY_PREFIX,
                operation_id,
                state::KEY_DC_MAP
            );
            let domain_lower = domain.to_lowercase();
            let _: () = redis::AsyncCommands::hset(&mut conn, &dc_key, &domain_lower, &ip).await?;
            info!("Registered DC: {domain_lower} -> {ip}");
        }
    }

    let n = state::publish_state_update(&mut conn, &operation_id)
        .await
        .unwrap_or(0);
    info!("{n} subscribers notified of host_added");

    Ok(())
}

pub(crate) struct OpsInjectHashParams {
    pub redis_url: Option<String>,
    pub operation_id: String,
    pub username: String,
    pub hash_value: String,
    pub domain: String,
    pub hash_type: String,
    pub source: String,
    pub aes_key: Option<String>,
}

pub(crate) async fn ops_inject_hash(p: OpsInjectHashParams) -> Result<()> {
    let OpsInjectHashParams {
        redis_url,
        operation_id,
        username,
        hash_value,
        domain,
        hash_type,
        source,
        aes_key,
    } = p;

    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let hash = Hash {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.clone(),
        hash_value: hash_value.clone(),
        hash_type: hash_type.clone(),
        domain: domain.clone(),
        cracked_password: None,
        source,
        discovered_at: Some(Utc::now()),
        parent_id: None,
        attack_step: 0,
        aes_key,
        is_previous: false,
        source_host: None,
        is_trust_key: false,
        trust_pair_label: None,
    };

    let added = reader.add_hash(&mut conn, &hash).await?;

    if added {
        let username_lower = username.trim().to_lowercase();
        if username_lower == "krbtgt" || username_lower == "administrator" {
            reader
                .set_meta_field(
                    &mut conn,
                    "has_domain_admin",
                    &serde_json::Value::Bool(true),
                )
                .await?;
            info!("Set has_domain_admin=true (injected {username_lower} hash)");
        }

        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        info!(
            "Injected hash: {}\\{}:{} ({n} subscribers notified)",
            domain, username, hash_type
        );
    } else {
        info!("Hash already exists: {}\\{}", domain, username);
    }

    Ok(())
}

pub(crate) async fn ops_inject_domain_sid(
    redis_url: Option<String>,
    operation_id: String,
    domain: String,
    sid: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    reader.set_domain_sid(&mut conn, &domain, &sid).await?;

    let n = state::publish_state_update(&mut conn, &operation_id)
        .await
        .unwrap_or(0);
    info!("Injected domain SID: {domain} = {sid} ({n} subscribers notified)");

    Ok(())
}

pub(crate) async fn ops_inject_trust(
    redis_url: Option<String>,
    operation_id: String,
    domain: String,
    trust_type: String,
    direction: String,
    flat_name: String,
    sid_filtering: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let flat_name = if flat_name.is_empty() {
        domain.split('.').next().unwrap_or(&domain).to_uppercase()
    } else {
        flat_name
    };

    let trust = TrustInfo {
        domain: domain.clone(),
        flat_name: flat_name.clone(),
        direction,
        trust_type: trust_type.clone(),
        sid_filtering,
        security_identifier: None,
    };

    let added = reader.add_trusted_domain(&mut conn, &trust).await?;

    if added {
        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        info!(
            "Injected trust: {domain} (type={trust_type}, flat={flat_name}, {n} subscribers notified)"
        );
    } else {
        info!("Trust already exists: {domain}");
    }

    Ok(())
}
