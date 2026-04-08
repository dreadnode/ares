use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use tracing::info;

use ares_core::models::{Credential, Hash, Host, VulnerabilityInfo};
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn ops_inject_vulnerability(
    redis_url: Option<String>,
    operation_id: String,
    vuln_type: String,
    target_ip: String,
    target_hostname: String,
    target_spn: String,
    account_name: String,
    domain: String,
    details_json: String,
) -> Result<()> {
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
        is_dc: false,
        owned: false,
    };
    host.is_dc = host.detect_dc();

    reader.add_host(&mut conn, &host).await?;
    info!("Injected host: {hostname} / {ip}");

    // Also add the domain if hostname has a domain part
    if hostname.contains('.') {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() > 1 {
            let domain = parts[1..].join(".");
            let added = reader.add_domain(&mut conn, &domain).await?;
            if added {
                info!("Added domain from hostname: {domain}");
            }
        }
    }

    let n = state::publish_state_update(&mut conn, &operation_id)
        .await
        .unwrap_or(0);
    info!("{n} subscribers notified of host_added");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn ops_inject_hash(
    redis_url: Option<String>,
    operation_id: String,
    username: String,
    hash_value: String,
    domain: String,
    hash_type: String,
    source: String,
    aes_key: Option<String>,
) -> Result<()> {
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
    };

    let added = reader.add_hash(&mut conn, &hash).await?;

    if added {
        // If username is krbtgt or Administrator, set has_domain_admin=True
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
