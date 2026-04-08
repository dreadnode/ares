//! Payload enrichment for delegation exploits and DC resolution.

use std::collections::HashMap;

use ares_core::models::{Credential, Host};

use super::dc_discovery::find_dc_ip;
use super::util::extract_host_from_spn;

/// Enrich a delegation exploit payload with credentials and target_ip from state.
///
/// Only processes `constrained_delegation` and `unconstrained_delegation` types.
pub fn enrich_delegation_payload(
    payload: &mut serde_json::Value,
    vuln_type: &str,
    credentials: &[Credential],
    hosts: &[Host],
) {
    if vuln_type != "constrained_delegation" && vuln_type != "unconstrained_delegation" {
        return;
    }

    // Credential enrichment: find password for the delegation account
    if payload
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        let account = payload
            .get("account_name")
            .or_else(|| payload.get("account"))
            .or_else(|| payload.get("target"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let account_lower = account.to_lowercase().trim_end_matches('$').to_string();

        if !account_lower.is_empty() {
            for cred in credentials {
                if cred.username.to_lowercase() == account_lower && !cred.password.is_empty() {
                    payload["password"] = serde_json::Value::String(cred.password.clone());
                    if payload
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .is_empty()
                        && !cred.domain.is_empty()
                    {
                        payload["domain"] = serde_json::Value::String(cred.domain.clone());
                    }
                    break;
                }
            }
        }
    }

    // Target IP resolution from SPN
    if payload
        .get("target_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        let target_spn = payload
            .get("target_spn")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if let Some(target_host) = extract_host_from_spn(target_spn) {
            let target_host_lower = target_host.to_lowercase();
            for host in hosts {
                if !host.hostname.is_empty()
                    && host.hostname.to_lowercase().contains(&target_host_lower)
                {
                    payload["target_ip"] = serde_json::Value::String(host.ip.clone());
                    break;
                }
            }
        }
    }
}

/// Resolve dc_ip for an exploit payload if not already set.
///
/// Uses domain from the payload to find a DC via the multi-tier discovery.
pub fn resolve_dc_for_payload(
    payload: &mut serde_json::Value,
    hosts: &[Host],
    domain_controllers: &HashMap<String, String>,
    netbios_to_fqdn: &HashMap<String, String>,
    target_ip: Option<&str>,
) {
    // Skip if dc_ip already set
    if !payload
        .get("dc_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        return;
    }

    // Need a domain to resolve DC
    let domain = match payload.get("domain").and_then(|v| v.as_str()) {
        Some(d) if !d.is_empty() => d,
        _ => return,
    };

    // Try multi-tier DC discovery
    if let Some(discovery) = find_dc_ip(
        domain,
        hosts,
        domain_controllers,
        netbios_to_fqdn,
        target_ip,
    ) {
        payload["dc_ip"] = serde_json::Value::String(discovery.ip);
        return;
    }

    // Fallback to target_ip from payload
    if let Some(tip) = payload.get("target_ip").and_then(|v| v.as_str()) {
        if !tip.is_empty() {
            payload["dc_ip"] = serde_json::Value::String(tip.to_string());
            return;
        }
    }

    // Last fallback to operation target
    if let Some(tip) = target_ip {
        payload["dc_ip"] = serde_json::Value::String(tip.to_string());
    }
}
