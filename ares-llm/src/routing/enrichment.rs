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
/// Returns the `DcDiscovery` if one was used, so callers can check `should_cache`
/// before writing to `domain_controllers`.
pub fn resolve_dc_for_payload(
    payload: &mut serde_json::Value,
    hosts: &[Host],
    domain_controllers: &HashMap<String, String>,
    netbios_to_fqdn: &HashMap<String, String>,
    target_ip: Option<&str>,
) -> Option<super::dc_discovery::DcDiscovery> {
    // Skip if dc_ip already set
    if !payload
        .get("dc_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        return None;
    }

    // Need a domain to resolve DC
    let domain = match payload.get("domain").and_then(|v| v.as_str()) {
        Some(d) if !d.is_empty() => d,
        _ => return None,
    };

    // Try multi-tier DC discovery
    if let Some(discovery) = find_dc_ip(
        domain,
        hosts,
        domain_controllers,
        netbios_to_fqdn,
        target_ip,
    ) {
        payload["dc_ip"] = serde_json::Value::String(discovery.ip.clone());
        return Some(discovery);
    }

    // Fallback to target_ip from payload
    if let Some(tip) = payload.get("target_ip").and_then(|v| v.as_str()) {
        if !tip.is_empty() {
            payload["dc_ip"] = serde_json::Value::String(tip.to_string());
            return None;
        }
    }

    // Last fallback to operation target
    if let Some(tip) = target_ip {
        payload["dc_ip"] = serde_json::Value::String(tip.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_cred(username: &str, domain: &str, password: &str) -> Credential {
        Credential {
            id: String::new(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc,
            owned: false,
        }
    }

    // --- enrich_delegation_payload ---

    #[test]
    fn test_enrich_delegation_payload_adds_password() {
        let creds = vec![make_cred("svc_sql", "contoso.local", "SvcP@ss1")];
        let mut payload = json!({"account_name": "svc_sql$", "domain": "contoso.local"});
        enrich_delegation_payload(&mut payload, "constrained_delegation", &creds, &[]);
        assert_eq!(payload["password"], "SvcP@ss1");
    }

    #[test]
    fn test_enrich_delegation_payload_skips_non_delegation() {
        let creds = vec![make_cred("svc_sql", "contoso.local", "SvcP@ss1")];
        let mut payload = json!({"account_name": "svc_sql$"});
        enrich_delegation_payload(&mut payload, "smb_signing", &creds, &[]);
        assert!(payload.get("password").is_none());
    }

    #[test]
    fn test_enrich_delegation_payload_doesnt_overwrite_password() {
        let creds = vec![make_cred("svc_sql", "contoso.local", "SvcP@ss1")];
        let mut payload = json!({"account_name": "svc_sql$", "password": "existing"});
        enrich_delegation_payload(&mut payload, "constrained_delegation", &creds, &[]);
        assert_eq!(payload["password"], "existing");
    }

    #[test]
    fn test_enrich_delegation_payload_resolves_target_ip_from_spn() {
        let hosts = vec![make_host("192.168.58.10", "dc01.contoso.local", true)];
        let mut payload = json!({
            "account_name": "svc_sql$",
            "target_spn": "CIFS/dc01.contoso.local"
        });
        enrich_delegation_payload(&mut payload, "constrained_delegation", &[], &hosts);
        assert_eq!(payload["target_ip"], "192.168.58.10");
    }

    #[test]
    fn test_enrich_delegation_payload_sets_domain_from_cred() {
        let creds = vec![make_cred("svc_sql", "contoso.local", "SvcP@ss1")];
        let mut payload = json!({"account_name": "svc_sql$"});
        enrich_delegation_payload(&mut payload, "unconstrained_delegation", &creds, &[]);
        assert_eq!(payload["domain"], "contoso.local");
    }

    // --- resolve_dc_for_payload ---

    #[test]
    fn test_resolve_dc_skips_if_already_set() {
        let mut payload = json!({"dc_ip": "192.168.58.10", "domain": "contoso.local"});
        resolve_dc_for_payload(&mut payload, &[], &HashMap::new(), &HashMap::new(), None);
        assert_eq!(payload["dc_ip"], "192.168.58.10");
    }

    #[test]
    fn test_resolve_dc_no_domain_skips() {
        let mut payload = json!({"target": "192.168.58.20"});
        resolve_dc_for_payload(&mut payload, &[], &HashMap::new(), &HashMap::new(), None);
        assert!(payload.get("dc_ip").is_none());
    }

    #[test]
    fn test_resolve_dc_falls_back_to_target_ip() {
        let mut payload = json!({"domain": "contoso.local", "target_ip": "192.168.58.20"});
        resolve_dc_for_payload(&mut payload, &[], &HashMap::new(), &HashMap::new(), None);
        assert_eq!(payload["dc_ip"], "192.168.58.20");
    }

    #[test]
    fn test_resolve_dc_falls_back_to_operation_target() {
        let mut payload = json!({"domain": "contoso.local"});
        resolve_dc_for_payload(
            &mut payload,
            &[],
            &HashMap::new(),
            &HashMap::new(),
            Some("192.168.58.10"),
        );
        assert_eq!(payload["dc_ip"], "192.168.58.10");
    }

    #[test]
    fn test_resolve_dc_from_dc_map() {
        let mut dc_map = HashMap::new();
        dc_map.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let mut payload = json!({"domain": "contoso.local"});
        resolve_dc_for_payload(&mut payload, &[], &dc_map, &HashMap::new(), None);
        assert_eq!(payload["dc_ip"], "192.168.58.10");
    }
}
