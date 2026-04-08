//! Routing enrichment — DC discovery, credential matching, domain normalization.
//!
//! Ports pure logic from `src/ares/core/dispatcher/routing.py`.
//! Provides domain normalization, credential lookup, multi-tier DC discovery,
//! and payload enrichment for delegation exploits.

use std::collections::HashMap;

use ares_core::models::{Credential, Host};

// ---------------------------------------------------------------------------
// Domain normalization
// ---------------------------------------------------------------------------

/// Normalize a domain name: resolve NetBIOS to FQDN, lowercase.
///
/// If the domain contains a dot, it's assumed to be an FQDN and returned as-is
/// (lowercased). Otherwise, the NetBIOS-to-FQDN map is consulted.
pub fn normalize_domain(domain: &str, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let lower = domain.to_lowercase();
    if lower.contains('.') {
        return lower;
    }
    // Try lowercase key
    if let Some(fqdn) = netbios_to_fqdn.get(&lower) {
        return fqdn.to_lowercase();
    }
    // Also try uppercase key (Python dict was case-insensitive)
    if let Some(fqdn) = netbios_to_fqdn.get(&domain.to_uppercase()) {
        return fqdn.to_lowercase();
    }
    lower
}

/// Check if a hostname belongs to a domain.
///
/// Extracts the domain portion from the hostname (everything after the first
/// dot) and compares exactly with the target domain. This prevents parent
/// domain false positives (e.g. `dc01.contoso.local` won't match
/// `child.contoso.local`).
fn hostname_matches_domain(hostname: &str, domain: &str) -> bool {
    if hostname.is_empty() || domain.is_empty() {
        return false;
    }
    let hostname_lower = hostname.to_lowercase();
    let domain_lower = domain.to_lowercase();

    // Extract domain from hostname: dc01.child.contoso.local → child.contoso.local
    if let Some(dot_pos) = hostname_lower.find('.') {
        let hostname_domain = &hostname_lower[dot_pos + 1..];
        if hostname_domain == domain_lower {
            return true;
        }
    }

    // Fallback: hostname IS the domain (rare edge case)
    hostname_lower == domain_lower
}

// ---------------------------------------------------------------------------
// DC indicator checks
// ---------------------------------------------------------------------------

/// DC role markers in host roles (case-insensitive substrings).
const DC_ROLE_MARKERS: &[&str] = &["dc", "domain controller", "ad dc", "domaincontroller"];

/// DC service port prefixes (prefix match to avoid 3389 matching 389).
const DC_PORT_PREFIXES: &[&str] = &["88/tcp", "389/tcp"];

/// DC service name keywords.
const DC_SERVICE_NAMES: &[&str] = &["kerberos", "ldap"];

/// Check if a host has a DC role assigned (from SRV lookup or BloodHound).
fn has_dc_role(host: &Host) -> bool {
    if host.is_dc {
        return true;
    }
    for role in &host.roles {
        let role_lower = role.to_lowercase();
        if DC_ROLE_MARKERS.iter().any(|m| role_lower.contains(m)) {
            return true;
        }
    }
    false
}

/// Check if a host has DC-specific services (Kerberos port 88, LDAP port 389).
fn has_dc_services(host: &Host) -> bool {
    for svc in &host.services {
        let svc_lower = svc.to_lowercase();
        if DC_PORT_PREFIXES
            .iter()
            .any(|prefix| svc_lower.starts_with(prefix))
        {
            return true;
        }
        if DC_SERVICE_NAMES.iter().any(|name| svc_lower.contains(name)) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Credential lookup
// ---------------------------------------------------------------------------

/// Find a credential for a given domain.
///
/// Prefers credentials with a password over those with only a hash.
/// Falls back to any credential for the domain.
pub fn find_domain_credential<'a>(
    domain: &str,
    credentials: &'a [Credential],
    netbios_to_fqdn: &HashMap<String, String>,
) -> Option<&'a Credential> {
    let normalized = normalize_domain(domain, netbios_to_fqdn);

    // First pass: credential with non-empty password matching domain
    let with_password = credentials.iter().find(|c| {
        let cred_domain = normalize_domain(&c.domain, netbios_to_fqdn);
        cred_domain == normalized && !c.password.is_empty()
    });

    if with_password.is_some() {
        return with_password;
    }

    // Second pass: any credential matching domain
    credentials.iter().find(|c| {
        let cred_domain = normalize_domain(&c.domain, netbios_to_fqdn);
        cred_domain == normalized
    })
}

// ---------------------------------------------------------------------------
// Multi-tier DC discovery
// ---------------------------------------------------------------------------

/// Full multi-tier DC IP discovery.
///
/// Implements 7 priority tiers matching the Python `_find_domain_controller_ip()`:
///
/// 0. Cached `domain_controllers` map
/// 1. Hosts with explicit DC roles matching domain
/// 2. Hosts with "dc" in hostname matching domain
/// 3. Hosts with DC services (port 88/389) matching domain
///    3.5. Forest-based: child domain → parent DC search
/// 5. Fallback: any host with DC role (cross-domain)
/// 6. Last resort: any host with DC services
///
/// Tiers 4 (DNS SRV) and 4.5 (LDAP rootDSE) require network calls and
/// are handled separately by the orchestrator.
pub fn find_dc_ip(
    domain: &str,
    hosts: &[Host],
    domain_controllers: &HashMap<String, String>,
    netbios_to_fqdn: &HashMap<String, String>,
    target_ip: Option<&str>,
) -> Option<DcDiscovery> {
    let domain_lower = normalize_domain(domain, netbios_to_fqdn);
    if domain_lower.is_empty() {
        return None;
    }

    // Tier 0: Cached domain controllers
    if let Some(ip) = domain_controllers.get(&domain_lower) {
        return Some(DcDiscovery {
            ip: ip.clone(),
            tier: DcTier::Cached,
            should_cache: false, // already cached
        });
    }

    // Target check: if target IP matches domain
    if let Some(tip) = target_ip {
        for host in hosts {
            if host.ip == tip
                && hostname_matches_domain(&host.hostname, &domain_lower)
                && (has_dc_role(host) || has_dc_services(host))
            {
                return Some(DcDiscovery {
                    ip: host.ip.clone(),
                    tier: DcTier::Target,
                    should_cache: true,
                });
            }
        }
    }

    // Tier 1: Hosts with DC role matching domain
    for host in hosts {
        if has_dc_role(host) && hostname_matches_domain(&host.hostname, &domain_lower) {
            return Some(DcDiscovery {
                ip: host.ip.clone(),
                tier: DcTier::Role,
                should_cache: true,
            });
        }
    }

    // Tier 2: Hosts with "dc" in hostname matching domain
    for host in hosts {
        let hostname_lower = host.hostname.to_lowercase();
        if hostname_lower.contains("dc") && hostname_matches_domain(&host.hostname, &domain_lower) {
            return Some(DcDiscovery {
                ip: host.ip.clone(),
                tier: DcTier::HostnamePattern,
                should_cache: true,
            });
        }
    }

    // Tier 3: Hosts with DC services matching domain
    for host in hosts {
        if hostname_matches_domain(&host.hostname, &domain_lower) && has_dc_services(host) {
            return Some(DcDiscovery {
                ip: host.ip.clone(),
                tier: DcTier::Services,
                should_cache: true,
            });
        }
    }

    // Tier 3.5: Forest-based child → parent DC discovery
    let parts: Vec<&str> = domain_lower.split('.').collect();
    if parts.len() >= 3 {
        let parent_domain = parts[1..].join(".");
        let parent_dc_ip = domain_controllers.get(&parent_domain);

        // Find all DCs in same forest (hostname ends with parent domain)
        let forest_dcs: Vec<&Host> = hosts
            .iter()
            .filter(|h| {
                has_dc_role(h)
                    && !h.hostname.is_empty()
                    && h.hostname
                        .to_lowercase()
                        .ends_with(&format!(".{parent_domain}"))
            })
            .collect();

        // Prefer DC that is NOT the parent domain's DC
        for dc in &forest_dcs {
            if parent_dc_ip.is_none_or(|pip| dc.ip != *pip) {
                return Some(DcDiscovery {
                    ip: dc.ip.clone(),
                    tier: DcTier::Forest,
                    should_cache: true,
                });
            }
        }

        // Fallback to parent DC — do NOT cache (allow discovering real child DC later)
        if let Some(pip) = parent_dc_ip {
            return Some(DcDiscovery {
                ip: pip.clone(),
                tier: DcTier::ForestParentFallback,
                should_cache: false,
            });
        }
    }

    // (Tiers 4 and 4.5 — DNS SRV and LDAP — handled by orchestrator)

    // Tier 5: Fallback — any host with DC role (cross-domain)
    for host in hosts {
        if has_dc_role(host) {
            return Some(DcDiscovery {
                ip: host.ip.clone(),
                tier: DcTier::FallbackRole,
                should_cache: false,
            });
        }
    }

    // Tier 6: Last resort — any host with DC services
    for host in hosts {
        if has_dc_services(host) {
            return Some(DcDiscovery {
                ip: host.ip.clone(),
                tier: DcTier::LastResort,
                should_cache: false,
            });
        }
    }

    None
}

/// Convenience wrapper: find DC IP and return just the IP string.
pub fn find_dc_ip_cached(
    domain: &str,
    domain_controllers: &HashMap<String, String>,
    netbios_to_fqdn: &HashMap<String, String>,
) -> Option<String> {
    let normalized = normalize_domain(domain, netbios_to_fqdn);
    domain_controllers.get(&normalized).cloned()
}

/// Result of DC discovery with metadata about which tier found it.
#[derive(Debug, Clone, PartialEq)]
pub struct DcDiscovery {
    pub ip: String,
    pub tier: DcTier,
    /// Whether the result should be cached in `domain_controllers`.
    /// False for parent fallbacks (to allow discovering real child DC later)
    /// and for cross-domain fallbacks.
    pub should_cache: bool,
}

/// DC discovery tier — indicates how the DC was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcTier {
    Cached,
    Target,
    Role,
    HostnamePattern,
    Services,
    Forest,
    ForestParentFallback,
    DnsSrv,
    LdapRootDse,
    FallbackRole,
    LastResort,
}

impl DcTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Target => "target",
            Self::Role => "role",
            Self::HostnamePattern => "hostname_pattern",
            Self::Services => "services",
            Self::Forest => "forest",
            Self::ForestParentFallback => "forest_parent_fallback",
            Self::DnsSrv => "dns_srv",
            Self::LdapRootDse => "ldap_rootdse",
            Self::FallbackRole => "fallback_role",
            Self::LastResort => "last_resort",
        }
    }
}

// ---------------------------------------------------------------------------
// Payload enrichment
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Check if a hash value is NTLM format (suitable for pass-the-hash).
///
/// Valid formats: 32 hex chars, or `LM:NT` (32:32 hex pair).
pub fn is_pass_the_hash_compatible(hash_value: &str) -> bool {
    let hash = hash_value.trim();
    if hash.is_empty() || hash.contains('$') {
        return false;
    }

    // Check for LM:NT format (64 chars with colon in middle)
    if let Some((lm, nt)) = hash.split_once(':') {
        return lm.len() == 32
            && nt.len() == 32
            && lm.chars().all(|c| c.is_ascii_hexdigit())
            && nt.chars().all(|c| c.is_ascii_hexdigit());
    }

    // Check for single 32-char hex (NT hash only)
    hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract a .ccache ticket path from command output.
pub fn extract_ticket_path(output: &str) -> Option<String> {
    let saving_re = regex::Regex::new(r"Saving ticket in ([^\s]+\.ccache)").ok()?;
    if let Some(caps) = saving_re.captures(output) {
        return Some(caps[1].to_string());
    }

    let fallback_re = regex::Regex::new(r"([A-Za-z0-9_.-]+\.ccache)").ok()?;
    if let Some(caps) = fallback_re.captures(output) {
        return Some(caps[1].to_string());
    }

    None
}

/// Extract the hostname from an SPN (e.g. "MSSQLSvc/db01.contoso.local" → "db01.contoso.local").
pub fn extract_host_from_spn(spn: &str) -> Option<String> {
    let parts: Vec<&str> = spn.splitn(2, '/').collect();
    if parts.len() == 2 && parts[1].contains('.') {
        // Strip port suffix if present (e.g. "db01.contoso.local:1433")
        let host = parts[1].split(':').next().unwrap_or(parts[1]);
        Some(host.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_netbios_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("CONTOSO".to_string(), "contoso.local".to_string());
        m.insert("FABRIKAM".to_string(), "fabrikam.local".to_string());
        m
    }

    fn make_host(ip: &str, hostname: &str, roles: Vec<&str>, services: Vec<&str>) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: roles.into_iter().map(|s| s.to_string()).collect(),
            services: services.into_iter().map(|s| s.to_string()).collect(),
            is_dc: false,
            owned: false,
        }
    }

    fn make_cred(username: &str, domain: &str, password: &str) -> Credential {
        Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            domain: domain.to_string(),
            password: password.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    // --- Domain normalization ---

    #[test]
    fn test_normalize_domain_fqdn() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("contoso.local", &map), "contoso.local");
        assert_eq!(normalize_domain("CONTOSO.LOCAL", &map), "contoso.local");
    }

    #[test]
    fn test_normalize_domain_netbios() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("CONTOSO", &map), "contoso.local");
        assert_eq!(normalize_domain("contoso", &map), "contoso.local");
    }

    #[test]
    fn test_normalize_domain_unknown() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("UNKNOWN", &map), "unknown");
    }

    // --- Hostname matching ---

    #[test]
    fn test_hostname_matches_domain() {
        assert!(hostname_matches_domain(
            "dc01.contoso.local",
            "contoso.local"
        ));
        assert!(hostname_matches_domain(
            "DC01.CONTOSO.LOCAL",
            "contoso.local"
        ));
        // Child domain hostname should NOT match parent
        assert!(!hostname_matches_domain(
            "dc01.child.contoso.local",
            "contoso.local"
        ));
        // Child domain match
        assert!(hostname_matches_domain(
            "dc01.child.contoso.local",
            "child.contoso.local"
        ));
        assert!(!hostname_matches_domain("", "contoso.local"));
        assert!(!hostname_matches_domain("dc01.contoso.local", ""));
    }

    // --- DC indicator checks ---

    #[test]
    fn test_has_dc_role() {
        let dc = make_host(
            "10.0.0.1",
            "dc01.contoso.local",
            vec!["Domain Controller"],
            vec![],
        );
        assert!(has_dc_role(&dc));

        let dc_flag = Host {
            is_dc: true,
            ..make_host("10.0.0.2", "srv01.contoso.local", vec![], vec![])
        };
        assert!(has_dc_role(&dc_flag));

        let non_dc = make_host("10.0.0.3", "web01.contoso.local", vec!["web"], vec![]);
        assert!(!has_dc_role(&non_dc));
    }

    #[test]
    fn test_has_dc_services() {
        let with_kerberos = make_host("10.0.0.1", "dc01", vec![], vec!["88/tcp kerberos"]);
        assert!(has_dc_services(&with_kerberos));

        let with_ldap = make_host("10.0.0.2", "dc02", vec![], vec!["389/tcp ldap"]);
        assert!(has_dc_services(&with_ldap));

        // 3389 should NOT match (prefix check prevents this)
        let rdp_only = make_host("10.0.0.3", "srv01", vec![], vec!["3389/tcp ms-wbt-server"]);
        assert!(!has_dc_services(&rdp_only));
    }

    // --- Credential lookup ---

    #[test]
    fn test_find_domain_credential() {
        let map = sample_netbios_map();
        let creds = vec![
            make_cred("user1", "contoso.local", ""),
            make_cred("admin", "contoso.local", "P@ss1"),
        ];
        let found = find_domain_credential("CONTOSO", &creds, &map).unwrap();
        assert_eq!(found.username, "admin"); // Prefers one with password
    }

    // --- Multi-tier DC discovery ---

    #[test]
    fn test_find_dc_ip_tier0_cached() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let result = find_dc_ip("contoso.local", &[], &dcs, &HashMap::new(), None);
        assert_eq!(result.unwrap().tier, DcTier::Cached);
    }

    #[test]
    fn test_find_dc_ip_tier1_role() {
        let hosts = vec![make_host(
            "192.168.58.10",
            "dc01.contoso.local",
            vec!["Domain Controller"],
            vec![],
        )];
        let result = find_dc_ip(
            "contoso.local",
            &hosts,
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        let d = result.unwrap();
        assert_eq!(d.ip, "192.168.58.10");
        assert_eq!(d.tier, DcTier::Role);
        assert!(d.should_cache);
    }

    #[test]
    fn test_find_dc_ip_tier2_hostname_pattern() {
        let hosts = vec![make_host(
            "192.168.58.10",
            "dc01.contoso.local",
            vec![],
            vec![],
        )];
        let result = find_dc_ip(
            "contoso.local",
            &hosts,
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        let d = result.unwrap();
        assert_eq!(d.tier, DcTier::HostnamePattern);
    }

    #[test]
    fn test_find_dc_ip_tier3_services() {
        let hosts = vec![make_host(
            "192.168.58.10",
            "srv01.contoso.local",
            vec![],
            vec!["88/tcp", "389/tcp"],
        )];
        let result = find_dc_ip(
            "contoso.local",
            &hosts,
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        let d = result.unwrap();
        assert_eq!(d.tier, DcTier::Services);
    }

    #[test]
    fn test_find_dc_ip_tier3_5_forest_child() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let hosts = vec![
            make_host("192.168.58.10", "dc01.contoso.local", vec!["dc"], vec![]),
            make_host(
                "192.168.58.11",
                "dc01.child.contoso.local",
                vec!["dc"],
                vec![],
            ),
        ];
        let result = find_dc_ip("child.contoso.local", &hosts, &dcs, &HashMap::new(), None);
        let d = result.unwrap();
        assert_eq!(d.ip, "192.168.58.11");
        // Host has "dc" role + hostname matches domain → found at Role tier
        assert_eq!(d.tier, DcTier::Role);
        assert!(d.should_cache);
    }

    #[test]
    fn test_find_dc_ip_tier3_5_parent_fallback_not_cached() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        // No child DC exists
        let result = find_dc_ip("child.contoso.local", &[], &dcs, &HashMap::new(), None);
        let d = result.unwrap();
        assert_eq!(d.ip, "192.168.58.10");
        assert_eq!(d.tier, DcTier::ForestParentFallback);
        assert!(!d.should_cache); // Must NOT cache parent fallback
    }

    #[test]
    fn test_find_dc_ip_tier5_fallback_role() {
        let hosts = vec![make_host(
            "10.0.0.1",
            "dc01.other.local",
            vec!["dc"],
            vec![],
        )];
        // Looking for contoso.local but only have other.local DC
        let result = find_dc_ip(
            "contoso.local",
            &hosts,
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        let d = result.unwrap();
        assert_eq!(d.tier, DcTier::FallbackRole);
        assert!(!d.should_cache);
    }

    #[test]
    fn test_find_dc_ip_tier6_last_resort() {
        let hosts = vec![make_host(
            "10.0.0.1",
            "unknown-host",
            vec![],
            vec!["88/tcp kerberos"],
        )];
        let result = find_dc_ip(
            "contoso.local",
            &hosts,
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        let d = result.unwrap();
        assert_eq!(d.tier, DcTier::LastResort);
    }

    #[test]
    fn test_find_dc_ip_none() {
        let result = find_dc_ip("contoso.local", &[], &HashMap::new(), &HashMap::new(), None);
        assert!(result.is_none());
    }

    // --- Payload enrichment ---

    #[test]
    fn test_enrich_delegation_payload_credential() {
        let creds = vec![make_cred("svc_sql", "contoso.local", "SqlPass1")];
        let mut payload = serde_json::json!({
            "account_name": "svc_sql$",
            "target_spn": "MSSQLSvc/db01.contoso.local:1433"
        });
        enrich_delegation_payload(&mut payload, "constrained_delegation", &creds, &[]);
        assert_eq!(payload["password"].as_str(), Some("SqlPass1"));
        assert_eq!(payload["domain"].as_str(), Some("contoso.local"));
    }

    #[test]
    fn test_enrich_delegation_skips_non_delegation() {
        let mut payload = serde_json::json!({"account_name": "svc_sql"});
        enrich_delegation_payload(&mut payload, "zerologon", &[], &[]);
        assert!(payload.get("password").is_none());
    }

    #[test]
    fn test_enrich_delegation_resolves_target_ip() {
        let hosts = vec![make_host(
            "192.168.58.20",
            "db01.contoso.local",
            vec![],
            vec![],
        )];
        let mut payload = serde_json::json!({
            "target_spn": "MSSQLSvc/db01.contoso.local:1433"
        });
        enrich_delegation_payload(&mut payload, "constrained_delegation", &[], &hosts);
        assert_eq!(payload["target_ip"].as_str(), Some("192.168.58.20"));
    }

    #[test]
    fn test_resolve_dc_for_payload() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let mut payload = serde_json::json!({"domain": "contoso.local"});
        resolve_dc_for_payload(&mut payload, &[], &dcs, &HashMap::new(), None);
        assert_eq!(payload["dc_ip"].as_str(), Some("192.168.58.10"));
    }

    #[test]
    fn test_resolve_dc_skips_if_already_set() {
        let mut payload = serde_json::json!({"domain": "contoso.local", "dc_ip": "10.0.0.1"});
        resolve_dc_for_payload(&mut payload, &[], &HashMap::new(), &HashMap::new(), None);
        assert_eq!(payload["dc_ip"].as_str(), Some("10.0.0.1")); // unchanged
    }

    // --- Utility ---

    #[test]
    fn test_is_pass_the_hash_compatible() {
        assert!(is_pass_the_hash_compatible(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        ));
        assert!(is_pass_the_hash_compatible(
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        ));
        assert!(!is_pass_the_hash_compatible("$2b$10$abcdef"));
        assert!(!is_pass_the_hash_compatible(""));
        assert!(!is_pass_the_hash_compatible("abc123"));
    }

    #[test]
    fn test_extract_ticket_path() {
        let output = "Saving ticket in Administrator.ccache\nDone.";
        assert_eq!(
            extract_ticket_path(output),
            Some("Administrator.ccache".to_string())
        );
    }

    #[test]
    fn test_extract_host_from_spn() {
        assert_eq!(
            extract_host_from_spn("MSSQLSvc/db01.contoso.local"),
            Some("db01.contoso.local".to_string())
        );
        assert_eq!(
            extract_host_from_spn("MSSQLSvc/db01.contoso.local:1433"),
            Some("db01.contoso.local".to_string())
        );
        assert_eq!(extract_host_from_spn("krbtgt"), None);
    }
}
