//! Multi-tier DC discovery.

use std::collections::HashMap;
use std::fmt;

use ares_core::models::Host;

use super::domain::{hostname_matches_domain, normalize_domain};

// ---------------------------------------------------------------------------
// DC indicator checks
// ---------------------------------------------------------------------------

/// DC role markers in host roles (case-insensitive substrings).
pub(crate) const DC_ROLE_MARKERS: &[&str] =
    &["dc", "domain controller", "ad dc", "domaincontroller"];

/// DC service port prefixes (prefix match to avoid 3389 matching 389).
pub(crate) const DC_PORT_PREFIXES: &[&str] = &["88/tcp", "389/tcp"];

/// DC service name keywords.
pub(crate) const DC_SERVICE_NAMES: &[&str] = &["kerberos", "ldap"];

/// Check if a host has a DC role assigned (from SRV lookup or BloodHound).
pub(crate) fn has_dc_role(host: &Host) -> bool {
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
pub(crate) fn has_dc_services(host: &Host) -> bool {
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
///    3.5. Forest-based: child domain -> parent DC search
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

    // Tier 3.5: Forest-based child -> parent DC discovery
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

        // Fallback to parent DC -- do NOT cache (allow discovering real child DC later)
        if let Some(pip) = parent_dc_ip {
            return Some(DcDiscovery {
                ip: pip.clone(),
                tier: DcTier::ForestParentFallback,
                should_cache: false,
            });
        }
    }

    // (Tiers 4 and 4.5 -- DNS SRV and LDAP -- handled by orchestrator)

    // Tier 5: Fallback -- any host with DC role (cross-domain)
    for host in hosts {
        if has_dc_role(host) {
            return Some(DcDiscovery {
                ip: host.ip.clone(),
                tier: DcTier::FallbackRole,
                should_cache: false,
            });
        }
    }

    // Tier 6: Last resort -- any host with DC services
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

/// DC discovery tier -- indicates how the DC was found.
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

impl fmt::Display for DcTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
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
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(ip: &str, hostname: &str, is_dc: bool, services: Vec<&str>) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: if is_dc {
                vec!["domain_controller".to_string()]
            } else {
                vec![]
            },
            services: services.into_iter().map(String::from).collect(),
            is_dc,
            owned: false,
        }
    }

    // --- has_dc_role ---

    #[test]
    fn test_has_dc_role_explicit_flag() {
        let host = make_host("192.168.58.10", "dc01", true, vec![]);
        assert!(has_dc_role(&host));
    }

    #[test]
    fn test_has_dc_role_from_role_string() {
        let mut host = make_host("192.168.58.10", "srv01", false, vec![]);
        host.roles = vec!["AD DC".to_string()];
        assert!(has_dc_role(&host));
    }

    #[test]
    fn test_has_dc_role_none() {
        let host = make_host("192.168.58.20", "srv01", false, vec![]);
        assert!(!has_dc_role(&host));
    }

    // --- has_dc_services ---

    #[test]
    fn test_has_dc_services_kerberos_port() {
        let host = make_host("192.168.58.10", "srv01", false, vec!["88/tcp (kerberos)"]);
        assert!(has_dc_services(&host));
    }

    #[test]
    fn test_has_dc_services_ldap_port() {
        let host = make_host("192.168.58.10", "srv01", false, vec!["389/tcp (ldap)"]);
        assert!(has_dc_services(&host));
    }

    #[test]
    fn test_has_dc_services_no_dc_services() {
        let host = make_host(
            "192.168.58.20",
            "srv01",
            false,
            vec!["445/tcp (microsoft-ds)"],
        );
        assert!(!has_dc_services(&host));
    }

    #[test]
    fn test_has_dc_services_3389_not_389() {
        // 3389 (RDP) should NOT match 389 prefix
        let host = make_host(
            "192.168.58.20",
            "srv01",
            false,
            vec!["3389/tcp (ms-wbt-server)"],
        );
        assert!(!has_dc_services(&host));
    }

    // --- find_dc_ip ---

    #[test]
    fn test_find_dc_ip_tier0_cached() {
        let mut dc_map = HashMap::new();
        dc_map.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let result = find_dc_ip("contoso.local", &[], &dc_map, &HashMap::new(), None);
        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.ip, "192.168.58.10");
        assert_eq!(d.tier, DcTier::Cached);
        assert!(!d.should_cache);
    }

    #[test]
    fn test_find_dc_ip_tier1_role() {
        let hosts = vec![make_host(
            "192.168.58.10",
            "dc01.contoso.local",
            true,
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
        let mut host = make_host("192.168.58.10", "dc01.contoso.local", false, vec![]);
        host.roles.clear();
        let result = find_dc_ip(
            "contoso.local",
            &[host],
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        let d = result.unwrap();
        assert_eq!(d.tier, DcTier::HostnamePattern);
    }

    #[test]
    fn test_find_dc_ip_tier3_services() {
        let host = make_host(
            "192.168.58.10",
            "srv01.contoso.local",
            false,
            vec!["88/tcp (kerberos)", "389/tcp (ldap)"],
        );
        let result = find_dc_ip(
            "contoso.local",
            &[host],
            &HashMap::new(),
            &HashMap::new(),
            None,
        );
        let d = result.unwrap();
        assert_eq!(d.tier, DcTier::Services);
    }

    #[test]
    fn test_find_dc_ip_tier5_fallback_role() {
        // DC exists but for a different domain
        let hosts = vec![make_host(
            "192.168.58.10",
            "dc01.fabrikam.local",
            true,
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
        assert_eq!(d.tier, DcTier::FallbackRole);
        assert!(!d.should_cache);
    }

    #[test]
    fn test_find_dc_ip_none() {
        let result = find_dc_ip("contoso.local", &[], &HashMap::new(), &HashMap::new(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_dc_ip_empty_domain() {
        let result = find_dc_ip("", &[], &HashMap::new(), &HashMap::new(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_dc_ip_forest_parent_fallback() {
        let mut dc_map = HashMap::new();
        dc_map.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        // Child domain with no specific DC, but parent DC exists
        let result = find_dc_ip("child.contoso.local", &[], &dc_map, &HashMap::new(), None);
        let d = result.unwrap();
        assert_eq!(d.ip, "192.168.58.10");
        assert_eq!(d.tier, DcTier::ForestParentFallback);
        assert!(!d.should_cache);
    }

    // --- find_dc_ip_cached ---

    #[test]
    fn test_find_dc_ip_cached_hit() {
        let mut dc_map = HashMap::new();
        dc_map.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        assert_eq!(
            find_dc_ip_cached("contoso.local", &dc_map, &HashMap::new()),
            Some("192.168.58.10".to_string())
        );
    }

    #[test]
    fn test_find_dc_ip_cached_miss() {
        assert_eq!(
            find_dc_ip_cached("contoso.local", &HashMap::new(), &HashMap::new()),
            None
        );
    }

    // --- DcTier Display ---

    #[test]
    fn test_dc_tier_display() {
        assert_eq!(DcTier::Cached.to_string(), "cached");
        assert_eq!(DcTier::Role.to_string(), "role");
        assert_eq!(DcTier::Forest.to_string(), "forest");
        assert_eq!(DcTier::LastResort.to_string(), "last_resort");
    }
}
