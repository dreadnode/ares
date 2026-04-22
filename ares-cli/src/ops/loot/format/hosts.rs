use std::collections::HashMap;

use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::Host;

pub(super) static OS_PAREN_METADATA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s*\([^)]*\)").unwrap());

pub(super) fn clean_os_string(os: &str) -> String {
    let cleaned = OS_PAREN_METADATA_RE.replace_all(os, "");
    cleaned.trim().to_string()
}

pub(super) fn is_real_service(svc: &str) -> bool {
    let trimmed = svc.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.contains("/tcp") || trimmed.contains("/udp")
}

fn is_aws_hostname(hostname: &str) -> bool {
    let lower = hostname.to_lowercase();
    lower.starts_with("ip-") && lower.contains("compute.internal")
}

fn resolve_display_hostname(host: &Host, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let hostname = host.hostname.trim().trim_end_matches('.');

    if hostname.is_empty() || is_aws_hostname(hostname) {
        return String::new();
    }

    if !hostname.contains('.') {
        let upper = hostname.to_uppercase();
        if let Some(fqdn) = netbios_to_fqdn.get(&upper) {
            return fqdn.to_lowercase();
        }
        let lower = hostname.to_lowercase();
        for (nb, fqdn) in netbios_to_fqdn {
            if fqdn.to_lowercase().starts_with(&format!("{lower}.")) || nb.to_lowercase() == lower {
                return fqdn.to_lowercase();
            }
        }
    }

    hostname.to_lowercase()
}

fn is_more_specific_fqdn(existing: &str, new: &str) -> bool {
    let ex_parts: Vec<&str> = existing.split('.').collect();
    let new_parts: Vec<&str> = new.split('.').collect();
    if ex_parts.len() < 2 || new_parts.len() < 2 {
        return false;
    }
    if ex_parts[0].to_lowercase() != new_parts[0].to_lowercase() {
        return false;
    }
    new_parts.len() > ex_parts.len()
}

fn looks_like_ip(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

pub(super) fn dedup_hosts(
    hosts: &[Host],
    netbios_to_fqdn: &HashMap<String, String>,
    domain_controllers: &HashMap<String, String>,
) -> Vec<Host> {
    let mut by_ip: HashMap<String, Host> = HashMap::new();
    let mut hostname_only: Vec<Host> = Vec::new();

    for host in hosts {
        let ip = host.ip.trim();

        if ip.contains('/') {
            continue;
        }

        let resolved = resolve_display_hostname(host, netbios_to_fqdn);

        if !looks_like_ip(ip) && !ip.is_empty() {
            let mut h = host.clone();
            if h.hostname.is_empty() {
                h.hostname = ip.trim_end_matches('.').to_string();
            }
            h.ip = String::new();
            hostname_only.push(h);
            continue;
        }

        if ip.is_empty() {
            continue;
        }

        if let Some(existing) = by_ip.get_mut(ip) {
            let existing_is_short = !existing.hostname.contains('.');
            let new_is_fqdn = !resolved.is_empty() && resolved.contains('.');

            if (existing.hostname.is_empty() && !resolved.is_empty())
                || (existing_is_short && new_is_fqdn)
                || is_more_specific_fqdn(&existing.hostname, &resolved)
            {
                existing.hostname = resolved;
            }

            for svc in &host.services {
                if !existing.services.contains(svc) {
                    existing.services.push(svc.clone());
                }
            }
            if host.is_dc {
                existing.is_dc = true;
            }
            if existing.os.is_empty() && !host.os.is_empty() {
                existing.os = host.os.clone();
            }
            for role in &host.roles {
                if !existing.roles.contains(role) {
                    existing.roles.push(role.clone());
                }
            }
        } else {
            let mut merged = host.clone();
            merged.hostname = resolved;
            by_ip.insert(ip.to_string(), merged);
        }
    }

    for h in hostname_only {
        let hostname_lower = h.hostname.to_lowercase();
        let mut merged = false;
        for existing in by_ip.values_mut() {
            if existing.hostname.to_lowercase() == hostname_lower {
                for svc in &h.services {
                    if !existing.services.contains(svc) {
                        existing.services.push(svc.clone());
                    }
                }
                if h.is_dc {
                    existing.is_dc = true;
                }
                if existing.os.is_empty() && !h.os.is_empty() {
                    existing.os = h.os.clone();
                }
                merged = true;
                break;
            }
        }
        if !merged && !h.services.is_empty() {
            by_ip.insert(format!("_hostname_{}", h.hostname), h);
        }
    }

    let mut ip_to_domains: HashMap<&str, Vec<&str>> = HashMap::new();
    for (domain, ip) in domain_controllers {
        ip_to_domains
            .entry(ip.as_str())
            .or_default()
            .push(domain.as_str());
    }

    for host in by_ip.values_mut() {
        if let Some(domains) = ip_to_domains.get(host.ip.as_str()) {
            host.is_dc = true;
            if host.hostname.is_empty() {
                for domain in domains {
                    let suffix = format!(".{}", domain.to_lowercase());
                    for fqdn in netbios_to_fqdn.values() {
                        if fqdn.to_lowercase().ends_with(&suffix) {
                            host.hostname = fqdn.clone();
                            break;
                        }
                    }
                    if !host.hostname.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    let mut result: Vec<Host> = by_ip.into_values().collect();
    result.sort_by(|a, b| a.ip.cmp(&b.ip));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── clean_os_string ──

    #[test]
    fn clean_os_removes_parenthetical() {
        assert_eq!(clean_os_string("Windows 10 (Build 19041)"), "Windows 10");
    }

    #[test]
    fn clean_os_removes_multiple_parentheticals() {
        assert_eq!(clean_os_string("Linux (Ubuntu) (22.04)"), "Linux");
    }

    #[test]
    fn clean_os_no_parens_unchanged() {
        assert_eq!(
            clean_os_string("Windows Server 2019"),
            "Windows Server 2019"
        );
    }

    #[test]
    fn clean_os_empty_string() {
        assert_eq!(clean_os_string(""), "");
    }

    #[test]
    fn clean_os_only_parens() {
        assert_eq!(clean_os_string("(metadata)"), "");
    }

    #[test]
    fn clean_os_trims_whitespace() {
        assert_eq!(clean_os_string("  Windows 10  "), "Windows 10");
    }

    // ── is_real_service ──

    #[test]
    fn real_service_tcp() {
        assert!(is_real_service("80/tcp"));
    }

    #[test]
    fn real_service_udp() {
        assert!(is_real_service("53/udp"));
    }

    #[test]
    fn real_service_empty() {
        assert!(!is_real_service(""));
    }

    #[test]
    fn real_service_whitespace_only() {
        assert!(!is_real_service("   "));
    }

    #[test]
    fn real_service_no_protocol() {
        assert!(!is_real_service("http"));
    }

    #[test]
    fn real_service_with_leading_whitespace() {
        assert!(is_real_service("  443/tcp"));
    }

    // ── looks_like_ip ──

    #[test]
    fn looks_like_ip_valid_ipv4() {
        assert!(looks_like_ip("192.168.58.1"));
    }

    #[test]
    fn looks_like_ip_digits_only() {
        assert!(looks_like_ip("12345"));
    }

    #[test]
    fn looks_like_ip_empty() {
        assert!(!looks_like_ip(""));
    }

    #[test]
    fn looks_like_ip_has_letters() {
        assert!(!looks_like_ip("192.168.1.abc"));
    }

    #[test]
    fn looks_like_ip_hostname() {
        assert!(!looks_like_ip("server.contoso.local"));
    }

    #[test]
    fn looks_like_ip_with_colon() {
        assert!(!looks_like_ip("::1"));
    }

    // ── is_more_specific_fqdn ──

    #[test]
    fn more_specific_fqdn_more_parts() {
        assert!(is_more_specific_fqdn(
            "dc01.contoso.local",
            "dc01.sub.contoso.local"
        ));
    }

    #[test]
    fn more_specific_fqdn_same_parts() {
        assert!(!is_more_specific_fqdn(
            "dc01.contoso.local",
            "dc01.contoso.local"
        ));
    }

    #[test]
    fn more_specific_fqdn_fewer_parts() {
        assert!(!is_more_specific_fqdn(
            "dc01.sub.contoso.local",
            "dc01.contoso.local"
        ));
    }

    #[test]
    fn more_specific_fqdn_different_host() {
        assert!(!is_more_specific_fqdn(
            "dc01.contoso.local",
            "web01.sub.contoso.local"
        ));
    }

    #[test]
    fn more_specific_fqdn_single_label_existing() {
        assert!(!is_more_specific_fqdn("dc", "dc01.contoso.local"));
    }

    #[test]
    fn more_specific_fqdn_single_label_new() {
        assert!(!is_more_specific_fqdn("dc01.contoso.local", "dc"));
    }

    #[test]
    fn more_specific_fqdn_case_insensitive_host() {
        assert!(is_more_specific_fqdn(
            "DC.contoso.local",
            "dc.sub.contoso.local"
        ));
    }

    // ── resolve_display_hostname ──

    fn make_host(ip: &str, hostname: &str) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn resolve_hostname_empty() {
        let host = make_host("192.168.58.1", "");
        let map = HashMap::new();
        assert_eq!(resolve_display_hostname(&host, &map), "");
    }

    #[test]
    fn resolve_hostname_aws_filtered() {
        let host = make_host("192.168.58.1", "ip-192-168-58-1.us-west-2.compute.internal");
        let map = HashMap::new();
        assert_eq!(resolve_display_hostname(&host, &map), "");
    }

    #[test]
    fn resolve_hostname_fqdn_passthrough() {
        let host = make_host("192.168.58.1", "dc01.contoso.local");
        let map = HashMap::new();
        assert_eq!(resolve_display_hostname(&host, &map), "dc01.contoso.local");
    }

    #[test]
    fn resolve_hostname_trailing_dot_stripped() {
        let host = make_host("192.168.58.1", "dc01.contoso.local.");
        let map = HashMap::new();
        assert_eq!(resolve_display_hostname(&host, &map), "dc01.contoso.local");
    }

    #[test]
    fn resolve_hostname_netbios_lookup() {
        let host = make_host("192.168.58.1", "DC01");
        let mut map = HashMap::new();
        map.insert("DC01".to_string(), "dc01.contoso.local".to_string());
        assert_eq!(resolve_display_hostname(&host, &map), "dc01.contoso.local");
    }

    #[test]
    fn resolve_hostname_netbios_fallback_fqdn_match() {
        let host = make_host("192.168.58.1", "dc01");
        let mut map = HashMap::new();
        map.insert("SOMEKEY".to_string(), "DC01.contoso.local".to_string());
        assert_eq!(resolve_display_hostname(&host, &map), "dc01.contoso.local");
    }

    #[test]
    fn resolve_hostname_uppercase_to_lowercase() {
        let host = make_host("192.168.58.1", "DC01.CONTOSO.LOCAL");
        let map = HashMap::new();
        assert_eq!(resolve_display_hostname(&host, &map), "dc01.contoso.local");
    }

    // ── is_aws_hostname ──

    #[test]
    fn aws_hostname_positive() {
        assert!(is_aws_hostname(
            "ip-192-168-58-1.us-west-2.compute.internal"
        ));
    }

    #[test]
    fn aws_hostname_negative() {
        assert!(!is_aws_hostname("dc01.contoso.local"));
    }

    #[test]
    fn aws_hostname_partial_match() {
        assert!(!is_aws_hostname("ip-192-168-58-1.contoso.local"));
    }
}
