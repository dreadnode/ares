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

pub(super) fn hostname_by_ip(hosts: &[Host]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for host in hosts {
        let ip = host.ip.trim();
        let hostname = host.hostname.trim().trim_end_matches('.').to_lowercase();
        if hostname.is_empty() || !looks_like_ip(ip) || is_aws_hostname(&hostname) {
            continue;
        }
        let is_better = match map.get(ip) {
            None => true,
            Some(existing) => {
                (!existing.contains('.') && hostname.contains('.'))
                    || is_more_specific_fqdn(existing, &hostname)
            }
        };
        if is_better {
            map.insert(ip.to_string(), hostname);
        }
    }
    map
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

    #[test]
    fn hostname_by_ip_maps_each_host() {
        let hosts = vec![
            make_host("192.168.58.10", "dc01.contoso.local"),
            make_host("192.168.58.50", "ca01.contoso.local"),
        ];
        let map = hostname_by_ip(&hosts);
        assert_eq!(map.get("192.168.58.10").unwrap(), "dc01.contoso.local");
        assert_eq!(map.get("192.168.58.50").unwrap(), "ca01.contoso.local");
    }

    #[test]
    fn hostname_by_ip_skips_hosts_without_a_hostname() {
        let map = hostname_by_ip(&[make_host("192.168.58.10", "")]);
        assert!(map.is_empty());
    }

    #[test]
    fn hostname_by_ip_skips_non_ip_keys() {
        let map = hostname_by_ip(&[make_host("dc01.contoso.local", "dc01.contoso.local")]);
        assert!(map.is_empty());
    }

    #[test]
    fn hostname_by_ip_skips_aws_hostnames() {
        let hosts = vec![make_host(
            "192.168.58.10",
            "ip-192-168-58-10.us-west-2.compute.internal",
        )];
        assert!(hostname_by_ip(&hosts).is_empty());
    }

    #[test]
    fn hostname_by_ip_prefers_the_fqdn_over_the_short_name() {
        let hosts = vec![
            make_host("192.168.58.10", "DC01"),
            make_host("192.168.58.10", "dc01.contoso.local"),
        ];
        let map = hostname_by_ip(&hosts);
        assert_eq!(map.get("192.168.58.10").unwrap(), "dc01.contoso.local");
    }

    #[test]
    fn hostname_by_ip_keeps_the_fqdn_when_the_short_name_arrives_second() {
        let hosts = vec![
            make_host("192.168.58.10", "dc01.contoso.local"),
            make_host("192.168.58.10", "DC01"),
        ];
        let map = hostname_by_ip(&hosts);
        assert_eq!(map.get("192.168.58.10").unwrap(), "dc01.contoso.local");
    }

    #[test]
    fn hostname_by_ip_normalizes_case_and_trailing_dot() {
        let map = hostname_by_ip(&[make_host("192.168.58.10", "DC01.CONTOSO.LOCAL.")]);
        assert_eq!(map.get("192.168.58.10").unwrap(), "dc01.contoso.local");
    }

    fn with_services(mut host: Host, services: &[&str]) -> Host {
        host.services = services.iter().map(|s| (*s).to_string()).collect();
        host
    }

    fn dedup(hosts: &[Host]) -> Vec<Host> {
        dedup_hosts(hosts, &HashMap::new(), &HashMap::new())
    }

    #[test]
    fn dedup_drops_cidr_rows_and_empty_ips() {
        let hosts = [
            make_host("192.168.58.0/24", "subnet"),
            make_host("", ""),
            make_host("192.168.58.10", "dc01.contoso.local"),
        ];

        let result = dedup(&hosts);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ip, "192.168.58.10");
    }

    #[test]
    fn dedup_merges_rows_sharing_an_ip() {
        let hosts = [
            with_services(make_host("192.168.58.10", "dc01"), &["445/tcp"]),
            with_services(make_host("192.168.58.10", ""), &["445/tcp", "389/tcp"]),
        ];

        let result = dedup(&hosts);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].services, vec!["445/tcp", "389/tcp"]);
    }

    #[test]
    fn dedup_upgrades_a_short_name_to_the_fqdn() {
        let hosts = [
            make_host("192.168.58.10", "dc01"),
            make_host("192.168.58.10", "dc01.contoso.local"),
        ];

        assert_eq!(dedup(&hosts)[0].hostname, "dc01.contoso.local");
    }

    #[test]
    fn dedup_keeps_the_fqdn_when_the_short_name_arrives_second() {
        let hosts = [
            make_host("192.168.58.10", "dc01.contoso.local"),
            make_host("192.168.58.10", "dc01"),
        ];

        assert_eq!(dedup(&hosts)[0].hostname, "dc01.contoso.local");
    }

    #[test]
    fn dedup_is_dc_is_sticky_across_merges() {
        let mut dc = make_host("192.168.58.10", "dc01.contoso.local");
        dc.is_dc = true;
        let hosts = [dc, make_host("192.168.58.10", "dc01.contoso.local")];

        assert!(dedup(&hosts)[0].is_dc);
    }

    #[test]
    fn dedup_fills_an_empty_os_but_never_overwrites_one() {
        let mut first = make_host("192.168.58.10", "dc01.contoso.local");
        first.os = "Windows Server 2019".to_string();
        let mut second = make_host("192.168.58.10", "dc01.contoso.local");
        second.os = "Windows Server 2022".to_string();

        assert_eq!(dedup(&[first, second.clone()])[0].os, "Windows Server 2019");

        let mut blank = make_host("192.168.58.10", "dc01.contoso.local");
        blank.os = String::new();
        assert_eq!(dedup(&[blank, second])[0].os, "Windows Server 2022");
    }

    #[test]
    fn dedup_unions_roles_without_duplicating() {
        let mut first = make_host("192.168.58.10", "dc01.contoso.local");
        first.roles = vec!["dc".to_string()];
        let mut second = make_host("192.168.58.10", "dc01.contoso.local");
        second.roles = vec!["dc".to_string(), "ca".to_string()];

        assert_eq!(dedup(&[first, second])[0].roles, vec!["dc", "ca"]);
    }

    #[test]
    fn dedup_folds_a_hostname_only_row_into_the_matching_ip_row() {
        let hosts = [
            make_host("192.168.58.10", "dc01.contoso.local"),
            with_services(make_host("dc01.contoso.local", ""), &["445/tcp"]),
        ];

        let result = dedup(&hosts);
        assert_eq!(
            result.len(),
            1,
            "hostname-only row should not become its own entry"
        );
        assert_eq!(result[0].ip, "192.168.58.10");
        assert_eq!(result[0].services, vec!["445/tcp"]);
    }

    #[test]
    fn dedup_keeps_an_unmatched_hostname_row_only_when_it_has_services() {
        let with_svc = [with_services(
            make_host("web01.contoso.local", ""),
            &["80/tcp"],
        )];
        let result = dedup(&with_svc);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].hostname, "web01.contoso.local");
        assert!(result[0].ip.is_empty());

        let without_svc = [make_host("web01.contoso.local", "")];
        assert!(dedup(&without_svc).is_empty());
    }

    #[test]
    fn dedup_marks_known_domain_controllers_and_backfills_the_fqdn() {
        let hosts = [make_host("192.168.58.10", "")];
        let netbios = HashMap::from([("DC01".to_string(), "dc01.contoso.local".to_string())]);
        let dcs = HashMap::from([("contoso.local".to_string(), "192.168.58.10".to_string())]);

        let result = dedup_hosts(&hosts, &netbios, &dcs);
        assert!(result[0].is_dc);
        assert_eq!(result[0].hostname, "dc01.contoso.local");
    }

    #[test]
    fn dedup_sorts_by_ip() {
        let hosts = [
            make_host("192.168.58.30", "ws01.contoso.local"),
            make_host("192.168.58.10", "dc01.contoso.local"),
            make_host("192.168.58.20", "sql01.contoso.local"),
        ];

        let result = dedup(&hosts);
        let ips: Vec<&str> = result.iter().map(|h| h.ip.as_str()).collect();
        assert_eq!(ips, ["192.168.58.10", "192.168.58.20", "192.168.58.30"]);
    }
}
