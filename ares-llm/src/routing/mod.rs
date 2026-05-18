//! Routing enrichment -- DC discovery, credential matching, domain normalization.
//!
//! Provides domain normalization, credential lookup, multi-tier DC discovery,
//! and payload enrichment for delegation exploits.

mod credentials;
mod dc_discovery;
mod domain;
mod enrichment;
mod util;

// Re-export all public items at the same paths they had before the split.
pub use credentials::{find_domain_credential, is_valid_credential_for_domain};
pub use dc_discovery::{find_dc_ip, find_dc_ip_cached, DcDiscovery, DcTier};
pub use domain::normalize_domain;
pub use enrichment::{enrich_delegation_payload, resolve_dc_for_payload};
pub use util::{extract_host_from_spn, extract_ticket_path, is_pass_the_hash_compatible};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ares_core::models::{Credential, Host};

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

    #[test]
    fn normalize_domain_fqdn() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("contoso.local", &map), "contoso.local");
        assert_eq!(normalize_domain("CONTOSO.LOCAL", &map), "contoso.local");
    }

    #[test]
    fn normalize_domain_netbios() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("CONTOSO", &map), "contoso.local");
        assert_eq!(normalize_domain("contoso", &map), "contoso.local");
    }

    #[test]
    fn normalize_domain_unknown() {
        let map = sample_netbios_map();
        assert_eq!(normalize_domain("UNKNOWN", &map), "unknown");
    }

    #[test]
    fn hostname_matches_domain() {
        assert!(domain::hostname_matches_domain(
            "dc01.contoso.local",
            "contoso.local"
        ));
        assert!(domain::hostname_matches_domain(
            "DC01.CONTOSO.LOCAL",
            "contoso.local"
        ));
        // Child domain hostname should NOT match parent
        assert!(!domain::hostname_matches_domain(
            "dc01.child.contoso.local",
            "contoso.local"
        ));
        // Child domain match
        assert!(domain::hostname_matches_domain(
            "dc01.child.contoso.local",
            "child.contoso.local"
        ));
        assert!(!domain::hostname_matches_domain("", "contoso.local"));
        assert!(!domain::hostname_matches_domain("dc01.contoso.local", ""));
    }

    #[test]
    fn has_dc_role() {
        let dc = make_host(
            "192.168.58.1",
            "dc01.contoso.local",
            vec!["Domain Controller"],
            vec![],
        );
        assert!(dc_discovery::has_dc_role(&dc));

        let dc_flag = Host {
            is_dc: true,
            ..make_host("192.168.58.2", "srv01.contoso.local", vec![], vec![])
        };
        assert!(dc_discovery::has_dc_role(&dc_flag));

        let non_dc = make_host("192.168.58.3", "web01.contoso.local", vec!["web"], vec![]);
        assert!(!dc_discovery::has_dc_role(&non_dc));
    }

    #[test]
    fn has_dc_services() {
        let with_kerberos = make_host("192.168.58.1", "dc01", vec![], vec!["88/tcp kerberos"]);
        assert!(dc_discovery::has_dc_services(&with_kerberos));

        let with_ldap = make_host("192.168.58.2", "dc02", vec![], vec!["389/tcp ldap"]);
        assert!(dc_discovery::has_dc_services(&with_ldap));

        // 3389 should NOT match (prefix check prevents this)
        let rdp_only = make_host(
            "192.168.58.3",
            "srv01",
            vec![],
            vec!["3389/tcp ms-wbt-server"],
        );
        assert!(!dc_discovery::has_dc_services(&rdp_only));
    }

    #[test]
    fn finds_domain_credential() {
        let map = sample_netbios_map();
        let creds = vec![
            make_cred("user1", "contoso.local", ""),
            make_cred("admin", "contoso.local", "P@ss1"),
        ];
        let trusts = std::collections::HashMap::new();
        let found = find_domain_credential("CONTOSO", &creds, &map, &trusts).unwrap();
        assert_eq!(found.username, "admin"); // Prefers one with password
    }

    #[test]
    fn find_dc_ip_tier0_cached() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let result = find_dc_ip("contoso.local", &[], &dcs, &HashMap::new(), None);
        assert_eq!(result.unwrap().tier, DcTier::Cached);
    }

    #[test]
    fn find_dc_ip_tier1_role() {
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
    fn find_dc_ip_tier2_hostname_pattern() {
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
    fn find_dc_ip_tier3_services() {
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
    fn find_dc_ip_tier3_5_forest_child() {
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
        // Host has "dc" role + hostname matches domain -> found at Role tier
        assert_eq!(d.tier, DcTier::Role);
        assert!(d.should_cache);
    }

    #[test]
    fn find_dc_ip_tier3_5_parent_fallback_not_cached() {
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
    fn find_dc_ip_tier5_fallback_role() {
        let hosts = vec![make_host(
            "192.168.58.1",
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
    fn find_dc_ip_tier6_last_resort() {
        let hosts = vec![make_host(
            "192.168.58.1",
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
    fn find_dc_ip_none() {
        let result = find_dc_ip("contoso.local", &[], &HashMap::new(), &HashMap::new(), None);
        assert!(result.is_none());
    }

    #[test]
    fn enrich_delegation_payload_credential() {
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
    fn enrich_delegation_skips_non_delegation() {
        let mut payload = serde_json::json!({"account_name": "svc_sql"});
        enrich_delegation_payload(&mut payload, "zerologon", &[], &[]);
        assert!(payload.get("password").is_none());
    }

    #[test]
    fn enrich_delegation_resolves_target_ip() {
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
    fn resolves_dc_for_payload() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".to_string(), "192.168.58.10".to_string());
        let mut payload = serde_json::json!({"domain": "contoso.local"});
        resolve_dc_for_payload(&mut payload, &[], &dcs, &HashMap::new(), None);
        assert_eq!(payload["dc_ip"].as_str(), Some("192.168.58.10"));
    }

    #[test]
    fn resolve_dc_skips_if_already_set() {
        let mut payload = serde_json::json!({"domain": "contoso.local", "dc_ip": "192.168.58.1"});
        resolve_dc_for_payload(&mut payload, &[], &HashMap::new(), &HashMap::new(), None);
        assert_eq!(payload["dc_ip"].as_str(), Some("192.168.58.1")); // unchanged
    }

    #[test]
    fn pass_the_hash_compatibility() {
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
    fn extracts_ticket_path() {
        let output = "Saving ticket in Administrator.ccache\nDone.";
        assert_eq!(
            extract_ticket_path(output),
            Some("Administrator.ccache".to_string())
        );
    }

    #[test]
    fn extracts_host_from_spn() {
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
