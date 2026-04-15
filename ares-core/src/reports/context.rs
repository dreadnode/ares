//! Template context helpers (serializable structs for Tera).

use std::collections::HashSet;

use serde::Serialize;

use crate::models::{Credential, Hash, Host, Share, User, VulnerabilityInfo};

use super::vuln_details::format_vuln_details;

#[derive(Serialize)]
pub(crate) struct HostCtx {
    pub label: String,
    pub ip: String,
    pub os: String,
    pub roles: String,
    pub services: Vec<String>,
    pub is_dc: bool,
}

/// Pseudo-services that represent findings rather than actual network services.
const NON_SERVICE_ENTRIES: &[&str] = &["smb_signing_disabled", "smb_signing_enabled"];

impl From<&Host> for HostCtx {
    fn from(h: &Host) -> Self {
        let is_dc = h.is_dc || h.detect_dc();

        // Deduplicate services: strip nmap uncertainty suffix (`?`) for the
        // dedup key so `445/tcp (microsoft-ds)` and `445/tcp (microsoft-ds?)`
        // collapse.  Also filter out pseudo-service entries like
        // `smb_signing_disabled`.
        let mut seen_ports = HashSet::new();
        let mut services = Vec::new();
        for svc in &h.services {
            let svc_trimmed = svc.trim();
            // Skip non-service entries
            if NON_SERVICE_ENTRIES
                .iter()
                .any(|ns| svc_trimmed.eq_ignore_ascii_case(ns))
            {
                continue;
            }
            // Normalize: strip trailing `?` inside parens for dedup key
            let key = svc_trimmed.replace("?)", ")").to_lowercase();
            if seen_ports.insert(key) {
                // Prefer the non-`?` variant; strip the `?` from display too
                services.push(svc_trimmed.replace("?)", ")").replace("?", ""));
            }
        }

        Self {
            label: if h.hostname.is_empty() {
                h.ip.clone()
            } else {
                h.hostname.clone()
            },
            ip: h.ip.clone(),
            os: if h.os.is_empty() {
                String::new()
            } else {
                h.os.clone()
            },
            roles: if h.roles.is_empty() {
                String::new()
            } else {
                h.roles.join(", ")
            },
            services,
            is_dc,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct UserCtx {
    pub username: String,
    pub domain: String,
    pub description: String,
    pub is_admin: bool,
    pub admin_display: String,
}

impl From<&User> for UserCtx {
    fn from(u: &User) -> Self {
        Self {
            username: u.username.clone(),
            domain: u.domain.clone(),
            description: if u.description.is_empty() {
                String::new()
            } else {
                u.description.clone()
            },
            is_admin: u.is_admin,
            admin_display: if u.is_admin {
                "Yes".to_string()
            } else {
                "No".to_string()
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct CredCtx {
    pub username: String,
    pub domain: String,
    pub password: String,
    pub source: String,
    pub is_admin: bool,
    pub admin_display: String,
}

impl From<&Credential> for CredCtx {
    fn from(c: &Credential) -> Self {
        Self {
            username: c.username.clone(),
            domain: if c.domain.is_empty() {
                "Unknown".to_string()
            } else {
                c.domain.to_lowercase()
            },
            password: c.password.clone(),
            source: c.source.clone(),
            is_admin: c.is_admin,
            admin_display: if c.is_admin {
                "Yes".to_string()
            } else {
                "No".to_string()
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct HashCtx {
    pub domain: String,
    pub username: String,
    pub hash_type: String,
    pub hash_value: String,
    pub source: String,
}

impl From<&Hash> for HashCtx {
    fn from(h: &Hash) -> Self {
        Self {
            domain: h.domain.to_lowercase(),
            username: h.username.clone(),
            hash_type: h.hash_type.clone(),
            hash_value: h.hash_value.clone(),
            source: h.source.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct ShareCtx {
    pub name: String,
    pub host: String,
    pub permissions: String,
    pub comment: String,
}

impl From<&Share> for ShareCtx {
    fn from(s: &Share) -> Self {
        Self {
            name: s.name.clone(),
            host: s.host.clone(),
            permissions: if s.permissions.is_empty() {
                String::new()
            } else {
                s.permissions.clone()
            },
            comment: if s.comment.is_empty() {
                String::new()
            } else {
                s.comment.clone()
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct TimelineEventCtx {
    pub timestamp: String,
    pub description: String,
    pub description_short: String,
    pub mitre_display: String,
    pub mitre_techniques: Vec<String>,
    pub confidence_display: String,
}

/// Tera context for a single step in the domain admin credential chain.
///
/// The comprehensive report template iterates these as `domain_admin_chain`.
#[derive(Serialize)]
pub(crate) struct ChainStepCtx {
    pub step_number: i32,
    /// `"hash"` or `"credential"`
    #[serde(rename = "type")]
    pub item_type: String,
    pub username: String,
    pub domain: String,
    pub source: String,
    pub hash_type: String,
}

#[derive(Serialize)]
pub(crate) struct VulnCtx {
    pub vuln_id: String,
    pub vuln_type: String,
    pub target: String,
    pub target_ip: String,
    pub target_host: String,
    pub priority: i32,
    pub exploited: bool,
    pub exploited_display: String,
    pub status_display: String,
    pub details: String,
}

pub(crate) fn build_vuln_ctx(
    vuln_id: &str,
    vuln: &VulnerabilityInfo,
    exploited_set: &HashSet<String>,
) -> VulnCtx {
    let exploited = exploited_set.contains(vuln_id);
    VulnCtx {
        vuln_id: vuln_id.to_string(),
        vuln_type: vuln.vuln_type.clone(),
        target: vuln.target.clone(),
        target_ip: vuln.target.clone(),
        target_host: vuln.target.clone(),
        priority: vuln.priority,
        exploited,
        exploited_display: if exploited {
            "\u{2713}".to_string() // checkmark
        } else {
            "\u{2717}".to_string() // cross
        },
        status_display: if exploited {
            "EXPLOITED".to_string()
        } else {
            "Not Exploited".to_string()
        },
        details: format_vuln_details(&vuln.details),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_host_ctx_from_host_with_hostname() {
        let host = Host {
            ip: "192.168.58.10".to_string(),
            hostname: "dc01.contoso.local".to_string(),
            os: "Windows Server 2019".to_string(),
            roles: vec!["domain_controller".to_string(), "winrm".to_string()],
            services: vec!["88/tcp (kerberos)".to_string()],
            is_dc: true,
            owned: false,
        };
        let ctx = HostCtx::from(&host);
        assert_eq!(ctx.label, "dc01.contoso.local");
        assert_eq!(ctx.ip, "192.168.58.10");
        assert_eq!(ctx.os, "Windows Server 2019");
        assert!(ctx.roles.contains("domain_controller"));
        assert!(ctx.is_dc);
    }

    #[test]
    fn test_host_ctx_from_host_no_hostname() {
        let host = Host {
            ip: "192.168.58.20".to_string(),
            hostname: String::new(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        };
        let ctx = HostCtx::from(&host);
        assert_eq!(ctx.label, "192.168.58.20");
        assert_eq!(ctx.os, "");
        assert_eq!(ctx.roles, "");
    }

    #[test]
    fn test_user_ctx_from_user() {
        let user = User {
            username: "admin".to_string(),
            domain: "contoso.local".to_string(),
            description: "Built-in admin".to_string(),
            is_admin: true,
            source: String::new(),
        };
        let ctx = UserCtx::from(&user);
        assert_eq!(ctx.username, "admin");
        assert_eq!(ctx.domain, "contoso.local");
        assert_eq!(ctx.admin_display, "Yes");
    }

    #[test]
    fn test_user_ctx_non_admin() {
        let user = User {
            username: "jdoe".to_string(),
            domain: "contoso.local".to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        };
        let ctx = UserCtx::from(&user);
        assert_eq!(ctx.admin_display, "No");
        assert_eq!(ctx.description, "");
    }

    #[test]
    fn test_cred_ctx_empty_domain() {
        let cred = Credential {
            id: String::new(),
            username: "admin".to_string(),
            password: "P@ss1".to_string(),
            domain: String::new(),
            source: "secretsdump".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        let ctx = CredCtx::from(&cred);
        assert_eq!(ctx.domain, "Unknown");
    }

    #[test]
    fn test_hash_ctx_from_hash() {
        let hash = Hash {
            id: String::new(),
            username: "krbtgt".to_string(),
            hash_value: "aabbccdd".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "secretsdump".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        };
        let ctx = HashCtx::from(&hash);
        assert_eq!(ctx.username, "krbtgt");
        assert_eq!(ctx.hash_type, "ntlm");
        assert_eq!(ctx.domain, "contoso.local");
    }

    #[test]
    fn test_share_ctx_from_share() {
        let share = Share {
            host: "192.168.58.10".to_string(),
            name: "SYSVOL".to_string(),
            permissions: "READ".to_string(),
            comment: "Logon server share".to_string(),
        };
        let ctx = ShareCtx::from(&share);
        assert_eq!(ctx.name, "SYSVOL");
        assert_eq!(ctx.host, "192.168.58.10");
        assert_eq!(ctx.permissions, "READ");
    }

    #[test]
    fn test_share_ctx_empty_fields() {
        let share = Share {
            host: "192.168.58.10".to_string(),
            name: "C$".to_string(),
            permissions: String::new(),
            comment: String::new(),
        };
        let ctx = ShareCtx::from(&share);
        assert_eq!(ctx.permissions, "");
        assert_eq!(ctx.comment, "");
    }

    #[test]
    fn test_build_vuln_ctx_not_exploited() {
        let vuln = VulnerabilityInfo {
            vuln_id: "smb_signing_192.168.58.10".to_string(),
            vuln_type: "smb_signing_disabled".to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "recon".to_string(),
            discovered_at: chrono::Utc::now(),
            details: HashMap::new(),
            recommended_agent: "exploit".to_string(),
            priority: 5,
        };
        let exploited = HashSet::new();
        let ctx = build_vuln_ctx("smb_signing_192.168.58.10", &vuln, &exploited);
        assert!(!ctx.exploited);
        assert_eq!(ctx.status_display, "Not Exploited");
        assert_eq!(ctx.exploited_display, "\u{2717}");
    }

    #[test]
    fn test_build_vuln_ctx_exploited() {
        let vuln = VulnerabilityInfo {
            vuln_id: "esc1_192.168.58.10".to_string(),
            vuln_type: "adcs_esc1".to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "recon".to_string(),
            discovered_at: chrono::Utc::now(),
            details: HashMap::new(),
            recommended_agent: "privesc".to_string(),
            priority: 10,
        };
        let mut exploited = HashSet::new();
        exploited.insert("esc1_192.168.58.10".to_string());
        let ctx = build_vuln_ctx("esc1_192.168.58.10", &vuln, &exploited);
        assert!(ctx.exploited);
        assert_eq!(ctx.status_display, "EXPLOITED");
        assert_eq!(ctx.exploited_display, "\u{2713}");
        assert_eq!(ctx.priority, 10);
    }

    #[test]
    fn test_host_ctx_deduplicates_services() {
        let host = Host {
            ip: "192.168.58.10".to_string(),
            hostname: "dc01.contoso.local".to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![
                "445/tcp (microsoft-ds)".to_string(),
                "445/tcp (microsoft-ds?)".to_string(),
            ],
            is_dc: false,
            owned: false,
        };
        let ctx = HostCtx::from(&host);
        assert_eq!(ctx.services.len(), 1);
        assert_eq!(ctx.services[0], "445/tcp (microsoft-ds)");
    }

    #[test]
    fn test_host_ctx_filters_pseudo_services() {
        let host = Host {
            ip: "192.168.58.23".to_string(),
            hostname: String::new(),
            os: String::new(),
            roles: vec![],
            services: vec![
                "445/tcp (microsoft-ds)".to_string(),
                "smb_signing_disabled".to_string(),
            ],
            is_dc: false,
            owned: false,
        };
        let ctx = HostCtx::from(&host);
        assert_eq!(ctx.services.len(), 1);
        assert_eq!(ctx.services[0], "445/tcp (microsoft-ds)");
    }

    #[test]
    fn test_cred_ctx_lowercases_domain() {
        let cred = Credential {
            id: String::new(),
            username: "admin".to_string(),
            password: "pass".to_string(),
            domain: "CONTOSO.LOCAL".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        let ctx = CredCtx::from(&cred);
        assert_eq!(ctx.domain, "contoso.local");
    }

    #[test]
    fn test_hash_ctx_lowercases_domain() {
        let hash = Hash {
            id: String::new(),
            username: "admin".to_string(),
            hash_value: "aabb".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "CHILD.CONTOSO.LOCAL".to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        };
        let ctx = HashCtx::from(&hash);
        assert_eq!(ctx.domain, "child.contoso.local");
    }
}
