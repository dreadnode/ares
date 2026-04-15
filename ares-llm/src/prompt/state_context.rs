//! State context formatting for LLM prompts.

use std::fmt::Write;

use ares_core::models::VulnerabilityInfo;

use super::StateSnapshot;

/// Maximum items to include in state context to avoid overwhelming the LLM.
pub(crate) const MAX_CREDENTIALS: usize = 8;
pub(crate) const MAX_HASHES: usize = 5;
pub(crate) const MAX_DCS: usize = 3;
pub(crate) const MAX_OTHER_HOSTS: usize = 5;
pub(crate) const MAX_VULNERABILITIES: usize = 5;

/// Format operation state as markdown context for the LLM.
///
/// Includes discovered credentials, hashes, hosts, and pending vulnerabilities.
/// Truncates to avoid exceeding context limits. The result is injected into
/// task templates as `{{ state_context }}`.
pub fn format_state_context(
    state: &StateSnapshot,
    task_type: &str,
    _current_target: Option<&str>,
) -> String {
    let mut ctx = String::with_capacity(2048);

    // Domains
    if !state.domains.is_empty() {
        let _ = writeln!(ctx, "### Discovered Domains");
        for d in &state.domains {
            let _ = writeln!(ctx, "- {d}");
        }
        let _ = writeln!(ctx);
    }

    // Credentials (relevant for lateral, credential_access, exploit, coercion)
    let show_creds = matches!(
        task_type,
        "lateral" | "credential_access" | "exploit" | "coercion"
    );
    if show_creds && !state.credentials.is_empty() {
        let _ = writeln!(ctx, "### Discovered Credentials");
        for cred in state.credentials.iter().take(MAX_CREDENTIALS) {
            let admin_marker = if cred.is_admin { " [ADMIN]" } else { "" };
            let deleg_marker = if state
                .delegation_accounts
                .contains(&cred.username.to_lowercase())
            {
                " [DELEGATION ONLY — do NOT use for auth]"
            } else {
                ""
            };
            let domain_part = if cred.domain.is_empty() {
                String::new()
            } else {
                format!("@{}", cred.domain)
            };
            let _ = writeln!(
                ctx,
                "- {}{}{}{}",
                cred.username, domain_part, admin_marker, deleg_marker
            );
        }
        if state.credentials.len() > MAX_CREDENTIALS {
            let _ = writeln!(
                ctx,
                "- ... and {} more",
                state.credentials.len() - MAX_CREDENTIALS
            );
        }
        let _ = writeln!(ctx);
    }

    // Cracked hashes
    let cracked: Vec<_> = state
        .hashes
        .iter()
        .filter(|h| h.cracked_password.is_some())
        .collect();
    if !cracked.is_empty() {
        let _ = writeln!(ctx, "### Cracked Hashes");
        for h in cracked.iter().take(MAX_HASHES) {
            let domain_part = if h.domain.is_empty() {
                String::new()
            } else {
                format!("@{}", h.domain)
            };
            let _ = writeln!(ctx, "- {}{} ({})", h.username, domain_part, h.hash_type);
        }
        if cracked.len() > MAX_HASHES {
            let _ = writeln!(ctx, "- ... and {} more", cracked.len() - MAX_HASHES);
        }
        let _ = writeln!(ctx);
    }

    // Hosts — separate DCs from others
    if !state.hosts.is_empty() {
        let dcs: Vec<_> = state.hosts.iter().filter(|h| h.is_dc).collect();
        let others: Vec<_> = state.hosts.iter().filter(|h| !h.is_dc).collect();

        if !dcs.is_empty() {
            let _ = writeln!(ctx, "### Domain Controllers");
            // Build reverse lookup: IP → domain from domain_controllers map
            let ip_to_domain: std::collections::HashMap<&str, &str> = state
                .domain_controllers
                .iter()
                .map(|(domain, ip)| (ip.as_str(), domain.as_str()))
                .collect();
            for h in dcs.iter().take(MAX_DCS) {
                let name = if h.hostname.is_empty() {
                    &h.ip
                } else {
                    &h.hostname
                };
                let domain_info = ip_to_domain
                    .get(h.ip.as_str())
                    .map(|d| format!(" [domain: {d}]"))
                    .unwrap_or_default();
                let _ = writeln!(ctx, "- {} ({}){}", name, h.ip, domain_info);
            }
            let _ = writeln!(ctx);
        }

        if !others.is_empty() {
            let _ = writeln!(ctx, "### Other Hosts");
            for h in others.iter().take(MAX_OTHER_HOSTS) {
                let name = if h.hostname.is_empty() {
                    &h.ip
                } else {
                    &h.hostname
                };
                let roles = if h.roles.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", h.roles.join(", "))
                };
                let _ = writeln!(ctx, "- {} ({}){}", name, h.ip, roles);
            }
            if others.len() > MAX_OTHER_HOSTS {
                let _ = writeln!(ctx, "- ... and {} more", others.len() - MAX_OTHER_HOSTS);
            }
            let _ = writeln!(ctx);
        }
    }

    // Pending vulnerabilities (for exploit/privesc tasks)
    if matches!(task_type, "exploit" | "privesc_enumeration") {
        let pending: Vec<&VulnerabilityInfo> = state
            .discovered_vulnerabilities
            .values()
            .filter(|v| !state.exploited_vulnerabilities.contains(&v.vuln_id))
            .collect();

        if !pending.is_empty() {
            let _ = writeln!(ctx, "### Pending Vulnerabilities");
            for v in pending.iter().take(MAX_VULNERABILITIES) {
                let _ = writeln!(ctx, "- {} ({}) on {}", v.vuln_id, v.vuln_type, v.target);
            }
            if pending.len() > MAX_VULNERABILITIES {
                let _ = writeln!(
                    ctx,
                    "- ... and {} more",
                    pending.len() - MAX_VULNERABILITIES
                );
            }
            let _ = writeln!(ctx);
        }
    }

    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Hash, Host};

    fn make_snapshot() -> StateSnapshot {
        StateSnapshot::default()
    }

    #[test]
    fn test_format_state_context_empty() {
        let snap = make_snapshot();
        let ctx = format_state_context(&snap, "recon", None);
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_format_state_context_domains() {
        let mut snap = make_snapshot();
        snap.domains = vec!["contoso.local".to_string()];
        let ctx = format_state_context(&snap, "recon", None);
        assert!(ctx.contains("### Discovered Domains"));
        assert!(ctx.contains("contoso.local"));
    }

    #[test]
    fn test_format_state_context_credentials_shown_for_lateral() {
        let mut snap = make_snapshot();
        snap.credentials = vec![Credential {
            id: String::new(),
            username: "admin".to_string(),
            password: "P@ss1".to_string(),
            domain: "contoso.local".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: true,
            parent_id: None,
            attack_step: 0,
        }];
        let ctx = format_state_context(&snap, "lateral", None);
        assert!(ctx.contains("### Discovered Credentials"));
        assert!(ctx.contains("admin@contoso.local [ADMIN]"));
    }

    #[test]
    fn test_format_state_context_credentials_hidden_for_recon() {
        let mut snap = make_snapshot();
        snap.credentials = vec![Credential {
            id: String::new(),
            username: "admin".to_string(),
            password: "P@ss1".to_string(),
            domain: "contoso.local".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];
        let ctx = format_state_context(&snap, "recon", None);
        assert!(!ctx.contains("### Discovered Credentials"));
    }

    #[test]
    fn test_format_state_context_truncates_credentials() {
        let mut snap = make_snapshot();
        snap.credentials = (0..12)
            .map(|i| Credential {
                id: String::new(),
                username: format!("user{i}"),
                password: "p".to_string(),
                domain: "contoso.local".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            })
            .collect();
        let ctx = format_state_context(&snap, "lateral", None);
        assert!(ctx.contains("... and 4 more"));
    }

    #[test]
    fn test_format_state_context_hosts_split_dc_and_other() {
        let mut snap = make_snapshot();
        snap.hosts = vec![
            Host {
                ip: "192.168.58.10".to_string(),
                hostname: "dc01.contoso.local".to_string(),
                os: String::new(),
                roles: vec![],
                services: vec![],
                is_dc: true,
                owned: false,
            },
            Host {
                ip: "192.168.58.20".to_string(),
                hostname: "srv01.contoso.local".to_string(),
                os: String::new(),
                roles: vec!["mssql".to_string()],
                services: vec![],
                is_dc: false,
                owned: false,
            },
        ];
        let ctx = format_state_context(&snap, "recon", None);
        assert!(ctx.contains("### Domain Controllers"));
        assert!(ctx.contains("dc01.contoso.local (192.168.58.10)"));
        assert!(ctx.contains("### Other Hosts"));
        assert!(ctx.contains("srv01.contoso.local"));
        assert!(ctx.contains("[mssql]"));
    }

    #[test]
    fn test_format_state_context_cracked_hashes() {
        let mut snap = make_snapshot();
        snap.hashes = vec![Hash {
            id: String::new(),
            username: "svc_sql".to_string(),
            hash_value: "aabb".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: Some("CrackedP@ss".to_string()),
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }];
        let ctx = format_state_context(&snap, "recon", None);
        assert!(ctx.contains("### Cracked Hashes"));
        assert!(ctx.contains("svc_sql@contoso.local (ntlm)"));
    }

    #[test]
    fn test_format_state_context_uncracked_hashes_not_shown() {
        let mut snap = make_snapshot();
        snap.hashes = vec![Hash {
            id: String::new(),
            username: "svc_sql".to_string(),
            hash_value: "aabb".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }];
        let ctx = format_state_context(&snap, "recon", None);
        assert!(!ctx.contains("### Cracked Hashes"));
    }
}
