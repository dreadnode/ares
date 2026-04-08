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
            let domain_part = if cred.domain.is_empty() {
                String::new()
            } else {
                format!("@{}", cred.domain)
            };
            let _ = writeln!(ctx, "- {}{}{}", cred.username, domain_part, admin_marker);
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
            for h in dcs.iter().take(MAX_DCS) {
                let name = if h.hostname.is_empty() {
                    &h.ip
                } else {
                    &h.hostname
                };
                let _ = writeln!(ctx, "- {} ({})", name, h.ip);
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
