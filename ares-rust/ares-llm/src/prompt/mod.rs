//! Task prompt generation for LLM agent steps.
//!
//! Ports the prompt building logic from `src/ares/core/worker/prompts.py`.
//! Each task type gets a specific prompt rendered from a Tera template.
//! Variable extraction from JSON payloads happens in Rust; prompt wording
//! and structure lives in `.tera` template files.

pub mod templates;

use std::collections::HashMap;
use std::fmt::Write;

use ares_core::models::{Credential, Hash, Host, Share, VulnerabilityInfo};
use serde_json::Value;
use tera::Context;

use templates::{
    render_template_with_context, TASK_ACL_ANALYSIS, TASK_COERCION, TASK_COMMAND, TASK_CRACK,
    TASK_CREDENTIAL_ACCESS, TASK_EXPLOIT, TASK_LATERAL, TASK_PRIVESC_ENUMERATION, TASK_RECON,
};

// ---------------------------------------------------------------------------
// StateSnapshot — cheap, clonable view of operation state
// ---------------------------------------------------------------------------

/// A snapshot of operation state used for prompt generation.
/// Cloned from `SharedState` to avoid holding the RwLock during LLM calls.
#[derive(Debug, Clone, Default)]
pub struct StateSnapshot {
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub shares: Vec<Share>,
    pub domains: Vec<String>,
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: std::collections::HashSet<String>,
    pub domain_controllers: HashMap<String, String>,
    pub netbios_to_fqdn: HashMap<String, String>,
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
}

// ---------------------------------------------------------------------------
// State context formatting (stays in Rust — data processing with truncation)
// ---------------------------------------------------------------------------

/// Maximum items to include in state context to avoid overwhelming the LLM.
const MAX_CREDENTIALS: usize = 8;
const MAX_HASHES: usize = 5;
const MAX_DCS: usize = 3;
const MAX_OTHER_HOSTS: usize = 5;
const MAX_VULNERABILITIES: usize = 5;

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
        writeln!(ctx, "### Discovered Domains").unwrap();
        for d in &state.domains {
            writeln!(ctx, "- {d}").unwrap();
        }
        writeln!(ctx).unwrap();
    }

    // Credentials (relevant for lateral, credential_access, exploit, coercion)
    let show_creds = matches!(
        task_type,
        "lateral" | "credential_access" | "exploit" | "coercion"
    );
    if show_creds && !state.credentials.is_empty() {
        writeln!(ctx, "### Discovered Credentials").unwrap();
        for cred in state.credentials.iter().take(MAX_CREDENTIALS) {
            let admin_marker = if cred.is_admin { " [ADMIN]" } else { "" };
            let domain_part = if cred.domain.is_empty() {
                String::new()
            } else {
                format!("@{}", cred.domain)
            };
            writeln!(ctx, "- {}{}{}", cred.username, domain_part, admin_marker).unwrap();
        }
        if state.credentials.len() > MAX_CREDENTIALS {
            writeln!(
                ctx,
                "- ... and {} more",
                state.credentials.len() - MAX_CREDENTIALS
            )
            .unwrap();
        }
        writeln!(ctx).unwrap();
    }

    // Cracked hashes
    let cracked: Vec<&Hash> = state
        .hashes
        .iter()
        .filter(|h| h.cracked_password.is_some())
        .collect();
    if !cracked.is_empty() {
        writeln!(ctx, "### Cracked Hashes").unwrap();
        for h in cracked.iter().take(MAX_HASHES) {
            let domain_part = if h.domain.is_empty() {
                String::new()
            } else {
                format!("@{}", h.domain)
            };
            writeln!(ctx, "- {}{} ({})", h.username, domain_part, h.hash_type).unwrap();
        }
        if cracked.len() > MAX_HASHES {
            writeln!(ctx, "- ... and {} more", cracked.len() - MAX_HASHES).unwrap();
        }
        writeln!(ctx).unwrap();
    }

    // Hosts — separate DCs from others
    if !state.hosts.is_empty() {
        let dcs: Vec<&Host> = state.hosts.iter().filter(|h| h.is_dc).collect();
        let others: Vec<&Host> = state.hosts.iter().filter(|h| !h.is_dc).collect();

        if !dcs.is_empty() {
            writeln!(ctx, "### Domain Controllers").unwrap();
            for h in dcs.iter().take(MAX_DCS) {
                let name = if h.hostname.is_empty() {
                    &h.ip
                } else {
                    &h.hostname
                };
                writeln!(ctx, "- {} ({})", name, h.ip).unwrap();
            }
            writeln!(ctx).unwrap();
        }

        if !others.is_empty() {
            writeln!(ctx, "### Other Hosts").unwrap();
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
                writeln!(ctx, "- {} ({}){}", name, h.ip, roles).unwrap();
            }
            if others.len() > MAX_OTHER_HOSTS {
                writeln!(ctx, "- ... and {} more", others.len() - MAX_OTHER_HOSTS).unwrap();
            }
            writeln!(ctx).unwrap();
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
            writeln!(ctx, "### Pending Vulnerabilities").unwrap();
            for v in pending.iter().take(MAX_VULNERABILITIES) {
                writeln!(ctx, "- {} ({}) on {}", v.vuln_id, v.vuln_type, v.target).unwrap();
            }
            if pending.len() > MAX_VULNERABILITIES {
                writeln!(
                    ctx,
                    "- ... and {} more",
                    pending.len() - MAX_VULNERABILITIES
                )
                .unwrap();
            }
            writeln!(ctx).unwrap();
        }
    }

    ctx
}

// ---------------------------------------------------------------------------
// Helper: extract credential fields from payload into context
// ---------------------------------------------------------------------------

fn insert_credential_context(ctx: &mut Context, payload: &Value) {
    if let Some(cred) = payload.get("credential") {
        let user = cred["username"].as_str().unwrap_or("");
        let cred_domain = cred["domain"].as_str().unwrap_or("");
        if !user.is_empty() {
            ctx.insert("credential_username", user);
            ctx.insert("credential_domain", cred_domain);

            let has_password = cred
                .get("password")
                .and_then(|v| v.as_str())
                .is_some_and(|p| !p.is_empty());
            ctx.insert(
                "auth_type",
                if has_password {
                    "password"
                } else {
                    "hash/ticket"
                },
            );
        }
    }
}

fn insert_state_context(
    ctx: &mut Context,
    state: Option<&StateSnapshot>,
    task_type: &str,
    target: Option<&str>,
) {
    if let Some(s) = state {
        let state_ctx = format_state_context(s, task_type, target);
        if !state_ctx.is_empty() {
            ctx.insert("state_context", &state_ctx);
        }
    }
}

// ---------------------------------------------------------------------------
// Task prompt generation
// ---------------------------------------------------------------------------

/// Generate a task prompt from a task type and JSON payload.
///
/// Returns `None` if the task type is not recognized.
/// Each task type extracts variables from the payload and renders
/// the corresponding `.tera` template.
pub fn generate_task_prompt(
    task_type: &str,
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> Option<String> {
    let result = match task_type {
        "recon" => generate_recon_prompt(task_id, payload, state),
        "crack" => generate_crack_prompt(task_id, payload),
        "credential_access" => generate_credential_access_prompt(task_id, payload, state),
        "lateral_movement" | "lateral" => generate_lateral_prompt(task_id, payload, state),
        "exploit" => generate_exploit_prompt(task_id, payload, state),
        "coercion" => generate_coercion_prompt(task_id, payload, state),
        "privesc_enumeration" => generate_privesc_enumeration_prompt(task_id, payload, state),
        "acl_analysis" => generate_acl_analysis_prompt(task_id, payload, state),
        "command" => generate_command_prompt(task_id, payload),
        _ => return None,
    };
    Some(result.unwrap_or_else(|e| format!("Error generating prompt: {e}")))
}

fn generate_recon_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    insert_credential_context(&mut ctx, payload);

    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !techniques.is_empty() {
        ctx.insert("techniques", &techniques);
    }

    insert_state_context(&mut ctx, state, "recon", payload["target_ip"].as_str());

    render_template_with_context(TASK_RECON, &ctx)
}

fn generate_crack_prompt(task_id: &str, payload: &Value) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "hash_type",
        payload["hash_type"].as_str().unwrap_or("unknown"),
    );
    ctx.insert("hash_value", payload["hash_value"].as_str().unwrap_or(""));

    let username = payload["username"].as_str().unwrap_or("");
    if !username.is_empty() {
        ctx.insert("username", username);
    }

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    render_template_with_context(TASK_CRACK, &ctx)
}

fn generate_credential_access_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "technique",
        payload["technique"].as_str().unwrap_or("secretsdump"),
    );
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    insert_credential_context(&mut ctx, payload);
    insert_state_context(
        &mut ctx,
        state,
        "credential_access",
        payload["target_ip"].as_str(),
    );

    render_template_with_context(TASK_CREDENTIAL_ACCESS, &ctx)
}

fn generate_lateral_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "technique",
        payload["technique"].as_str().unwrap_or("psexec"),
    );
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );

    insert_credential_context(&mut ctx, payload);
    insert_state_context(&mut ctx, state, "lateral", payload["target_ip"].as_str());

    render_template_with_context(TASK_LATERAL, &ctx)
}

fn generate_exploit_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "vuln_type",
        payload["vuln_type"].as_str().unwrap_or("unknown"),
    );
    ctx.insert("target", payload["target"].as_str().unwrap_or("unknown"));

    if let Some(details) = payload.get("details") {
        if details.is_object() {
            ctx.insert(
                "details_json",
                &serde_json::to_string_pretty(details).unwrap_or_default(),
            );
        }
    }

    insert_state_context(&mut ctx, state, "exploit", payload["target"].as_str());

    render_template_with_context(TASK_EXPLOIT, &ctx)
}

fn generate_coercion_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );
    ctx.insert("listener_ip", payload["listener_ip"].as_str().unwrap_or(""));

    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !techniques.is_empty() {
        ctx.insert("techniques", &techniques);
    }

    insert_state_context(&mut ctx, state, "coercion", payload["target_ip"].as_str());

    render_template_with_context(TASK_COERCION, &ctx)
}

fn generate_privesc_enumeration_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "technique",
        payload["technique"].as_str().unwrap_or("enumeration"),
    );
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    insert_credential_context(&mut ctx, payload);
    insert_state_context(
        &mut ctx,
        state,
        "privesc_enumeration",
        payload["target_ip"].as_str(),
    );

    render_template_with_context(TASK_PRIVESC_ENUMERATION, &ctx)
}

fn generate_acl_analysis_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);

    if let Some(chain) = payload.get("chain") {
        ctx.insert(
            "chain_json",
            &serde_json::to_string_pretty(chain).unwrap_or_default(),
        );
    }

    insert_state_context(&mut ctx, state, "acl_analysis", None);

    render_template_with_context(TASK_ACL_ANALYSIS, &ctx)
}

fn generate_command_prompt(task_id: &str, payload: &Value) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("command", payload["command"].as_str().unwrap_or("unknown"));

    render_template_with_context(TASK_COMMAND, &ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> StateSnapshot {
        StateSnapshot {
            credentials: vec![Credential {
                id: "cred-1".into(),
                username: "admin".into(),
                password: "P@ss1".into(),
                domain: "contoso.local".into(),
                source: String::new(),
                discovered_at: None,
                is_admin: true,
                parent_id: None,
                attack_step: 0,
            }],
            hosts: vec![Host {
                ip: "192.168.58.10".into(),
                hostname: "dc01.contoso.local".into(),
                os: String::new(),
                roles: vec!["AD DS".into()],
                services: Vec::new(),
                is_dc: true,
                owned: false,
            }],
            domains: vec!["contoso.local".into()],
            ..Default::default()
        }
    }

    #[test]
    fn test_generate_recon_prompt() {
        let payload = serde_json::json!({
            "target_ip": "192.168.58.0/24",
            "domain": "contoso.local",
            "techniques": ["nmap_scan", "enumerate_users"]
        });
        let state = sample_state();
        let prompt = generate_task_prompt("recon", "task-001", &payload, Some(&state)).unwrap();
        assert!(prompt.contains("Recon Task: task-001"));
        assert!(prompt.contains("192.168.58.0/24"));
        assert!(prompt.contains("contoso.local"));
        assert!(prompt.contains("- nmap_scan"));
    }

    #[test]
    fn test_generate_crack_prompt() {
        let payload = serde_json::json!({
            "hash_type": "ntlm",
            "hash_value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "username": "admin",
            "domain": "contoso.local"
        });
        let prompt = generate_task_prompt("crack", "task-002", &payload, None).unwrap();
        assert!(prompt.contains("Crack Task: task-002"));
        assert!(prompt.contains("ntlm"));
        assert!(prompt.contains("admin"));
    }

    #[test]
    fn test_generate_credential_access_prompt() {
        let payload = serde_json::json!({
            "technique": "secretsdump",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ss1",
                "domain": "contoso.local"
            }
        });
        let prompt = generate_task_prompt("credential_access", "task-003", &payload, None).unwrap();
        assert!(prompt.contains("secretsdump"));
        assert!(prompt.contains("admin"));
        assert!(prompt.contains("contoso.local"));
    }

    #[test]
    fn test_generate_lateral_prompt() {
        let payload = serde_json::json!({
            "technique": "psexec",
            "target_ip": "192.168.58.20",
            "credential": {
                "username": "admin",
                "password": "P@ss1",
                "domain": "contoso.local"
            }
        });
        let prompt = generate_task_prompt("lateral_movement", "task-004", &payload, None).unwrap();
        assert!(prompt.contains("Lateral Movement"));
        assert!(prompt.contains("psexec"));
    }

    #[test]
    fn test_generate_exploit_prompt() {
        let payload = serde_json::json!({
            "vuln_type": "constrained_delegation",
            "target": "192.168.58.30",
            "details": {"account": "svc_sql", "spn": "MSSQLSvc/db01.contoso.local"}
        });
        let prompt = generate_task_prompt("exploit", "task-005", &payload, None).unwrap();
        assert!(prompt.contains("constrained_delegation"));
        assert!(prompt.contains("svc_sql"));
    }

    #[test]
    fn test_generate_coercion_prompt() {
        let payload = serde_json::json!({
            "target_ip": "192.168.58.10",
            "listener_ip": "192.168.58.100",
            "techniques": ["petitpotam", "coercer"]
        });
        let prompt = generate_task_prompt("coercion", "task-006", &payload, None).unwrap();
        assert!(prompt.contains("Coercion Task: task-006"));
        assert!(prompt.contains("192.168.58.10"));
        assert!(prompt.contains("- petitpotam"));
    }

    #[test]
    fn test_generate_privesc_prompt() {
        let payload = serde_json::json!({
            "technique": "find_delegation",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        let prompt =
            generate_task_prompt("privesc_enumeration", "task-007", &payload, None).unwrap();
        assert!(prompt.contains("Privilege Escalation"));
        assert!(prompt.contains("find_delegation"));
    }

    #[test]
    fn test_generate_acl_prompt() {
        let payload = serde_json::json!({
            "chain": [{"source": "user1", "target": "admin", "right": "GenericAll"}]
        });
        let prompt = generate_task_prompt("acl_analysis", "task-008", &payload, None).unwrap();
        assert!(prompt.contains("ACL Analysis"));
        assert!(prompt.contains("GenericAll"));
    }

    #[test]
    fn test_generate_command_prompt() {
        let payload = serde_json::json!({"command": "whoami"});
        let prompt = generate_task_prompt("command", "task-009", &payload, None).unwrap();
        assert!(prompt.contains("whoami"));
        assert!(prompt.contains("Command Task: task-009"));
    }

    #[test]
    fn test_format_state_context_truncation() {
        let mut state = StateSnapshot::default();
        for i in 0..20 {
            state.credentials.push(Credential {
                id: format!("cred-{i}"),
                username: format!("user{i}"),
                password: "pass".into(),
                domain: "contoso.local".into(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            });
        }
        let ctx = format_state_context(&state, "credential_access", None);
        assert!(ctx.contains("and 12 more"));
    }

    #[test]
    fn test_unknown_task_type_returns_none() {
        let payload = serde_json::json!({});
        assert!(generate_task_prompt("unknown_type", "task-x", &payload, None).is_none());
    }

    #[test]
    fn test_state_context_injected_into_template() {
        let payload = serde_json::json!({
            "technique": "secretsdump",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        let state = sample_state();
        let prompt =
            generate_task_prompt("credential_access", "task-010", &payload, Some(&state)).unwrap();
        // State context includes the domain
        assert!(prompt.contains("Discovered Domains"));
        assert!(prompt.contains("contoso.local"));
    }
}
