//! Task prompt generation for LLM agent steps.
//!
//! Ports the prompt building logic from `src/ares/core/worker/prompts.py`.
//! Each task type gets a specific prompt that includes relevant state context
//! (credentials, hosts, vulnerabilities) formatted as markdown for the LLM.

pub mod templates;

use std::collections::HashMap;
use std::fmt::Write;

use ares_core::models::{Credential, Hash, Host, Share, VulnerabilityInfo};
use serde_json::Value;

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
// State context formatting
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
/// Truncates to avoid exceeding context limits.
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
// Task prompt generation
// ---------------------------------------------------------------------------

/// Generate a task prompt from a task type and JSON payload.
///
/// Returns `None` if the task type is not recognized.
pub fn generate_task_prompt(
    task_type: &str,
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> Option<String> {
    match task_type {
        "recon" => Some(generate_recon_prompt(task_id, payload, state)),
        "crack" => Some(generate_crack_prompt(task_id, payload)),
        "credential_access" => Some(generate_credential_access_prompt(task_id, payload, state)),
        "lateral_movement" | "lateral" => Some(generate_lateral_prompt(task_id, payload, state)),
        "exploit" => Some(generate_exploit_prompt(task_id, payload, state)),
        "coercion" => Some(generate_coercion_prompt(task_id, payload, state)),
        "privesc_enumeration" => Some(generate_privesc_enumeration_prompt(task_id, payload, state)),
        "acl_analysis" => Some(generate_acl_analysis_prompt(task_id, payload, state)),
        "command" => Some(generate_command_prompt(task_id, payload)),
        _ => None,
    }
}

fn generate_recon_prompt(task_id: &str, payload: &Value, state: Option<&StateSnapshot>) -> String {
    let target_ip = payload["target_ip"].as_str().unwrap_or("unknown");
    let domain = payload["domain"].as_str().unwrap_or("");
    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let mut prompt = format!(
        "## Recon Task: {task_id}\n\n\
         **Target:** {target_ip}\n"
    );

    if !domain.is_empty() {
        writeln!(prompt, "**Domain:** {domain}").unwrap();
    }

    // Credential for authenticated scans
    if let Some(cred) = payload.get("credential") {
        let user = cred["username"].as_str().unwrap_or("");
        let cred_domain = cred["domain"].as_str().unwrap_or("");
        if !user.is_empty() {
            writeln!(prompt, "**Credential:** {user}@{cred_domain}").unwrap();
        }
    }

    if !techniques.is_empty() {
        writeln!(prompt, "\n**Requested Techniques:**").unwrap();
        for t in &techniques {
            writeln!(prompt, "- {t}").unwrap();
        }
    } else {
        writeln!(
            prompt,
            "\nPerform a comprehensive reconnaissance scan of the target."
        )
        .unwrap();
    }

    // Add state context
    if let Some(s) = state {
        let ctx = format_state_context(s, "recon", Some(target_ip));
        if !ctx.is_empty() {
            writeln!(prompt, "\n## Current Operation State\n\n{ctx}").unwrap();
        }
    }

    writeln!(
        prompt,
        "\nCall `task_complete` with your findings when done."
    )
    .unwrap();

    prompt
}

fn generate_crack_prompt(task_id: &str, payload: &Value) -> String {
    let hash_type = payload["hash_type"].as_str().unwrap_or("unknown");
    let hash_value = payload["hash_value"].as_str().unwrap_or("");
    let username = payload["username"].as_str().unwrap_or("");
    let domain = payload["domain"].as_str().unwrap_or("");

    let mut prompt = format!(
        "## Crack Task: {task_id}\n\n\
         **Hash Type:** {hash_type}\n\
         **Hash:** {hash_value}\n"
    );

    if !username.is_empty() {
        writeln!(prompt, "**Username:** {username}").unwrap();
    }
    if !domain.is_empty() {
        writeln!(prompt, "**Domain:** {domain}").unwrap();
    }

    writeln!(
        prompt,
        "\nCrack this hash using hashcat or john. Try rockyou.txt first, then rules."
    )
    .unwrap();
    writeln!(
        prompt,
        "Call `task_complete` with the cracked password or report failure."
    )
    .unwrap();

    prompt
}

fn generate_credential_access_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> String {
    let technique = payload["technique"].as_str().unwrap_or("secretsdump");
    let target_ip = payload["target_ip"].as_str().unwrap_or("unknown");
    let domain = payload["domain"].as_str().unwrap_or("");

    let mut prompt = format!(
        "## Credential Access Task: {task_id}\n\n\
         **Technique:** {technique}\n\
         **Target:** {target_ip}\n"
    );

    if !domain.is_empty() {
        writeln!(prompt, "**Domain:** {domain}").unwrap();
    }

    if let Some(cred) = payload.get("credential") {
        let user = cred["username"].as_str().unwrap_or("");
        let cred_domain = cred["domain"].as_str().unwrap_or("");
        let has_password = cred
            .get("password")
            .and_then(|v| v.as_str())
            .is_some_and(|p| !p.is_empty());
        if !user.is_empty() {
            let auth_type = if has_password {
                "password"
            } else {
                "hash/ticket"
            };
            writeln!(prompt, "**Credential:** {user}@{cred_domain} ({auth_type})").unwrap();
        }
    }

    writeln!(
        prompt,
        "\nExecute the {technique} attack against the target."
    )
    .unwrap();

    if let Some(s) = state {
        let ctx = format_state_context(s, "credential_access", Some(target_ip));
        if !ctx.is_empty() {
            writeln!(prompt, "\n## Current Operation State\n\n{ctx}").unwrap();
        }
    }

    writeln!(
        prompt,
        "Call `task_complete` with extracted credentials/hashes."
    )
    .unwrap();

    prompt
}

fn generate_lateral_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> String {
    let technique = payload["technique"].as_str().unwrap_or("psexec");
    let target_ip = payload["target_ip"].as_str().unwrap_or("unknown");

    let mut prompt = format!(
        "## Lateral Movement Task: {task_id}\n\n\
         **Technique:** {technique}\n\
         **Target:** {target_ip}\n"
    );

    if let Some(cred) = payload.get("credential") {
        let user = cred["username"].as_str().unwrap_or("");
        let cred_domain = cred["domain"].as_str().unwrap_or("");
        if !user.is_empty() {
            writeln!(prompt, "**Credential:** {user}@{cred_domain}").unwrap();
        }
    }

    writeln!(prompt, "\nMove laterally to the target using {technique}.").unwrap();

    if let Some(s) = state {
        let ctx = format_state_context(s, "lateral", Some(target_ip));
        if !ctx.is_empty() {
            writeln!(prompt, "\n## Current Operation State\n\n{ctx}").unwrap();
        }
    }

    writeln!(
        prompt,
        "Call `task_complete` when lateral movement succeeds or fails."
    )
    .unwrap();

    prompt
}

fn generate_exploit_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> String {
    let vuln_type = payload["vuln_type"].as_str().unwrap_or("unknown");
    let target = payload["target"].as_str().unwrap_or("unknown");

    let mut prompt = format!(
        "## Exploit Task: {task_id}\n\n\
         **Vulnerability:** {vuln_type}\n\
         **Target:** {target}\n"
    );

    if let Some(details) = payload.get("details") {
        if let Some(obj) = details.as_object() {
            writeln!(prompt, "\n**Details:**").unwrap();
            for (k, v) in obj {
                writeln!(prompt, "- {k}: {v}").unwrap();
            }
        }
    }

    writeln!(prompt, "\nExploit this vulnerability on the target.").unwrap();

    if let Some(s) = state {
        let ctx = format_state_context(s, "exploit", Some(target));
        if !ctx.is_empty() {
            writeln!(prompt, "\n## Current Operation State\n\n{ctx}").unwrap();
        }
    }

    writeln!(prompt, "Call `task_complete` with the exploitation result.").unwrap();

    prompt
}

fn generate_coercion_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> String {
    let target_ip = payload["target_ip"].as_str().unwrap_or("unknown");
    let listener_ip = payload["listener_ip"].as_str().unwrap_or("");
    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let mut prompt = format!(
        "## Coercion Task: {task_id}\n\n\
         **Target:** {target_ip}\n\
         **Listener:** {listener_ip}\n"
    );

    if !techniques.is_empty() {
        writeln!(prompt, "\n**Techniques:**").unwrap();
        for t in &techniques {
            writeln!(prompt, "- {t}").unwrap();
        }
    }

    writeln!(
        prompt,
        "\nAttempt to coerce authentication from the target to the listener."
    )
    .unwrap();

    if let Some(s) = state {
        let ctx = format_state_context(s, "coercion", Some(target_ip));
        if !ctx.is_empty() {
            writeln!(prompt, "\n## Current Operation State\n\n{ctx}").unwrap();
        }
    }

    writeln!(
        prompt,
        "Call `task_complete` when coercion attempt finishes."
    )
    .unwrap();

    prompt
}

fn generate_privesc_enumeration_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> String {
    let technique = payload["technique"].as_str().unwrap_or("enumeration");
    let target_ip = payload["target_ip"].as_str().unwrap_or("unknown");
    let domain = payload["domain"].as_str().unwrap_or("");

    let mut prompt = format!(
        "## Privilege Escalation Enumeration: {task_id}\n\n\
         **Technique:** {technique}\n\
         **Target:** {target_ip}\n"
    );

    if !domain.is_empty() {
        writeln!(prompt, "**Domain:** {domain}").unwrap();
    }

    if let Some(cred) = payload.get("credential") {
        let user = cred["username"].as_str().unwrap_or("");
        let cred_domain = cred["domain"].as_str().unwrap_or("");
        if !user.is_empty() {
            writeln!(prompt, "**Credential:** {user}@{cred_domain}").unwrap();
        }
    }

    writeln!(
        prompt,
        "\nEnumerate privilege escalation opportunities using {technique}."
    )
    .unwrap();

    if let Some(s) = state {
        let ctx = format_state_context(s, "privesc_enumeration", Some(target_ip));
        if !ctx.is_empty() {
            writeln!(prompt, "\n## Current Operation State\n\n{ctx}").unwrap();
        }
    }

    writeln!(
        prompt,
        "Call `task_complete` with discovered escalation paths."
    )
    .unwrap();

    prompt
}

fn generate_acl_analysis_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> String {
    let mut prompt = format!("## ACL Analysis Task: {task_id}\n\n");

    if let Some(chain) = payload.get("chain") {
        writeln!(prompt, "**ACL Chain to Analyze:**").unwrap();
        writeln!(prompt, "```json").unwrap();
        writeln!(
            prompt,
            "{}",
            serde_json::to_string_pretty(chain).unwrap_or_default()
        )
        .unwrap();
        writeln!(prompt, "```").unwrap();
    }

    writeln!(
        prompt,
        "\nAnalyze and execute this ACL abuse chain step by step."
    )
    .unwrap();

    if let Some(s) = state {
        let ctx = format_state_context(s, "acl_analysis", None);
        if !ctx.is_empty() {
            writeln!(prompt, "\n## Current Operation State\n\n{ctx}").unwrap();
        }
    }

    writeln!(
        prompt,
        "Call `task_complete` when the ACL chain has been exploited or fails."
    )
    .unwrap();

    prompt
}

fn generate_command_prompt(task_id: &str, payload: &Value) -> String {
    let command = payload["command"].as_str().unwrap_or("unknown");

    format!(
        "## Command Task: {task_id}\n\n\
         Execute the following command:\n\n\
         ```\n{command}\n```\n\n\
         Call `task_complete` with the command output."
    )
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
        assert!(prompt.contains("nmap_scan"));
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
        assert!(prompt.contains("admin@contoso.local"));
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
    fn test_command_prompt() {
        let payload = serde_json::json!({"command": "whoami"});
        let prompt = generate_task_prompt("command", "task-006", &payload, None).unwrap();
        assert!(prompt.contains("whoami"));
    }
}
