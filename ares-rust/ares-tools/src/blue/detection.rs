//! Pre-built detection query templates for AD attack techniques.
//!
//! Maps MITRE ATT&CK techniques to LogQL queries for common attacks.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::loki;

/// Run a pre-built detection query template.
pub async fn run_detection_query(args: &Value) -> Result<ToolOutput> {
    let query_name = required_str(args, "query_name")?;
    let target_host = optional_str(args, "target_host");
    let hours_back = optional_i64(args, "hours_back").unwrap_or(24);

    let (logql, description) = match build_detection_query(query_name, target_host) {
        Some(q) => q,
        None => {
            return Ok(ToolOutput {
                stdout: String::new(),
                stderr: format!("Unknown detection template: {query_name}. Use list_detection_templates to see available templates."),
                exit_code: Some(1),
                success: false,
            });
        }
    };

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    let query_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 200,
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!("## {description}\nQuery: `{logql}`\n\n{}", result.stdout);
    Ok(result)
}

/// Run multiple detection queries in parallel.
pub async fn run_parallel_detections(args: &Value) -> Result<ToolOutput> {
    let query_names = args
        .get("query_names")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let target_host = optional_str(args, "target_host");
    let hours_back = optional_i64(args, "hours_back").unwrap_or(24);

    let mut handles = Vec::new();
    for name in query_names {
        let host = target_host.map(|s| s.to_string());
        handles.push(tokio::spawn(async move {
            let query_args = serde_json::json!({
                "query_name": name,
                "target_host": host,
                "hours_back": hours_back,
            });
            let result = run_detection_query(&query_args).await;
            (name, result)
        }));
    }

    let mut output_parts = Vec::new();
    for handle in handles {
        match handle.await {
            Ok((name, Ok(output))) => {
                if output.success {
                    output_parts.push(output.stdout);
                } else {
                    output_parts.push(format!("### {name}\nError: {}", output.stderr));
                }
            }
            Ok((name, Err(e))) => {
                output_parts.push(format!("### {name}\nError: {e}"));
            }
            Err(e) => {
                output_parts.push(format!("### Query failed\nError: {e}"));
            }
        }
    }

    Ok(ToolOutput {
        stdout: output_parts.join("\n\n---\n\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// List all available detection templates.
pub async fn list_detection_templates(_args: &Value) -> Result<ToolOutput> {
    let templates = vec![
        (
            "detect_kerberoasting",
            "T1558.003 - Kerberos TGS ticket requests for service accounts",
        ),
        (
            "detect_asrep_roasting",
            "T1558.004 - AS-REP roasting against accounts without pre-auth",
        ),
        (
            "detect_password_spray",
            "T1110.003 - Password spray attempts across multiple accounts",
        ),
        (
            "detect_secretsdump",
            "T1003.003 - Credential dumping via DCSync/secretsdump",
        ),
        (
            "detect_lateral_movement",
            "T1021 - Lateral movement via SMB, WMI, WinRM, RDP, PsExec",
        ),
        (
            "detect_dcsync",
            "T1003.006 - DCSync replication requests from non-DC sources",
        ),
        (
            "detect_golden_ticket",
            "T1558.001 - Forged Kerberos golden ticket usage",
        ),
        (
            "detect_pass_the_hash",
            "T1550.002 - NTLM authentication with hash-based logons",
        ),
        (
            "detect_brute_force",
            "T1110.001 - Brute force login attempts",
        ),
        (
            "detect_account_enumeration",
            "T1087 - Active Directory account enumeration",
        ),
        (
            "detect_share_enumeration",
            "T1135 - SMB share enumeration activity",
        ),
        (
            "detect_port_scanning",
            "T1046 - Network port scanning activity",
        ),
        (
            "detect_service_creation",
            "T1543.003 - Suspicious service creation (PsExec, etc.)",
        ),
        (
            "detect_scheduled_task",
            "T1053.005 - Suspicious scheduled task creation",
        ),
        ("detect_ntlm_relay", "T1557 - NTLM relay attack indicators"),
        (
            "detect_certificate_abuse",
            "T1649 - ADCS certificate template abuse",
        ),
        (
            "detect_delegation_abuse",
            "T1134 - Kerberos delegation exploitation",
        ),
        (
            "detect_bloodhound",
            "T1069/T1087 - BloodHound/SharpHound data collection",
        ),
    ];

    let formatted: Vec<String> = templates
        .iter()
        .map(|(name, desc)| format!("- **{name}**: {desc}"))
        .collect();

    Ok(ToolOutput {
        stdout: format!(
            "Available detection templates ({}):\n\n{}",
            templates.len(),
            formatted.join("\n")
        ),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Build a LogQL query from a detection template name.
fn build_detection_query(name: &str, target_host: Option<&str>) -> Option<(String, String)> {
    let selector = match target_host {
        Some(host) => format!("{{hostname=\"{host}\"}}"),
        None => "{job=\"windows\"}".to_string(),
    };

    let (query, desc) = match name {
        "detect_kerberoasting" => (
            format!("{selector} |= \"4769\" |~ \"0x17|0x12\" |~ \"Ticket Encryption Type\""),
            "Kerberoasting Detection (Event 4769 with RC4/AES encryption)".to_string(),
        ),
        "detect_asrep_roasting" => (
            format!("{selector} |= \"4768\" |~ \"0x17\" |~ \"Pre-Authentication Type.*0\""),
            "AS-REP Roasting Detection (Event 4768 without pre-auth)".to_string(),
        ),
        "detect_password_spray" => (
            format!("{selector} |= \"4625\" |~ \"Status.*0xC000006A|0xC0000064\""),
            "Password Spray Detection (Multiple Event 4625 failures)".to_string(),
        ),
        "detect_secretsdump" => (
            format!("{selector} |= \"4662\" |~ \"Replicating Directory Changes\""),
            "Secretsdump/DCSync Detection (Event 4662 replication)".to_string(),
        ),
        "detect_lateral_movement" => (
            format!("{selector} |= \"4624\" |~ \"Logon Type.*(3|10)\" |~ \"Logon Process.*(NtLmSsp|seclogo)\""),
            "Lateral Movement Detection (Event 4624 Type 3/10 logons)".to_string(),
        ),
        "detect_dcsync" => (
            format!("{selector} |= \"4662\" |~ \"1131f6ad|1131f6aa|89e95b76\""),
            "DCSync Detection (Replication rights GUIDs in Event 4662)".to_string(),
        ),
        "detect_golden_ticket" => (
            format!("{selector} |= \"4769\" |~ \"krbtgt\" |~ \"0x17\""),
            "Golden Ticket Detection (krbtgt service ticket with RC4)".to_string(),
        ),
        "detect_pass_the_hash" => (
            format!("{selector} |= \"4624\" |~ \"Logon Type.*9|Logon Process.*seclogo\" |~ \"NTLM\""),
            "Pass-the-Hash Detection (Event 4624 Type 9 NTLM logons)".to_string(),
        ),
        "detect_brute_force" => (
            format!("{selector} |= \"4625\""),
            "Brute Force Detection (Event 4625 failed logons)".to_string(),
        ),
        "detect_account_enumeration" => (
            format!("{selector} |~ \"4661|4662|4799\" |~ \"SAM_|Domain (Users|Admins)\""),
            "Account Enumeration Detection (SAM/Domain group queries)".to_string(),
        ),
        "detect_share_enumeration" => (
            format!("{selector} |= \"5140\" |~ \"ShareName.*\\$\""),
            "Share Enumeration Detection (Event 5140 share access)".to_string(),
        ),
        "detect_port_scanning" => (
            format!("{selector} |~ \"nmap|masscan|SYN scan\""),
            "Port Scanning Detection (nmap/masscan patterns)".to_string(),
        ),
        "detect_service_creation" => (
            format!("{selector} |= \"7045\" |~ \"PSEXE|BTOBTO|cmd\\.exe|powershell\""),
            "Service Creation Detection (Event 7045 suspicious services)".to_string(),
        ),
        "detect_scheduled_task" => (
            format!("{selector} |= \"4698\" |~ \"cmd\\.exe|powershell|mshta\""),
            "Scheduled Task Detection (Event 4698 suspicious tasks)".to_string(),
        ),
        "detect_ntlm_relay" => (
            format!("{selector} |~ \"4624|4625\" |~ \"NTLM\" |~ \"Workstation.*LOCALHOST|127\\.0\\.0\\.1\""),
            "NTLM Relay Detection (local NTLM authentication patterns)".to_string(),
        ),
        "detect_certificate_abuse" => (
            format!("{selector} |~ \"4886|4887|4888\" |~ \"Certificate (Services|Request)\""),
            "Certificate Abuse Detection (ADCS Events 4886-4888)".to_string(),
        ),
        "detect_delegation_abuse" => (
            format!("{selector} |= \"4769\" |~ \"constrained|S4U\""),
            "Delegation Abuse Detection (S4U/constrained delegation requests)".to_string(),
        ),
        "detect_bloodhound" => (
            format!("{selector} |~ \"4662|5145\" |~ \"LDAP|objectCategory|objectClass\""),
            "BloodHound Detection (LDAP enumeration patterns)".to_string(),
        ),
        _ => return None,
    };

    Some((query, desc))
}
