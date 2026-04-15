//! MITRE ATT&CK learning tools for blue team agents.
//!
//! Provides offline lookup of MITRE ATT&CK techniques and evidence-based
//! technique suggestions without requiring external API calls.

use std::collections::HashMap;

use anyhow::Result;
use serde_json::Value;
use std::sync::LazyLock;

use crate::args::required_str;
use crate::ToolOutput;

// ---------------------------------------------------------------------------
// Technique database
// ---------------------------------------------------------------------------

struct Technique {
    name: &'static str,
    description: &'static str,
    tactics: &'static [&'static str],
    detection: &'static str,
}

static TECHNIQUES: LazyLock<HashMap<&'static str, Technique>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    m.insert("T1003", Technique {
        name: "OS Credential Dumping",
        description: "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.",
        tactics: &["Credential Access"],
        detection: "Monitor for unexpected processes accessing LSASS (Event 10), SAM registry hive access, and NTDS.dit access. Look for Event 4662 with replication rights GUIDs.",
    });

    m.insert("T1003.001", Technique {
        name: "LSASS Memory",
        description: "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). LSASS stores credentials of logged-in users including plaintext passwords, NTLM hashes, and Kerberos tickets.",
        tactics: &["Credential Access"],
        detection: "Monitor for processes opening LSASS (Event 10 with TargetImage lsass.exe). Watch for tools like mimikatz, procdump, or comsvcs.dll MiniDump. Enable Credential Guard where possible.",
    });

    m.insert("T1003.003", Technique {
        name: "NTDS",
        description: "Adversaries may attempt to access or create a copy of the Active Directory domain database (NTDS.dit) to steal credential information. The NTDS.dit contains password hashes for all domain users and computers.",
        tactics: &["Credential Access"],
        detection: "Monitor for Volume Shadow Copy creation (Event 7036 for VSS service), ntdsutil.exe execution, and access to NTDS.dit file. Watch for secretsdump-style DCSync operations via Event 4662.",
    });

    m.insert("T1003.006", Technique {
        name: "DCSync",
        description: "Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's replication API (MS-DRSR). This requires Replicating Directory Changes permissions.",
        tactics: &["Credential Access"],
        detection: "Monitor Event 4662 for DS-Replication-Get-Changes (GUID 1131f6ad-...) and DS-Replication-Get-Changes-All (GUID 1131f6aa-...) from non-DC sources. Alert on replication requests from workstations.",
    });

    m.insert("T1059", Technique {
        name: "Command and Scripting Interpreter",
        description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces provide ways of interacting with computer systems and are often used for administration and automation.",
        tactics: &["Execution"],
        detection: "Monitor process creation (Event 4688) for cmd.exe, powershell.exe, wscript.exe, cscript.exe, and mshta.exe. Implement Script Block Logging (Event 4104) for PowerShell.",
    });

    m.insert("T1059.001", Technique {
        name: "PowerShell",
        description: "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.",
        tactics: &["Execution"],
        detection: "Enable PowerShell Script Block Logging (Event 4104), Module Logging (Event 4103), and Transcription. Monitor for encoded commands (-enc), download cradles (IEX/Invoke-Expression), and AMSI bypass attempts.",
    });

    m.insert("T1078", Technique {
        name: "Valid Accounts",
        description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        tactics: &["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        detection: "Monitor logon events (Event 4624/4625) for anomalous patterns: unusual times, source IPs, or logon types. Correlate with account creation (Event 4720) and group modification (Event 4728/4732).",
    });

    m.insert("T1078.002", Technique {
        name: "Domain Accounts",
        description: "Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are managed by Active Directory.",
        tactics: &["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        detection: "Monitor for domain logons (Event 4624 Type 3/10) from unusual sources. Track privileged account usage across the domain. Alert on service account interactive logons and admin account use from non-admin workstations.",
    });

    m.insert("T1021", Technique {
        name: "Remote Services",
        description: "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as RDP, SSH, SMB, WinRM, or VNC.",
        tactics: &["Lateral Movement"],
        detection: "Monitor for network logon events (Event 4624 Type 3/10), especially from unusual sources. Track RDP connections (Event 1149), SMB share access (Event 5140/5145), and WinRM sessions.",
    });

    m.insert("T1021.001", Technique {
        name: "Remote Desktop Protocol",
        description: "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). An adversary may use RDP to access systems for lateral movement.",
        tactics: &["Lateral Movement"],
        detection: "Monitor for RDP connections via Event 4624 (Type 10), Event 1149 (TerminalServices-RemoteConnectionManager), and Event 21/22 (TerminalServices-LocalSessionManager). Track unusual source IPs for RDP sessions.",
    });

    m.insert("T1021.002", Technique {
        name: "SMB/Windows Admin Shares",
        description: "Adversaries may use Valid Accounts to interact with a remote network share using SMB. They may access admin shares (C$, ADMIN$, IPC$) or user-created shares for lateral movement and data staging.",
        tactics: &["Lateral Movement"],
        detection: "Monitor for SMB share access (Event 5140/5145) especially to ADMIN$, C$, and IPC$ shares. Track network logons (Event 4624 Type 3) correlated with share access. Watch for PsExec service creation (Event 7045).",
    });

    m.insert("T1069", Technique {
        name: "Permission Groups Discovery",
        description: "Adversaries may attempt to find group and permission settings for local and domain accounts. This information can help adversaries determine which accounts have elevated privileges.",
        tactics: &["Discovery"],
        detection: "Monitor for LDAP queries targeting group objects (objectClass=group). Watch for net.exe group enumeration commands. Track Event 4661 (SAM object access) and Event 4799 (security-enabled group membership enumeration).",
    });

    m.insert("T1087", Technique {
        name: "Account Discovery",
        description: "Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.",
        tactics: &["Discovery"],
        detection: "Monitor for LDAP queries enumerating user objects. Watch for net.exe user/group commands, BloodHound/SharpHound execution, and bulk SAM queries (Event 4661). Track unusual volumes of directory service queries.",
    });

    m.insert("T1558", Technique {
        name: "Steal or Forge Kerberos Tickets",
        description: "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket, Golden Ticket, or Silver Ticket attacks.",
        tactics: &["Credential Access"],
        detection: "Monitor Kerberos ticket requests (Event 4768/4769) for anomalies: RC4 encryption (Type 0x17) when AES is expected, unusual service ticket requests, and tickets with abnormal lifetimes. Watch for TGT requests without prior AS-REQ.",
    });

    m.insert("T1558.001", Technique {
        name: "Golden Ticket",
        description: "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT). Golden tickets enable adversaries to generate authentication material for any account in Active Directory.",
        tactics: &["Credential Access"],
        detection: "Monitor for TGS requests (Event 4769) that reference the krbtgt service with RC4 encryption. Look for tickets with unusually long lifetimes or issued by non-existent accounts. Compare TGT encrypted timestamps against DC records.",
    });

    m.insert("T1558.003", Technique {
        name: "Kerberoasting",
        description: "Adversaries may abuse a valid Kerberos TGT or sniff network traffic to obtain a TGS ticket that may be vulnerable to brute force. Service accounts with SPNs are targeted for offline password cracking.",
        tactics: &["Credential Access"],
        detection: "Monitor Event 4769 for TGS requests with RC4 encryption (Type 0x17) targeting service accounts with SPNs. Alert on bulk TGS requests from a single source in a short time window. Correlate with service account password age.",
    });

    m.insert("T1046", Technique {
        name: "Network Service Discovery",
        description: "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote exploitation.",
        tactics: &["Discovery"],
        detection: "Monitor for network connection attempts to many ports on remote hosts. Detect nmap/masscan patterns in network traffic. Watch for unusual volumes of failed connection attempts (firewall logs) from a single source.",
    });

    m.insert("T1098", Technique {
        name: "Account Manipulation",
        description: "Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of modifying credentials, permissions, or adding new accounts to maintain persistence.",
        tactics: &["Persistence", "Privilege Escalation"],
        detection: "Monitor for account modification events: Event 4738 (user account changed), Event 4728/4732 (member added to security group), Event 4720 (account created). Watch for SPN modification on user accounts and delegation flag changes.",
    });

    m.insert("T1110", Technique {
        name: "Brute Force",
        description: "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. This includes password spraying, credential stuffing, and online brute force.",
        tactics: &["Credential Access"],
        detection: "Monitor Event 4625 (failed logon) for high volumes from a single source or targeting a single account. Track lockout events (Event 4740). Correlate failed logons followed by successful logon (Event 4624) for the same account.",
    });

    m.insert("T1110.003", Technique {
        name: "Password Spraying",
        description: "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid credentials. This avoids account lockouts from brute forcing a single account.",
        tactics: &["Credential Access"],
        detection: "Monitor for Event 4625 with Status 0xC000006A (wrong password) across many accounts from few source IPs in a short time window. Alert when failed logon count exceeds threshold across distinct accounts.",
    });

    m.insert("T1136", Technique {
        name: "Create Account",
        description: "Adversaries may create an account to maintain access to victim systems. Accounts may be created on the local system, within a domain, or within cloud environments.",
        tactics: &["Persistence"],
        detection: "Monitor for account creation events: Event 4720 (local/domain account created). Watch for accounts created outside normal provisioning processes. Alert on accounts added to privileged groups (Event 4728/4732) immediately after creation.",
    });

    m.insert("T1543", Technique {
        name: "Create or Modify System Process",
        description: "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. System processes such as Windows services are common targets.",
        tactics: &["Persistence", "Privilege Escalation"],
        detection: "Monitor Event 7045 (new service installed) for suspicious service names, paths, or execution patterns. Watch for sc.exe and service-related registry modifications. Track services running as SYSTEM with unusual binaries.",
    });

    m.insert("T1543.003", Technique {
        name: "Windows Service",
        description: "Adversaries may create or modify Windows services to repeatedly execute malicious payloads. Windows service configuration information is stored in the Registry. Adversaries may install new services or modify existing ones.",
        tactics: &["Persistence", "Privilege Escalation"],
        detection: "Monitor Event 7045 for new service installations with suspicious characteristics: services named PSEXESVC/BTOBTO, services with cmd.exe/powershell.exe in the binary path, and services with random names. Track service configuration changes in the registry.",
    });

    m.insert("T1547", Technique {
        name: "Boot or Logon Autostart Execution",
        description: "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems.",
        tactics: &["Persistence", "Privilege Escalation"],
        detection: "Monitor Run/RunOnce registry keys for modifications. Watch for scheduled tasks (Event 4698), startup folder changes, and WMI event subscription creation. Track Group Policy modifications that could enable autostart execution.",
    });

    m.insert("T1550", Technique {
        name: "Use Alternate Authentication Material",
        description: "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.",
        tactics: &["Defense Evasion", "Lateral Movement"],
        detection: "Monitor for Event 4624 with unusual authentication packages. Watch for NTLM Type 3 logons (pass-the-hash), Kerberos ticket anomalies (pass-the-ticket), and token impersonation patterns. Correlate authentication events across systems.",
    });

    m.insert("T1550.002", Technique {
        name: "Pass the Hash",
        description: "Adversaries may authenticate to systems using stolen password hashes rather than plaintext passwords. Pass the Hash allows lateral movement without needing to crack the hash for a cleartext password.",
        tactics: &["Defense Evasion", "Lateral Movement"],
        detection: "Monitor for Event 4624 with LogonType 9 (NewCredentials) and NtLmSsp authentication package. Watch for NTLM authentication where the workstation name does not match the source. Detect tools like mimikatz sekurlsa::pth.",
    });

    m.insert("T1552", Technique {
        name: "Unsecured Credentials",
        description: "Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored in many locations including plaintext files, registries, and Group Policy Preferences.",
        tactics: &["Credential Access"],
        detection: "Monitor for access to known credential storage locations: Group Policy Preferences XML files, unattend.xml, web.config files, and credential manager stores. Watch for findstr/grep commands searching for password patterns.",
    });

    m.insert("T1562", Technique {
        name: "Impair Defenses",
        description: "Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms. This includes disabling security tools, modifying firewall rules, and clearing logs.",
        tactics: &["Defense Evasion"],
        detection: "Monitor for security tool process termination, Windows Defender exclusion additions, audit policy changes (Event 4719), and log clearing events (Event 1102/104). Watch for firewall rule modifications and tamper protection disabling.",
    });

    m.insert("T1570", Technique {
        name: "Lateral Tool Transfer",
        description: "Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied between internal systems to stage adversary tools or other files over the course of an operation.",
        tactics: &["Lateral Movement"],
        detection: "Monitor for file transfers via SMB (Event 5145 with write access), administrative share access (ADMIN$, C$), and PsExec-style service installations. Watch for unusual binaries appearing in TEMP or Windows directories on multiple systems.",
    });

    m.insert("T1053", Technique {
        name: "Scheduled Task/Job",
        description: "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Scheduled tasks can be created remotely for lateral movement.",
        tactics: &["Execution", "Persistence", "Privilege Escalation"],
        detection: "Monitor Event 4698 (scheduled task created) for suspicious task actions. Watch for schtasks.exe and at.exe usage. Track remote task creation via RPC. Alert on tasks executing from unusual paths or with SYSTEM privileges.",
    });

    m.insert("T1053.005", Technique {
        name: "Scheduled Task",
        description: "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. The schtasks utility can be used to create, delete, query, and modify scheduled tasks.",
        tactics: &["Execution", "Persistence", "Privilege Escalation"],
        detection: "Monitor Event 4698 for task creation with cmd.exe, powershell.exe, mshta.exe, or rundll32.exe in the action. Watch for remote task creation and tasks with one-time triggers executing immediately.",
    });

    m.insert("T1557", Technique {
        name: "Adversary-in-the-Middle",
        description: "Adversaries may attempt to position themselves between two or more networked devices to support follow-on behaviors such as network sniffing or credential access via LLMNR/NBT-NS poisoning.",
        tactics: &["Credential Access", "Collection"],
        detection: "Monitor for LLMNR (UDP 5355) and NBT-NS (UDP 137) traffic. Watch for ARP spoofing patterns. Detect Responder/mitm6 activity via WPAD broadcast responses. Track NTLM authentication to suspicious destinations.",
    });

    m.insert("T1135", Technique {
        name: "Network Share Discovery",
        description: "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor to Collection and to identify potential systems of interest for Lateral Movement.",
        tactics: &["Discovery"],
        detection: "Monitor for net.exe share/view commands and SMB tree connect requests. Watch for bulk share enumeration from a single source. Track Event 5140 (share access) patterns across many remote hosts.",
    });

    m.insert("T1134", Technique {
        name: "Access Token Manipulation",
        description: "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Kerberos delegation abuse falls under this technique.",
        tactics: &["Defense Evasion", "Privilege Escalation"],
        detection: "Monitor for token manipulation via Event 4624 (impersonation logons), Event 4672 (special privileges assigned), and S4U2Self/S4U2Proxy Kerberos extensions. Watch for constrained delegation abuse patterns.",
    });

    m.insert("T1649", Technique {
        name: "Steal or Forge Authentication Certificates",
        description: "Adversaries may steal or forge certificates used for authentication to access remote systems or resources. ADCS misconfigurations can allow certificate template abuse for privilege escalation.",
        tactics: &["Credential Access"],
        detection: "Monitor ADCS certificate enrollment events (Event 4886/4887). Watch for certificate requests from unusual accounts or for templates allowing client authentication. Track certipy/Certify tool usage.",
    });

    m.insert("T1558.004", Technique {
        name: "AS-REP Roasting",
        description: "Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by sending AS-REQ messages to the KDC. The response contains an encrypted portion that can be cracked offline.",
        tactics: &["Credential Access"],
        detection: "Monitor Event 4768 for AS-REQ requests with pre-authentication type 0 (disabled). Watch for bulk AS-REQ requests targeting multiple accounts. Audit accounts with DONT_REQUIRE_PREAUTH flag set.",
    });

    m.insert("T1021.006", Technique {
        name: "Windows Remote Management",
        description: "Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). WinRM allows remote execution of commands and PowerShell sessions.",
        tactics: &["Lateral Movement"],
        detection: "Monitor for WinRM connections via Event 4624 and WinRM operational logs (Event 6/8/15/16 in Microsoft-Windows-WinRM/Operational). Track unusual source hosts initiating WinRM sessions. Watch for WSMan shell creation events.",
    });

    m.insert("T1021.003", Technique {
        name: "Distributed Component Object Model",
        description: "Adversaries may use DCOM to move laterally. DCOM allows remote code execution through various COM objects that can be abused for lateral movement.",
        tactics: &["Lateral Movement"],
        detection: "Monitor for DCOM-related network connections (Event 4624 with specific authentication packages). Watch for unusual COM object instantiation across the network and mmc.exe/excel.exe spawning child processes remotely.",
    });

    m.insert("T1047", Technique {
        name: "Windows Management Instrumentation",
        description: "Adversaries may abuse WMI to execute malicious commands and payloads. WMI provides a uniform environment for local and remote access to Windows system components.",
        tactics: &["Execution"],
        detection: "Monitor for WMI process creation (wmiprvse.exe spawning child processes). Watch for wmic.exe command-line execution, WMI event subscriptions (Event 5857-5861), and remote WMI connections (Event 4624 with WMI-related logon processes).",
    });

    m
});

// ---------------------------------------------------------------------------
// Evidence type to technique mapping
// ---------------------------------------------------------------------------

static EVIDENCE_MAP: LazyLock<HashMap<&'static str, Vec<&'static str>>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    m.insert(
        "credential_access",
        vec![
            "T1003",
            "T1003.001",
            "T1003.003",
            "T1003.006",
            "T1558",
            "T1558.001",
            "T1558.003",
            "T1558.004",
            "T1110",
            "T1110.003",
            "T1552",
            "T1557",
            "T1649",
        ],
    );

    m.insert(
        "lateral_movement",
        vec![
            "T1021",
            "T1021.001",
            "T1021.002",
            "T1021.003",
            "T1021.006",
            "T1550",
            "T1550.002",
            "T1570",
            "T1047",
        ],
    );

    m.insert(
        "persistence",
        vec![
            "T1078",
            "T1078.002",
            "T1098",
            "T1136",
            "T1543",
            "T1543.003",
            "T1547",
            "T1053",
            "T1053.005",
        ],
    );

    m.insert("discovery", vec!["T1046", "T1069", "T1087", "T1135"]);

    m.insert(
        "execution",
        vec!["T1059", "T1059.001", "T1047", "T1053", "T1053.005"],
    );

    m.insert(
        "privilege_escalation",
        vec![
            "T1078",
            "T1078.002",
            "T1098",
            "T1134",
            "T1543",
            "T1543.003",
            "T1547",
            "T1649",
        ],
    );

    m.insert(
        "defense_evasion",
        vec!["T1078", "T1078.002", "T1134", "T1550", "T1550.002", "T1562"],
    );

    m.insert(
        "kerberos",
        vec![
            "T1558",
            "T1558.001",
            "T1558.003",
            "T1558.004",
            "T1550",
            "T1134",
        ],
    );

    m.insert("brute_force", vec!["T1110", "T1110.003"]);

    m.insert("pass_the_hash", vec!["T1550", "T1550.002"]);

    m.insert("dcsync", vec!["T1003.006"]);

    m.insert("golden_ticket", vec!["T1558.001"]);

    m.insert("service_creation", vec!["T1543", "T1543.003"]);

    m.insert("certificate_abuse", vec!["T1649"]);

    m
});

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

/// Look up a MITRE ATT&CK technique by ID.
///
/// Returns the technique name, description, associated tactics, and
/// detection recommendations from a built-in database of ~50 common
/// AD/Windows techniques.
pub fn lookup_technique(args: &Value) -> Result<ToolOutput> {
    let technique_id = required_str(args, "technique_id")?;

    // Normalize: uppercase the T prefix if needed
    let normalized = if technique_id.starts_with('t') || technique_id.starts_with('T') {
        let mut s = technique_id.to_string();
        s.replace_range(0..1, "T");
        s
    } else {
        technique_id.to_string()
    };

    if let Some(tech) = TECHNIQUES.get(normalized.as_str()) {
        let tactics_str = tech.tactics.join(", ");
        let output = format!(
            "## {normalized}: {name}\n\n\
             **Tactics**: {tactics}\n\n\
             **Description**:\n{description}\n\n\
             **Detection Recommendations**:\n{detection}",
            name = tech.name,
            tactics = tactics_str,
            description = tech.description,
            detection = tech.detection,
        );
        Ok(ToolOutput {
            stdout: output,
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        })
    } else {
        // Try parent technique if subtechnique not found
        let parent_id = if normalized.contains('.') {
            normalized.split('.').next().unwrap_or(&normalized)
        } else {
            ""
        };

        if !parent_id.is_empty() {
            if let Some(tech) = TECHNIQUES.get(parent_id) {
                let tactics_str = tech.tactics.join(", ");
                let output = format!(
                    "Subtechnique {normalized} not in database. Showing parent technique:\n\n\
                     ## {parent_id}: {name}\n\n\
                     **Tactics**: {tactics}\n\n\
                     **Description**:\n{description}\n\n\
                     **Detection Recommendations**:\n{detection}",
                    name = tech.name,
                    tactics = tactics_str,
                    description = tech.description,
                    detection = tech.detection,
                );
                return Ok(ToolOutput {
                    stdout: output,
                    stderr: String::new(),
                    exit_code: Some(0),
                    success: true,
                });
            }
        }

        Ok(ToolOutput {
            stdout: String::new(),
            stderr: format!(
                "Technique {normalized} not found in local database. \
                 Available techniques include T1003, T1021, T1046, T1059, T1069, T1078, \
                 T1087, T1098, T1110, T1134, T1135, T1136, T1543, T1547, T1550, T1552, \
                 T1557, T1558, T1562, T1570, T1649 and their subtechniques."
            ),
            exit_code: Some(1),
            success: false,
        })
    }
}

/// Suggest MITRE ATT&CK techniques based on an evidence type.
///
/// Maps high-level evidence categories (e.g., "credential_access",
/// "lateral_movement") to relevant technique IDs with descriptions.
pub fn suggest_techniques(args: &Value) -> Result<ToolOutput> {
    let evidence_type = required_str(args, "evidence_type")?;

    // Normalize: lowercase, replace spaces/hyphens with underscores
    let normalized = evidence_type.to_lowercase().replace([' ', '-'], "_");

    if let Some(technique_ids) = EVIDENCE_MAP.get(normalized.as_str()) {
        let mut lines = Vec::new();
        lines.push(format!("## Techniques relevant to: {evidence_type}\n"));

        for tid in technique_ids {
            if let Some(tech) = TECHNIQUES.get(*tid) {
                lines.push(format!(
                    "- **{tid}** ({name}): {desc}",
                    name = tech.name,
                    desc = truncate_description(tech.description, 150),
                ));
            } else {
                lines.push(format!("- **{tid}**: (details not in local database)"));
            }
        }

        lines.push(String::new());
        lines.push("Use `lookup_technique` with a specific technique ID for full details and detection guidance.".to_string());

        Ok(ToolOutput {
            stdout: lines.join("\n"),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        })
    } else {
        let available: Vec<&&str> = EVIDENCE_MAP.keys().collect();
        let mut sorted = available.clone();
        sorted.sort();
        Ok(ToolOutput {
            stdout: String::new(),
            stderr: format!(
                "Unknown evidence type: {evidence_type}. Available types: {}",
                sorted.iter().map(|s| **s).collect::<Vec<_>>().join(", ")
            ),
            exit_code: Some(1),
            success: false,
        })
    }
}

/// Truncate a description string to a maximum character length, adding "..." if truncated.
fn truncate_description(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let truncated = &s[..s
            .char_indices()
            .take_while(|(i, _)| *i < max_len)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(max_len)];
        format!("{truncated}...")
    }
}

// ---------------------------------------------------------------------------
// Investigation learning tools (backed by persistence store)
// ---------------------------------------------------------------------------

/// Find similar past investigations for learning and guidance.
///
/// Parameters:
/// - `alert_name` (optional)
/// - `technique_id` (optional)
/// - `severity` (optional)
/// - `limit` (optional, default: 5)
pub fn find_similar_investigations(args: &Value) -> Result<ToolOutput> {
    let alert_name = args.get("alert_name").and_then(Value::as_str);
    let technique_id = args.get("technique_id").and_then(Value::as_str);
    let severity = args.get("severity").and_then(Value::as_str);
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(5) as usize;

    if alert_name.is_none() && technique_id.is_none() && severity.is_none() {
        return Ok(ToolOutput {
            stdout: String::new(),
            stderr: "At least one of alert_name, technique_id, or severity is required".into(),
            exit_code: Some(1),
            success: false,
        });
    }

    let store = super::persistence::get_investigation_store();
    let similar = store.find_similar_investigations(
        alert_name,
        None, // fingerprint not available in tool context
        technique_id,
        severity,
        limit,
    );

    if similar.is_empty() {
        return Ok(ToolOutput {
            stdout: "No similar past investigations found.".into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let mut lines = vec![format!(
        "Found {} similar investigation(s):\n",
        similar.len()
    )];

    let completed_count = similar
        .iter()
        .filter(|s| s.investigation.status == "completed")
        .count();
    let tp_count = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive == Some(true))
        .count();
    let fp_count = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive == Some(false))
        .count();

    lines.push(format!(
        "Summary: {completed_count} completed, {tp_count} true positive(s), {fp_count} false positive(s)\n"
    ));

    for (i, sim) in similar.iter().enumerate() {
        let inv = &sim.investigation;
        let tp_label = match inv.is_true_positive {
            Some(true) => " [TRUE POSITIVE]",
            Some(false) => " [FALSE POSITIVE]",
            None => "",
        };

        lines.push(format!(
            "{}. {} (similarity: {:.0}%, matched: {}){tp_label}",
            i + 1,
            inv.alert_name,
            sim.similarity_score * 100.0,
            sim.matching_factors.join(", "),
        ));
        lines.push(format!(
            "   Status: {}, Evidence: {}, Techniques: {}, Duration: {:.0}s",
            inv.status,
            inv.evidence_count,
            inv.techniques_identified.len(),
            inv.duration_seconds,
        ));
        if !inv.effective_queries.is_empty() {
            lines.push(format!(
                "   Effective queries: {}",
                inv.effective_queries.join(", ")
            ));
        }
    }

    // Generate guidance from best completed investigation
    if let Some(best) = similar
        .iter()
        .find(|s| {
            s.investigation.status == "completed" && s.investigation.is_true_positive == Some(true)
        })
        .or_else(|| {
            similar
                .iter()
                .find(|s| s.investigation.status == "completed")
        })
    {
        lines.push(String::new());
        lines.push("**Guidance from best match**:".to_string());
        if !best.investigation.techniques_identified.is_empty() {
            lines.push(format!(
                "- Previously identified techniques: {}",
                best.investigation.techniques_identified.join(", ")
            ));
        }
        if !best.investigation.effective_queries.is_empty() {
            lines.push(format!(
                "- Recommended queries: {}",
                best.investigation.effective_queries.join(", ")
            ));
        }
        lines.push(format!(
            "- Previous query success rate: {:.0}%",
            best.investigation.query_success_rate * 100.0
        ));
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Get effective queries that have historically produced evidence.
///
/// Parameters:
/// - `alert_name` (optional): Filter by alert type
/// - `limit` (optional, default: 10)
pub fn get_effective_queries(args: &Value) -> Result<ToolOutput> {
    let alert_name = args.get("alert_name").and_then(Value::as_str);
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize;

    let store = super::persistence::get_investigation_store();
    let queries = store.get_effective_queries(alert_name, 0.2, limit);

    if queries.is_empty() {
        return Ok(ToolOutput {
            stdout: "No effective queries found yet. Query effectiveness is tracked as investigations are completed.".into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let mut lines = vec![format!(
        "Top {} effective queries (min 3 executions, 20%+ evidence rate):\n",
        queries.len()
    )];

    for (i, q) in queries.iter().enumerate() {
        lines.push(format!(
            "{}. {} — success: {:.0}%, evidence: {:.0}% ({} executions)",
            i + 1,
            q.query_pattern,
            q.success_rate() * 100.0,
            q.evidence_rate() * 100.0,
            q.total_executions,
        ));
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Check if an alert matches known false positive patterns.
///
/// Parameters:
/// - `alert_name` (required)
/// - `alert_fingerprint` (optional)
pub fn check_false_positive_pattern(args: &Value) -> Result<ToolOutput> {
    let alert_name = required_str(args, "alert_name")?;
    let alert_fingerprint = args.get("alert_fingerprint").and_then(Value::as_str);

    let store = super::persistence::get_investigation_store();

    // Find similar investigations to compute FP rate
    let similar =
        store.find_similar_investigations(Some(alert_name), alert_fingerprint, None, None, 20);

    if similar.is_empty() {
        return Ok(ToolOutput {
            stdout: format!(
                "No historical data for alert '{alert_name}'. Cannot assess false positive likelihood."
            ),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let labeled = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive.is_some())
        .count();
    let fp_count = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive == Some(false))
        .count();

    let fp_rate = if labeled > 0 {
        fp_count as f64 / labeled as f64
    } else {
        0.0
    };

    // Check known FP patterns
    let fp_patterns = store.get_false_positive_patterns(2);
    let matching_pattern = fp_patterns
        .iter()
        .find(|p| p.alert_name.to_lowercase() == alert_name.to_lowercase());

    let confidence = if fp_rate > 0.8 {
        "HIGH"
    } else if fp_rate > 0.5 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let mut lines = Vec::new();
    lines.push(format!("False positive assessment for '{alert_name}':"));
    lines.push(format!(
        "  Historical FP rate: {:.0}% ({fp_count}/{labeled} labeled investigations)",
        fp_rate * 100.0
    ));
    lines.push(format!("  Confidence: {confidence}"));
    lines.push(format!("  Total similar investigations: {}", similar.len()));

    if let Some(pattern) = matching_pattern {
        lines.push(format!(
            "  Known FP pattern: {} occurrences, {:.0}% FP rate",
            pattern.occurrences,
            pattern.fp_rate * 100.0
        ));
    }

    if fp_rate > 0.5 {
        lines.push(String::new());
        lines.push(
            "  Recommendation: This alert has a high false positive rate. \
             Consider tuning the detection rule or adding exclusions."
                .to_string(),
        );
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Get aggregate investigation statistics.
pub fn get_investigation_statistics(_args: &Value) -> Result<ToolOutput> {
    let store = super::persistence::get_investigation_store();
    let stats = store.get_statistics();

    if stats.total_investigations == 0 {
        return Ok(ToolOutput {
            stdout: "No investigations recorded yet.".into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let fp_rate = if stats.labeled > 0 {
        stats.false_positives as f64 / stats.labeled as f64
    } else {
        0.0
    };

    let lines = [
        "=== Investigation Statistics ===".to_string(),
        format!("Total investigations: {}", stats.total_investigations),
        format!(
            "  Completed: {}, Escalated: {}, Failed: {}",
            stats.completed, stats.escalated, stats.failed
        ),
        format!(
            "  True positives: {}, False positives: {} ({} labeled, {:.0}% FP rate)",
            stats.true_positives,
            stats.false_positives,
            stats.labeled,
            fp_rate * 100.0
        ),
        format!(
            "  Avg duration: {:.0}s, Avg evidence: {:.1} items",
            stats.avg_duration_seconds, stats.avg_evidence_count
        ),
    ];

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

// ---------------------------------------------------------------------------
// Red team playbook integration
// ---------------------------------------------------------------------------

/// Load a red team operation's state from Redis and generate a detection
/// playbook with prioritized LogQL queries.
///
/// Parameters:
/// - `operation_id` (optional): Specific op ID. If omitted, finds latest.
/// - `redis_url` (optional): Redis URL override.
pub async fn get_attack_playbook(args: &Value) -> anyhow::Result<ToolOutput> {
    let operation_id = args.get("operation_id").and_then(Value::as_str);
    let redis_url = args
        .get("redis_url")
        .and_then(Value::as_str)
        .unwrap_or("redis://127.0.0.1:6379");

    let redis_url = std::env::var("ARES_REDIS_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| redis_url.to_string());

    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            return Ok(ToolOutput {
                stdout: String::new(),
                stderr: format!("Failed to connect to Redis: {e}"),
                exit_code: Some(1),
                success: false,
            })
        }
    };
    let mut conn = match client.get_multiplexed_tokio_connection().await {
        Ok(c) => c,
        Err(e) => {
            return Ok(ToolOutput {
                stdout: String::new(),
                stderr: format!("Redis connection failed: {e}"),
                exit_code: Some(1),
                success: false,
            })
        }
    };

    // Find operation ID
    let op_id = if let Some(id) = operation_id {
        id.to_string()
    } else {
        // Scan for latest operation
        match find_latest_operation(&mut conn).await {
            Some(id) => id,
            None => {
                return Ok(ToolOutput {
                    stdout: "No red team operations found in Redis.".into(),
                    stderr: String::new(),
                    exit_code: Some(0),
                    success: true,
                })
            }
        }
    };

    // Load red team state: credentials, techniques, targets
    let meta_key = format!("ares:op:{op_id}:meta");
    let meta_exists: bool = redis::AsyncCommands::exists(&mut conn, &meta_key)
        .await
        .unwrap_or(false);
    if !meta_exists {
        return Ok(ToolOutput {
            stdout: format!("Operation {op_id} not found in Redis."),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    // Get credentials (compromised accounts)
    let creds_key = format!("ares:op:{op_id}:credentials");
    let creds: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &creds_key, 0, -1)
        .await
        .unwrap_or_default();

    // Get discovered hosts
    let hosts_key = format!("ares:op:{op_id}:hosts");
    let hosts: std::collections::HashSet<String> =
        redis::AsyncCommands::smembers(&mut conn, &hosts_key)
            .await
            .unwrap_or_default();

    // Get loot/techniques
    let loot_key = format!("ares:op:{op_id}:loot");
    let loot: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &loot_key, 0, -1)
        .await
        .unwrap_or_default();

    // Get operation metadata
    let meta: std::collections::HashMap<String, String> =
        redis::AsyncCommands::hgetall(&mut conn, &meta_key)
            .await
            .unwrap_or_default();

    // Build playbook
    let mut lines = Vec::new();
    lines.push(format!(
        "=== Detection Playbook for Operation {op_id} ===\n"
    ));

    if let Some(started) = meta.get("started_at") {
        lines.push(format!("Operation started: {started}"));
    }
    if let Some(domain) = meta.get("domain") {
        lines.push(format!("Target domain: {domain}"));
    }

    // Extract usernames and IPs from credentials for targeted queries
    let mut target_users = Vec::new();
    let mut target_ips = Vec::new();
    for cred in &creds {
        if let Ok(cred_json) = serde_json::from_str::<Value>(cred) {
            if let Some(user) = cred_json.get("username").and_then(|u| u.as_str()) {
                if !target_users.contains(&user.to_string()) {
                    target_users.push(user.to_string());
                }
            }
            if let Some(ip) = cred_json.get("ip").and_then(|i| i.as_str()) {
                if !target_ips.contains(&ip.to_string()) {
                    target_ips.push(ip.to_string());
                }
            }
        }
    }

    // Extract techniques from loot
    let mut techniques_used = Vec::new();
    for item in &loot {
        if let Ok(loot_json) = serde_json::from_str::<Value>(item) {
            if let Some(technique) = loot_json.get("technique").and_then(|t| t.as_str()) {
                if !techniques_used.contains(&technique.to_string()) {
                    techniques_used.push(technique.to_string());
                }
            }
        }
    }

    // Priority queries based on what the red team actually did
    lines.push("\n--- Priority Detection Queries ---".to_string());

    let mut query_count = 0;
    let technique_queries: Vec<(&str, &str, &str)> = vec![
        ("T1003.006", "detect_dcsync", "DCSync replication attack"),
        ("T1003", "detect_secretsdump", "Credential dumping"),
        ("T1558.003", "detect_kerberoasting", "Kerberoasting"),
        ("T1558.004", "detect_asrep_roasting", "AS-REP Roasting"),
        ("T1558.001", "detect_golden_ticket", "Golden ticket usage"),
        ("T1550.002", "detect_pass_the_hash", "Pass-the-Hash"),
        ("T1021", "detect_lateral_movement", "Lateral movement"),
        ("T1110", "detect_brute_force", "Brute force / spray"),
        (
            "T1649",
            "detect_adcs_exploitation",
            "ADCS certificate abuse",
        ),
    ];

    for (tech_id, query_name, description) in &technique_queries {
        if techniques_used.iter().any(|t| t.starts_with(tech_id)) || query_count < 5 {
            let priority = if techniques_used.iter().any(|t| t.starts_with(tech_id)) {
                "HIGH (confirmed red team technique)"
            } else {
                "MEDIUM (recommended baseline)"
            };
            lines.push(format!(
                "  [{priority}] {query_name} — {description} ({tech_id})"
            ));
            query_count += 1;
        }
    }

    // IOC targets
    if !target_users.is_empty() {
        lines.push(format!(
            "\n--- Compromised Accounts ({}) ---",
            target_users.len()
        ));
        for user in target_users.iter().take(20) {
            lines.push(format!("  {user}"));
        }
    }

    if !target_ips.is_empty() {
        lines.push(format!("\n--- Target IPs ({}) ---", target_ips.len()));
        for ip in target_ips.iter().take(20) {
            lines.push(format!("  {ip}"));
        }
    }

    if !hosts.is_empty() {
        lines.push(format!("\n--- Discovered Hosts ({}) ---", hosts.len()));
        let mut sorted_hosts: Vec<&String> = hosts.iter().collect();
        sorted_hosts.sort();
        for host in sorted_hosts.iter().take(20) {
            lines.push(format!("  {host}"));
        }
    }

    if !techniques_used.is_empty() {
        lines.push(format!(
            "\n--- Techniques Used ({}) ---",
            techniques_used.len()
        ));
        for tech in &techniques_used {
            lines.push(format!("  {tech}"));
        }
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Get detection queries specific to a MITRE technique, optionally informed
/// by red team operation state.
///
/// Parameters:
/// - `technique_id` (required)
/// - `operation_id` (optional)
/// - `redis_url` (optional)
pub async fn get_detection_queries_for_technique(args: &Value) -> anyhow::Result<ToolOutput> {
    let technique_id = crate::args::required_str(args, "technique_id")?;

    // Normalize
    let normalized = if technique_id.starts_with('t') || technique_id.starts_with('T') {
        let mut s = technique_id.to_string();
        s.replace_range(0..1, "T");
        s
    } else {
        technique_id.to_string()
    };

    // Static technique → detection template mapping
    let technique_to_queries: HashMap<&str, Vec<(&str, &str)>> = {
        let mut m = HashMap::new();
        m.insert(
            "T1003",
            vec![
                ("detect_secretsdump", "Credential dumping via secretsdump"),
                ("detect_dcsync", "DCSync replication attack"),
                ("detect_lsa_secrets_access", "LSA secrets registry access"),
            ],
        );
        m.insert(
            "T1003.006",
            vec![
                ("detect_dcsync", "DCSync replication attack"),
                (
                    "detect_dcsync_replication",
                    "DCSync via RPC replication calls",
                ),
            ],
        );
        m.insert(
            "T1558.003",
            vec![(
                "detect_kerberoasting",
                "Kerberoasting TGS requests with RC4",
            )],
        );
        m.insert(
            "T1558.004",
            vec![
                ("detect_asrep_roasting", "AS-REP Roasting pre-auth disabled"),
                ("detect_asrep_roasting_bulk", "Bulk AS-REP Roasting"),
            ],
        );
        m.insert(
            "T1558.001",
            vec![("detect_golden_ticket", "Golden ticket anomalous TGT")],
        );
        m.insert(
            "T1550.002",
            vec![("detect_pass_the_hash", "Pass-the-Hash NTLM authentication")],
        );
        m.insert(
            "T1021",
            vec![
                ("detect_lateral_movement", "Remote service lateral movement"),
                ("detect_smb_file_access", "SMB share access"),
            ],
        );
        m.insert(
            "T1021.002",
            vec![
                ("detect_smb_file_access", "SMB/admin share access"),
                ("detect_lateral_movement", "SMB lateral movement"),
            ],
        );
        m.insert(
            "T1110",
            vec![
                ("detect_brute_force", "Password brute force"),
                ("detect_password_spray", "Password spray"),
            ],
        );
        m.insert(
            "T1078",
            vec![("detect_lateral_movement", "Anomalous logon patterns")],
        );
        m.insert(
            "T1649",
            vec![
                ("detect_adcs_exploitation", "ADCS exploitation"),
                ("detect_certipy_enumeration", "Certipy enumeration"),
                ("detect_esc1_attack", "ESC1 template abuse"),
            ],
        );
        m.insert(
            "T1134",
            vec![
                ("detect_s4u_delegation", "S4U delegation abuse"),
                ("detect_delegation_abuse", "Kerberos delegation abuse"),
            ],
        );
        m
    };

    // Try exact match, then parent technique
    let queries = technique_to_queries.get(normalized.as_str()).or_else(|| {
        normalized
            .split('.')
            .next()
            .and_then(|parent| technique_to_queries.get(parent))
    });

    let mut lines = vec![format!("Detection queries for {normalized}:\n")];

    match queries {
        Some(query_list) => {
            for (name, desc) in query_list {
                lines.push(format!("  run_detection_query(\"{name}\") — {desc}"));
            }
        }
        None => {
            lines.push("  No specific detection templates for this technique.".to_string());
            lines.push(
                "  Try using suggest_techniques or list_detection_templates to find relevant queries."
                    .to_string(),
            );
        }
    }

    // If an operation ID is provided, add context from the playbook
    if args.get("operation_id").is_some() {
        lines.push("\nFetching operation context...".to_string());
        let playbook_result = get_attack_playbook(args).await?;
        if playbook_result.success && !playbook_result.stdout.is_empty() {
            lines.push(String::new());
            lines.push("--- Operation Context ---".to_string());
            // Extract just the relevant IOC lines
            for line in playbook_result.stdout.lines() {
                if line.contains("Compromised")
                    || line.contains("Target IP")
                    || line.starts_with("  ")
                {
                    lines.push(line.to_string());
                }
            }
        }
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Find the latest operation ID in Redis by scanning `ares:op:*:meta` keys.
async fn find_latest_operation(conn: &mut redis::aio::MultiplexedConnection) -> Option<String> {
    let mut cursor: u64 = 0;
    let mut latest_id: Option<String> = None;

    loop {
        let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("ares:op:*:meta")
            .arg("COUNT")
            .arg(100)
            .query_async(conn)
            .await
            .ok()?;

        for key in keys {
            // Extract op ID from "ares:op:{id}:meta"
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() >= 3 {
                let id = parts[2].to_string();
                // Pick latest alphabetically (UUIDs sort chronologically for v7,
                // otherwise just pick the last one found)
                latest_id = Some(match latest_id {
                    Some(prev) if prev > id => prev,
                    _ => id,
                });
            }
        }

        cursor = new_cursor;
        if cursor == 0 {
            break;
        }
    }

    latest_id
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_lookup_known_technique() {
        let args = json!({"technique_id": "T1003"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("OS Credential Dumping"));
        assert!(result.stdout.contains("Credential Access"));
    }

    #[test]
    fn test_lookup_subtechnique() {
        let args = json!({"technique_id": "T1003.001"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("LSASS Memory"));
    }

    #[test]
    fn test_lookup_unknown_falls_back_to_parent() {
        let args = json!({"technique_id": "T1003.999"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("OS Credential Dumping"));
        assert!(result.stdout.contains("parent technique"));
    }

    #[test]
    fn test_lookup_completely_unknown() {
        let args = json!({"technique_id": "T9999"});
        let result = lookup_technique(&args).unwrap();
        assert!(!result.success);
        assert!(result.stderr.contains("not found"));
    }

    #[test]
    fn test_lookup_case_insensitive() {
        let args = json!({"technique_id": "t1003"});
        let result = lookup_technique(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("OS Credential Dumping"));
    }

    #[test]
    fn test_suggest_credential_access() {
        let args = json!({"evidence_type": "credential_access"});
        let result = suggest_techniques(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("T1003"));
        assert!(result.stdout.contains("T1558"));
    }

    #[test]
    fn test_suggest_lateral_movement() {
        let args = json!({"evidence_type": "lateral_movement"});
        let result = suggest_techniques(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("T1021"));
        assert!(result.stdout.contains("T1550"));
    }

    #[test]
    fn test_suggest_with_hyphens() {
        let args = json!({"evidence_type": "lateral-movement"});
        let result = suggest_techniques(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("T1021"));
    }

    #[test]
    fn test_suggest_unknown_type() {
        let args = json!({"evidence_type": "nonexistent"});
        let result = suggest_techniques(&args).unwrap();
        assert!(!result.success);
        assert!(result.stderr.contains("Unknown evidence type"));
        assert!(result.stderr.contains("Available types"));
    }

    #[test]
    fn test_missing_required_arg() {
        let args = json!({});
        let result = lookup_technique(&args);
        assert!(result.is_err());
    }
}
