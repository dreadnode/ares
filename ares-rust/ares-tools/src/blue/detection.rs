//! Pre-built query templates for detecting red team attack patterns.
//!
//! Provides ready-to-use LogQL queries mapped to MITRE ATT&CK techniques,
//! designed to detect attacks performed by the Ares red team agent.
//!
//! Query optimization follows Grafana Loki best practices:
//! - Label selectors are the most important filter — narrow them first
//! - Use `|=` (contains) before `|~` (regex) — contains is faster
//! - Put most selective filters (event IDs) first
//! - Avoid broad patterns like `{job=~".+"}` — use specific labels

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::loki;

// ─── Label constants ────────────────────────────────────────────────────────

const WIN_SECURITY: &str = r#"job="windows-security""#;
const WIN_SYSTEM: &str = r#"job="windows-system""#;

// ─── Query builder helpers ──────────────────────────────────────────────────

/// Build an optimized label selector.
///
/// Starts with a base job label, optionally adds hostname regex match.
/// Per Grafana docs: Loki optimizes `hostname=~"dc"` better than
/// `hostname=~".*dc.*"`.
fn build_selector(base: &str, hostname: Option<&str>) -> String {
    match hostname {
        Some(host) => format!("{{{base}, hostname=~\"{host}\"}}"),
        None => format!("{{{base}}}"),
    }
}

/// Build an optimized filter for Windows Event IDs.
///
/// Uses `|=` (contains) for single IDs and `|~` (regex alternation) for
/// multiple. Per Grafana docs: "Loki evaluates contains faster than regex."
fn build_event_filter(ids: &[&str]) -> String {
    match ids.len() {
        0 => String::new(),
        1 => format!(r#" |= "{}""#, ids[0]),
        _ => format!(r#" |~ "({})""#, ids.join("|")),
    }
}

/// Build a case-insensitive regex filter for tool/attack patterns.
fn build_pattern_filter(patterns: &[&str]) -> String {
    if patterns.is_empty() {
        return String::new();
    }
    format!(r#" |~ "(?i)({})""#, patterns.join("|"))
}

// ─── Template metadata ─────────────────────────────────────────────────────

struct DetectionTemplate {
    logql: String,
    description: &'static str,
    mitre_id: &'static str,
    tactic: &'static str,
    severity: &'static str,
    red_team_tool: Option<&'static str>,
    auto_pivot: bool,
}

impl DetectionTemplate {
    fn format_header(&self) -> String {
        let mut header = format!(
            "## {} ({})\n**Severity:** {} | **Tactic:** {}",
            self.description, self.mitre_id, self.severity, self.tactic,
        );
        if let Some(tool) = self.red_team_tool {
            header.push_str(&format!(" | **Red Team Tool:** {tool}"));
        }
        if self.auto_pivot {
            header.push_str(" | **Auto-Pivot:** yes");
        }
        header.push_str(&format!("\n**Query:** `{}`\n", self.logql));
        header
    }
}

// ─── Template builder ───────────────────────────────────────────────────────

fn build_detection_template(name: &str, host: Option<&str>) -> Option<DetectionTemplate> {
    let sel = build_selector(WIN_SECURITY, host);

    let tmpl = match name {
        // ═════════════════════════════════════════════════════════════════════
        // RECONNAISSANCE & DISCOVERY (TA0007)
        // ═════════════════════════════════════════════════════════════════════
        "detect_port_scanning" => {
            let tool_filter = build_pattern_filter(&[
                "nmap",
                "masscan",
                "syn.scan",
                "port.scan",
                "connection.refused",
            ]);
            let mut logql = format!("{sel}{tool_filter}");
            if let Some(ip) = host {
                logql.push_str(&format!(r#" |= "{ip}""#));
            }
            DetectionTemplate {
                logql,
                description: "Network Port Scanning Detection",
                mitre_id: "T1046",
                tactic: "discovery",
                severity: "medium",
                red_team_tool: Some("nmap_scan"),
                auto_pivot: false,
            }
        }

        "detect_user_enumeration" | "detect_account_enumeration" => {
            let event_filter = build_event_filter(&["4662", "4798", "4799"]);
            let tool_filter = build_pattern_filter(&[
                "samr",
                "lsarpc",
                "ldap",
                "net.user",
                "net.group",
                "enumerate",
                "crackmapexec",
                "netexec",
                "ldapsearch",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{tool_filter}"),
                description: "AD User/Account Enumeration Detection",
                mitre_id: "T1087.002",
                tactic: "discovery",
                severity: "medium",
                red_team_tool: Some("enumerate_users"),
                auto_pivot: false,
            }
        }

        "detect_share_enumeration" => {
            let event_filter = build_event_filter(&["5140", "5145"]);
            let tool_filter = build_pattern_filter(&[
                "srvsvc",
                "netuse",
                "net.share",
                "net.view",
                "smbclient",
                "crackmapexec",
                "netexec",
                "enum.share",
                "share.enum",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{tool_filter}"),
                description: "SMB Share Enumeration Detection",
                mitre_id: "T1135",
                tactic: "discovery",
                severity: "medium",
                red_team_tool: Some("enumerate_shares"),
                auto_pivot: false,
            }
        }

        // ═════════════════════════════════════════════════════════════════════
        // CREDENTIAL ACCESS (TA0006)
        // ═════════════════════════════════════════════════════════════════════
        "detect_secretsdump" => {
            let tool_filter = build_pattern_filter(&[
                "drsuapi",
                "samr",
                "secretsdump",
                "lsadump",
                "ntds.dit",
                "sam.dump",
                "replicate",
                "1131f6",
                "ds-replication",
                "mimikatz",
                "impacket",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{tool_filter}"),
                description: "Credential Dumping Detection (secretsdump)",
                mitre_id: "T1003",
                tactic: "credential_access",
                severity: "critical",
                red_team_tool: Some("secretsdump"),
                auto_pivot: false,
            }
        }

        "detect_dcsync" => {
            let event_filter = build_event_filter(&["4662"]);
            let tool_filter = build_pattern_filter(&[
                "dcsync",
                "ds-replication",
                "1131f6aa",
                "1131f6ad",
                "replication",
                "drsuapi",
                "directory.service.access",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{tool_filter}"),
                description: "DCSync Attack Detection",
                mitre_id: "T1003.006",
                tactic: "credential_access",
                severity: "critical",
                red_team_tool: Some("secretsdump"),
                auto_pivot: false,
            }
        }

        "detect_dcsync_replication" => {
            let event_filter = build_event_filter(&["4662"]);
            let guid_filter = build_pattern_filter(&[
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                "89e95b76-444d-4c62-991a-0facbeda640c",
                "1131f6aa",
                "1131f6ad",
                "89e95b76",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{guid_filter}"),
                description: "DCSync Replication GUID Detection",
                mitre_id: "T1003.006",
                tactic: "credential_access",
                severity: "critical",
                red_team_tool: Some("secretsdump"),
                auto_pivot: false,
            }
        }

        "detect_kerberoasting" => DetectionTemplate {
            logql: format!(
                r#"{sel} |= "4769" |~ "(?i)(encryption.*type.*(0x17|rc4)|ticket.*encryption.*(0x17|rc4)|servicename.*(mssql|http|ldap|cifs))""#
            ),
            description: "Kerberoasting Detection (TGS with RC4)",
            mitre_id: "T1558.003",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("kerberoast"),
            auto_pivot: false,
        },

        "detect_asrep_roasting" => DetectionTemplate {
            logql: format!(
                r#"{sel} |= "4768" |~ "(?i)(preauthtype.*0|pre.?auth.*type.*0|encryption.*type.*(0x17|rc4)|ticket.*options.*0x4)""#
            ),
            description: "AS-REP Roasting Detection (TGT without pre-auth)",
            mitre_id: "T1558.004",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("asrep_roast"),
            auto_pivot: false,
        },

        "detect_asrep_roasting_bulk" => DetectionTemplate {
            logql: format!(r#"{sel} |= "4768""#),
            description: "Bulk AS-REP Roasting Spray Detection",
            mitre_id: "T1558.004",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("asrep_roast"),
            auto_pivot: false,
        },

        "detect_brute_force" | "detect_password_spray" => {
            let event_filter = build_event_filter(&["4625", "4771"]);
            DetectionTemplate {
                logql: format!(
                    r#"{sel}{event_filter} |~ "(?i)(failed|invalid|denied)" |~ "(?i)(logon|auth)""#
                ),
                description: "Brute Force / Password Spray Detection",
                mitre_id: "T1110",
                tactic: "credential_access",
                severity: "medium",
                red_team_tool: None,
                auto_pivot: false,
            }
        }

        "detect_s4u_delegation" => {
            let event_filter = build_event_filter(&["4769"]);
            let tool_filter = build_pattern_filter(&[
                "s4u2self",
                "s4u2proxy",
                "constrained.delegation",
                "impersonate",
                "forwardable",
                "getst",
                "cifs/",
                "http/",
                "administrator",
                "trustedfordelegation",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{tool_filter}"),
                description: "S4U Constrained Delegation Abuse Detection",
                mitre_id: "T1558.003",
                tactic: "credential_access",
                severity: "critical",
                red_team_tool: Some("get_st"),
                auto_pivot: false,
            }
        }

        "detect_lsa_secrets_access" => {
            let event_filter = build_event_filter(&["4656", "4663", "4658"]);
            let tool_filter = build_pattern_filter(&[
                "security.policy.secrets",
                "lsa.secrets",
                "dpapi",
                "defaultpassword",
                "nlkm",
                "cachedlogon",
                "lsadump",
                "reg.query.*security",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{tool_filter}"),
                description: "LSA Secrets Extraction Detection",
                mitre_id: "T1003.004",
                tactic: "credential_access",
                severity: "high",
                red_team_tool: Some("secretsdump"),
                auto_pivot: false,
            }
        }

        // ═════════════════════════════════════════════════════════════════════
        // LATERAL MOVEMENT (TA0008)
        // ═════════════════════════════════════════════════════════════════════
        "detect_pass_the_hash" => {
            let event_filter = build_event_filter(&["4624"]);
            let tool_filter = build_pattern_filter(&[
                "ntlm",
                "ntlmssp",
                "pass.the.hash",
                "logon.type.3",
                "network.logon",
                "crackmapexec",
                "netexec",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{tool_filter}"),
                description: "Pass-the-Hash Detection",
                mitre_id: "T1550.002",
                tactic: "lateral_movement",
                severity: "high",
                red_team_tool: Some("domain_admin_checker"),
                auto_pivot: true,
            }
        }

        "detect_lateral_movement" => {
            let event_filter = build_event_filter(&["7045", "4648"]);
            let tool_filter = build_pattern_filter(&[
                r"psexec",
                "wmic",
                "winrm",
                r"powershell.-session",
                r"admin\$",
                r"c\$",
                r"ipc\$",
                "service.install",
                "remote.execution",
            ]);
            DetectionTemplate {
                logql: format!("{sel}{event_filter}{tool_filter}"),
                description: "Lateral Movement Detection (PSExec/WMI/WinRM)",
                mitre_id: "T1021",
                tactic: "lateral_movement",
                severity: "high",
                red_team_tool: None,
                auto_pivot: true,
            }
        }

        "detect_smb_file_access" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(5145|file.*access|share.*access|smbclient)" |~ "(?i)(\.ps1|\.bat|\.cmd|\.xml|\.config|sysvol|netlogon|groups\.xml)""#
            ),
            description: "Suspicious SMB File Access Detection",
            mitre_id: "T1039",
            tactic: "collection",
            severity: "medium",
            red_team_tool: Some("download_file_content"),
            auto_pivot: false,
        },

        // ═════════════════════════════════════════════════════════════════════
        // PRIVILEGE ESCALATION (TA0004)
        // ═════════════════════════════════════════════════════════════════════
        "detect_adcs_exploitation" | "detect_certificate_abuse" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(4886|4887|4876|certipy|certificate.*request)" |~ "(?i)(esc[0-9]|enrollee.*supplies.*subject|altname|upn)""#
            ),
            description: "ADCS Certificate Abuse Detection (ESC1-ESC15)",
            mitre_id: "T1649",
            tactic: "privilege_escalation",
            severity: "high",
            red_team_tool: Some("certipy_*"),
            auto_pivot: false,
        },

        "detect_delegation_abuse" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(delegation|msds-allowedtoactonbehalf|rbcd|s4u)" |~ "(?i)(impersonate|constrained|unconstrained|getst|addcomputer)""#
            ),
            description: "Kerberos Delegation Abuse Detection",
            mitre_id: "T1134.001",
            tactic: "privilege_escalation",
            severity: "high",
            red_team_tool: Some("rbcd_write"),
            auto_pivot: false,
        },

        "detect_bloodhound" | "detect_bloodhound_collection" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(bloodhound|sharphound|adexplorer|ldap.*query)" |~ "(?i)(acl|objectsid|memberof|primarygroup|msds)""#
            ),
            description: "BloodHound/SharpHound Collection Detection",
            mitre_id: "T1087",
            tactic: "discovery",
            severity: "medium",
            red_team_tool: Some("run_bloodhound"),
            auto_pivot: false,
        },

        // ═════════════════════════════════════════════════════════════════════
        // PERSISTENCE (TA0003)
        // ═════════════════════════════════════════════════════════════════════
        "detect_golden_ticket" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(golden.*ticket|krbtgt|ticketer|krbcred)" |~ "(?i)(forged|4769|kerberos.*ticket|enterprise.*admin)""#
            ),
            description: "Golden Ticket Detection",
            mitre_id: "T1558.001",
            tactic: "persistence",
            severity: "critical",
            red_team_tool: Some("generate_golden_ticket"),
            auto_pivot: false,
        },

        // ═════════════════════════════════════════════════════════════════════
        // EXECUTION (TA0002)
        // ═════════════════════════════════════════════════════════════════════
        "detect_suspicious_execution" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(4688|powershell|pwsh|cmd\.exe|wscript|cscript)" |~ "(?i)(encodedcommand|bypass|hidden|downloadstring|invoke)""#
            ),
            description: "Suspicious Command Execution Detection",
            mitre_id: "T1059",
            tactic: "execution",
            severity: "medium",
            red_team_tool: None,
            auto_pivot: false,
        },

        "detect_service_creation" => DetectionTemplate {
            logql: format!(r#"{sel} |= "7045" |~ "(?i)(PSEXE|BTOBTO|cmd\.exe|powershell|remcom)""#),
            description: "Suspicious Service Creation Detection",
            mitre_id: "T1543.003",
            tactic: "execution",
            severity: "high",
            red_team_tool: Some("psexec"),
            auto_pivot: true,
        },

        "detect_scheduled_task" => DetectionTemplate {
            logql: format!(
                r#"{sel} |= "4698" |~ "(?i)(cmd\.exe|powershell|mshta|atexec|schtasks)""#
            ),
            description: "Suspicious Scheduled Task Detection",
            mitre_id: "T1053.005",
            tactic: "execution",
            severity: "medium",
            red_team_tool: Some("atexec"),
            auto_pivot: false,
        },

        "detect_ntlm_relay" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(ntlm|relay|responder|inveigh)" |~ "(?i)(ntlmrelayx|smbrelay|signing.*not.*required|coerce)""#
            ),
            description: "NTLM Relay Attack Detection",
            mitre_id: "T1557",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("ntlmrelayx"),
            auto_pivot: false,
        },

        // ═════════════════════════════════════════════════════════════════════
        // ADCS / CERTIPY SPECIFIC (ESC attacks)
        // ═════════════════════════════════════════════════════════════════════
        "detect_certipy_enumeration" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(certipy|ldap|389|636)" |~ "(?i)(mspki|pkienrollmentservice|certificatetemplates|pki)""#
            ),
            description: "Certipy Certificate Template Recon Detection",
            mitre_id: "T1649",
            tactic: "discovery",
            severity: "medium",
            red_team_tool: Some("certipy_find"),
            auto_pivot: false,
        },

        "detect_esc1_attack" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(4886|4887|certificate.*request|certipy)" |~ "(?i)(san=|subjectaltname|upn=|enrollee.*supplies|ct_flag)""#
            ),
            description: "ESC1 — Enrollee Supplies Subject Attack Detection",
            mitre_id: "T1649",
            tactic: "privilege_escalation",
            severity: "critical",
            red_team_tool: Some("certipy_req_esc1"),
            auto_pivot: false,
        },

        "detect_esc4_attack" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(5136|ldap.*modify|template.*modif)" |~ "(?i)(pki|certificatetemplate|mspki|enrollmentflag)""#
            ),
            description: "ESC4 — Certificate Template ACL Modification Detection",
            mitre_id: "T1649",
            tactic: "privilege_escalation",
            severity: "high",
            red_team_tool: None,
            auto_pivot: false,
        },

        "detect_esc8_attack" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(certsrv|certfnsh|certenroll|ntlmrelayx)" |~ "(?i)(relay|coerce|petitpotam|printerbug|dfscoerce)""#
            ),
            description: "ESC8 — NTLM Relay to AD CS HTTP Endpoints Detection",
            mitre_id: "T1649",
            tactic: "privilege_escalation",
            severity: "critical",
            red_team_tool: Some("ntlmrelayx"),
            auto_pivot: false,
        },

        "detect_certificate_authentication" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(pkinit|pkca|smartcard|certificate.*auth)" |~ "(?i)(4768|tgt.*request|kerberos|certipy.*auth)""#
            ),
            description: "Certificate-Based Authentication Detection",
            mitre_id: "T1649",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("certipy_auth"),
            auto_pivot: false,
        },

        // ═════════════════════════════════════════════════════════════════════
        // BLOODHOUND SPECIFIC LDAP SIGNATURES
        // ═════════════════════════════════════════════════════════════════════
        "detect_bloodhound_domain_enum" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(ldap|389|636|bloodhound|sharphound)" |~ "(?i)(trusteddomain|crossref|trusttype|trustdirection|trustattributes)""#
            ),
            description: "BloodHound Domain Trust Recon Detection",
            mitre_id: "T1482",
            tactic: "discovery",
            severity: "medium",
            red_team_tool: Some("run_bloodhound"),
            auto_pivot: false,
        },

        "detect_bloodhound_acl_enum" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(ldap|389|636|bloodhound|sharphound)" |~ "(?i)(ntsecuritydescriptor|dacl|securitydescriptor|allowedtoactonbehalf)""#
            ),
            description: "BloodHound ACL/DACL Collection Detection",
            mitre_id: "T1069.002",
            tactic: "discovery",
            severity: "medium",
            red_team_tool: Some("run_bloodhound"),
            auto_pivot: false,
        },

        "detect_bloodhound_session_enum" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(srvsvc|wkssvc|netsession|netwksta)" |~ "(?i)(enum|bloodhound|sharphound|session.*collection)""#
            ),
            description: "BloodHound Session Recon Detection",
            mitre_id: "T1033",
            tactic: "discovery",
            severity: "medium",
            red_team_tool: Some("run_bloodhound"),
            auto_pivot: false,
        },

        "detect_bloodhound_gpo_enum" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(ldap|389|636|bloodhound|sharphound)" |~ "(?i)(grouppolicycontainer|gplink|gpcfilesyspath|gpo)""#
            ),
            description: "BloodHound GPO Recon Detection",
            mitre_id: "T1615",
            tactic: "discovery",
            severity: "medium",
            red_team_tool: Some("run_bloodhound"),
            auto_pivot: false,
        },

        "detect_bloodhound_computer_enum" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(ldap|389|636|bloodhound|sharphound)" |~ "(?i)(objectclass=computer|operatingsystem|serviceprincipalname|allowedtodelegateto)""#
            ),
            description: "BloodHound Computer Object Recon Detection",
            mitre_id: "T1018",
            tactic: "discovery",
            severity: "medium",
            red_team_tool: Some("run_bloodhound"),
            auto_pivot: false,
        },

        // ═════════════════════════════════════════════════════════════════════
        // IMPACKET TOOL FINGERPRINTS
        // ═════════════════════════════════════════════════════════════════════
        "detect_impacket_wmiexec" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(wmi|win32_process|root\\cimv2)" |~ "(?i)(wmiexec|impacket|cmd.*/q.*/c|127\.0\.0\.1.*admin\$)""#
            ),
            description: "Impacket wmiexec WMI Remote Execution Detection",
            mitre_id: "T1047",
            tactic: "execution",
            severity: "high",
            red_team_tool: Some("wmiexec"),
            auto_pivot: true,
        },

        "detect_impacket_psexec" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(7045|service.*install|psexec|remcom)" |~ "(?i)(admin\$|\\\\.*\\admin|service.*creat|cmd\.exe)""#
            ),
            description: "Impacket psexec Service-Based Execution Detection",
            mitre_id: "T1569.002",
            tactic: "execution",
            severity: "high",
            red_team_tool: Some("psexec"),
            auto_pivot: true,
        },

        "detect_impacket_smbexec" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(7045|service|smbexec)" |~ "(?i)(btobto|cmd.*echo.*\^>|__output|execute\.bat)""#
            ),
            description: "Impacket smbexec Stealthy Service Execution Detection",
            mitre_id: "T1569.002",
            tactic: "execution",
            severity: "high",
            red_team_tool: Some("smbexec"),
            auto_pivot: true,
        },

        "detect_impacket_atexec" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(4698|4699|4700|4701|schtask|taskscheduler|atsvc)" |~ "(?i)(atexec|impacket|cmd.*/c|schtasks)""#
            ),
            description: "Impacket atexec Scheduled Task Execution Detection",
            mitre_id: "T1053.002",
            tactic: "execution",
            severity: "medium",
            red_team_tool: Some("atexec"),
            auto_pivot: false,
        },

        "detect_impacket_dcomexec" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(dcom|135/tcp|rpc|mmc20|shellwindows|shellbrowser)" |~ "(?i)(dcomexec|impacket|executeshellcommand|document\.application)""#
            ),
            description: "Impacket dcomexec DCOM Remote Execution Detection",
            mitre_id: "T1021.003",
            tactic: "lateral_movement",
            severity: "high",
            red_team_tool: Some("dcomexec"),
            auto_pivot: true,
        },

        "detect_impacket_secretsdump_sam" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(registry|hklm|winreg|samr)" |~ "(?i)(sam|system|security|secretsdump|reg.*save)""#
            ),
            description: "Secretsdump SAM Database Extraction Detection",
            mitre_id: "T1003.002",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("secretsdump"),
            auto_pivot: false,
        },

        "detect_impacket_secretsdump_lsa" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(lsa|security|policy|secrets)" |~ "(?i)(\$machine|defaultpassword|nl\$|dpapi|secretsdump)""#
            ),
            description: "Secretsdump LSA Secrets Extraction Detection",
            mitre_id: "T1003.004",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("secretsdump"),
            auto_pivot: false,
        },

        "detect_impacket_ntlmrelayx" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(ntlm|relay|responder|inveigh)" |~ "(?i)(ntlmrelayx|smbrelay|signing.*not.*required|coerce)""#
            ),
            description: "Impacket ntlmrelayx NTLM Relay Detection",
            mitre_id: "T1557.001",
            tactic: "credential_access",
            severity: "high",
            red_team_tool: Some("ntlmrelayx"),
            auto_pivot: false,
        },

        "detect_impacket_smbclient" => DetectionTemplate {
            logql: format!(
                r#"{sel} |~ "(?i)(smb|445/tcp|cifs|smbclient)" |~ "(?i)(impacket|tree.*connect|shares.*enum|file.*access)""#
            ),
            description: "Impacket smbclient Share Access Detection",
            mitre_id: "T1021.002",
            tactic: "lateral_movement",
            severity: "medium",
            red_team_tool: Some("smbclient"),
            auto_pivot: false,
        },

        // ═════════════════════════════════════════════════════════════════════
        // SERVICE / REGISTRY PRECURSORS
        // ═════════════════════════════════════════════════════════════════════
        "detect_remote_registry_start" => {
            // Uses Windows System log, not Security
            let sys_sel = build_selector(WIN_SYSTEM, host);
            DetectionTemplate {
                logql: format!(
                    r#"{sys_sel} |~ "(7036|7045)" |~ "(?i)(remoteregistry|remote.registry)" |~ "(?i)(running|started|start)""#
                ),
                description: "RemoteRegistry Service Start Detection",
                mitre_id: "T1569.002",
                tactic: "execution",
                severity: "medium",
                red_team_tool: Some("secretsdump"),
                auto_pivot: false,
            }
        }

        _ => return None,
    };

    Some(tmpl)
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Run a pre-built detection query template.
pub async fn run_detection_query(args: &Value) -> Result<ToolOutput> {
    let query_name = required_str(args, "query_name")?;
    let target_host = optional_str(args, "target_host");
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1);

    let tmpl = match build_detection_template(query_name, target_host) {
        Some(t) => t,
        None => {
            return Ok(ToolOutput {
                stdout: String::new(),
                stderr: format!(
                    "Unknown detection template: '{query_name}'. Use list_detection_templates to see available templates."
                ),
                exit_code: Some(1),
                success: false,
            });
        }
    };

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    let query_args = serde_json::json!({
        "logql": tmpl.logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 500,
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!("{}\n{}", tmpl.format_header(), result.stdout);
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
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1);
    let max_concurrent = optional_i64(args, "max_concurrent").unwrap_or(5) as usize;

    let mut output_parts = Vec::new();

    // Process in batches
    for batch in query_names.chunks(max_concurrent) {
        let mut handles = Vec::new();
        for name in batch {
            let name = name.clone();
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
    }

    Ok(ToolOutput {
        stdout: format!(
            "Parallel detections completed: {}/{} queries\n\n---\n\n{}",
            output_parts.len(),
            query_names.len(),
            output_parts.join("\n\n---\n\n")
        ),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// List all available detection templates with MITRE mappings.
pub async fn list_detection_templates(_args: &Value) -> Result<ToolOutput> {
    let templates: &[(&str, &str, &str, &str, Option<&str>)] = &[
        // (name, mitre, tactic, severity, red_team_tool)
        // ── Reconnaissance ──
        (
            "detect_port_scanning",
            "T1046",
            "discovery",
            "medium",
            Some("nmap_scan"),
        ),
        (
            "detect_user_enumeration",
            "T1087.002",
            "discovery",
            "medium",
            Some("enumerate_users"),
        ),
        (
            "detect_account_enumeration",
            "T1087.002",
            "discovery",
            "medium",
            Some("enumerate_users"),
        ),
        (
            "detect_share_enumeration",
            "T1135",
            "discovery",
            "medium",
            Some("enumerate_shares"),
        ),
        // ── Credential Access ──
        (
            "detect_secretsdump",
            "T1003",
            "credential_access",
            "critical",
            Some("secretsdump"),
        ),
        (
            "detect_dcsync",
            "T1003.006",
            "credential_access",
            "critical",
            Some("secretsdump"),
        ),
        (
            "detect_dcsync_replication",
            "T1003.006",
            "credential_access",
            "critical",
            Some("secretsdump"),
        ),
        (
            "detect_kerberoasting",
            "T1558.003",
            "credential_access",
            "high",
            Some("kerberoast"),
        ),
        (
            "detect_asrep_roasting",
            "T1558.004",
            "credential_access",
            "high",
            Some("asrep_roast"),
        ),
        (
            "detect_asrep_roasting_bulk",
            "T1558.004",
            "credential_access",
            "high",
            Some("asrep_roast"),
        ),
        (
            "detect_brute_force",
            "T1110",
            "credential_access",
            "medium",
            None,
        ),
        (
            "detect_password_spray",
            "T1110",
            "credential_access",
            "medium",
            None,
        ),
        (
            "detect_s4u_delegation",
            "T1558.003",
            "credential_access",
            "critical",
            Some("get_st"),
        ),
        (
            "detect_lsa_secrets_access",
            "T1003.004",
            "credential_access",
            "high",
            Some("secretsdump"),
        ),
        (
            "detect_ntlm_relay",
            "T1557",
            "credential_access",
            "high",
            Some("ntlmrelayx"),
        ),
        (
            "detect_certificate_authentication",
            "T1649",
            "credential_access",
            "high",
            Some("certipy_auth"),
        ),
        // ── Lateral Movement ──
        (
            "detect_pass_the_hash",
            "T1550.002",
            "lateral_movement",
            "high",
            Some("domain_admin_checker"),
        ),
        (
            "detect_lateral_movement",
            "T1021",
            "lateral_movement",
            "high",
            None,
        ),
        (
            "detect_smb_file_access",
            "T1039",
            "collection",
            "medium",
            Some("download_file_content"),
        ),
        // ── Privilege Escalation ──
        (
            "detect_adcs_exploitation",
            "T1649",
            "privilege_escalation",
            "high",
            Some("certipy_*"),
        ),
        (
            "detect_certificate_abuse",
            "T1649",
            "privilege_escalation",
            "high",
            Some("certipy_*"),
        ),
        (
            "detect_delegation_abuse",
            "T1134.001",
            "privilege_escalation",
            "high",
            Some("rbcd_write"),
        ),
        // ── Persistence ──
        (
            "detect_golden_ticket",
            "T1558.001",
            "persistence",
            "critical",
            Some("generate_golden_ticket"),
        ),
        // ── Execution ──
        (
            "detect_suspicious_execution",
            "T1059",
            "execution",
            "medium",
            None,
        ),
        (
            "detect_service_creation",
            "T1543.003",
            "execution",
            "high",
            Some("psexec"),
        ),
        (
            "detect_scheduled_task",
            "T1053.005",
            "execution",
            "medium",
            Some("atexec"),
        ),
        (
            "detect_remote_registry_start",
            "T1569.002",
            "execution",
            "medium",
            Some("secretsdump"),
        ),
        // ── ADCS/Certipy Specific ──
        (
            "detect_certipy_enumeration",
            "T1649",
            "discovery",
            "medium",
            Some("certipy_find"),
        ),
        (
            "detect_esc1_attack",
            "T1649",
            "privilege_escalation",
            "critical",
            Some("certipy_req_esc1"),
        ),
        (
            "detect_esc4_attack",
            "T1649",
            "privilege_escalation",
            "high",
            None,
        ),
        (
            "detect_esc8_attack",
            "T1649",
            "privilege_escalation",
            "critical",
            Some("ntlmrelayx"),
        ),
        // ── BloodHound Specific ──
        (
            "detect_bloodhound",
            "T1087",
            "discovery",
            "medium",
            Some("run_bloodhound"),
        ),
        (
            "detect_bloodhound_collection",
            "T1087",
            "discovery",
            "medium",
            Some("run_bloodhound"),
        ),
        (
            "detect_bloodhound_domain_enum",
            "T1482",
            "discovery",
            "medium",
            Some("run_bloodhound"),
        ),
        (
            "detect_bloodhound_acl_enum",
            "T1069.002",
            "discovery",
            "medium",
            Some("run_bloodhound"),
        ),
        (
            "detect_bloodhound_session_enum",
            "T1033",
            "discovery",
            "medium",
            Some("run_bloodhound"),
        ),
        (
            "detect_bloodhound_gpo_enum",
            "T1615",
            "discovery",
            "medium",
            Some("run_bloodhound"),
        ),
        (
            "detect_bloodhound_computer_enum",
            "T1018",
            "discovery",
            "medium",
            Some("run_bloodhound"),
        ),
        // ── Impacket Tool Fingerprints ──
        (
            "detect_impacket_wmiexec",
            "T1047",
            "execution",
            "high",
            Some("wmiexec"),
        ),
        (
            "detect_impacket_psexec",
            "T1569.002",
            "execution",
            "high",
            Some("psexec"),
        ),
        (
            "detect_impacket_smbexec",
            "T1569.002",
            "execution",
            "high",
            Some("smbexec"),
        ),
        (
            "detect_impacket_atexec",
            "T1053.002",
            "execution",
            "medium",
            Some("atexec"),
        ),
        (
            "detect_impacket_dcomexec",
            "T1021.003",
            "lateral_movement",
            "high",
            Some("dcomexec"),
        ),
        (
            "detect_impacket_secretsdump_sam",
            "T1003.002",
            "credential_access",
            "high",
            Some("secretsdump"),
        ),
        (
            "detect_impacket_secretsdump_lsa",
            "T1003.004",
            "credential_access",
            "high",
            Some("secretsdump"),
        ),
        (
            "detect_impacket_ntlmrelayx",
            "T1557.001",
            "credential_access",
            "high",
            Some("ntlmrelayx"),
        ),
        (
            "detect_impacket_smbclient",
            "T1021.002",
            "lateral_movement",
            "medium",
            Some("smbclient"),
        ),
        // ── Investigation ──
        ("get_host_activity", "-", "investigation", "-", None),
        ("get_user_activity", "-", "investigation", "-", None),
    ];

    let formatted: Vec<String> = templates
        .iter()
        .map(|(name, mitre, tactic, severity, tool)| {
            let tool_str = tool.unwrap_or("-");
            format!("- **{name}** [{mitre}] ({tactic}) severity={severity} tool={tool_str}")
        })
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

/// Get all activity for a specific host.
pub async fn get_host_activity(args: &Value) -> Result<ToolOutput> {
    let hostname = required_str(args, "hostname")?;
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1);
    let attack_patterns_only = args
        .get("attack_patterns_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let sel = build_selector(WIN_SECURITY, Some(hostname));

    let logql = if attack_patterns_only {
        let event_filter = build_event_filter(&[
            "4625", "4624", "4662", "4769", "4768", "5140", "7045", "4688",
        ]);
        format!("{sel}{event_filter}")
    } else {
        sel
    };

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    let query_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 1000,
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!(
        "## Host Activity: {hostname}\n**Query:** `{logql}`\n**Attack patterns only:** {attack_patterns_only}\n\n{}",
        result.stdout
    );
    Ok(result)
}

/// Get all activity for a specific user.
pub async fn get_user_activity(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1);

    let sel = build_selector(WIN_SECURITY, None);
    // Escape regex metacharacters in the username so that special characters
    // (e.g. `.`, `+`, `(`) do not corrupt the LogQL regex or match unintended lines.
    let escaped_username = regex::escape(username);
    let logql = format!(r#"{sel} |~ "(?i){escaped_username}""#);

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    let query_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 1000,
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!(
        "## User Activity: {username}\n**Query:** `{logql}`\n\n{}",
        result.stdout
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_selector_no_host() {
        let sel = build_selector(WIN_SECURITY, None);
        assert_eq!(sel, r#"{job="windows-security"}"#);
    }

    #[test]
    fn build_selector_with_host() {
        let sel = build_selector(WIN_SECURITY, Some("dc01"));
        assert_eq!(sel, r#"{job="windows-security", hostname=~"dc01"}"#);
    }

    #[test]
    fn event_filter_single() {
        assert_eq!(build_event_filter(&["4624"]), r#" |= "4624""#);
    }

    #[test]
    fn event_filter_multiple() {
        assert_eq!(
            build_event_filter(&["4624", "4625"]),
            r#" |~ "(4624|4625)""#
        );
    }

    #[test]
    fn event_filter_empty() {
        assert_eq!(build_event_filter(&[]), "");
    }

    #[test]
    fn pattern_filter_builds_case_insensitive() {
        let filter = build_pattern_filter(&["nmap", "masscan"]);
        assert_eq!(filter, r#" |~ "(?i)(nmap|masscan)""#);
    }

    #[test]
    fn pattern_filter_empty() {
        assert_eq!(build_pattern_filter(&[]), "");
    }

    #[test]
    fn all_templates_resolve() {
        let names = [
            "detect_port_scanning",
            "detect_user_enumeration",
            "detect_account_enumeration",
            "detect_share_enumeration",
            "detect_secretsdump",
            "detect_dcsync",
            "detect_dcsync_replication",
            "detect_kerberoasting",
            "detect_asrep_roasting",
            "detect_asrep_roasting_bulk",
            "detect_brute_force",
            "detect_password_spray",
            "detect_s4u_delegation",
            "detect_lsa_secrets_access",
            "detect_ntlm_relay",
            "detect_certificate_authentication",
            "detect_pass_the_hash",
            "detect_lateral_movement",
            "detect_smb_file_access",
            "detect_adcs_exploitation",
            "detect_certificate_abuse",
            "detect_delegation_abuse",
            "detect_golden_ticket",
            "detect_suspicious_execution",
            "detect_service_creation",
            "detect_scheduled_task",
            "detect_remote_registry_start",
            "detect_certipy_enumeration",
            "detect_esc1_attack",
            "detect_esc4_attack",
            "detect_esc8_attack",
            "detect_bloodhound",
            "detect_bloodhound_collection",
            "detect_bloodhound_domain_enum",
            "detect_bloodhound_acl_enum",
            "detect_bloodhound_session_enum",
            "detect_bloodhound_gpo_enum",
            "detect_bloodhound_computer_enum",
            "detect_impacket_wmiexec",
            "detect_impacket_psexec",
            "detect_impacket_smbexec",
            "detect_impacket_atexec",
            "detect_impacket_dcomexec",
            "detect_impacket_secretsdump_sam",
            "detect_impacket_secretsdump_lsa",
            "detect_impacket_ntlmrelayx",
            "detect_impacket_smbclient",
        ];
        for name in &names {
            assert!(
                build_detection_template(name, None).is_some(),
                "template {name} should resolve"
            );
        }
    }

    #[test]
    fn unknown_template_returns_none() {
        assert!(build_detection_template("detect_nonexistent", None).is_none());
    }

    #[test]
    fn template_with_host_includes_hostname() {
        let tmpl = build_detection_template("detect_kerberoasting", Some("dc01")).unwrap();
        assert!(tmpl.logql.contains(r#"hostname=~"dc01""#));
    }

    #[test]
    fn remote_registry_uses_system_log() {
        let tmpl = build_detection_template("detect_remote_registry_start", None).unwrap();
        assert!(tmpl.logql.contains("windows-system"));
        assert!(!tmpl.logql.contains("windows-security"));
    }

    #[test]
    fn aliases_produce_same_queries() {
        let a = build_detection_template("detect_brute_force", None).unwrap();
        let b = build_detection_template("detect_password_spray", None).unwrap();
        assert_eq!(a.logql, b.logql);

        let a = build_detection_template("detect_bloodhound", None).unwrap();
        let b = build_detection_template("detect_bloodhound_collection", None).unwrap();
        assert_eq!(a.logql, b.logql);

        let a = build_detection_template("detect_adcs_exploitation", None).unwrap();
        let b = build_detection_template("detect_certificate_abuse", None).unwrap();
        assert_eq!(a.logql, b.logql);
    }

    #[test]
    fn critical_templates_have_critical_severity() {
        let critical = [
            "detect_secretsdump",
            "detect_dcsync",
            "detect_dcsync_replication",
            "detect_s4u_delegation",
            "detect_golden_ticket",
            "detect_esc1_attack",
            "detect_esc8_attack",
        ];
        for name in &critical {
            let tmpl = build_detection_template(name, None).unwrap();
            assert_eq!(
                tmpl.severity, "critical",
                "{name} should be critical severity"
            );
        }
    }

    #[test]
    fn auto_pivot_templates() {
        let pivots = [
            "detect_pass_the_hash",
            "detect_lateral_movement",
            "detect_service_creation",
            "detect_impacket_wmiexec",
            "detect_impacket_psexec",
            "detect_impacket_smbexec",
            "detect_impacket_dcomexec",
        ];
        for name in &pivots {
            let tmpl = build_detection_template(name, None).unwrap();
            assert!(tmpl.auto_pivot, "{name} should have auto_pivot=true");
        }
    }

    #[test]
    fn header_format_includes_metadata() {
        let tmpl = build_detection_template("detect_kerberoasting", None).unwrap();
        let header = tmpl.format_header();
        assert!(header.contains("T1558.003"));
        assert!(header.contains("high"));
        assert!(header.contains("credential_access"));
        assert!(header.contains("kerberoast"));
    }
}
