//! Detection template metadata and builder.

use super::{build_event_filter, build_pattern_filter, build_selector, WIN_SECURITY, WIN_SYSTEM};

// ─── Template metadata ─────────────────────────────────────────────────────

pub(super) struct DetectionTemplate {
    pub(super) logql: String,
    pub(super) description: &'static str,
    pub(super) mitre_id: &'static str,
    pub(super) tactic: &'static str,
    pub(super) severity: &'static str,
    pub(super) red_team_tool: Option<&'static str>,
    pub(super) auto_pivot: bool,
}

impl DetectionTemplate {
    pub(super) fn format_header(&self) -> String {
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

pub(super) fn build_detection_template(
    name: &str,
    host: Option<&str>,
) -> Option<DetectionTemplate> {
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
