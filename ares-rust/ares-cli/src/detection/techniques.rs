use std::collections::HashMap;

use chrono::{DateTime, Utc};

use ares_core::models::SharedRedTeamState;

use super::types::{PlaybookQuery, TechniqueDetection, TimeWindow};

pub(crate) fn get_technique_name(id: &str) -> &'static str {
    match id {
        "T1046" => "Network Service Discovery",
        "T1003" => "OS Credential Dumping",
        "T1003.001" => "LSASS Memory",
        "T1003.006" => "DCSync",
        "T1078" => "Valid Accounts",
        "T1078.002" => "Domain Accounts",
        "T1110" => "Brute Force",
        "T1558" => "Steal or Forge Kerberos Tickets",
        "T1558.001" => "Golden Ticket",
        "T1558.003" => "Kerberoasting",
        "T1558.004" => "AS-REP Roasting",
        "T1021" => "Remote Services",
        "T1021.002" => "SMB/Windows Admin Shares",
        "T1649" => "ADCS Certificate Theft",
        "T1550" => "Use Alternate Authentication Material",
        "T1550.002" => "Pass the Hash",
        "T1484" => "Domain Policy Modification",
        "T1087" => "Account Discovery",
        _ => "",
    }
}

pub(crate) fn pyramid_level_name(level: u8) -> &'static str {
    match level {
        1 => "Hash Values (L1)",
        2 => "IP Addresses (L2)",
        3 => "Domain Names (L3)",
        4 => "Network/Host Artifacts (L4)",
        5 => "Tools (L5)",
        6 => "TTPs (L6)",
        _ => "Unknown",
    }
}

fn make_time_window(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TimeWindow {
    TimeWindow {
        start: Some(start.to_rfc3339()),
        end: Some(end.to_rfc3339()),
    }
}

pub(crate) fn build_technique_detections(
    state: &SharedRedTeamState,
    techniques: &[String],
    attack_start: &DateTime<Utc>,
    attack_end: &DateTime<Utc>,
) -> HashMap<String, TechniqueDetection> {
    let mut detections = HashMap::new();

    for technique_id in techniques {
        let detection = match technique_id.as_str() {
            "T1046" => build_t1046(state, attack_start, attack_end),
            "T1003" => build_t1003(state, attack_start, attack_end),
            "T1003.001" => build_t1003_001(attack_start, attack_end),
            "T1003.006" => build_t1003_006(attack_start, attack_end),
            "T1078" => build_t1078(state, attack_start, attack_end),
            "T1078.002" => build_t1078_002(attack_start, attack_end),
            "T1110" => build_t1110(attack_start, attack_end),
            "T1558" => build_t1558(attack_start, attack_end),
            "T1558.001" => build_t1558_001(attack_start, attack_end),
            "T1558.003" => build_t1558_003(attack_start, attack_end),
            "T1021" => build_t1021(state, attack_start, attack_end),
            "T1021.002" => build_t1021_002(state, attack_start, attack_end),
            "T1649" => build_t1649(attack_start, attack_end),
            "T1550" => build_t1550(attack_start, attack_end),
            "T1550.002" => build_t1550_002(attack_start, attack_end),
            other => {
                // Try parent technique for sub-techniques
                let parent = other.split('.').next().unwrap_or(other);
                match parent {
                    "T1046" => build_t1046(state, attack_start, attack_end),
                    "T1003" => build_t1003(state, attack_start, attack_end),
                    "T1078" => build_t1078(state, attack_start, attack_end),
                    "T1558" => build_t1558(attack_start, attack_end),
                    "T1021" => build_t1021(state, attack_start, attack_end),
                    "T1550" => build_t1550(attack_start, attack_end),
                    _ => {
                        let name = get_technique_name(other);
                        let display_name = if name.is_empty() {
                            other.to_string()
                        } else {
                            name.to_string()
                        };
                        TechniqueDetection {
                            technique_id: other.to_string(),
                            technique_name: display_name,
                            description: format!("Technique {other} was used during the attack."),
                            occurred_at: vec![],
                            targets: vec![],
                            credentials_used: vec![],
                            detection_queries: vec![],
                            windows_event_ids: vec![],
                            log_sources: vec![],
                            detection_guidance: format!(
                                "Review MITRE ATT&CK documentation for {other} detection guidance."
                            ),
                        }
                    }
                }
            }
        };
        detections.insert(technique_id.clone(), detection);
    }
    detections
}

// ---- Individual technique detection builders ----

fn build_t1046(
    state: &SharedRedTeamState,
    start: &DateTime<Utc>,
    end: &DateTime<Utc>,
) -> TechniqueDetection {
    let targets: Vec<String> = state.all_hosts.iter().map(|h| h.ip.clone()).collect();
    TechniqueDetection {
        technique_id: "T1046".into(),
        technique_name: "Network Service Discovery".into(),
        description: "Attacker performed network scanning to discover hosts and services.".into(),
        occurred_at: vec![],
        targets,
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1046".into(),
            technique_name: "Network Scan Detection".into(),
            description: "Detect port scanning activity".into(),
            logql:
                r#"{job="firewall"} |~ "(?i)(scan|probe)" or {job="windows-security"} |= "5156""#
                    .into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "medium".into(),
            windows_event_ids: vec!["5156".into(), "5157".into()],
        }],
        windows_event_ids: vec!["5156".into(), "5157".into()],
        log_sources: vec![
            "firewall".into(),
            "windows-security".into(),
            "netflow".into(),
        ],
        detection_guidance: "Look for rapid connection attempts to multiple ports. \
            Monitor Windows Filtering Platform events (5156/5157) for connection patterns."
            .into(),
    }
}

fn build_t1003(
    state: &SharedRedTeamState,
    start: &DateTime<Utc>,
    end: &DateTime<Utc>,
) -> TechniqueDetection {
    let credentials_used: Vec<String> = state
        .all_credentials
        .iter()
        .take(5)
        .map(|c| {
            if c.domain.is_empty() {
                c.username.clone()
            } else {
                format!(r"{}\{}", c.domain, c.username)
            }
        })
        .collect();
    TechniqueDetection {
        technique_id: "T1003".into(),
        technique_name: "OS Credential Dumping".into(),
        description: "Attacker dumped credentials from the operating system.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used,
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1003".into(),
            technique_name: "Credential Dump Detection".into(),
            description: "Detect LSASS access or credential dumping tools".into(),
            logql: r#"{job="windows-security"} |~ "(?i)(lsass|mimikatz|procdump|secretsdump)""#
                .into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4624".into(), "4648".into(), "4672".into(), "1".into()],
        }],
        windows_event_ids: vec!["4624".into(), "4648".into(), "4672".into(), "10".into()],
        log_sources: vec!["windows-security".into(), "sysmon".into()],
        detection_guidance: "Monitor Sysmon Event ID 10 (ProcessAccess) for LSASS access. \
            Alert on known credential dumping tools in command lines."
            .into(),
    }
}

fn build_t1003_001(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1003.001".into(),
        technique_name: "LSASS Memory".into(),
        description: "Attacker accessed LSASS process memory to extract credentials.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1003.001".into(),
            technique_name: "LSASS Access Detection".into(),
            description: "Detect processes accessing LSASS memory".into(),
            logql: r#"{job="sysmon"} |= "10" |~ "(?i)lsass.exe" |~ "GrantedAccess""#.into(),
            label_selector: r#"{job="sysmon"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["10".into()],
        }],
        windows_event_ids: vec!["10".into()],
        log_sources: vec!["sysmon".into()],
        detection_guidance:
            "Sysmon Event ID 10 with TargetImage containing lsass.exe is highly suspicious. \
             Legitimate access typically comes from specific system processes only."
                .into(),
    }
}

fn build_t1003_006(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1003.006".into(),
        technique_name: "DCSync".into(),
        description: "Attacker used DCSync to replicate domain credentials.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1003.006".into(),
            technique_name: "DCSync Detection".into(),
            description: "Detect directory replication requests from non-DC".into(),
            logql: r#"{job="windows-security"} |= "4662" |~ "(?i)(1131f6aa|1131f6ad|89e95b76)""#
                .into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec!["Replicating Directory Changes requests".into()],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4662".into()],
        }],
        windows_event_ids: vec!["4662".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Monitor Event ID 4662 for DS-Replication-Get-Changes requests. \
             GUIDs: 1131f6aa (Get-Changes), 1131f6ad (Get-Changes-All). \
             Alert when source is not a domain controller."
            .into(),
    }
}

fn build_t1078(
    state: &SharedRedTeamState,
    start: &DateTime<Utc>,
    end: &DateTime<Utc>,
) -> TechniqueDetection {
    let credentials: Vec<String> = state
        .all_credentials
        .iter()
        .take(10)
        .map(|c| {
            if c.domain.is_empty() {
                c.username.clone()
            } else {
                format!(r"{}\{}", c.domain, c.username)
            }
        })
        .collect();
    TechniqueDetection {
        technique_id: "T1078".into(),
        technique_name: "Valid Accounts".into(),
        description: "Attacker used valid credentials for access.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: credentials,
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1078".into(),
            technique_name: "Account Usage Detection".into(),
            description: "Detect authentication from compromised accounts".into(),
            logql: r#"{job="windows-security"} |~ "(4624|4625)" |~ "LogonType.*(3|10)""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "high".into(),
            windows_event_ids: vec!["4624".into(), "4625".into()],
        }],
        windows_event_ids: vec!["4624".into(), "4625".into(), "4648".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance:
            "Monitor authentication events for unusual source IPs, times, or logon types. \
             Implement impossible travel detection for user accounts."
                .into(),
    }
}

fn build_t1078_002(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1078.002".into(),
        technique_name: "Domain Accounts".into(),
        description: "Attacker used domain account credentials.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1078.002".into(),
            technique_name: "Domain Account Abuse".into(),
            description: "Detect domain admin or privileged account usage".into(),
            logql: r#"{job="windows-security"} |= "4672" |~ "(?i)admin""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4672".into(), "4624".into()],
        }],
        windows_event_ids: vec!["4672".into(), "4624".into(), "4648".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Monitor Event ID 4672 (special privileges assigned). \
             Alert on Domain Admin logons from unusual sources."
            .into(),
    }
}

fn build_t1110(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1110".into(),
        technique_name: "Brute Force".into(),
        description: "Attacker attempted credential guessing attacks.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1110".into(),
            technique_name: "Brute Force Detection".into(),
            description: "Detect multiple failed authentication attempts".into(),
            logql: r#"{job="windows-security"} |= "4625""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec!["Multiple failed logon attempts".into()],
            time_window: make_time_window(start, end),
            priority: "high".into(),
            windows_event_ids: vec!["4625".into()],
        }],
        windows_event_ids: vec!["4625".into(), "4771".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Count Event ID 4625 per source IP and username. \
             Alert on >5 failures in 5 minutes from same source."
            .into(),
    }
}

fn build_t1558(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1558".into(),
        technique_name: "Steal or Forge Kerberos Tickets".into(),
        description: "Attacker manipulated Kerberos tickets for access.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1558".into(),
            technique_name: "Kerberos Attack Detection".into(),
            description: "Detect suspicious Kerberos ticket requests".into(),
            logql: r#"{job="windows-security"} |~ "(4768|4769)" |~ "(?i)(RC4|0x17)""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4768".into(), "4769".into()],
        }],
        windows_event_ids: vec!["4768".into(), "4769".into(), "4770".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Monitor for TGS requests with RC4 encryption (Kerberoasting). \
             Alert on TGT requests without pre-authentication (AS-REP Roasting)."
            .into(),
    }
}

fn build_t1558_001(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1558.001".into(),
        technique_name: "Golden Ticket".into(),
        description: "Attacker forged a Kerberos TGT using the krbtgt hash.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1558.001".into(),
            technique_name: "Golden Ticket Detection".into(),
            description: "Detect forged TGT usage patterns".into(),
            logql: r#"{job="windows-security"} |= "4769" |~ "(?i)krbtgt""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![
                "TGS requests for krbtgt".into(),
                "Unusual ticket lifetimes".into(),
            ],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4769".into()],
        }],
        windows_event_ids: vec!["4768".into(), "4769".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Golden Tickets have unusual properties: long lifetimes, \
             non-standard encryption, requests from unusual clients. \
             Compare TGT properties against normal baselines."
            .into(),
    }
}

fn build_t1558_003(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1558.003".into(),
        technique_name: "Kerberoasting".into(),
        description: "Attacker requested service tickets for offline cracking.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1558.003".into(),
            technique_name: "Kerberoasting Detection".into(),
            description: "Detect TGS requests with RC4 encryption".into(),
            logql: r#"{job="windows-security"} |= "4769" |~ "(?i)(0x17|RC4)""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec!["TGS requests with RC4-HMAC encryption".into()],
            time_window: make_time_window(start, end),
            priority: "high".into(),
            windows_event_ids: vec!["4769".into()],
        }],
        windows_event_ids: vec!["4769".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Monitor Event ID 4769 for encryption type 0x17 (RC4-HMAC). \
             Modern environments should use AES. Alert on RC4 TGS requests."
            .into(),
    }
}

fn build_t1021(
    state: &SharedRedTeamState,
    start: &DateTime<Utc>,
    end: &DateTime<Utc>,
) -> TechniqueDetection {
    let targets: Vec<String> = state.all_hosts.iter().map(|h| h.ip.clone()).collect();
    TechniqueDetection {
        technique_id: "T1021".into(),
        technique_name: "Remote Services".into(),
        description: "Attacker used remote services for lateral movement.".into(),
        occurred_at: vec![],
        targets,
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1021".into(),
            technique_name: "Remote Service Usage".into(),
            description: "Detect lateral movement via remote services".into(),
            logql: r#"{job="windows-security"} |= "4624" |~ "LogonType.*(3|10)""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "high".into(),
            windows_event_ids: vec!["4624".into()],
        }],
        windows_event_ids: vec!["4624".into(), "4648".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Monitor Type 3 (network) and Type 10 (remote interactive) logons. \
             Correlate with process execution for lateral movement detection."
            .into(),
    }
}

fn build_t1021_002(
    state: &SharedRedTeamState,
    start: &DateTime<Utc>,
    end: &DateTime<Utc>,
) -> TechniqueDetection {
    let targets: Vec<String> = state.all_hosts.iter().map(|h| h.ip.clone()).collect();
    let shares: Vec<String> = state
        .all_shares
        .iter()
        .take(5)
        .map(|s| format!("{}:{}", s.host, s.name))
        .collect();
    TechniqueDetection {
        technique_id: "T1021.002".into(),
        technique_name: "SMB/Windows Admin Shares".into(),
        description: "Attacker accessed admin shares for lateral movement.".into(),
        occurred_at: vec![],
        targets,
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1021.002".into(),
            technique_name: "Admin Share Access".into(),
            description: r#"Detect access to C$, ADMIN$, IPC$ shares"#.into(),
            logql: r#"{job="windows-security"} |= "5140" |~ "(?i)(C\$|ADMIN\$|IPC\$)""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: shares
                .iter()
                .map(|s| format!("Share access: {s}"))
                .collect(),
            time_window: make_time_window(start, end),
            priority: "high".into(),
            windows_event_ids: vec!["5140".into(), "5145".into()],
        }],
        windows_event_ids: vec!["5140".into(), "5145".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Monitor Event ID 5140/5145 for admin share access. \
             Alert on C$, ADMIN$, or IPC$ access from non-admin workstations."
            .into(),
    }
}

fn build_t1649(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1649".into(),
        technique_name: "Steal or Forge Authentication Certificates".into(),
        description: "Attacker exploited AD Certificate Services.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1649".into(),
            technique_name: "ADCS Attack Detection".into(),
            description: "Detect suspicious certificate requests".into(),
            logql: r#"{job="windows-security"} |~ "(4886|4887)" |~ "(?i)certificate""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4886".into(), "4887".into()],
        }],
        windows_event_ids: vec!["4886".into(), "4887".into(), "4768".into()],
        log_sources: vec!["windows-security".into(), "ad-cs".into()],
        detection_guidance: "Monitor certificate enrollment events (4886/4887). \
             Alert on certificate requests with unusual templates or SANs. \
             Watch for ESC1-ESC8 vulnerability patterns."
            .into(),
    }
}

fn build_t1550(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1550".into(),
        technique_name: "Use Alternate Authentication Material".into(),
        description: "Attacker used stolen authentication material (hashes, tickets).".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1550".into(),
            technique_name: "Auth Material Abuse".into(),
            description: "Detect pass-the-hash or ticket reuse".into(),
            logql: r#"{job="windows-security"} |= "4624" |~ "NTLM" |~ "LogonType.*3""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4624".into()],
        }],
        windows_event_ids: vec!["4624".into(), "4648".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Monitor for NTLM authentication anomalies. \
             Pass-the-hash often shows as Type 3 logon with NTLM package."
            .into(),
    }
}

fn build_t1550_002(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
    TechniqueDetection {
        technique_id: "T1550.002".into(),
        technique_name: "Pass the Hash".into(),
        description: "Attacker used NTLM hashes for authentication.".into(),
        occurred_at: vec![],
        targets: vec![],
        credentials_used: vec![],
        detection_queries: vec![PlaybookQuery {
            technique_id: "T1550.002".into(),
            technique_name: "Pass-the-Hash Detection".into(),
            description: "Detect NTLM Type 3 logons indicating PtH".into(),
            logql: r#"{job="windows-security"} |= "4624" |~ "NTLM" |~ "LogonType.*3""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec!["Network logon with NTLM authentication".into()],
            time_window: make_time_window(start, end),
            priority: "critical".into(),
            windows_event_ids: vec!["4624".into()],
        }],
        windows_event_ids: vec!["4624".into()],
        log_sources: vec!["windows-security".into()],
        detection_guidance: "Pass-the-Hash shows as Event 4624 with LogonType 3 and NTLM package. \
             Correlate with process creation to detect lateral movement chains."
            .into(),
    }
}
