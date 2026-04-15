use chrono::{DateTime, Utc};

use ares_core::models::SharedRedTeamState;

use super::super::types::{PlaybookQuery, TechniqueDetection};
use super::builders::make_time_window;

pub(super) fn build_t1021(
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

pub(super) fn build_t1021_002(
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

pub(super) fn build_t1649(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1550(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1550_002(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1046(
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
