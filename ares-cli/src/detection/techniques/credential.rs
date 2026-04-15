use chrono::{DateTime, Utc};

use ares_core::models::SharedRedTeamState;

use super::super::types::{PlaybookQuery, TechniqueDetection};
use super::builders::make_time_window;

pub(super) fn build_t1003(
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

pub(super) fn build_t1003_001(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1003_006(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1078(
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

pub(super) fn build_t1078_002(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1110(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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
