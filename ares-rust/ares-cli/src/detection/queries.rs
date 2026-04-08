use chrono::{DateTime, Utc};

use ares_core::models::SharedRedTeamState;

use super::types::{PlaybookQuery, TimeWindow};

fn make_time_window(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TimeWindow {
    TimeWindow {
        start: Some(start.to_rfc3339()),
        end: Some(end.to_rfc3339()),
    }
}

pub(crate) fn build_priority_queries(
    state: &SharedRedTeamState,
    techniques: &[String],
    attack_start: &DateTime<Utc>,
    attack_end: &DateTime<Utc>,
) -> Vec<PlaybookQuery> {
    let mut queries = Vec::new();

    // 1. Domain Admin detection (highest priority if achieved)
    if state.has_domain_admin {
        queries.push(PlaybookQuery {
            technique_id: "T1078.002".into(),
            technique_name: "Domain Admin Access".into(),
            description: "Detect Domain Admin logon events".into(),
            logql: r#"{job="windows-security"} |= "4672" |~ "(?i)(Domain Admins|Administrator)""#
                .into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec!["Special privileges assigned to new logon".into()],
            time_window: make_time_window(attack_start, attack_end),
            priority: "critical".into(),
            windows_event_ids: vec!["4672".into(), "4624".into()],
        });
    }

    // 2. Credential dumping detection
    if !state.all_hashes.is_empty() {
        let usernames: Vec<&str> = state
            .all_hashes
            .iter()
            .take(5)
            .map(|h| h.username.as_str())
            .collect();
        let username_pattern = usernames.join("|");
        queries.push(PlaybookQuery {
            technique_id: "T1003".into(),
            technique_name: "Credential Dumping".into(),
            description: format!(
                "Detect credential access for dumped accounts: {}",
                usernames.join(", ")
            ),
            logql: format!(
                r#"{{job="windows-security"}} |~ "(?i)(4624|4648)" |~ "(?i)({username_pattern})""#
            ),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: usernames
                .iter()
                .map(|u| format!("Logon events for {u}"))
                .collect(),
            time_window: make_time_window(attack_start, attack_end),
            priority: "critical".into(),
            windows_event_ids: vec!["4624".into(), "4648".into(), "4672".into()],
        });
    }

    // 3. Lateral movement detection
    if state.all_hosts.len() > 1 {
        let host_ips: Vec<&str> = state
            .all_hosts
            .iter()
            .take(5)
            .map(|h| h.ip.as_str())
            .collect();
        let ip_pattern = host_ips.join("|");
        queries.push(PlaybookQuery {
            technique_id: "T1021.002".into(),
            technique_name: "Lateral Movement via SMB".into(),
            description: "Detect lateral movement to discovered hosts".into(),
            logql: format!(
                r#"{{job="windows-security"}} |= "4624" |~ "LogonType.*(3|10)" |~ "({ip_pattern})""#
            ),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec!["Network logon (Type 3) events".into()],
            time_window: make_time_window(attack_start, attack_end),
            priority: "high".into(),
            windows_event_ids: vec!["4624".into(), "4648".into()],
        });
    }

    // 4. Kerberos attack detection
    if techniques.iter().any(|t| t.starts_with("T1558")) {
        queries.push(PlaybookQuery {
            technique_id: "T1558".into(),
            technique_name: "Kerberos Ticket Attacks".into(),
            description: "Detect Kerberoasting, AS-REP Roasting, or Golden Ticket".into(),
            logql: r#"{job="windows-security"} |~ "(4768|4769)" |~ "(?i)(RC4|0x17|0x18)""#.into(),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![
                "TGS requests with RC4 encryption (Kerberoasting indicator)".into()
            ],
            time_window: make_time_window(attack_start, attack_end),
            priority: "high".into(),
            windows_event_ids: vec!["4768".into(), "4769".into()],
        });
    }

    // 5. Network discovery detection
    queries.push(PlaybookQuery {
        technique_id: "T1046".into(),
        technique_name: "Network Service Discovery".into(),
        description: "Detect network scanning activity".into(),
        logql:
            r#"{job="firewall"} |~ "(?i)(scan|nmap|masscan)" or {job="windows-security"} |= "5156""#
                .into(),
        label_selector: r#"{job="windows-security"}"#.into(),
        expected_evidence: vec![
            "Firewall connection events".into(),
            "Port scan patterns".into(),
        ],
        time_window: make_time_window(attack_start, attack_end),
        priority: "medium".into(),
        windows_event_ids: vec!["5156".into()],
    });

    // 6. Compromised account activity (top 3)
    for cred in state.all_credentials.iter().take(3) {
        let account = if cred.domain.is_empty() {
            cred.username.clone()
        } else {
            format!(r"{}\{}", cred.domain, cred.username)
        };
        queries.push(PlaybookQuery {
            technique_id: "T1078".into(),
            technique_name: "Valid Account Usage".into(),
            description: format!("Detect activity from compromised account: {account}"),
            logql: format!(
                r#"{{job="windows-security"}} |~ "(?i)(4624|4625|4648|4672)" |~ "(?i){}""#,
                cred.username
            ),
            label_selector: r#"{job="windows-security"}"#.into(),
            expected_evidence: vec![format!("Authentication events for {account}")],
            time_window: make_time_window(attack_start, attack_end),
            priority: "high".into(),
            windows_event_ids: vec!["4624".into(), "4625".into(), "4648".into(), "4672".into()],
        });
    }

    // Sort by priority
    let priority_order = |p: &str| -> u8 {
        match p {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    };
    queries.sort_by_key(|q| priority_order(&q.priority));

    queries
}
