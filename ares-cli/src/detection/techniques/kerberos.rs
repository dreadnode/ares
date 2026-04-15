use chrono::{DateTime, Utc};

use super::super::types::{PlaybookQuery, TechniqueDetection};
use super::builders::make_time_window;

pub(super) fn build_t1558(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1558_001(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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

pub(super) fn build_t1558_003(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TechniqueDetection {
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
