use std::collections::HashMap;

use chrono::{DateTime, Utc};

use ares_core::models::SharedRedTeamState;

use super::super::types::{TechniqueDetection, TimeWindow};
use super::credential::{
    build_t1003, build_t1003_001, build_t1003_006, build_t1078, build_t1078_002, build_t1110,
};
use super::kerberos::{build_t1558, build_t1558_001, build_t1558_003};
use super::lateral::{
    build_t1021, build_t1021_002, build_t1046, build_t1550, build_t1550_002, build_t1649,
};
use super::names::get_technique_name;

pub(super) fn make_time_window(start: &DateTime<Utc>, end: &DateTime<Utc>) -> TimeWindow {
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
