//! MITRE ATT&CK technique lookup.

use std::collections::HashMap;

use std::sync::LazyLock;

const MITRE_TECHNIQUES_YAML: &str = include_str!("data/mitre_techniques.yaml");

#[derive(Debug, serde::Deserialize)]
struct TechniqueEntry {
    name: String,
    tactic: String,
}

static MITRE_TECHNIQUES: LazyLock<HashMap<String, TechniqueEntry>> = LazyLock::new(|| {
    serde_yaml::from_str::<HashMap<String, TechniqueEntry>>(MITRE_TECHNIQUES_YAML)
        .unwrap_or_default()
});

fn lookup(technique_id: &str) -> Option<&'static TechniqueEntry> {
    MITRE_TECHNIQUES.get(technique_id).or_else(|| {
        // An unlisted sub-technique still belongs to its parent's tactic, and
        // reporting the parent's name beats reporting nothing.
        technique_id
            .split_once('.')
            .and_then(|(parent, _)| MITRE_TECHNIQUES.get(parent))
    })
}

/// Get a display string for a MITRE technique ID (e.g. "T1003.006 (DCSync)").
///
/// Uses the same parent fallback as [`get_technique_tactic`], so an unlisted
/// sub-technique renders under its parent's name rather than as a bare ID.
pub fn get_technique_display(technique_id: &str) -> String {
    match lookup(technique_id) {
        Some(e) => format!("{technique_id} ({})", e.name),
        None => technique_id.to_string(),
    }
}

/// Get the human-readable name for a MITRE technique ID, if known.
///
/// Falls back to the parent technique's name for an unlisted sub-technique.
/// Resolving the tactic but not the name left report rows half-populated — a
/// known tactic beside a bare `T1558.999` — which is the gap [`lookup`] exists
/// to close.
pub fn get_technique_name(technique_id: &str) -> Option<&'static str> {
    lookup(technique_id).map(|e| e.name.as_str())
}

/// Get the ATT&CK tactic a technique is attributed to.
///
/// Falls back to the parent technique's tactic for an unlisted sub-technique,
/// and to `Unknown` only when neither is known — a report that labels every
/// technique `Unknown` tells the reader nothing about attack-lifecycle spread.
pub fn get_technique_tactic(technique_id: &str) -> &'static str {
    lookup(technique_id).map_or("Unknown", |e| e.tactic.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_display_known_id() {
        let display = get_technique_display("T1003");
        assert!(display.starts_with("T1003"));
        assert!(display.contains('('));
    }

    #[test]
    fn technique_display_unknown_id_returns_raw() {
        let display = get_technique_display("T9999.999");
        assert_eq!(display, "T9999.999");
    }

    #[test]
    fn technique_display_empty_string() {
        let display = get_technique_display("");
        assert_eq!(display, "");
    }

    #[test]
    fn mitre_techniques_map_loads() {
        let _ = MITRE_TECHNIQUES.len();
    }

    #[test]
    fn tactic_lookup_resolves_known_techniques() {
        assert_eq!(get_technique_tactic("T1003.006"), "Credential Access");
        assert_eq!(get_technique_tactic("T1021.002"), "Lateral Movement");
        assert_eq!(get_technique_tactic("T1134.005"), "Privilege Escalation");
        assert_eq!(get_technique_tactic("T1505"), "Persistence");
    }

    #[test]
    fn unlisted_sub_technique_inherits_its_parent_tactic() {
        assert!(!MITRE_TECHNIQUES.contains_key("T1558.999"));
        assert_eq!(get_technique_tactic("T1558.999"), "Credential Access");
    }

    #[test]
    fn unlisted_sub_technique_inherits_its_parent_name() {
        // The tactic fallback alone left report rows half-populated: a
        // resolved tactic beside a bare `T1558.999` where a name belongs.
        assert!(!MITRE_TECHNIQUES.contains_key("T1558.999"));
        assert_eq!(
            get_technique_name("T1558.999"),
            get_technique_name("T1558"),
            "an unlisted sub-technique must resolve to its parent's name"
        );
        assert!(get_technique_display("T1558.999").starts_with("T1558.999 ("));
    }

    #[test]
    fn wholly_unknown_technique_has_no_name_and_renders_bare() {
        assert_eq!(get_technique_name("T9999"), None);
        assert_eq!(get_technique_display("T9999"), "T9999");
        // A parent that is itself uncatalogued must not invent a name.
        assert_eq!(get_technique_name("T9999.001"), None);
    }

    #[test]
    fn wholly_unknown_technique_is_unknown() {
        assert_eq!(get_technique_tactic("T9999"), "Unknown");
        assert_eq!(get_technique_tactic(""), "Unknown");
    }

    #[test]
    fn every_catalogued_technique_has_a_name_and_tactic() {
        assert!(
            MITRE_TECHNIQUES.len() >= 60,
            "catalog looks truncated: {}",
            MITRE_TECHNIQUES.len()
        );
        for (id, entry) in MITRE_TECHNIQUES.iter() {
            assert!(!entry.name.trim().is_empty(), "{id} has no name");
            assert!(!entry.tactic.trim().is_empty(), "{id} has no tactic");
            assert_ne!(entry.tactic, "Unknown", "{id} is catalogued as Unknown");
        }
    }

    #[test]
    fn techniques_ares_actually_reports_are_all_catalogued() {
        // Observed across live operations; an uncatalogued one renders as a
        // bare ID with tactic Unknown, which is the gap this data file closes.
        for id in [
            "T1003",
            "T1003.002",
            "T1003.006",
            "T1021",
            "T1021.002",
            "T1046",
            "T1078",
            "T1078.002",
            "T1087.002",
            "T1110",
            "T1134",
            "T1134.001",
            "T1134.005",
            "T1135",
            "T1210",
            "T1505",
            "T1550.002",
            "T1550.003",
            "T1552",
            "T1558",
            "T1558.001",
            "T1558.003",
            "T1558.004",
            "T1569.002",
            "T1615",
            "T1649",
        ] {
            assert_ne!(get_technique_tactic(id), "Unknown", "{id} uncatalogued");
            assert!(get_technique_name(id).is_some(), "{id} has no name");
        }
    }
}
