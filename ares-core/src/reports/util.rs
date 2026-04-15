//! Report utility functions.

use super::context::TimelineEventCtx;
pub(crate) fn timeline_event_from_json(event: &serde_json::Value) -> TimelineEventCtx {
    let ts = event
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let desc = event
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let mitre_arr = event
        .get("mitre_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let confidence = event
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    TimelineEventCtx {
        timestamp: ts,
        description_short: if desc.chars().count() > 60 {
            let truncated: String = desc.chars().take(60).collect();
            format!("{truncated}...")
        } else {
            desc.clone()
        },
        description: desc,
        mitre_display: if mitre_arr.is_empty() {
            "-".to_string()
        } else {
            mitre_arr.join(", ")
        },
        mitre_techniques: mitre_arr,
        confidence_display: format!("{:.0}%", confidence * 100.0),
    }
}

/// Format a chrono Duration as "Xh Ym Zs".
pub(crate) fn format_duration_chrono(duration: chrono::Duration) -> String {
    let total_seconds = duration.num_seconds().max(0) as u64;
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours}:{minutes:02}:{seconds:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_timeline_event_from_json_full() {
        let event = json!({
            "timestamp": "2026-04-08T12:00:00Z",
            "description": "Credential dumped via secretsdump",
            "mitre_techniques": ["T1003", "T1003.006"],
            "confidence": 0.95,
        });
        let ctx = timeline_event_from_json(&event);
        assert_eq!(ctx.timestamp, "2026-04-08T12:00:00Z");
        assert_eq!(ctx.description, "Credential dumped via secretsdump");
        assert_eq!(ctx.description_short, "Credential dumped via secretsdump");
        assert_eq!(ctx.mitre_display, "T1003, T1003.006");
        assert_eq!(ctx.mitre_techniques.len(), 2);
        assert_eq!(ctx.confidence_display, "95%");
    }

    #[test]
    fn test_timeline_event_from_json_defaults() {
        let event = json!({});
        let ctx = timeline_event_from_json(&event);
        assert_eq!(ctx.timestamp, "-");
        assert_eq!(ctx.description, "-");
        assert_eq!(ctx.mitre_display, "-");
        assert_eq!(ctx.confidence_display, "0%");
    }

    #[test]
    fn test_timeline_event_long_description_truncated() {
        let long_desc = "A".repeat(100);
        let event = json!({"description": long_desc});
        let ctx = timeline_event_from_json(&event);
        assert_eq!(ctx.description_short.len(), 63); // 60 chars + "..."
        assert!(ctx.description_short.ends_with("..."));
        assert_eq!(ctx.description.len(), 100); // full preserved
    }

    #[test]
    fn test_format_duration_chrono_zero() {
        let d = chrono::Duration::seconds(0);
        assert_eq!(format_duration_chrono(d), "0:00:00");
    }

    #[test]
    fn test_format_duration_chrono_minutes() {
        let d = chrono::Duration::seconds(150);
        assert_eq!(format_duration_chrono(d), "0:02:30");
    }

    #[test]
    fn test_format_duration_chrono_hours() {
        let d = chrono::Duration::seconds(3661);
        assert_eq!(format_duration_chrono(d), "1:01:01");
    }

    #[test]
    fn test_format_duration_chrono_negative_clamped() {
        let d = chrono::Duration::seconds(-10);
        assert_eq!(format_duration_chrono(d), "0:00:00");
    }
}
