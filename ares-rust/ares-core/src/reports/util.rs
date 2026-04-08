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
