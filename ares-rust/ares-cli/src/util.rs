use anyhow::Result;
use chrono::{DateTime, Utc};

pub(crate) fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

pub(crate) fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    let fixed = s.replace('Z', "+00:00");
    DateTime::parse_from_rfc3339(&fixed)
        .or_else(|_| DateTime::parse_from_rfc3339(s))
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|ndt| ndt.and_utc())
        })
        .map_err(|e| anyhow::anyhow!("Failed to parse datetime '{s}': {e}"))
}

pub(crate) fn truncate_str(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{truncated}...")
    }
}

pub(crate) fn compute_duration_str(
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
) -> String {
    let seconds = if let Some(completed) = completed_at {
        (completed - started_at).num_seconds().max(0) as u64
    } else {
        (Utc::now() - started_at).num_seconds().max(0) as u64
    };

    if completed_at.is_none() {
        format!("{} (running)", format_duration(seconds))
    } else {
        format_duration(seconds)
    }
}
