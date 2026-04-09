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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration_seconds_only() {
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(60), "1m 0s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
        assert_eq!(format_duration(7200), "2h 0m 0s");
    }

    #[test]
    fn test_parse_datetime_rfc3339() {
        let dt = parse_datetime("2026-04-08T12:00:00+00:00").unwrap();
        assert_eq!(dt.year(), 2026);
    }

    #[test]
    fn test_parse_datetime_with_z() {
        let dt = parse_datetime("2026-04-08T12:00:00Z").unwrap();
        assert_eq!(dt.month(), 4);
    }

    #[test]
    fn test_parse_datetime_naive() {
        let dt = parse_datetime("2026-04-08T12:00:00.000").unwrap();
        assert_eq!(dt.day(), 8);
    }

    #[test]
    fn test_parse_datetime_invalid() {
        assert!(parse_datetime("not-a-date").is_err());
    }

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_long() {
        assert_eq!(truncate_str("hello world", 5), "hello...");
    }

    #[test]
    fn test_compute_duration_str_completed() {
        let start = Utc::now() - chrono::Duration::seconds(120);
        let end = Utc::now();
        let s = compute_duration_str(start, Some(end));
        assert!(s.contains("2m"));
    }

    #[test]
    fn test_compute_duration_str_running() {
        let start = Utc::now() - chrono::Duration::seconds(30);
        let s = compute_duration_str(start, None);
        assert!(s.contains("(running)"));
    }

    use chrono::Datelike;
}
