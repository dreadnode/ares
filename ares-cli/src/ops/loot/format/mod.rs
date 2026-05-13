mod display;
mod hosts;
mod json;
mod report_filter;

use ares_core::models::SharedRedTeamState;

use crate::dedup::{normalize_state_domains, sanitize_credentials};

/// Format a duration as a human-readable string (e.g. "1h 23m 45s").
pub(super) fn format_duration(dur: chrono::Duration) -> String {
    let total_secs = dur.num_seconds();
    if total_secs < 0 {
        return "0s".to_string();
    }
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

pub(crate) fn print_loot(state: &SharedRedTeamState, json_output: bool) {
    let mut credentials = state.all_credentials.clone();
    let mut hashes = state.all_hashes.clone();
    let mut domains: Vec<String> = state.all_domains.clone();

    sanitize_credentials(&mut credentials);

    let target_domain = state.target.as_ref().map(|t| t.domain.as_str());

    normalize_state_domains(
        &state.all_users,
        &mut credentials,
        &mut hashes,
        &mut domains,
        &state.all_hosts,
        target_domain,
    );

    if json_output {
        json::print_loot_json(state, &credentials, &hashes, &domains);
    } else {
        display::print_loot_human(state, &credentials, &hashes, &domains);
    }
}

/// Compact runtime view: DA/GT banner + per-domain breakdown + host/DC count.
/// Shares the normalization pipeline with `print_loot` so the two views agree.
pub(crate) fn print_runtime_summary(state: &SharedRedTeamState) {
    let mut credentials = state.all_credentials.clone();
    let mut hashes = state.all_hashes.clone();
    let mut domains: Vec<String> = state.all_domains.clone();

    sanitize_credentials(&mut credentials);

    let target_domain = state.target.as_ref().map(|t| t.domain.as_str());

    normalize_state_domains(
        &state.all_users,
        &mut credentials,
        &mut hashes,
        &mut domains,
        &state.all_hosts,
        target_domain,
    );

    display::print_runtime_summary(state, &credentials, &hashes, &domains);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_zero() {
        assert_eq!(format_duration(chrono::Duration::zero()), "0s");
    }

    #[test]
    fn duration_seconds_only() {
        assert_eq!(format_duration(chrono::Duration::seconds(45)), "45s");
    }

    #[test]
    fn duration_minutes_and_seconds() {
        assert_eq!(format_duration(chrono::Duration::seconds(125)), "2m 05s");
    }

    #[test]
    fn duration_hours_minutes_seconds() {
        assert_eq!(
            format_duration(chrono::Duration::seconds(3723)),
            "1h 02m 03s"
        );
    }

    #[test]
    fn duration_exact_hour() {
        assert_eq!(
            format_duration(chrono::Duration::seconds(3600)),
            "1h 00m 00s"
        );
    }

    #[test]
    fn duration_exact_minute() {
        assert_eq!(format_duration(chrono::Duration::seconds(60)), "1m 00s");
    }

    #[test]
    fn duration_negative() {
        assert_eq!(format_duration(chrono::Duration::seconds(-10)), "0s");
    }

    #[test]
    fn duration_large() {
        assert_eq!(
            format_duration(chrono::Duration::seconds(86400 + 3661)),
            "25h 01m 01s"
        );
    }
}
