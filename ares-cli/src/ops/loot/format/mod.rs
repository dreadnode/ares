mod display;
mod hosts;
mod json;

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
