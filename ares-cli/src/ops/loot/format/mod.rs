mod display;
mod hosts;
mod json;
mod report_filter;

use ares_core::models::SharedRedTeamState;

use self::report_filter::{is_reportable_credential, is_reportable_hash};
use crate::dedup::{
    dedup_credentials, dedup_hashes, normalize_state_domains, sanitize_credentials,
};

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
    let domains = display::canonicalize_display_domains(&domains, &state.netbios_to_fqdn);

    if json_output {
        json::print_loot_json(state, &credentials, &hashes, &domains);
    } else {
        display::print_loot_human(state, &credentials, &hashes, &domains);
    }
}

/// Vulnerability counts split the same way `ops loot` tables them.
///
/// `orphan_credits` is the number of ids in `exploited_vulnerabilities` with no
/// matching record in `discovered_vulnerabilities`. Those ids are credited by
/// primitives that never emit a vulnerability record, so folding them into a
/// single "exploited" total reports successes that no view can itemise.
pub(crate) struct VulnCounts {
    pub exploitable: usize,
    pub exploitable_exploited: usize,
    pub findings: usize,
    pub findings_exploited: usize,
    pub orphan_credits: usize,
}

pub(crate) fn vulnerability_counts(state: &SharedRedTeamState) -> VulnCounts {
    let mut counts = VulnCounts {
        exploitable: 0,
        exploitable_exploited: 0,
        findings: 0,
        findings_exploited: 0,
        orphan_credits: 0,
    };

    for (id, vuln) in &state.discovered_vulnerabilities {
        let exploited = state.exploited_vulnerabilities.contains(id);
        if display::is_exploitable(vuln) {
            counts.exploitable += 1;
            counts.exploitable_exploited += usize::from(exploited);
        } else {
            counts.findings += 1;
            counts.findings_exploited += usize::from(exploited);
        }
    }

    counts.orphan_credits = state
        .exploited_vulnerabilities
        .iter()
        .filter(|id| !state.discovered_vulnerabilities.contains_key(*id))
        .count();

    counts
}

/// Credential and hash counts that match what `ops loot --json` would surface
/// in its `credentials` and `hashes` arrays — i.e. after the normalize → dedup
/// → report-filter pipeline. `ops runtime` uses these so its headline numbers
/// agree with the JSON view consumed by external scoreboards.
pub(crate) fn reportable_counts(state: &SharedRedTeamState) -> (usize, usize) {
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

    let unique_creds = dedup_credentials(&credentials);
    let unique_hashes = dedup_hashes(&hashes);

    let cred_count = unique_creds
        .iter()
        .filter(|c| is_reportable_credential(c))
        .count();
    let hash_count = unique_hashes
        .iter()
        .filter(|h| is_reportable_hash(h))
        .count();
    (cred_count, hash_count)
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
    let domains = display::canonicalize_display_domains(&domains, &state.netbios_to_fqdn);

    display::print_runtime_summary(state, &credentials, &hashes, &domains);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Hash, VulnerabilityInfo};

    fn mk_vuln(id: &str, priority: i32) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: "adcs_esc8".to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "recon-1".to_string(),
            discovered_at: chrono::Utc::now(),
            details: std::collections::HashMap::new(),
            recommended_agent: String::new(),
            priority,
        }
    }

    fn state_with_vulns(vulns: &[(&str, i32)], exploited: &[&str]) -> SharedRedTeamState {
        let mut state = SharedRedTeamState::new("op-test".to_string());
        for (id, priority) in vulns {
            state
                .discovered_vulnerabilities
                .insert((*id).to_string(), mk_vuln(id, *priority));
        }
        for id in exploited {
            state.exploited_vulnerabilities.insert((*id).to_string());
        }
        state
    }

    #[test]
    fn vulnerability_counts_splits_on_the_same_priority_boundary_as_loot() {
        let state = state_with_vulns(&[("v1", 1), ("v2", 3), ("v3", 4), ("v4", 5)], &["v1", "v4"]);

        let counts = vulnerability_counts(&state);

        assert_eq!(counts.exploitable, 2);
        assert_eq!(counts.exploitable_exploited, 1);
        assert_eq!(counts.findings, 2);
        assert_eq!(counts.findings_exploited, 1);
    }

    #[test]
    fn vulnerability_counts_reports_exploit_credits_with_no_record() {
        let state = state_with_vulns(&[("v1", 1)], &["v1", "kerberoast_alice", "kerberoast_bob"]);

        let counts = vulnerability_counts(&state);

        assert_eq!(counts.orphan_credits, 2);
        assert_eq!(counts.exploitable_exploited, 1);
    }

    #[test]
    fn vulnerability_counts_has_no_orphans_when_every_credit_has_a_record() {
        let state = state_with_vulns(&[("v1", 1), ("v2", 5)], &["v1", "v2"]);

        assert_eq!(vulnerability_counts(&state).orphan_credits, 0);
    }

    #[test]
    fn vulnerability_counts_never_double_counts_an_acl_graph_dump() {
        let mut vulns: Vec<(String, i32)> = (0..216).map(|i| (format!("acl-{i}"), 5)).collect();
        vulns.extend((0..17).map(|i| (format!("exp-{i}"), 2)));
        let borrowed: Vec<(&str, i32)> = vulns.iter().map(|(id, p)| (id.as_str(), *p)).collect();
        let exploited: Vec<&str> = (0..6).map(|_| "exp-0").collect();

        let state = state_with_vulns(&borrowed, &exploited);
        let counts = vulnerability_counts(&state);

        assert_eq!(counts.exploitable, 17);
        assert_eq!(counts.findings, 216);
        assert_eq!(counts.exploitable + counts.findings, 233);
    }

    #[test]
    fn reportable_counts_drops_machine_and_krbtgt_and_cracked_hashes() {
        let mut state = SharedRedTeamState::new("op-test".to_string());

        let mk_hash = |user: &str, domain: &str, cracked: Option<&str>| Hash {
            id: format!("h-{user}"),
            username: user.to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
                .to_string(),
            hash_type: "ntlm".to_string(),
            domain: domain.to_string(),
            cracked_password: cracked.map(str::to_string),
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        };
        let mk_cred = |user: &str, domain: &str| Credential {
            id: format!("c-{user}"),
            username: user.to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };

        state.all_hashes = vec![
            mk_hash("alice", "contoso.local", None),
            mk_hash("DC01$", "contoso.local", None), // machine account: dropped
            mk_hash("krbtgt", "contoso.local", None), // noise username: dropped
            mk_hash("bob", "contoso.local", Some("hunter2")), // cracked: dropped
        ];
        state.all_credentials = vec![
            mk_cred("alice", "contoso.local"),
            mk_cred("DC01$", "contoso.local"),
        ];

        let (cred_count, hash_count) = reportable_counts(&state);
        assert_eq!(cred_count, 1);
        assert_eq!(hash_count, 1);
    }

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
