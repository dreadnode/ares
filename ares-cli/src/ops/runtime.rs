use anyhow::{Context, Result};
use chrono::Utc;

use ares_core::models::SharedRedTeamState;
use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};
use crate::util::{format_duration, format_model_cost_line, format_number, format_role_cost_line};

fn finalizing_note(state: &SharedRedTeamState) -> Option<String> {
    if state.completed_at.is_some() || state.red_completed_at.is_none() {
        return None;
    }
    if state.red_blocked_on_blue {
        return Some("waiting on blue investigations".to_string());
    }
    state.red_completion_reason.clone()
}

const BREAKDOWN_LIMIT: usize = 6;

fn breakdown_line(label: &str, rows: &[(&str, u64)]) -> Option<String> {
    if rows.is_empty() {
        return None;
    }
    let shown: Vec<String> = rows
        .iter()
        .take(BREAKDOWN_LIMIT)
        .map(|(name, count)| format!("{name} {count}"))
        .collect();
    let mut line = format!("  by {label}: {}", shown.join(", "));
    if rows.len() > BREAKDOWN_LIMIT {
        line.push_str(&format!(", +{} more", rows.len() - BREAKDOWN_LIMIT));
    }
    Some(line)
}

fn format_retained(counts: &ares_core::blue_invalidation::BlueInvalidatedTasks) -> Vec<String> {
    if counts.retained_total == 0 {
        return Vec::new();
    }
    let plural = if counts.retained_total == 1 { "" } else { "s" };
    let cause = if counts.blue_was_off() {
        "no KDC_ERR_CLIENT_REVOKED, blue not running"
    } else {
        "no KDC_ERR_CLIENT_REVOKED, no blue revocation on the principal"
    };
    let mut lines = vec![format!(
        "Note: {} deferred task{plural} kept despite an inferred credential rejection — credential hidden from the LLM, queued work left intact ({cause})",
        counts.retained_total
    )];
    if let Some(line) = breakdown_line("role", &counts.retained_roles_by_count()) {
        lines.push(line);
    }
    lines
}

fn format_blue_invalidated(
    counts: &ares_core::blue_invalidation::BlueInvalidatedTasks,
) -> Vec<String> {
    if counts.is_empty() {
        return Vec::new();
    }
    if counts.total == 0 {
        return format_retained(counts);
    }

    let plural = if counts.total == 1 { "" } else { "s" };
    let blue = counts.blue_active_total();
    let inferred = counts.red_inferred_total();
    let headline = if inferred > 0 && blue > 0 {
        format!(
            "Warning: {} deferred task{plural} deleted before dispatch — {blue} by a blue action, {inferred} inferred from red's own tool failures with no blue action behind them (red verification may be voided)",
            counts.total
        )
    } else if inferred > 0 && counts.blue_was_off() {
        format!(
            "Warning: {} deferred task{plural} deleted before dispatch by inferred credential/host failure — blue was not running, so this is red's own auth noise and NOT blue containment (red verification may be voided)",
            counts.total
        )
    } else if inferred > 0 {
        format!(
            "Warning: {} deferred task{plural} deleted before dispatch by inferred credential/host failure — no blue action stands behind these, so this is red's own auth noise and NOT blue containment (red verification may be voided)",
            counts.total
        )
    } else {
        format!(
            "Warning: {} deferred task{plural} deleted by blue containment before dispatch (red verification may be voided)",
            counts.total
        )
    };
    let mut lines = vec![headline];

    let roles = counts.roles_by_count();
    let task_types = counts.task_types_by_count();
    if let Some(line) = breakdown_line("reason", &counts.reasons_by_count()) {
        lines.push(line);
    }
    if let Some(line) = breakdown_line("role", &roles) {
        lines.push(line);
    }
    if task_types != roles {
        if let Some(line) = breakdown_line("task type", &task_types) {
            lines.push(line);
        }
    }
    lines.extend(format_retained(counts));

    lines
}

pub(crate) async fn ops_runtime(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let is_running = reader.is_running(&mut conn).await?;
    let now = Utc::now();

    let (runtime_seconds, status) = if let Some(completed) = state.completed_at {
        (
            (completed - state.started_at).num_seconds().max(0) as u64,
            "completed",
        )
    } else if let Some(red_completed) = state.red_completed_at {
        (
            (red_completed - state.started_at).num_seconds().max(0) as u64,
            "completed",
        )
    } else if is_running {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "running",
        )
    } else {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "stopped",
        )
    };

    println!("Operation: {op_id}");
    println!("Status:    {status}");
    println!("Started:   {}", state.started_at.to_rfc3339());
    println!("Runtime:   {}", format_duration(runtime_seconds));
    if let Some(note) = finalizing_note(&state) {
        println!("Finalizing: {note}");
    }
    println!();

    let (creds, hashes) = super::loot::reportable_counts(&state);
    let vulns = super::loot::vulnerability_counts(&state);

    println!("Credentials: {creds}  Hashes: {hashes}");
    println!(
        "Vulns: {} exploitable ({} exploited), {} findings ({} exploited)",
        vulns.exploitable, vulns.exploitable_exploited, vulns.findings, vulns.findings_exploited
    );
    if vulns.not_exploitable_by_construction > 0 {
        if vulns.not_exploitable_by_construction_exploited > 0 {
            println!(
                "Warning: {} observed but not exploitable (no on-target execution primitive), of which {} carry an EXPLOITED status \u{2014} the dispatch-gate decline leaked, investigate",
                vulns.not_exploitable_by_construction,
                vulns.not_exploitable_by_construction_exploited
            );
        } else {
            println!(
                "Note: {} observed but not exploitable (no on-target execution primitive; itemised under Observed but not exploitable in `ops loot`)",
                vulns.not_exploitable_by_construction
            );
        }
    }
    if vulns.attributed_credits > 0 {
        let plural = if vulns.attributed_credits == 1 {
            ""
        } else {
            "s"
        };
        println!(
            "Note: {} primitive credit{plural} carry no vulnerability record (capture-time credit; itemised under Token Coverage in `ops loot`)",
            vulns.attributed_credits
        );
    }
    if vulns.unattributed_credits > 0 {
        let plural = if vulns.unattributed_credits == 1 {
            ""
        } else {
            "s"
        };
        println!(
            "Warning: {} exploit credit{plural} match no known technique category (no vulnerability record; `ops loot` can only table them as `other`)",
            vulns.unattributed_credits
        );
    }

    let invalidated = ares_core::blue_invalidation::get_blue_invalidated_tasks(&mut conn, &op_id)
        .await
        .unwrap_or_default();
    for line in format_blue_invalidated(&invalidated) {
        println!("{line}");
    }
    println!();

    super::loot::print_runtime_summary(&state);

    // Token usage & estimated cost (from Redis counters set by workers)
    match ares_core::token_usage::get_token_usage(&mut conn, &op_id).await {
        Ok(Some(usage)) if usage.input_tokens > 0 || usage.output_tokens > 0 => {
            let in_tok = usage.input_tokens;
            let cached_tok = usage.cache_read_input_tokens;
            let out_tok = usage.output_tokens;
            let total_tok = in_tok + cached_tok + out_tok;
            let total_input = in_tok + cached_tok;

            println!(
                "\nTokens: {} (in: {}  out: {})",
                format_number(total_tok),
                format_number(total_input),
                format_number(out_tok)
            );
            if total_input > 0 {
                let pct = (cached_tok as f64 / total_input as f64) * 100.0;
                println!(
                    "Cache:  hit {} / {} tokens ({:.1}%)",
                    format_number(cached_tok),
                    format_number(total_input),
                    pct
                );
            }

            if !usage.models.is_empty() {
                let mut model_names: Vec<_> = usage.models.keys().collect();
                model_names.sort();
                let label = if model_names.len() > 1 {
                    "Models"
                } else {
                    "Model"
                };
                println!(
                    "{label}:  {}",
                    model_names
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                let (total_cost, breakdown, unpriced) =
                    ares_core::token_usage::estimate_usage_cost(&usage);

                if let Some(cost) = total_cost {
                    let suffix = if breakdown.len() > 1 {
                        " (blended)"
                    } else {
                        ""
                    };
                    println!("Cost:   ${cost:.4}{suffix}");
                } else if !usage.model.is_empty() {
                    println!("Cost:   unavailable");
                }

                // Per-model breakdown for multi-model operations
                if breakdown.len() > 1 {
                    for item in &breakdown {
                        println!("{}", format_model_cost_line(item));
                    }
                }

                if !unpriced.is_empty() {
                    println!("Unpriced models: {}", unpriced.join(", "));
                }

                let roles = ares_core::token_usage::estimate_role_costs(&usage);
                if !roles.is_empty() {
                    println!("By role:");
                    for item in &roles {
                        println!("{}", format_role_cost_line(item));
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32, min: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, hour, min, 0).unwrap()
    }

    fn running_state() -> SharedRedTeamState {
        let mut state = SharedRedTeamState::new("op-test-001".to_string());
        state.started_at = at(3, 46);
        state
    }

    fn red_done_state() -> SharedRedTeamState {
        let mut state = running_state();
        state.red_completed_at = Some(at(4, 10));
        state.red_completion_reason = Some("all forests dominated".to_string());
        state.red_blocked_on_blue = true;
        state
    }

    #[test]
    fn running_op_has_no_finalizing_note() {
        assert_eq!(finalizing_note(&running_state()), None);
    }

    #[test]
    fn red_done_blocked_on_blue_reports_blue_wait() {
        assert_eq!(
            finalizing_note(&red_done_state()),
            Some("waiting on blue investigations".to_string())
        );
    }

    #[test]
    fn red_done_without_blue_reports_completion_reason() {
        let mut state = red_done_state();
        state.red_blocked_on_blue = false;
        assert_eq!(
            finalizing_note(&state),
            Some("all forests dominated".to_string())
        );
    }

    #[test]
    fn fully_completed_op_has_no_finalizing_note() {
        let mut state = red_done_state();
        state.completed_at = Some(at(4, 30));
        assert_eq!(finalizing_note(&state), None);
    }

    fn counts(
        total: u64,
        by_role: &[(&str, u64)],
        by_task_type: &[(&str, u64)],
    ) -> ares_core::blue_invalidation::BlueInvalidatedTasks {
        ares_core::blue_invalidation::BlueInvalidatedTasks {
            total,
            by_role: by_role
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            by_task_type: by_task_type
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            by_reason: Default::default(),
            by_attribution: Default::default(),
            retained_total: 0,
            retained_by_role: Default::default(),
            blue_team_enabled: None,
        }
    }

    fn with_attribution(
        mut c: ares_core::blue_invalidation::BlueInvalidatedTasks,
        blue_active: u64,
        red_inferred: u64,
    ) -> ares_core::blue_invalidation::BlueInvalidatedTasks {
        if blue_active > 0 {
            c.by_attribution
                .insert("blue_active".to_string(), blue_active);
        }
        if red_inferred > 0 {
            c.by_attribution
                .insert("red_inferred".to_string(), red_inferred);
        }
        c
    }

    #[test]
    fn no_blue_drops_renders_nothing() {
        assert!(format_blue_invalidated(&counts(0, &[], &[])).is_empty());
    }

    #[test]
    fn blue_drops_render_total_and_role_breakdown() {
        let lines = format_blue_invalidated(&counts(
            5,
            &[("acl", 2), ("recon", 3)],
            &[("acl_chain_step", 2), ("recon", 3)],
        ));
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("5 deferred tasks deleted by blue containment"));
        assert_eq!(lines[1], "  by role: recon 3, acl 2");
        assert_eq!(lines[2], "  by task type: recon 3, acl_chain_step 2");
    }

    #[test]
    fn task_type_breakdown_is_suppressed_when_it_repeats_the_roles() {
        let lines = format_blue_invalidated(&counts(3, &[("recon", 3)], &[("recon", 3)]));
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1], "  by role: recon 3");
    }

    #[test]
    fn single_drop_is_not_pluralised() {
        let lines = format_blue_invalidated(&counts(1, &[("acl", 1)], &[("acl_chain_step", 1)]));
        assert!(lines[0].contains("1 deferred task deleted"));
        assert!(!lines[0].contains("tasks deleted"));
    }

    #[test]
    fn reason_breakdown_leads_the_drop_detail() {
        let mut c = counts(75, &[("recon", 40), ("lateral", 35)], &[]);
        c.by_reason = [
            ("credential_revoked".to_string(), 59_u64),
            ("host_isolated".to_string(), 16),
        ]
        .into_iter()
        .collect();

        let lines = format_blue_invalidated(&c);

        assert_eq!(
            lines[1],
            "  by reason: credential_revoked 59, host_isolated 16"
        );
        assert_eq!(lines[2], "  by role: recon 40, lateral 35");
    }

    fn inferred_credential_drops(
        blue_team_enabled: Option<bool>,
    ) -> ares_core::blue_invalidation::BlueInvalidatedTasks {
        let mut c = with_attribution(counts(11, &[("recon", 11)], &[]), 0, 11);
        c.by_reason = [("credential_rejected_inferred".to_string(), 11_u64)]
            .into_iter()
            .collect();
        c.blue_team_enabled = blue_team_enabled;
        c
    }

    #[test]
    fn blue_off_drops_are_never_reported_as_blue_containment() {
        let lines = format_blue_invalidated(&inferred_credential_drops(Some(false)));

        assert!(
            !lines[0].contains("by blue containment"),
            "headline still blames blue: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("blue was not running"),
            "got {}",
            lines[0]
        );
        assert!(lines[0].contains("11 deferred tasks deleted"));
        assert_eq!(lines[1], "  by reason: credential_rejected_inferred 11");
    }

    #[test]
    fn inferred_drops_with_blue_running_do_not_claim_blue_was_off() {
        let lines = format_blue_invalidated(&inferred_credential_drops(Some(true)));

        assert!(
            !lines[0].contains("blue was not running"),
            "headline calls a live blue team absent: {}",
            lines[0]
        );
        assert!(
            !lines[0].contains("by blue containment"),
            "headline still blames blue: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("no blue action stands behind these"),
            "got {}",
            lines[0]
        );
    }

    #[test]
    fn drops_from_an_operation_predating_the_flag_stay_agnostic() {
        let lines = format_blue_invalidated(&inferred_credential_drops(None));
        assert!(
            !lines[0].contains("blue was not running"),
            "unknown enablement asserted as blue-off: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("no blue action stands behind these"),
            "got {}",
            lines[0]
        );
    }

    #[test]
    fn mixed_attribution_headline_splits_the_two_causes() {
        let c = with_attribution(counts(9, &[("recon", 9)], &[]), 4, 5);
        let lines = format_blue_invalidated(&c);
        assert!(lines[0].contains("4 by a blue action"), "got {}", lines[0]);
        assert!(
            lines[0].contains("5 inferred from red's own tool failures"),
            "got {}",
            lines[0]
        );
    }

    #[test]
    fn blue_active_only_keeps_the_containment_headline() {
        let c = with_attribution(counts(6, &[("lateral", 6)], &[]), 6, 0);
        let lines = format_blue_invalidated(&c);
        assert!(
            lines[0].contains("6 deferred tasks deleted by blue containment"),
            "got {}",
            lines[0]
        );
    }

    #[test]
    fn pre_attribution_operations_render_the_legacy_headline() {
        let lines = format_blue_invalidated(&counts(238, &[("recon", 238)], &[]));
        assert!(
            lines[0].contains("238 deferred tasks deleted by blue containment"),
            "got {}",
            lines[0]
        );
    }

    #[test]
    fn retained_tasks_are_reported_when_nothing_was_dropped() {
        let mut c = counts(0, &[], &[]);
        c.retained_total = 40;
        c.retained_by_role = [("recon".to_string(), 40_u64)].into_iter().collect();

        let lines = format_blue_invalidated(&c);

        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].contains("40 deferred tasks kept despite an inferred credential rejection"),
            "got {}",
            lines[0]
        );
        assert!(!lines[0].contains("blue containment"), "got {}", lines[0]);
        assert_eq!(lines[1], "  by role: recon 40");
    }

    #[test]
    fn retained_tasks_are_appended_to_a_drop_report() {
        let mut c = with_attribution(counts(2, &[("lateral", 2)], &[]), 0, 2);
        c.retained_total = 40;
        c.retained_by_role = [("recon".to_string(), 40_u64)].into_iter().collect();

        let lines = format_blue_invalidated(&c);

        assert!(
            lines[0].contains("2 deferred tasks deleted"),
            "got {}",
            lines[0]
        );
        assert!(
            lines
                .iter()
                .any(|l| l
                    .contains("40 deferred tasks kept despite an inferred credential rejection"))
        );
    }

    #[test]
    fn long_breakdowns_collapse_their_tail() {
        let rows = [
            ("recon", 24),
            ("lateral", 12),
            ("coercion", 11),
            ("credential_access", 8),
            ("privesc", 8),
            ("exploit", 4),
            ("acl", 2),
            ("cracker", 1),
        ];
        let lines = format_blue_invalidated(&counts(70, &rows, &[]));
        assert_eq!(lines.len(), 2);
        assert!(lines[1].ends_with(", +2 more"), "got {}", lines[1]);
        assert!(!lines[1].contains("cracker"));
    }
}
