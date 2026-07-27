//! Deterministic baseline detection sweep.
//!
//! Runs the entire detection-template catalog in code, once, BEFORE the
//! orchestrator LLM loop starts, and records the MITRE technique for every
//! template that fires directly into blue investigation state.
//!
//! ## Why this exists
//!
//! The LLM hunter is not a reliable way to guarantee full catalog coverage.
//! Under a finite token/context budget it tends to explore one or two
//! techniques deeply, floods its context with raw Loki output, compacts, and
//! terminates long before it has queried every template. When that happens the
//! techniques a template *would* have caught never get queried, so they never
//! get tagged — the investigation is then graded on partial coverage even
//! though the detections themselves are correct. Prompt nudges ("run the sweep
//! first") don't fix this; the truncation is structural, not a wording problem.
//!
//! The sweep makes catalog coverage deterministic. Every template runs exactly
//! once with bounded concurrency, and any hit is written to blue state
//! regardless of what the LLM later does with its remaining budget. The LLM
//! loop then starts from a recorded baseline (fed in via the task prompt) and
//! spends its budget on the work the sweep can't do — chaining, IOC-level
//! evidence, cross-correlation, timeline, and the verdict — instead of
//! rediscovering detections.
//!
//! Toggle with `ARES_BLUE_DETERMINISTIC_SWEEP=0` to fall back to the pure
//! LLM-driven hunt.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use ares_core::detection::detection_config;

/// Default max concurrent Loki detection queries during the sweep. Loki through
/// the Grafana proxy is the bottleneck (~25-40s/query); a handful in flight
/// keeps the wall-clock down without stressing the datasource.
const DEFAULT_SWEEP_CONCURRENCY: usize = 6;

/// Default overall wall-clock cap for the sweep. Whatever fired by the deadline
/// is recorded; the LLM loop still runs and can cover any templates the cap cut
/// off. Comfortably under the runner's 2700s investigation timeout.
const DEFAULT_SWEEP_TIMEOUT_SECS: u64 = 360;

/// Hours of history each detection query scans. The detection runner clamps
/// this to 2 (larger windows time out through the Grafana proxy).
const SWEEP_HOURS_BACK: i64 = 2;

// ─── Golden ticket correlation ──────────────────────────────────────────────
//
// A Golden Ticket is a TGT forged offline from the krbtgt key, so the DC never
// sees the AS-REQ that would normally mint it — there is no 4768. Using the
// ticket still requires asking the DC for service tickets, which does log 4769.
// The signal is therefore the *absence* of a partner event, and no single-line
// filter can express absence: every field-level attempt (RC4 downgrade, DC
// service class) either matches ordinary Kerberoasting or matches nothing at
// all. That is why `detect_golden_ticket` in the template catalog cannot fire
// honestly and why this lives here, in code, instead.

/// Windows event ID for a Kerberos service-ticket request (TGS-REQ).
const EVENT_SERVICE_TICKET: &str = "4769";

/// Windows event ID for a Kerberos TGT request (AS-REQ).
const EVENT_TGT_REQUEST: &str = "4768";

const GOLDEN_TICKET_MITRE_ID: &str = "T1558.001";

/// Source name recorded for correlation hits. Deliberately distinct from the
/// `detect_golden_ticket` template so evidence points at the rule that actually
/// concluded something.
const GOLDEN_TICKET_SOURCE: &str = "golden_ticket_correlation";

/// Loki labels the account identity is aggregated into.
const ACCOUNT_LABEL: &str = "ares_account";
const DOMAIN_LABEL: &str = "ares_domain";

/// LogQL `regexp` parsers lifting `TargetUserName` / `TargetDomainName` out of
/// the event XML.
///
/// Loki stores the Windows XML JSON-escaped, so the `>` closing the field name
/// is the six literal characters `>`: `\\u003e` matches the backslash and
/// `[^\\]*` then runs up to the next escape, which opens `</Data>`. Same
/// escaping trick the DCSync and AS-REP templates use.
const ACCOUNT_REGEXP: &str = r#"TargetUserName'\\u003e(?P<ares_account>[^\\]*)"#;
const DOMAIN_REGEXP: &str = r#"TargetDomainName'\\u003e(?P<ares_domain>[^\\]*)"#;

/// Hours of TGT history forming the "this account got a ticket legitimately"
/// baseline.
///
/// Deliberately wider than the candidate window. A TGT is good for ~10h, so an
/// account that authenticated before the candidate window opened keeps
/// requesting service tickets with no 4768 inside it — window-boundary
/// artifacts that are indistinguishable from a forged ticket if both sides are
/// measured over the same span. Measured against live logs: symmetric 8h/8h
/// windows left 5 orphans out of 26 accounts, while candidates over 2h against
/// this 8h baseline left none.
const DEFAULT_GOLDEN_BASELINE_HOURS: i64 = 8;

/// Cap on principals enumerated in the timeline and the prompt. The count
/// reported is always the true one; only the enumeration is bounded.
const MAX_REPORTED_ORPHANS: usize = 20;

/// An account that requested service tickets without ever requesting a TGT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrphanAccount {
    /// `account@domain`, both normalised.
    pub account: String,
    pub service_ticket_count: u64,
}

/// A completed 4769-without-4768 comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GoldenTicketCorrelation {
    /// Distinct accounts that requested a service ticket in the candidate window.
    pub candidates: usize,
    /// Distinct accounts with a TGT request across the wider baseline window.
    pub baseline: usize,
    /// Candidates with no TGT request anywhere in the baseline window.
    pub orphans: Vec<OrphanAccount>,
}

/// What the correlation was able to conclude.
#[derive(Debug, Clone)]
pub(crate) enum GoldenTicketOutcome {
    Correlated(GoldenTicketCorrelation),
    /// Ran but drew no conclusion — reported rather than silently treated as
    /// "clean", because "we could not tell" and "nothing was there" carry very
    /// different follow-up obligations for the analyst.
    Inconclusive(String),
}

/// Why a comparison could not conclude.
#[derive(Debug, PartialEq, Eq)]
enum CorrelationGap {
    /// No service-ticket activity at all — nothing to correlate against.
    NoCandidates,
    /// No TGT activity anywhere in the baseline window. A live domain always
    /// mints TGTs, so this means the baseline query broke or the log shape
    /// changed. Failing closed matters here: an empty baseline makes *every*
    /// account look orphaned and would report the whole domain as forged.
    NoBaseline,
}

/// Normalise a `TargetUserName` so the two event types can be compared.
///
/// The events disagree on format: 4768 logs the bare SAM name (`alice`) while
/// 4769 logs it UPN-style with the realm appended (`alice@CONTOSO.LOCAL`), and
/// casing is not stable between them. Diffing the raw field would put every
/// account on both sides at once and flag an entire domain as forged —
/// confirmed against live logs, where no 4768 name carried an `@` suffix and
/// the 4769 names were a mix of both forms.
fn normalize_account(raw: &str) -> Option<String> {
    let base = raw.trim().split('@').next().unwrap_or_default().trim();
    (!base.is_empty()).then(|| base.to_ascii_lowercase())
}

/// Normalise a `TargetDomainName` to its first DNS label.
///
/// These disagree too: 4768 logs the NetBIOS short name (`CONTOSO`) while 4769
/// logs the FQDN (`CONTOSO.LOCAL`, and for a child domain
/// `CHILD.CONTOSO.LOCAL`). Taking the first label reconciles them, since the
/// NetBIOS name is conventionally the leftmost DNS label.
fn normalize_domain(raw: &str) -> Option<String> {
    let base = raw.trim().split('.').next().unwrap_or_default().trim();
    (!base.is_empty()).then(|| base.to_ascii_lowercase())
}

/// Build the compound identity a Kerberos principal is correlated on.
///
/// Account name alone is NOT a sufficient key. `Administrator` (the account
/// `ticketer` forges by default) exists in every domain of a forest, so keying
/// on the bare name lets a legitimate `Administrator` logon in one domain mask
/// a forged ticket for `Administrator` in another — a false negative in the
/// single most likely golden-ticket scenario. Verified live: this forest logs
/// `Administrator` TGTs from multiple distinct domains.
///
/// Returns `None` when either half is missing, so the pair is dropped rather
/// than compared on a partial key: an identity that can't be matched against
/// the baseline would otherwise surface as a bogus orphan.
fn principal_key(labels: &BTreeMap<String, String>) -> Option<String> {
    let account = normalize_account(labels.get(ACCOUNT_LABEL)?)?;
    let domain = normalize_domain(labels.get(DOMAIN_LABEL)?)?;
    Some(format!("{account}@{domain}"))
}

/// Fold raw series into normalised per-principal totals.
fn principal_totals(series: &[ares_tools::blue::loki::MetricSeries]) -> BTreeMap<String, u64> {
    let mut totals = BTreeMap::new();
    for (labels, count) in series {
        if let Some(key) = principal_key(labels) {
            *totals.entry(key).or_insert(0) += count;
        }
    }
    totals
}

/// Diff service-ticket principals against TGT principals.
fn correlate(
    service_tickets: &[ares_tools::blue::loki::MetricSeries],
    tgt_requests: &[ares_tools::blue::loki::MetricSeries],
) -> Result<GoldenTicketCorrelation, CorrelationGap> {
    let candidates = principal_totals(service_tickets);
    let baseline = principal_totals(tgt_requests);

    if candidates.is_empty() {
        return Err(CorrelationGap::NoCandidates);
    }
    if baseline.is_empty() {
        return Err(CorrelationGap::NoBaseline);
    }

    let mut orphans: Vec<OrphanAccount> = candidates
        .iter()
        .filter(|(account, _)| !baseline.contains_key(account.as_str()))
        .map(|(account, count)| OrphanAccount {
            account: account.clone(),
            service_ticket_count: *count,
        })
        .collect();
    // Loudest first — the account with the most service tickets is the one that
    // actually did something with the forged TGT.
    orphans.sort_by(|a, b| {
        b.service_ticket_count
            .cmp(&a.service_ticket_count)
            .then_with(|| a.account.cmp(&b.account))
    });

    Ok(GoldenTicketCorrelation {
        candidates: candidates.len(),
        baseline: baseline.len(),
        orphans,
    })
}

/// Build the aggregation that returns one series per account for `event_id`.
///
/// The event filter matches the `event_id` JSON field rather than the bare
/// number the template catalog uses. A bare `|= "4768"` also matches any line
/// whose record ID, SID or ticket hash happens to contain those digits: live,
/// it pulled 3607 lines over 8h against 203 for the field-anchored form, and
/// the extra lines were mostly 4769s. Folding those into the TGT baseline would
/// mark a forged account as legitimately authenticated — a false negative in
/// exactly the case this rule exists to catch.
fn account_aggregation_query(event_id: &str, hours: i64) -> String {
    let selector = ares_tools::blue::detection::build_selector(
        ares_tools::blue::detection::WIN_SECURITY,
        None,
    );
    format!(
        r#"sum by ({ACCOUNT_LABEL}, {DOMAIN_LABEL}) (count_over_time({selector} |= `"event_id":{event_id}` | regexp `{ACCOUNT_REGEXP}` | regexp `{DOMAIN_REGEXP}` [{hours}h]))"#
    )
}

/// Run the correlation: which accounts used service tickets without ever
/// having been issued a TGT?
///
/// Both queries must succeed. A partial answer is worse than none — a failed
/// baseline query is indistinguishable from a domain where nobody
/// authenticated, and would turn every active account into a reported forgery.
async fn run_golden_ticket_correlation(
    candidate_hours: i64,
    baseline_hours: i64,
) -> Result<GoldenTicketCorrelation, String> {
    let candidate_query = account_aggregation_query(EVENT_SERVICE_TICKET, candidate_hours);
    let baseline_query = account_aggregation_query(EVENT_TGT_REQUEST, baseline_hours);
    let (service_tickets, tgt_requests) = tokio::join!(
        ares_tools::blue::loki::query_metric_series(&candidate_query, None),
        ares_tools::blue::loki::query_metric_series(&baseline_query, None),
    );

    let service_tickets = service_tickets
        .map_err(|e| format!("service-ticket ({EVENT_SERVICE_TICKET}) query failed: {e}"))?;
    let tgt_requests =
        tgt_requests.map_err(|e| format!("TGT ({EVENT_TGT_REQUEST}) query failed: {e}"))?;

    correlate(&service_tickets, &tgt_requests).map_err(|gap| match gap {
        CorrelationGap::NoCandidates => format!(
            "no {EVENT_SERVICE_TICKET} activity in the last {candidate_hours}h — nothing to correlate"
        ),
        CorrelationGap::NoBaseline => format!(
            "no {EVENT_TGT_REQUEST} activity in the last {baseline_hours}h; a live domain always \
             issues TGTs, so the baseline is untrustworthy and no verdict is drawn"
        ),
    })
}

impl GoldenTicketCorrelation {
    /// Represent orphaned accounts as a fired detection so they flow through
    /// the same recording and prompt path as every template hit.
    fn as_fired(&self) -> Option<FiredDetection> {
        (!self.orphans.is_empty()).then(|| FiredDetection {
            template: GOLDEN_TICKET_SOURCE.to_string(),
            mitre_id: GOLDEN_TICKET_MITRE_ID.to_string(),
            description: "Golden Ticket Detection (service tickets with no preceding TGT request)"
                .to_string(),
            tactic: "persistence".to_string(),
            severity: "critical".to_string(),
            event_count: self
                .orphans
                .iter()
                .map(|o| o.service_ticket_count as usize)
                .sum(),
            first_event_at: None,
            last_event_at: None,
            hosts: Vec::new(),
        })
    }
}

/// A detection template that returned matching events during the sweep.
#[derive(Debug, Clone)]
pub(crate) struct FiredDetection {
    pub template: String,
    pub mitre_id: String,
    pub description: String,
    pub tactic: String,
    pub severity: String,
    pub event_count: usize,
    /// Timestamp of the earliest matched log event. This, not the moment the
    /// sweep noticed, is what a detection is worth correlating against: every
    /// hit in one sweep shares a recording time, so recording time cannot
    /// establish that a detection followed the activity it describes.
    pub first_event_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_event_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hosts the matched events came from.
    pub hosts: Vec<String>,
}

/// Result of a baseline sweep — what fired, what came back empty, and what the
/// time cap cut off before it could run.
#[derive(Debug, Default)]
pub(crate) struct SweepOutcome {
    pub templates_total: usize,
    pub fired: Vec<FiredDetection>,
    /// Templates that ran and returned no matches.
    pub no_match: Vec<String>,
    /// Templates the time cap prevented from running (empty on a clean finish).
    pub not_run: Vec<String>,
    pub timed_out: bool,
    /// Golden-ticket correlation result; `None` when it was disabled.
    pub golden_ticket: Option<GoldenTicketOutcome>,
}

impl SweepOutcome {
    /// Whether the sweep produced anything worth injecting into the prompt.
    pub fn ran(&self) -> bool {
        self.templates_total > 0
    }

    /// Compact, directive summary of the baseline for the orchestrator prompt.
    ///
    /// The point is to seed coverage AND cut token burn: the LLM is told the
    /// catalog is already covered and every fired technique is already
    /// recorded, so it does not re-run detection templates or wade through raw
    /// Loki dumps — it goes straight to depth (chaining, IOCs, timeline,
    /// verdict).
    pub fn prompt_summary(&self) -> String {
        let mut s = String::new();
        s.push_str("## Baseline detection sweep — ALREADY COMPLETED\n\n");
        s.push_str(&format!(
            "A deterministic sweep ran {} detection templates against Loki before you \
             started. Every technique listed as FIRED below is ALREADY recorded as evidence \
             and a MITRE technique in this investigation's state. Do NOT re-run these \
             detection templates — that work is done.\n\n",
            self.templates_total
        ));

        if self.fired.is_empty() {
            s.push_str(
                "FIRED: none. No detection template matched in the scanned window. Investigate \
                 from the alert directly — pull host/user activity around the alert time and \
                 hunt for indicators the templates may not cover.\n\n",
            );
        } else {
            s.push_str(&format!("Detections that FIRED ({}):\n", self.fired.len()));
            for f in &self.fired {
                s.push_str(&format!(
                    "- {} ({}) — {} matching event(s) [{}]\n",
                    f.mitre_id, f.description, f.event_count, f.template
                ));
            }
            s.push('\n');
        }

        if !self.no_match.is_empty() {
            s.push_str(&format!(
                "Ran and returned no matches (do NOT re-query): {}\n\n",
                self.no_match.join(", ")
            ));
        }

        s.push_str(&self.golden_ticket_summary());

        if self.timed_out && !self.not_run.is_empty() {
            s.push_str(&format!(
                "The sweep hit its time cap before running these templates — run them yourself \
                 if the alert context makes them relevant: {}\n\n",
                self.not_run.join(", ")
            ));
        }

        s.push_str(
            "Your budget is best spent on what the sweep CANNOT do — dispatch TARGETED \
             follow-ups, do not re-scan:\n\
             1. For each fired technique, dispatch_threat_hunt with that technique_id and a \
             context note, to chase its chain: affected users/hosts and what they touched.\n\
             2. Where a host or account looks central, dispatch_lateral_analysis to map movement \
             and compromised accounts.\n\
             3. Record cross-cutting findings directly with add_evidence / add_technique / \
             record_timeline_event.\n\
             4. Decide the verdict and whether to escalate, then call complete_investigation.\n\n\
             The full detection catalog is already covered, so do NOT dispatch broad \
             \"scan everything\" hunts — they just re-run finished work and exhaust the budget. \
             Dispatch narrow, technique-scoped hunts, or go straight to the verdict when the \
             picture is already clear.",
        );
        s
    }

    /// Report the golden-ticket correlation, including when it concluded
    /// nothing. `detect_golden_ticket` in the template catalog structurally
    /// cannot fire, so silence here would read as "checked, clean" when the
    /// truth may be "never checked".
    fn golden_ticket_summary(&self) -> String {
        let Some(outcome) = &self.golden_ticket else {
            return String::new();
        };
        let mut s = String::from("Golden ticket correlation (4769 with no preceding 4768): ");
        match outcome {
            GoldenTicketOutcome::Inconclusive(reason) => {
                s.push_str(&format!(
                    "NO VERDICT — {reason}. Treat {GOLDEN_TICKET_MITRE_ID} as unchecked, not as \
                     absent.\n\n"
                ));
            }
            GoldenTicketOutcome::Correlated(c) if c.orphans.is_empty() => {
                s.push_str(&format!(
                    "CLEAN — all {} account(s) that requested a service ticket also requested a \
                     TGT (baseline: {} account(s)). There was no forged-TGT usage.\n\
                     This correlation is the authoritative answer for \
                     {GOLDEN_TICKET_MITRE_ID}; it is the only signal that can distinguish a forged \
                     TGT from ordinary Kerberos traffic. Do NOT record \
                     {GOLDEN_TICKET_MITRE_ID} on top of it. In particular, none of these are \
                     golden-ticket indicators — each matches ordinary traffic: a 4769 whose \
                     ServiceName is krbtgt (that is a TGT renewal), a TicketOptions value like \
                     0x40810010 (that is the ordinary value), a request from a non-DC IP (every \
                     workstation does that), or an RC4 session key (present on nearly every \
                     event). An RC4 *ticket* is Kerberoasting (T1558.003), not golden.\n\n",
                    c.candidates, c.baseline
                ));
            }
            GoldenTicketOutcome::Correlated(c) => {
                s.push_str(&format!(
                    "{} of {} account(s) used service tickets with NO TGT request in the baseline \
                     window — the signature of a forged TGT. Already recorded as \
                     {GOLDEN_TICKET_MITRE_ID}:\n",
                    c.orphans.len(),
                    c.candidates
                ));
                for o in c.orphans.iter().take(MAX_REPORTED_ORPHANS) {
                    s.push_str(&format!(
                        "- {} ({} service ticket(s))\n",
                        o.account, o.service_ticket_count
                    ));
                }
                if c.orphans.len() > MAX_REPORTED_ORPHANS {
                    s.push_str(&format!(
                        "- …and {} more (listing capped at {MAX_REPORTED_ORPHANS})\n",
                        c.orphans.len() - MAX_REPORTED_ORPHANS
                    ));
                }
                s.push_str(
                    "Pivot on these accounts: what they authenticated to and what they touched.\n\n",
                );
            }
        }
        s
    }
}

/// Run the deterministic baseline detection sweep and record every hit.
///
/// Enumerates the full detection catalog, runs each template's query with
/// bounded concurrency under an overall time cap, and for every template that
/// returns matching events records the technique into blue state (technique
/// set + TTP-level evidence + a timeline event). Returns a summary the caller
/// folds into the orchestrator prompt. Best-effort throughout: a failed query
/// or a failed record is logged and skipped — the sweep never sinks the
/// investigation.
pub(crate) async fn run_detection_sweep(investigation_id: &str) -> SweepOutcome {
    let all_names: BTreeSet<String> = detection_config().templates.keys().cloned().collect();
    let templates: Vec<FiredDetection> = detection_config()
        .templates
        .iter()
        .map(|(name, e)| FiredDetection {
            template: name.clone(),
            mitre_id: e.mitre_id.clone(),
            description: e.description.clone(),
            tactic: e.tactic.clone(),
            severity: e.severity.clone(),
            event_count: 0,
            first_event_at: None,
            last_event_at: None,
            hosts: Vec::new(),
        })
        .collect();
    let templates_total = templates.len();

    info!(
        investigation_id,
        templates = templates_total,
        "Starting deterministic baseline detection sweep"
    );

    // Start the golden-ticket correlation alongside the catalog so its two Loki
    // round-trips overlap the template sweep instead of extending it.
    let mut golden_task = golden_ticket_enabled().then(|| {
        tokio::spawn(run_golden_ticket_correlation(
            SWEEP_HOURS_BACK,
            golden_baseline_hours(),
        ))
    });

    let sem = Arc::new(Semaphore::new(sweep_concurrency()));
    let mut set: tokio::task::JoinSet<(String, Option<FiredDetection>)> =
        tokio::task::JoinSet::new();
    for tmpl in templates {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return (tmpl.template.clone(), None);
            };
            let out = ares_tools::blue::detection::run_detection_query_events(
                &tmpl.template,
                None,
                SWEEP_HOURS_BACK,
            )
            .await;
            let fired = match out {
                Ok(ev) if ev.event_count > 0 => Some(FiredDetection {
                    event_count: ev.event_count,
                    first_event_at: ev.first_event_at,
                    last_event_at: ev.last_event_at,
                    hosts: ev.hosts,
                    ..tmpl.clone()
                }),
                Ok(_) => None,
                Err(e) => {
                    warn!(template = %tmpl.template, error = %e, "Sweep detection query failed");
                    None
                }
            };
            (tmpl.template, fired)
        });
    }

    let mut fired: Vec<FiredDetection> = Vec::new();
    let mut completed: BTreeSet<String> = BTreeSet::new();
    let mut timed_out = false;

    let deadline_at = tokio::time::Instant::now() + Duration::from_secs(sweep_timeout_secs());
    let deadline = tokio::time::sleep_until(deadline_at);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                timed_out = true;
                set.abort_all();
                break;
            }
            res = set.join_next() => {
                match res {
                    Some(Ok((name, hit))) => {
                        completed.insert(name);
                        if let Some(f) = hit {
                            fired.push(f);
                        }
                    }
                    // Task panic or abort — skip it, don't sink the sweep.
                    Some(Err(_)) => {}
                    None => break,
                }
            }
        }
    }

    // Collect the correlation against whatever is left of the same deadline. It
    // shares the cap rather than getting its own, so a hung Loki can't push the
    // sweep past the budget the investigation runner allows it.
    let golden_ticket = match golden_task.as_mut() {
        None => None,
        Some(handle) => Some(
            match tokio::time::timeout_at(deadline_at, &mut *handle).await {
                Ok(Ok(Ok(c))) => GoldenTicketOutcome::Correlated(c),
                Ok(Ok(Err(reason))) => GoldenTicketOutcome::Inconclusive(reason),
                Ok(Err(e)) => {
                    GoldenTicketOutcome::Inconclusive(format!("correlation task failed: {e}"))
                }
                Err(_) => {
                    // Dropping a JoinHandle only detaches the task; abort so the
                    // in-flight Loki queries actually stop.
                    handle.abort();
                    timed_out = true;
                    GoldenTicketOutcome::Inconclusive(
                        "hit the sweep time cap before both Kerberos queries returned".to_string(),
                    )
                }
            },
        ),
    };

    if let Some(GoldenTicketOutcome::Correlated(c)) = &golden_ticket {
        if let Some(f) = c.as_fired() {
            warn!(
                investigation_id,
                orphan_accounts = c.orphans.len(),
                candidates = c.candidates,
                baseline = c.baseline,
                "Golden ticket correlation found service tickets with no preceding TGT request"
            );
            fired.push(f);
        }
    }

    fired.sort_by(|a, b| a.template.cmp(&b.template));

    // Record every hit into blue state (sequential, cheap: a few Redis writes
    // each). Deduped by the underlying tools, so overlap with the LLM's own
    // later recording is harmless.
    for f in &fired {
        record_fired(investigation_id, f).await;
    }

    // The technique record above says "a golden ticket was used"; these say
    // which accounts, which is what the analyst actually pivots on.
    if let Some(GoldenTicketOutcome::Correlated(c)) = &golden_ticket {
        record_orphan_accounts(investigation_id, &c.orphans).await;
    }

    let no_match: Vec<String> = completed
        .iter()
        .filter(|n| !fired.iter().any(|f| &f.template == *n))
        .cloned()
        .collect();
    let not_run: Vec<String> = all_names.difference(&completed).cloned().collect();

    info!(
        investigation_id,
        fired = fired.len(),
        no_match = no_match.len(),
        not_run = not_run.len(),
        timed_out,
        golden_ticket = %golden_ticket_log_value(&golden_ticket),
        "Baseline detection sweep complete"
    );

    SweepOutcome {
        templates_total,
        fired,
        no_match,
        not_run,
        timed_out,
        golden_ticket,
    }
}

/// Re-run the golden-ticket correlation as the investigation closes.
///
/// The baseline sweep runs BEFORE the LLM loop, so its window closes the moment
/// the investigation opens — typically minutes before the attack it is
/// investigating has finished. Domain compromise is the LAST phase of an
/// intrusion, so the forged-TGT usage this rule exists to catch routinely lands
/// after the sweep has already answered "clean".
///
/// That is not hypothetical. On op-20260726-003632 the sweep queried at
/// 00:38:47 and returned clean; the orphaned principal's service-ticket request
/// was logged at 00:39:14 — 27 seconds later. Red went on to obtain golden
/// tickets in all three domains and blue never looked again, so a correct rule
/// with a correct verdict still produced a missed detection.
///
/// Re-running only this correlation is cheap (two aggregation queries) and is
/// the only way T1558.001 can be found at all, since no template can express
/// an absent partner event. Records are deduped by the underlying tools, so an
/// overlap with the opening sweep is harmless.
pub(crate) async fn recheck_golden_tickets(investigation_id: &str) -> Option<GoldenTicketOutcome> {
    if !sweep_enabled() || !golden_ticket_enabled() {
        return None;
    }

    let outcome =
        match run_golden_ticket_correlation(SWEEP_HOURS_BACK, golden_baseline_hours()).await {
            Ok(c) => GoldenTicketOutcome::Correlated(c),
            Err(reason) => GoldenTicketOutcome::Inconclusive(reason),
        };

    info!(
        investigation_id,
        golden_ticket = %golden_ticket_log_value(&Some(outcome.clone())),
        "Golden ticket correlation re-checked at investigation close"
    );

    if let GoldenTicketOutcome::Correlated(c) = &outcome {
        if let Some(f) = c.as_fired() {
            warn!(
                investigation_id,
                orphan_accounts = c.orphans.len(),
                candidates = c.candidates,
                baseline = c.baseline,
                "Golden ticket correlation found forged-TGT usage on the closing re-check \
                 (the opening sweep ran before this activity was logged)"
            );
            record_fired(investigation_id, &f).await;
            record_orphan_accounts(investigation_id, &c.orphans).await;
        }
    }

    Some(outcome)
}

/// Render the correlation's verdict for the sweep's completion log.
///
/// Every outcome has to be distinguishable from the log alone. Previously only
/// a hit was logged (via `warn!`), which made "ran, found nothing" and "never
/// produced an answer" look identical — silence. That is the one ambiguity this
/// rule cannot afford, since a clean verdict is treated downstream as
/// authoritative that no forged TGT was used.
fn golden_ticket_log_value(outcome: &Option<GoldenTicketOutcome>) -> String {
    match outcome {
        None => "disabled".to_string(),
        Some(GoldenTicketOutcome::Inconclusive(reason)) => format!("no_verdict ({reason})"),
        Some(GoldenTicketOutcome::Correlated(c)) if c.orphans.is_empty() => {
            format!(
                "clean ({} candidates vs {} baseline)",
                c.candidates, c.baseline
            )
        }
        Some(GoldenTicketOutcome::Correlated(c)) => format!(
            "{} orphan(s) of {} candidates",
            c.orphans.len(),
            c.candidates
        ),
    }
}

/// Dispatch a blue-state write and log whatever went wrong.
///
/// `dispatch_blue` reports a *rejected* write as `Ok(ToolOutput { success:
/// false })`; only transport-level problems come back as `Err`. Matching on
/// `Err` alone therefore swallows exactly the failures worth knowing about —
/// a validation or grounding refusal looks identical to success.
async fn record_state(context: &str, tool: &str, args: &serde_json::Value) {
    match ares_tools::blue::dispatch_blue(tool, args).await {
        Ok(o) if !o.success => {
            warn!(context, tool, reason = %o.stderr, "Blue state write rejected");
        }
        Err(e) => warn!(context, tool, error = %e, "Blue state write failed"),
        Ok(_) => {}
    }
}

/// Name the orphaned principals in the investigation timeline.
///
/// These go in the timeline rather than `add_evidence` on purpose. Evidence
/// values are gated by a grounding check that requires the value to appear
/// verbatim in a stored query result, and `account@domain` is a *derived*
/// identity — normalised from two fields across two different event types, so
/// it appears nowhere in any raw log line. Pushing it through `add_evidence`
/// would be silently rejected, and satisfying the check by injecting a
/// synthetic query result would hollow out a safeguard that exists to stop
/// fabricated IOCs. The technique-level record in [`record_fired`] already
/// carries T1558.001 (its value is the MITRE ID, which auto-grounds); this
/// adds the names an analyst needs to pivot on.
///
/// The enumeration is capped, and the cap is logged rather than applied
/// silently — a truncated list that looks complete would understate the blast
/// radius of a domain-wide forgery.
async fn record_orphan_accounts(investigation_id: &str, orphans: &[OrphanAccount]) {
    if orphans.is_empty() {
        return;
    }
    if orphans.len() > MAX_REPORTED_ORPHANS {
        warn!(
            investigation_id,
            total = orphans.len(),
            recorded = MAX_REPORTED_ORPHANS,
            "Golden ticket orphan list truncated; not every principal was named in the timeline"
        );
    }

    let named: Vec<String> = orphans
        .iter()
        .take(MAX_REPORTED_ORPHANS)
        .map(|o| {
            format!(
                "{} ({} service ticket(s))",
                o.account, o.service_ticket_count
            )
        })
        .collect();
    let suffix = if orphans.len() > named.len() {
        format!(" …and {} more", orphans.len() - named.len())
    } else {
        String::new()
    };

    record_state(
        GOLDEN_TICKET_SOURCE,
        "record_timeline_event",
        &json!({
            "investigation_id": investigation_id,
            "description": format!(
                "Forged-TGT usage: {} principal(s) requested Kerberos service tickets with no \
                 TGT request in the baseline window — {}{}",
                orphans.len(),
                named.join(", "),
                suffix
            ),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "mitre_techniques": [GOLDEN_TICKET_MITRE_ID],
            "source": format!("detection_sweep:{GOLDEN_TICKET_SOURCE}"),
            "confidence": 0.9,
        }),
    )
    .await;
}

/// Record a fired detection as blue-team state: a MITRE technique (for coverage
/// scoring + the report technique table), a TTP-level evidence item (for
/// evidence count, pyramid, precision, and evidence-based chaining), and a
/// timeline event (for the narrative + timeline scoring). The evidence value is
/// the MITRE ID, which auto-validates the grounding check.
async fn record_fired(investigation_id: &str, f: &FiredDetection) {
    let confidence = confidence_for_severity(&f.severity);
    let observed_at = f
        .first_event_at
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let calls = [
        (
            "add_technique",
            json!({
                "investigation_id": investigation_id,
                "technique_id": f.mitre_id,
                "technique_name": f.description,
            }),
        ),
        (
            "add_evidence",
            json!({
                "investigation_id": investigation_id,
                "evidence_type": evidence_type_for_tactic(&f.tactic),
                "value": f.mitre_id,
                "source": format!("detection_sweep:{}", f.template),
                "confidence": confidence,
                "pyramid_level": "ttps",
                "mitre_techniques": [f.mitre_id],
                "timestamp": observed_at,
            }),
        ),
        (
            "record_timeline_event",
            json!({
                "investigation_id": investigation_id,
                "description": format!(
                    "Baseline detection {} fired: {} ({} event(s){})",
                    f.template,
                    f.description,
                    f.event_count,
                    detection_scope_suffix(f),
                ),
                "timestamp": observed_at,
                "mitre_techniques": [f.mitre_id],
                "source": "detection_sweep",
                "confidence": confidence,
            }),
        ),
    ];

    for (tool, args) in calls {
        record_state(&f.template, tool, &args).await;
    }
}

/// Render a detection's observed event window and hosts for the timeline
/// narrative. Empty when the detection carries neither.
fn detection_scope_suffix(f: &FiredDetection) -> String {
    let mut parts = Vec::new();
    if let (Some(first), Some(last)) = (f.first_event_at, f.last_event_at) {
        parts.push(if first == last {
            format!("at {}", first.to_rfc3339())
        } else {
            format!("{} to {}", first.to_rfc3339(), last.to_rfc3339())
        });
    }
    if !f.hosts.is_empty() {
        parts.push(format!("hosts: {}", f.hosts.join(", ")));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" · {}", parts.join(" · "))
    }
}

/// Map a detection's evidence confidence from its severity.
fn confidence_for_severity(severity: &str) -> f64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0.9,
        "high" => 0.8,
        "medium" => 0.6,
        _ => 0.5,
    }
}

/// Pick a valid `evidence_type` (see `validation::KNOWN_EVIDENCE_TYPES`) from a
/// detection's tactic. The pyramid level is passed explicitly as `ttps`, so the
/// type only drives the dedup key and report display; a fired detection is a
/// behavioural observation, so map to the closest known behavioural type.
fn evidence_type_for_tactic(tactic: &str) -> &'static str {
    let t = tactic.to_ascii_lowercase();
    if t.contains("credential") {
        "credential_access"
    } else if t.contains("lateral") {
        "lateral_movement"
    } else if t.contains("privilege") {
        "privilege_escalation"
    } else if t.contains("persistence") {
        "persistence_mechanism"
    } else {
        "log_entry"
    }
}

/// Whether the deterministic sweep should run. Defaults on; set
/// `ARES_BLUE_DETERMINISTIC_SWEEP=0` to disable.
pub(crate) fn sweep_enabled() -> bool {
    match std::env::var("ARES_BLUE_DETERMINISTIC_SWEEP") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Whether the golden-ticket correlation should run. Defaults on; set
/// `ARES_BLUE_GOLDEN_TICKET_CORRELATION=0` to disable.
fn golden_ticket_enabled() -> bool {
    match std::env::var("ARES_BLUE_GOLDEN_TICKET_CORRELATION") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Baseline width for the correlation, overridable via
/// `ARES_BLUE_GOLDEN_BASELINE_HOURS`. Clamped to at least the candidate window;
/// a baseline narrower than the candidates would manufacture orphans out of
/// window-boundary artifacts rather than find forged tickets.
fn golden_baseline_hours() -> i64 {
    std::env::var("ARES_BLUE_GOLDEN_BASELINE_HOURS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|h| *h >= 1)
        .unwrap_or(DEFAULT_GOLDEN_BASELINE_HOURS)
        .max(SWEEP_HOURS_BACK)
}

/// Concurrency for the sweep, overridable via `ARES_BLUE_SWEEP_CONCURRENCY`.
fn sweep_concurrency() -> usize {
    std::env::var("ARES_BLUE_SWEEP_CONCURRENCY")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_SWEEP_CONCURRENCY)
}

/// Overall time cap for the sweep, overridable via `ARES_BLUE_SWEEP_TIMEOUT_SECS`.
fn sweep_timeout_secs() -> u64 {
    std::env::var("ARES_BLUE_SWEEP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_SWEEP_TIMEOUT_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fired(first: Option<&str>, last: Option<&str>, hosts: &[&str]) -> FiredDetection {
        let parse = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .expect("valid rfc3339")
                .with_timezone(&chrono::Utc)
        };
        FiredDetection {
            template: "detect_dcsync".to_string(),
            mitre_id: "T1003.006".to_string(),
            description: "DCSync Detection".to_string(),
            tactic: "credential_access".to_string(),
            severity: "critical".to_string(),
            event_count: 3,
            first_event_at: first.map(parse),
            last_event_at: last.map(parse),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    #[test]
    fn scope_suffix_renders_window_and_hosts() {
        let f = fired(
            Some("2026-07-26T21:41:13Z"),
            Some("2026-07-26T21:55:02Z"),
            &["dc01.contoso.local"],
        );
        let s = detection_scope_suffix(&f);
        assert!(s.contains("2026-07-26T21:41:13"), "{s}");
        assert!(s.contains("to 2026-07-26T21:55:02"), "{s}");
        assert!(s.contains("dc01.contoso.local"), "{s}");
    }

    #[test]
    fn scope_suffix_collapses_single_instant() {
        let f = fired(
            Some("2026-07-26T21:41:13Z"),
            Some("2026-07-26T21:41:13Z"),
            &[],
        );
        let s = detection_scope_suffix(&f);
        assert!(s.contains("at 2026-07-26T21:41:13"), "{s}");
        assert!(!s.contains(" to "), "{s}");
    }

    #[test]
    fn scope_suffix_empty_without_times_or_hosts() {
        assert_eq!(detection_scope_suffix(&fired(None, None, &[])), "");
    }

    #[test]
    fn confidence_scales_with_severity() {
        assert_eq!(confidence_for_severity("critical"), 0.9);
        assert_eq!(confidence_for_severity("HIGH"), 0.8);
        assert_eq!(confidence_for_severity("medium"), 0.6);
        assert_eq!(confidence_for_severity("low"), 0.5);
        assert_eq!(confidence_for_severity("weird"), 0.5);
    }

    #[test]
    fn evidence_type_maps_known_tactics() {
        assert_eq!(
            evidence_type_for_tactic("credential_access"),
            "credential_access"
        );
        assert_eq!(
            evidence_type_for_tactic("lateral_movement"),
            "lateral_movement"
        );
        assert_eq!(
            evidence_type_for_tactic("privilege_escalation"),
            "privilege_escalation"
        );
        assert_eq!(
            evidence_type_for_tactic("persistence"),
            "persistence_mechanism"
        );
        assert_eq!(evidence_type_for_tactic("discovery"), "log_entry");
        assert_eq!(evidence_type_for_tactic("defense_evasion"), "log_entry");
    }

    #[test]
    fn evidence_types_are_all_known_to_validation() {
        // Every value this maps to must be accepted by validate_evidence, or the
        // swept add_evidence call is silently rejected.
        for tactic in [
            "credential_access",
            "lateral_movement",
            "privilege_escalation",
            "persistence",
            "discovery",
            "execution",
            "defense_evasion",
        ] {
            let et = evidence_type_for_tactic(tactic);
            let vr =
                ares_tools::blue::validation::validate_evidence(et, "T1003.006", "detection_sweep");
            assert!(
                vr.valid,
                "evidence_type '{et}' (tactic '{tactic}') rejected by validation"
            );
        }
    }

    #[test]
    fn sweep_enabled_defaults_on_and_respects_off() {
        std::env::remove_var("ARES_BLUE_DETERMINISTIC_SWEEP");
        assert!(sweep_enabled());
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "0");
        assert!(!sweep_enabled());
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "off");
        assert!(!sweep_enabled());
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "1");
        assert!(sweep_enabled());
        std::env::remove_var("ARES_BLUE_DETERMINISTIC_SWEEP");
    }

    #[test]
    fn prompt_summary_lists_fired_and_no_match() {
        let outcome = SweepOutcome {
            templates_total: 3,
            fired: vec![FiredDetection {
                template: "detect_dcsync".into(),
                mitre_id: "T1003.006".into(),
                description: "DCSync Detection".into(),
                tactic: "credential_access".into(),
                severity: "critical".into(),
                event_count: 5,
                first_event_at: None,
                last_event_at: None,
                hosts: Vec::new(),
            }],
            no_match: vec!["detect_golden_ticket".into()],
            not_run: vec![],
            timed_out: false,
            golden_ticket: None,
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("T1003.006"));
        assert!(s.contains("5 matching event"));
        assert!(s.contains("detect_golden_ticket"));
        assert!(s.contains("ALREADY"));
        // Clean finish → no "time cap" note.
        assert!(!s.contains("time cap"));
    }

    #[test]
    fn prompt_summary_notes_timeout_gap() {
        let outcome = SweepOutcome {
            templates_total: 3,
            fired: vec![],
            no_match: vec![],
            not_run: vec!["detect_esc1_attack".into()],
            timed_out: true,
            golden_ticket: None,
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("FIRED: none"));
        assert!(s.contains("time cap"));
        assert!(s.contains("detect_esc1_attack"));
    }

    // ─── Golden ticket correlation ──────────────────────────────────────────

    /// Build metric series from `(account, domain, count)` triples.
    fn series(rows: &[(&str, &str, u64)]) -> Vec<ares_tools::blue::loki::MetricSeries> {
        rows.iter()
            .map(|(account, domain, count)| {
                let mut labels = BTreeMap::new();
                labels.insert(ACCOUNT_LABEL.to_string(), account.to_string());
                labels.insert(DOMAIN_LABEL.to_string(), domain.to_string());
                (labels, *count)
            })
            .collect()
    }

    #[test]
    fn normalize_account_strips_realm_and_case() {
        assert_eq!(
            normalize_account("alice@CONTOSO.LOCAL").as_deref(),
            Some("alice")
        );
        assert_eq!(normalize_account("Alice").as_deref(), Some("alice"));
        assert_eq!(normalize_account("  bob  ").as_deref(), Some("bob"));
        assert_eq!(
            normalize_account("WS01$@CONTOSO.LOCAL").as_deref(),
            Some("ws01$")
        );
    }

    #[test]
    fn normalize_account_rejects_unusable_values() {
        assert_eq!(normalize_account(""), None);
        assert_eq!(normalize_account("   "), None);
        // A bare realm with no account part identifies nobody.
        assert_eq!(normalize_account("@CONTOSO.LOCAL"), None);
    }

    #[test]
    fn normalize_domain_reconciles_netbios_and_fqdn() {
        // 4768 logs `CONTOSO`, 4769 logs `CONTOSO.LOCAL`.
        assert_eq!(normalize_domain("CONTOSO").as_deref(), Some("contoso"));
        assert_eq!(
            normalize_domain("CONTOSO.LOCAL").as_deref(),
            Some("contoso")
        );
        assert_eq!(
            normalize_domain("CHILD.CONTOSO.LOCAL").as_deref(),
            Some("child")
        );
        assert_eq!(normalize_domain(""), None);
    }

    #[test]
    fn principal_totals_merges_both_field_formats() {
        // 4769 logs `alice@REALM` + FQDN domain, 4768 logs `alice` + NetBIOS.
        // If these don't fold together every account lands on both sides at once.
        let totals = principal_totals(&series(&[
            ("alice@CONTOSO.LOCAL", "CONTOSO.LOCAL", 3),
            ("alice", "CONTOSO", 2),
            ("ALICE@CONTOSO.LOCAL", "contoso.local", 1),
        ]));
        assert_eq!(totals.get("alice@contoso"), Some(&6));
        assert_eq!(totals.len(), 1);
    }

    #[test]
    fn principal_key_requires_both_halves() {
        // A half-identity can't be matched against the baseline, so it must be
        // dropped rather than surface as a bogus orphan.
        let mut only_account = BTreeMap::new();
        only_account.insert(ACCOUNT_LABEL.to_string(), "alice".to_string());
        assert_eq!(principal_key(&only_account), None);

        let mut only_domain = BTreeMap::new();
        only_domain.insert(DOMAIN_LABEL.to_string(), "CONTOSO".to_string());
        assert_eq!(principal_key(&only_domain), None);
    }

    #[test]
    fn correlate_flags_account_with_no_tgt_request() {
        // bob used service tickets but never asked for a TGT — a forged one was
        // supplied out of band. alice did both and is ordinary.
        let result = correlate(
            &series(&[
                ("alice@CONTOSO.LOCAL", "CONTOSO.LOCAL", 4),
                ("bob@CONTOSO.LOCAL", "CONTOSO.LOCAL", 9),
            ]),
            &series(&[("alice", "CONTOSO", 2), ("carol", "CONTOSO", 1)]),
        )
        .expect("both sides populated");

        assert_eq!(result.candidates, 2);
        assert_eq!(result.baseline, 2);
        assert_eq!(
            result.orphans,
            vec![OrphanAccount {
                account: "bob@contoso".to_string(),
                service_ticket_count: 9,
            }]
        );
    }

    #[test]
    fn correlate_does_not_flag_account_present_in_both_formats() {
        // The regression that would make this rule useless: comparing the raw
        // fields flags the entire domain, because 4769 appends the realm and
        // uses the FQDN while 4768 does neither.
        let result = correlate(
            &series(&[
                ("alice@CONTOSO.LOCAL", "CONTOSO.LOCAL", 5),
                ("svc_sql@CONTOSO.LOCAL", "CONTOSO.LOCAL", 2),
            ]),
            &series(&[("alice", "CONTOSO", 1), ("svc_sql", "CONTOSO", 1)]),
        )
        .expect("both sides populated");
        assert!(
            result.orphans.is_empty(),
            "realm-suffixed names must match their bare counterparts, got {:?}",
            result.orphans
        );
    }

    #[test]
    fn correlate_does_not_let_one_domain_mask_another() {
        // The false negative this compound key exists to prevent: `admin` is
        // forged in fabrikam, while a legitimate `admin` authenticates in
        // contoso. Keying on the bare account name would hide the forgery.
        let result = correlate(
            &series(&[("admin@FABRIKAM.LOCAL", "FABRIKAM.LOCAL", 12)]),
            &series(&[("admin", "CONTOSO", 30)]),
        )
        .expect("both sides populated");
        assert_eq!(
            result.orphans,
            vec![OrphanAccount {
                account: "admin@fabrikam".to_string(),
                service_ticket_count: 12,
            }],
            "a same-named account in a different domain must not mask the forgery"
        );
    }

    #[test]
    fn correlate_fails_closed_on_empty_baseline() {
        // A live domain always issues TGTs, so an empty baseline means the
        // query broke. Reporting orphans here would flag every active account.
        assert_eq!(
            correlate(&series(&[("alice@CONTOSO.LOCAL", "CONTOSO.LOCAL", 3)]), &[]),
            Err(CorrelationGap::NoBaseline)
        );
    }

    #[test]
    fn correlate_reports_no_candidates_when_no_service_tickets() {
        assert_eq!(
            correlate(&[], &series(&[("alice", "CONTOSO", 1)])),
            Err(CorrelationGap::NoCandidates)
        );
    }

    #[test]
    fn correlate_orders_orphans_by_service_ticket_volume() {
        let result = correlate(
            &series(&[
                ("carol", "CONTOSO", 2),
                ("bob", "CONTOSO", 11),
                ("admin", "CONTOSO", 7),
            ]),
            &series(&[("alice", "CONTOSO", 1)]),
        )
        .expect("both sides populated");
        let names: Vec<&str> = result.orphans.iter().map(|o| o.account.as_str()).collect();
        assert_eq!(names, vec!["bob@contoso", "admin@contoso", "carol@contoso"]);
    }

    #[test]
    fn aggregation_query_anchors_event_id_to_its_json_field() {
        let q = account_aggregation_query(EVENT_TGT_REQUEST, 8);
        // A bare `|= "4768"` also matches record IDs and ticket hashes that
        // merely contain those digits — live, 3607 lines vs 203 — and the
        // surplus is mostly 4769s, which would mask forged accounts.
        assert!(
            q.contains(r#"|= `"event_id":4768`"#),
            "event filter must be anchored to the event_id field, got: {q}"
        );
        assert!(
            q.contains(&format!("sum by ({ACCOUNT_LABEL}, {DOMAIN_LABEL})")),
            "must aggregate per account AND domain — account alone is ambiguous \
             across a forest, got: {q}"
        );
        assert!(
            q.contains("[8h]"),
            "must apply the requested window, got: {q}"
        );
        assert!(
            q.contains(r#"TargetUserName'\\u003e"#),
            "must match the JSON-escaped XML field, got: {q}"
        );
        assert!(
            q.contains(r#"TargetDomainName'\\u003e"#),
            "must extract the domain too, got: {q}"
        );
    }

    #[test]
    fn correlation_fires_only_with_orphans() {
        let clean = GoldenTicketCorrelation {
            candidates: 3,
            baseline: 3,
            orphans: vec![],
        };
        assert!(clean.as_fired().is_none());

        let hit = GoldenTicketCorrelation {
            candidates: 3,
            baseline: 2,
            orphans: vec![
                OrphanAccount {
                    account: "bob".into(),
                    service_ticket_count: 9,
                },
                OrphanAccount {
                    account: "admin".into(),
                    service_ticket_count: 4,
                },
            ],
        };
        let fired = hit.as_fired().expect("orphans must fire");
        assert_eq!(fired.mitre_id, GOLDEN_TICKET_MITRE_ID);
        assert_eq!(fired.event_count, 13);
        assert_eq!(fired.severity, "critical");
    }

    #[test]
    fn summary_distinguishes_clean_from_unchecked() {
        let clean = SweepOutcome {
            golden_ticket: Some(GoldenTicketOutcome::Correlated(GoldenTicketCorrelation {
                candidates: 4,
                baseline: 19,
                orphans: vec![],
            })),
            ..Default::default()
        };
        let s = clean.golden_ticket_summary();
        assert!(s.contains("CLEAN"), "{s}");
        assert!(!s.contains("NO VERDICT"), "{s}");

        let broken = SweepOutcome {
            golden_ticket: Some(GoldenTicketOutcome::Inconclusive("query failed".into())),
            ..Default::default()
        };
        let s = broken.golden_ticket_summary();
        // A failed correlation must never read as an all-clear.
        assert!(s.contains("NO VERDICT"), "{s}");
        assert!(s.contains("unchecked"), "{s}");
        assert!(!s.contains("CLEAN"), "{s}");
    }

    #[test]
    fn clean_verdict_forbids_retagging_from_field_heuristics() {
        // A live investigation tagged T1558.001 off `ServiceName=krbtgt`,
        // `TicketOptions=0x40810010` and an RC4 session key from a non-DC IP —
        // every one of which matches ordinary Kerberos traffic. The clean
        // verdict has to say so, or the LLM re-derives the same false positive
        // on top of a correlation that already answered the question.
        let clean = SweepOutcome {
            golden_ticket: Some(GoldenTicketOutcome::Correlated(GoldenTicketCorrelation {
                candidates: 4,
                baseline: 19,
                orphans: vec![],
            })),
            ..Default::default()
        };
        let s = clean.golden_ticket_summary();
        assert!(
            s.contains("authoritative"),
            "clean verdict must claim authority over {GOLDEN_TICKET_MITRE_ID}: {s}"
        );
        assert!(
            s.contains("Do NOT record"),
            "clean verdict must forbid re-tagging: {s}"
        );
        for non_signal in ["krbtgt", "0x40810010", "non-DC IP", "RC4 session key"] {
            assert!(
                s.contains(non_signal),
                "clean verdict must name the non-signal '{non_signal}': {s}"
            );
        }
    }

    #[test]
    fn summary_names_orphans_and_declares_truncation() {
        let orphans: Vec<OrphanAccount> = (0..MAX_REPORTED_ORPHANS + 5)
            .map(|i| OrphanAccount {
                account: format!("svc_{i:02}"),
                service_ticket_count: 1,
            })
            .collect();
        let outcome = SweepOutcome {
            golden_ticket: Some(GoldenTicketOutcome::Correlated(GoldenTicketCorrelation {
                candidates: 40,
                baseline: 12,
                orphans,
            })),
            ..Default::default()
        };
        let s = outcome.golden_ticket_summary();
        assert!(s.contains("svc_00"), "{s}");
        assert!(s.contains(GOLDEN_TICKET_MITRE_ID), "{s}");
        // The cap is stated, not applied silently.
        assert!(s.contains("5 more"), "{s}");
        assert!(!s.contains("svc_24"), "listing must stop at the cap: {s}");
    }

    #[tokio::test]
    async fn recheck_is_disabled_by_the_same_toggles_as_the_sweep() {
        // The close-of-investigation re-check must respect both switches, or
        // disabling the sweep would still fire two Loki queries per
        // investigation.
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "0");
        assert!(recheck_golden_tickets("inv-test").await.is_none());
        std::env::remove_var("ARES_BLUE_DETERMINISTIC_SWEEP");

        std::env::set_var("ARES_BLUE_GOLDEN_TICKET_CORRELATION", "0");
        assert!(recheck_golden_tickets("inv-test").await.is_none());
        std::env::remove_var("ARES_BLUE_GOLDEN_TICKET_CORRELATION");
    }

    #[test]
    fn every_correlation_outcome_is_distinguishable_in_the_log() {
        // "ran and found nothing" must never look like "never produced an
        // answer". A clean verdict is treated as authoritative downstream, so
        // the log has to say which one actually happened.
        assert_eq!(golden_ticket_log_value(&None), "disabled");

        let clean = golden_ticket_log_value(&Some(GoldenTicketOutcome::Correlated(
            GoldenTicketCorrelation {
                candidates: 4,
                baseline: 19,
                orphans: vec![],
            },
        )));
        assert!(clean.starts_with("clean"), "{clean}");
        assert!(clean.contains('4') && clean.contains("19"), "{clean}");

        let hit = golden_ticket_log_value(&Some(GoldenTicketOutcome::Correlated(
            GoldenTicketCorrelation {
                candidates: 5,
                baseline: 19,
                orphans: vec![OrphanAccount {
                    account: "admin@contoso".into(),
                    service_ticket_count: 3,
                }],
            },
        )));
        assert!(hit.contains("1 orphan"), "{hit}");

        let broken = golden_ticket_log_value(&Some(GoldenTicketOutcome::Inconclusive(
            "baseline query failed".into(),
        )));
        assert!(broken.starts_with("no_verdict"), "{broken}");
        assert!(broken.contains("baseline query failed"), "{broken}");

        // All four must be mutually distinct.
        let all = [clean, hit, broken, "disabled".to_string()];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "log values must be distinguishable");
            }
        }
    }

    #[test]
    fn golden_summary_absent_when_correlation_disabled() {
        assert!(SweepOutcome::default().golden_ticket_summary().is_empty());
    }

    #[test]
    fn baseline_window_never_narrower_than_candidate_window() {
        // A baseline narrower than the candidate window manufactures orphans
        // out of boundary artifacts instead of finding forged tickets.
        std::env::set_var("ARES_BLUE_GOLDEN_BASELINE_HOURS", "1");
        assert!(golden_baseline_hours() >= SWEEP_HOURS_BACK);
        std::env::set_var("ARES_BLUE_GOLDEN_BASELINE_HOURS", "12");
        assert_eq!(golden_baseline_hours(), 12);
        std::env::remove_var("ARES_BLUE_GOLDEN_BASELINE_HOURS");
        assert_eq!(golden_baseline_hours(), DEFAULT_GOLDEN_BASELINE_HOURS);
    }

    #[test]
    fn ran_reflects_template_total() {
        assert!(!SweepOutcome::default().ran());
        assert!(SweepOutcome {
            templates_total: 1,
            ..Default::default()
        }
        .ran());
    }
}
