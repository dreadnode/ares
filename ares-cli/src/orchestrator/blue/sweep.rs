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
use tracing::{error, info, warn};

use ares_core::detection::detection_config;
use ares_core::models::SWEEP_TIMELINE_SOURCE;

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

const DEFAULT_SWEEP_REFRESH_SECS: u64 = 900;

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

/// Windows event ID for a successful logon.
const EVENT_LOGON: &str = "4624";

/// Source name recorded for correlation hits. Deliberately distinct from the
/// catalog template names so evidence points at the rule that actually
/// concluded something rather than at the anchor that cannot fire.
const GOLDEN_TICKET_RULE: TicketRule = TicketRule {
    mitre_id: "T1558.001",
    source: "golden_ticket_correlation",
    description: "Golden Ticket Detection (service tickets with no preceding TGT request)",
    tactic: "persistence",
    severity: "critical",
    event_noun: "service ticket",
    finding_label: "Forged-TGT usage",
    finding_detail: "requested Kerberos service tickets with no TGT request in the baseline window",
};

/// A Silver Ticket is the mirror image of a Golden Ticket: a TGS forged offline
/// with the *service account's* key and handed straight to that service, so the
/// KDC mints nothing and there is no 4769 anywhere. The service host still logs
/// a successful Kerberos network logon (4624, LogonType 3), which line-by-line
/// is indistinguishable from every legitimate SMB, LDAP, MSSQL and WinRM access
/// in the domain. The discriminating signal is again an absent partner event,
/// this time one host over — so `detect_silver_ticket` is the same kind of
/// non-firing catalog anchor and the real rule is
/// [`run_silver_ticket_correlation`].
const SILVER_TICKET_RULE: TicketRule = TicketRule {
    mitre_id: "T1558.002",
    source: "silver_ticket_correlation",
    description: "Silver Ticket Detection (Kerberos service logon with no KDC-issued ticket)",
    tactic: "credential_access",
    severity: "critical",
    event_noun: "Kerberos logon",
    finding_label: "Forged service-ticket usage",
    finding_detail: "completed Kerberos network logons with no service ticket issued by any DC in \
                     the baseline window",
};

/// Identity and prose for one forged-ticket correlation.
///
/// Both rules share the whole comparison pipeline and differ only in which pair
/// of events they diff and how the result is worded, so the differences live in
/// data rather than in a duplicated code path.
struct TicketRule {
    mitre_id: &'static str,
    source: &'static str,
    description: &'static str,
    tactic: &'static str,
    severity: &'static str,
    /// Unit for the per-principal event count in prose.
    event_noun: &'static str,
    /// Short name for what the orphans did, opening the timeline sentence.
    finding_label: &'static str,
    /// Rest of that sentence, describing the absence that was observed.
    finding_detail: &'static str,
}

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

/// Line filters narrowing 4624 to a Kerberos *network* logon — the shape a
/// forged service ticket produces on the host it is presented to.
///
/// `LogonType` 3 excludes interactive (2), service (5), unlock (7) and RDP (10)
/// logons, none of which a silver ticket drives, and the trailing `\\u003c`
/// anchors the value so `3` cannot also match a two-digit type. The
/// authentication package excludes NTLM, which is Pass-the-Hash (T1550.002),
/// not a forged ticket. Same JSON-escaped XML shape the catalog templates match.
const LOGON_TYPE_NETWORK_REGEXP: &str = r#"LogonType'\\u003e3\\u003c"#;
const KERBEROS_PACKAGE_REGEXP: &str = r#"AuthenticationPackageName'\\u003eKerberos"#;

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

/// Hours of service-ticket history forming the silver-ticket baseline.
///
/// Wider than the golden baseline on purpose. The quantity being bounded here is
/// how long a *service ticket* stays usable without going back to the KDC, and
/// that is the domain's 10h maximum ticket lifetime — a client with a cached TGS
/// keeps authenticating to the service for the whole of it, emitting 4624s with
/// no matching 4769. Anything under 10h therefore turns ordinary long-lived
/// sessions into reported forgeries, which is the one error this rule cannot
/// afford.
const DEFAULT_SILVER_BASELINE_HOURS: i64 = 12;

/// Suffix marking a Windows machine account.
///
/// Machine accounts are dropped from the silver-ticket candidate set. Computers
/// authenticate to each other constantly and cache their service tickets for the
/// full ticket lifetime, so they dominate the 4624 network-logon population and
/// would swamp the real signal with boundary artifacts — the same reason the
/// DCSync templates exclude them. The cost is a blind spot for a ticket forged
/// under a machine-account client name; the point of a silver ticket is to
/// impersonate a privileged *user* to one service, so that is the cheaper error.
const MACHINE_ACCOUNT_SUFFIX: char = '$';

/// Cap on principals enumerated in the timeline and the prompt. The count
/// reported is always the true one; only the enumeration is bounded.
const MAX_REPORTED_ORPHANS: usize = 20;

/// A principal whose Kerberos activity has no matching KDC event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrphanAccount {
    /// `account@domain`, both normalised.
    pub account: String,
    /// Candidate-side events observed for this principal — service-ticket
    /// requests for the golden rule, network logons for the silver rule.
    pub event_count: u64,
}

/// A completed candidate-versus-baseline comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TicketCorrelation {
    /// Distinct principals seen on the candidate side of the diff.
    pub candidates: usize,
    /// Distinct principals with the partner KDC event across the wider baseline
    /// window.
    pub baseline: usize,
    /// Candidates with no partner event anywhere in the baseline window.
    pub orphans: Vec<OrphanAccount>,
}

/// What a correlation was able to conclude.
#[derive(Debug, Clone)]
pub(crate) enum TicketOutcome {
    Correlated(TicketCorrelation),
    /// Ran but drew no conclusion — reported rather than silently treated as
    /// "clean", because "we could not tell" and "nothing was there" carry very
    /// different follow-up obligations for the analyst.
    Inconclusive(String),
}

/// Why a comparison could not conclude.
#[derive(Debug, PartialEq, Eq)]
enum CorrelationGap {
    /// No candidate-side activity at all — nothing to correlate against.
    NoCandidates,
    /// No KDC activity anywhere in the baseline window. A live domain always
    /// mints tickets, so this means the baseline query broke or the log shape
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

/// Diff candidate principals against the principals the KDC has a record for.
///
/// Orphans come back loudest first: the principal with the most candidate events
/// is the one that actually did something with the forged ticket, so it is the
/// one worth naming when the enumeration is capped.
fn correlate(
    candidate_events: &[ares_tools::blue::loki::MetricSeries],
    kdc_events: &[ares_tools::blue::loki::MetricSeries],
) -> Result<TicketCorrelation, CorrelationGap> {
    let candidates = principal_totals(candidate_events);
    let baseline = principal_totals(kdc_events);

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
            event_count: *count,
        })
        .collect();
    orphans.sort_by(|a, b| {
        b.event_count
            .cmp(&a.event_count)
            .then_with(|| a.account.cmp(&b.account))
    });

    Ok(TicketCorrelation {
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
    event_aggregation_query(event_id, hours, &[])
}

/// Build the aggregation that returns one series per account for `event_id`,
/// narrowed by any additional line-filter regexes.
///
/// The extra filters are applied before the `regexp` parsers so Loki discards
/// non-matching lines without paying for label extraction.
fn event_aggregation_query(event_id: &str, hours: i64, line_filters: &[&str]) -> String {
    let selector = ares_tools::blue::detection::build_selector(
        ares_tools::blue::detection::WIN_SECURITY,
        None,
    );
    let filters: String = line_filters
        .iter()
        .map(|f| format!(" |~ `{f}`"))
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"sum by ({ACCOUNT_LABEL}, {DOMAIN_LABEL}) (count_over_time({selector} |= `"event_id":{event_id}`{filters} | regexp `{ACCOUNT_REGEXP}` | regexp `{DOMAIN_REGEXP}` [{hours}h]))"#
    )
}

/// Build the aggregation over Kerberos *network* logons — the silver-ticket
/// candidate set.
fn kerberos_logon_aggregation_query(hours: i64) -> String {
    event_aggregation_query(
        EVENT_LOGON,
        hours,
        &[LOGON_TYPE_NETWORK_REGEXP, KERBEROS_PACKAGE_REGEXP],
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
) -> Result<TicketCorrelation, String> {
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

/// Whether a candidate series belongs to a Windows machine account.
fn is_machine_account(labels: &BTreeMap<String, String>) -> bool {
    labels
        .get(ACCOUNT_LABEL)
        .and_then(|raw| normalize_account(raw))
        .is_some_and(|a| a.ends_with(MACHINE_ACCOUNT_SUFFIX))
}

/// Run the correlation: which principals completed a Kerberos network logon that
/// no DC ever issued a service ticket for?
///
/// The baseline is the 4769 stream, so a legitimate client — which must ask the
/// KDC for a TGS before it can present one — always appears on both sides. A
/// silver ticket appears only on the candidate side, because the service host
/// validates it with its own key and the KDC is never involved.
///
/// Both queries must succeed, for the same reason as the golden correlation: an
/// empty baseline is indistinguishable from a domain nobody authenticated in and
/// would report every active principal as a forgery.
async fn run_silver_ticket_correlation(
    candidate_hours: i64,
    baseline_hours: i64,
) -> Result<TicketCorrelation, String> {
    let candidate_query = kerberos_logon_aggregation_query(candidate_hours);
    let baseline_query = account_aggregation_query(EVENT_SERVICE_TICKET, baseline_hours);
    let (logons, service_tickets) = tokio::join!(
        ares_tools::blue::loki::query_metric_series(&candidate_query, None),
        ares_tools::blue::loki::query_metric_series(&baseline_query, None),
    );

    let logons = logons.map_err(|e| format!("Kerberos logon ({EVENT_LOGON}) query failed: {e}"))?;
    let service_tickets = service_tickets
        .map_err(|e| format!("service-ticket ({EVENT_SERVICE_TICKET}) query failed: {e}"))?;

    let user_logons: Vec<ares_tools::blue::loki::MetricSeries> = logons
        .into_iter()
        .filter(|(labels, _)| !is_machine_account(labels))
        .collect();

    correlate(&user_logons, &service_tickets).map_err(|gap| match gap {
        CorrelationGap::NoCandidates => format!(
            "no user Kerberos network logons ({EVENT_LOGON}, logon type 3) in the last \
             {candidate_hours}h — nothing to correlate"
        ),
        CorrelationGap::NoBaseline => format!(
            "no {EVENT_SERVICE_TICKET} activity in the last {baseline_hours}h; a live domain always \
             issues service tickets, so the baseline is untrustworthy and no verdict is drawn"
        ),
    })
}

impl TicketCorrelation {
    /// Represent orphaned accounts as a fired detection so they flow through
    /// the same recording and prompt path as every template hit.
    fn as_fired(&self, rule: &TicketRule) -> Option<FiredDetection> {
        (!self.orphans.is_empty()).then(|| FiredDetection {
            template: rule.source.to_string(),
            mitre_id: rule.mitre_id.to_string(),
            description: rule.description.to_string(),
            tactic: rule.tactic.to_string(),
            severity: rule.severity.to_string(),
            event_count: self.orphans.iter().map(|o| o.event_count as usize).sum(),
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

pub(crate) fn attack_window_start(
    alert: &serde_json::Value,
) -> Option<chrono::DateTime<chrono::Utc>> {
    alert
        .get("operation_context")?
        .get("attack_window_start")?
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

fn attributable(f: &FiredDetection, attack_start: Option<chrono::DateTime<chrono::Utc>>) -> bool {
    match (attack_start, f.last_event_at.or(f.first_event_at)) {
        (Some(start), Some(last)) => last >= start,
        _ => true,
    }
}

/// What one detection template's query produced.
enum TemplateResult {
    Fired(Box<FiredDetection>),
    NoMatch,
    Failed,
}

/// Result of a baseline sweep — what fired, what came back empty, and what the
/// time cap cut off before it could run.
#[derive(Debug, Default)]
pub(crate) struct SweepOutcome {
    pub templates_total: usize,
    pub fired: Vec<FiredDetection>,
    /// Detections whose matched events all predate the operation's attack
    /// window. Reported, never recorded: they belong to earlier activity.
    pub out_of_window: Vec<FiredDetection>,
    /// Templates that ran and returned no matches.
    pub no_match: Vec<String>,
    /// Templates whose query errored. NOT the same as `no_match`: nothing was
    /// observed either way, so the technique is unchecked, not clean. Folding
    /// these into `no_match` told the analyst a technique was cleared when the
    /// query never returned.
    pub failed: Vec<String>,
    /// Templates the time cap prevented from running (empty on a clean finish).
    pub not_run: Vec<String>,
    /// `template/tool` pairs whose blue-state write was refused or errored.
    /// A detection listed in `fired` whose write appears here did NOT become
    /// coverage, so the sweep's own report would otherwise overstate what the
    /// scorecard can see.
    pub rejected_writes: Vec<String>,
    pub timed_out: bool,
    /// Golden-ticket correlation result; `None` when it was disabled.
    pub golden_ticket: Option<TicketOutcome>,
    /// Silver-ticket correlation result; `None` when it was disabled.
    pub silver_ticket: Option<TicketOutcome>,
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

        if !self.failed.is_empty() {
            s.push_str(&format!(
                "FAILED to run ({}) — the query errored, so these techniques are UNCHECKED, not \
                 clean. Nothing was observed either way. Re-run these yourself before concluding \
                 anything about them, and do NOT report them as absent: {}\n\n",
                self.failed.len(),
                self.failed.join(", ")
            ));
        }

        if !self.out_of_window.is_empty() {
            s.push_str(&format!(
                "Matched only OUTSIDE this operation's attack window ({}) — earlier activity, \
                 NOT this operation's. These are deliberately not recorded as evidence or \
                 techniques. Do NOT claim them as detections of this operation: {}\n\n",
                self.out_of_window.len(),
                self.out_of_window
                    .iter()
                    .map(|f| format!("{} [{}]", f.mitre_id, f.template))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if !self.rejected_writes.is_empty() {
            s.push_str(&format!(
                "WARNING — {} sweep state write(s) were REJECTED, so the detections they carried \
                 are NOT recorded as evidence or techniques despite being listed as FIRED above. \
                 Re-record these yourself with add_technique / add_evidence, or they will be \
                 missing from coverage entirely: {}\n\n",
                self.rejected_writes.len(),
                self.rejected_writes.join(", ")
            ));
        }

        s.push_str(&self.golden_ticket_summary());
        s.push_str(&self.silver_ticket_summary());

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
        let id = GOLDEN_TICKET_RULE.mitre_id;
        let mut s = String::from("Golden ticket correlation (4769 with no preceding 4768): ");
        match outcome {
            TicketOutcome::Inconclusive(reason) => {
                s.push_str(&format!(
                    "NO VERDICT — {reason}. Treat {id} as unchecked, not as absent.\n\n"
                ));
            }
            TicketOutcome::Correlated(c) if c.orphans.is_empty() => {
                s.push_str(&format!(
                    "CLEAN — all {} account(s) that requested a service ticket also requested a \
                     TGT (baseline: {} account(s)). There was no forged-TGT usage.\n\
                     This correlation is the authoritative answer for \
                     {id}; it is the only signal that can distinguish a forged \
                     TGT from ordinary Kerberos traffic. Do NOT record \
                     {id} on top of it. In particular, none of these are \
                     golden-ticket indicators — each matches ordinary traffic: a 4769 whose \
                     ServiceName is krbtgt (that is a TGT renewal), a TicketOptions value like \
                     0x40810010 (that is the ordinary value), a request from a non-DC IP (every \
                     workstation does that), or an RC4 session key (present on nearly every \
                     event). An RC4 *ticket* is Kerberoasting (T1558.003), not golden.\n\n",
                    c.candidates, c.baseline
                ));
            }
            TicketOutcome::Correlated(c) => {
                s.push_str(&format!(
                    "{} of {} account(s) used service tickets with NO TGT request in the baseline \
                     window — the signature of a forged TGT. Already recorded as {id}:\n",
                    c.orphans.len(),
                    c.candidates
                ));
                s.push_str(&orphan_listing(&c.orphans, GOLDEN_TICKET_RULE.event_noun));
                s.push_str(
                    "Pivot on these accounts: what they authenticated to and what they touched.\n\n",
                );
            }
        }
        s
    }

    /// Report the silver-ticket correlation, including when it concluded
    /// nothing.
    ///
    /// Held to the same standard as the golden summary: `detect_silver_ticket`
    /// cannot fire, so if this section were silent the analyst would read the
    /// template's absence from the FIRED list as "checked, clean" when the truth
    /// may be that the correlation never returned an answer.
    fn silver_ticket_summary(&self) -> String {
        let Some(outcome) = &self.silver_ticket else {
            return String::new();
        };
        let id = SILVER_TICKET_RULE.mitre_id;
        let mut s = String::from(
            "Silver ticket correlation (Kerberos network logon on a service host with no 4769 on \
             any DC): ",
        );
        match outcome {
            TicketOutcome::Inconclusive(reason) => {
                s.push_str(&format!(
                    "NO VERDICT — {reason}. Treat {id} as unchecked, not as absent.\n\n"
                ));
            }
            TicketOutcome::Correlated(c) if c.orphans.is_empty() => {
                s.push_str(&format!(
                    "CLEAN — all {} user account(s) that completed a Kerberos network logon were \
                     also issued a service ticket by a DC (baseline: {} account(s)). No forged \
                     service ticket was presented. Machine accounts are excluded from the \
                     candidate set: they cache service tickets for the full ticket lifetime, so \
                     they generate boundary artifacts rather than signal.\n\
                     This correlation is the authoritative answer for {id}; it is the only signal \
                     that can distinguish a forged service ticket from ordinary Kerberos traffic, \
                     because the forged ticket is validated by the service's own key and the KDC \
                     is never involved. Do NOT record {id} on top of it. In particular, none of \
                     these are silver-ticket indicators — each matches ordinary traffic: a 4624 \
                     with logon type 3 and AuthenticationPackageName Kerberos (that is every SMB, \
                     LDAP, MSSQL and WinRM access in the domain), a 4672 next to it (every \
                     administrative logon emits one), an RC4 session key, or a logon from a \
                     non-DC IP. A forged ticket that the DC DID issue a 4769 for is not a silver \
                     ticket — check the golden correlation instead.\n\n",
                    c.candidates, c.baseline
                ));
            }
            TicketOutcome::Correlated(c) => {
                s.push_str(&format!(
                    "{} of {} user account(s) completed Kerberos network logons that NO DC issued \
                     a service ticket for in the baseline window — the signature of a service \
                     ticket forged with the service account's own key. Already recorded as \
                     {id}:\n",
                    c.orphans.len(),
                    c.candidates
                ));
                s.push_str(&orphan_listing(&c.orphans, SILVER_TICKET_RULE.event_noun));
                s.push_str(
                    "Pivot on these accounts: which hosts and services they logged on to, whether \
                     a 4672 accompanied the logon (a forged PAC claiming privileged groups), and \
                     what the session then accessed. The service account whose key was used is \
                     compromised too — find how its hash was obtained.\n\n",
                );
            }
        }
        s
    }
}

/// Render orphaned principals as a bounded bullet list.
///
/// The cap is declared in the output rather than applied silently: a truncated
/// list that looks complete would understate the blast radius.
fn orphan_listing(orphans: &[OrphanAccount], noun: &str) -> String {
    let mut s = String::new();
    for o in orphans.iter().take(MAX_REPORTED_ORPHANS) {
        s.push_str(&format!("- {} ({} {noun}(s))\n", o.account, o.event_count));
    }
    if orphans.len() > MAX_REPORTED_ORPHANS {
        s.push_str(&format!(
            "- …and {} more (listing capped at {MAX_REPORTED_ORPHANS})\n",
            orphans.len() - MAX_REPORTED_ORPHANS
        ));
    }
    s
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
pub(crate) async fn run_detection_sweep(
    investigation_id: &str,
    attack_start: Option<chrono::DateTime<chrono::Utc>>,
) -> SweepOutcome {
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
    let mut silver_task = silver_ticket_enabled().then(|| {
        tokio::spawn(run_silver_ticket_correlation(
            SWEEP_HOURS_BACK,
            silver_baseline_hours(),
        ))
    });

    let sem = Arc::new(Semaphore::new(sweep_concurrency()));
    let mut set: tokio::task::JoinSet<(String, TemplateResult)> = tokio::task::JoinSet::new();
    for tmpl in templates {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return (tmpl.template.clone(), TemplateResult::Failed);
            };
            let out = ares_tools::blue::detection::run_detection_query_events(
                &tmpl.template,
                None,
                SWEEP_HOURS_BACK,
                attack_start,
            )
            .await;
            let result = match out {
                Ok(ev) if ev.event_count > 0 => TemplateResult::Fired(Box::new(FiredDetection {
                    event_count: ev.event_count,
                    first_event_at: ev.first_event_at,
                    last_event_at: ev.last_event_at,
                    hosts: ev.hosts,
                    ..tmpl.clone()
                })),
                Ok(_) => TemplateResult::NoMatch,
                Err(e) => {
                    warn!(template = %tmpl.template, error = %e, "Sweep detection query failed");
                    TemplateResult::Failed
                }
            };
            (tmpl.template, result)
        });
    }

    let mut fired: Vec<FiredDetection> = Vec::new();
    let mut completed: BTreeSet<String> = BTreeSet::new();
    let mut failed: BTreeSet<String> = BTreeSet::new();
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
                    Some(Ok((name, result))) => {
                        match result {
                            TemplateResult::Fired(f) => {
                                completed.insert(name);
                                fired.push(*f);
                            }
                            TemplateResult::NoMatch => {
                                completed.insert(name);
                            }
                            TemplateResult::Failed => {
                                failed.insert(name);
                            }
                        }
                    }
                    // Task panic or abort — skip it, don't sink the sweep.
                    Some(Err(_)) => {}
                    None => break,
                }
            }
        }
    }

    let mut golden_ticket = None;
    if let Some(handle) = golden_task.as_mut() {
        let (outcome, capped) = collect_correlation(handle, deadline_at).await;
        timed_out |= capped;
        golden_ticket = Some(outcome);
    }
    let mut silver_ticket = None;
    if let Some(handle) = silver_task.as_mut() {
        let (outcome, capped) = collect_correlation(handle, deadline_at).await;
        timed_out |= capped;
        silver_ticket = Some(outcome);
    }

    for (rule, outcome) in [
        (&GOLDEN_TICKET_RULE, &golden_ticket),
        (&SILVER_TICKET_RULE, &silver_ticket),
    ] {
        let Some(TicketOutcome::Correlated(c)) = outcome else {
            continue;
        };
        if let Some(f) = c.as_fired(rule) {
            warn!(
                investigation_id,
                rule = rule.source,
                mitre_id = rule.mitre_id,
                orphan_accounts = c.orphans.len(),
                candidates = c.candidates,
                baseline = c.baseline,
                "Forged-ticket correlation found Kerberos activity with no matching KDC record"
            );
            fired.push(f);
        }
    }

    fired.sort_by(|a, b| a.template.cmp(&b.template));

    let (fired, out_of_window): (Vec<FiredDetection>, Vec<FiredDetection>) = fired
        .into_iter()
        .partition(|f| attributable(f, attack_start));

    if !out_of_window.is_empty() {
        warn!(
            investigation_id,
            out_of_window = out_of_window.len(),
            attack_start = %attack_start.map(|t| t.to_rfc3339()).unwrap_or_default(),
            templates = %out_of_window.iter().map(|f| f.template.as_str()).collect::<Vec<_>>().join(", "),
            "Detections fired outside the attack window — not attributed to this operation"
        );
    }

    // Record every hit into blue state (sequential, cheap: a few Redis writes
    // each). Deduped by the underlying tools, so overlap with the LLM's own
    // later recording is harmless.
    let mut rejected_writes = Vec::new();
    for f in &fired {
        rejected_writes.extend(record_fired(investigation_id, f).await);
    }

    for (rule, outcome) in [
        (&GOLDEN_TICKET_RULE, &golden_ticket),
        (&SILVER_TICKET_RULE, &silver_ticket),
    ] {
        if let Some(TicketOutcome::Correlated(c)) = outcome {
            rejected_writes
                .extend(record_orphan_accounts(investigation_id, rule, &c.orphans).await);
        }
    }

    if !rejected_writes.is_empty() {
        error!(
            investigation_id,
            rejected = rejected_writes.len(),
            writes = %rejected_writes.join(", "),
            "Sweep detections did not reach blue state — coverage is lower than this sweep reports"
        );
    }

    let no_match: Vec<String> = completed
        .iter()
        .filter(|n| {
            !fired.iter().any(|f| &f.template == *n)
                && !out_of_window.iter().any(|f| &f.template == *n)
        })
        .cloned()
        .collect();
    let not_run: Vec<String> = all_names
        .difference(&completed)
        .filter(|n| !failed.contains(*n))
        .cloned()
        .collect();
    let failed: Vec<String> = failed.into_iter().collect();

    if !failed.is_empty() {
        warn!(
            investigation_id,
            failed = failed.len(),
            templates = %failed.join(", "),
            "Detection queries errored — these techniques are UNCHECKED, not clean"
        );
    }

    info!(
        investigation_id,
        fired = fired.len(),
        out_of_window = out_of_window.len(),
        no_match = no_match.len(),
        failed = failed.len(),
        not_run = not_run.len(),
        timed_out,
        golden_ticket = %ticket_log_value(&golden_ticket),
        silver_ticket = %ticket_log_value(&silver_ticket),
        "Baseline detection sweep complete"
    );

    SweepOutcome {
        templates_total,
        fired,
        out_of_window,
        no_match,
        failed,
        not_run,
        rejected_writes,
        timed_out,
        golden_ticket,
        silver_ticket,
    }
}

/// Await one correlation task under the sweep's shared deadline.
///
/// The deadline is the sweep's, not the task's own, so a hung Loki cannot push
/// the sweep past the budget the investigation runner allows it. Returns whether
/// the deadline was what ended it, so the caller can mark the sweep as capped.
///
/// Every failure mode collapses to `Inconclusive` rather than to a clean verdict:
/// a task that never answered has not cleared the technique. On timeout the
/// handle is aborted rather than dropped — dropping a `JoinHandle` only detaches
/// the task, leaving the in-flight Loki queries running.
async fn collect_correlation(
    handle: &mut tokio::task::JoinHandle<Result<TicketCorrelation, String>>,
    deadline_at: tokio::time::Instant,
) -> (TicketOutcome, bool) {
    match tokio::time::timeout_at(deadline_at, &mut *handle).await {
        Ok(Ok(Ok(c))) => (TicketOutcome::Correlated(c), false),
        Ok(Ok(Err(reason))) => (TicketOutcome::Inconclusive(reason), false),
        Ok(Err(e)) => (
            TicketOutcome::Inconclusive(format!("correlation task failed: {e}")),
            false,
        ),
        Err(_) => {
            handle.abort();
            (
                TicketOutcome::Inconclusive(
                    "hit the sweep time cap before both Kerberos queries returned".to_string(),
                ),
                true,
            )
        }
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
pub(crate) async fn recheck_golden_tickets(investigation_id: &str) -> Option<TicketOutcome> {
    if !sweep_enabled() || !golden_ticket_enabled() {
        return None;
    }
    let result = run_golden_ticket_correlation(SWEEP_HOURS_BACK, golden_baseline_hours()).await;
    Some(record_recheck(investigation_id, &GOLDEN_TICKET_RULE, result).await)
}

/// Re-run the silver-ticket correlation as the investigation closes.
///
/// Same reason as the golden re-check, and if anything more acute: a silver
/// ticket is forged from a service-account key that red only obtains partway
/// through the intrusion, so the forged logon lands even later in the timeline
/// than a forged TGT. The opening sweep's window closes before the ticket exists.
pub(crate) async fn recheck_silver_tickets(investigation_id: &str) -> Option<TicketOutcome> {
    if !sweep_enabled() || !silver_ticket_enabled() {
        return None;
    }
    let result = run_silver_ticket_correlation(SWEEP_HOURS_BACK, silver_baseline_hours()).await;
    Some(record_recheck(investigation_id, &SILVER_TICKET_RULE, result).await)
}

/// Log a closing re-check's verdict and record it if it found anything.
async fn record_recheck(
    investigation_id: &str,
    rule: &TicketRule,
    result: Result<TicketCorrelation, String>,
) -> TicketOutcome {
    let outcome = match result {
        Ok(c) => TicketOutcome::Correlated(c),
        Err(reason) => TicketOutcome::Inconclusive(reason),
    };

    info!(
        investigation_id,
        rule = rule.source,
        mitre_id = rule.mitre_id,
        verdict = %ticket_log_value(&Some(outcome.clone())),
        "Forged-ticket correlation re-checked at investigation close"
    );

    if let TicketOutcome::Correlated(c) = &outcome {
        if let Some(f) = c.as_fired(rule) {
            warn!(
                investigation_id,
                rule = rule.source,
                mitre_id = rule.mitre_id,
                orphan_accounts = c.orphans.len(),
                candidates = c.candidates,
                baseline = c.baseline,
                "Forged-ticket correlation found a forgery on the closing re-check \
                 (the opening sweep ran before this activity was logged)"
            );
            let mut rejected = record_fired(investigation_id, &f).await;
            rejected.extend(record_orphan_accounts(investigation_id, rule, &c.orphans).await);
            if !rejected.is_empty() {
                error!(
                    investigation_id,
                    rule = rule.source,
                    writes = %rejected.join(", "),
                    "Closing re-check found a forgery but its state writes were refused — \
                     the detection will not appear as coverage"
                );
            }
        }
    }

    outcome
}

/// Render a correlation's verdict for the sweep's completion log.
///
/// Every outcome has to be distinguishable from the log alone. Previously only
/// a hit was logged (via `warn!`), which made "ran, found nothing" and "never
/// produced an answer" look identical — silence. That is the one ambiguity these
/// rules cannot afford, since a clean verdict is treated downstream as
/// authoritative that no ticket was forged.
fn ticket_log_value(outcome: &Option<TicketOutcome>) -> String {
    match outcome {
        None => "disabled".to_string(),
        Some(TicketOutcome::Inconclusive(reason)) => format!("no_verdict ({reason})"),
        Some(TicketOutcome::Correlated(c)) if c.orphans.is_empty() => {
            format!(
                "clean ({} candidates vs {} baseline)",
                c.candidates, c.baseline
            )
        }
        Some(TicketOutcome::Correlated(c)) => format!(
            "{} orphan(s) of {} candidates",
            c.orphans.len(),
            c.candidates
        ),
    }
}

/// Dispatch a blue-state write, returning whether it landed.
///
/// `dispatch_blue` reports a *rejected* write as `Ok(ToolOutput { success:
/// false })`; only transport-level problems come back as `Err`. Matching on
/// `Err` alone therefore swallows exactly the failures worth knowing about —
/// a validation or grounding refusal looks identical to success.
///
/// A refusal is logged at `error!` and reported to the caller rather than
/// absorbed here. These writes are how a sweep-confirmed detection becomes
/// coverage: when one is refused the technique is gone from the scorecard while
/// the sweep still reports it as fired. Any future tightening of the grounding
/// gate would otherwise degrade coverage with nothing failing — which is how a
/// grounded-technique change came within one edit of deleting the golden- and
/// silver-ticket detections silently.
async fn record_state(context: &str, tool: &str, args: &serde_json::Value) -> bool {
    match ares_tools::blue::dispatch_blue(tool, args).await {
        Ok(o) if !o.success => {
            error!(context, tool, reason = %o.stderr, "Blue state write REJECTED — detection will not appear as coverage");
            false
        }
        Err(e) => {
            error!(context, tool, error = %e, "Blue state write FAILED — detection will not appear as coverage");
            false
        }
        Ok(_) => true,
    }
}

/// Name the orphaned principals in the investigation timeline.
///
/// The technique record from [`record_fired`] says a ticket was forged; this says
/// which accounts, which is what the analyst actually pivots on.
///
/// These go in the timeline rather than `add_evidence` on purpose. Evidence
/// values are gated by a grounding check that requires the value to appear
/// verbatim in a stored query result, and `account@domain` is a *derived*
/// identity — normalised from two fields across two different event types, so
/// it appears nowhere in any raw log line. Pushing it through `add_evidence`
/// would be silently rejected, and satisfying the check by injecting a
/// synthetic query result would hollow out a safeguard that exists to stop
/// fabricated IOCs. The technique-level record in [`record_fired`] already
/// carries the rule's MITRE ID (grounded there by the fired detection itself);
/// this adds the names an analyst needs to pivot on.
///
/// The enumeration is capped, and the cap is logged rather than applied
/// silently — a truncated list that looks complete would understate the blast
/// radius of a domain-wide forgery.
async fn record_orphan_accounts(
    investigation_id: &str,
    rule: &TicketRule,
    orphans: &[OrphanAccount],
) -> Vec<String> {
    if orphans.is_empty() {
        return Vec::new();
    }
    if orphans.len() > MAX_REPORTED_ORPHANS {
        warn!(
            investigation_id,
            rule = rule.source,
            total = orphans.len(),
            recorded = MAX_REPORTED_ORPHANS,
            "Forged-ticket orphan list truncated; not every principal was named in the timeline"
        );
    }

    let named: Vec<String> = orphans
        .iter()
        .take(MAX_REPORTED_ORPHANS)
        .map(|o| format!("{} ({} {}(s))", o.account, o.event_count, rule.event_noun))
        .collect();
    let suffix = if orphans.len() > named.len() {
        format!(" …and {} more", orphans.len() - named.len())
    } else {
        String::new()
    };

    let recorded = record_state(
        rule.source,
        "record_timeline_event",
        &json!({
            "investigation_id": investigation_id,
            "description": format!(
                "{}: {} principal(s) {} — {}{}",
                rule.finding_label,
                orphans.len(),
                rule.finding_detail,
                named.join(", "),
                suffix
            ),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "mitre_techniques": [rule.mitre_id],
            "source": format!("{SWEEP_TIMELINE_SOURCE}:{}", rule.source),
            "confidence": 0.9,
        }),
    )
    .await;

    if recorded {
        Vec::new()
    } else {
        vec![format!("{}/record_timeline_event", rule.source)]
    }
}

/// Record a fired detection as blue-team state: a MITRE technique (for coverage
/// scoring + the report technique table), a TTP-level evidence item (for
/// evidence count, pyramid, precision, and evidence-based chaining), and a
/// timeline event (for the narrative + timeline scoring).
///
/// The evidence value is the MITRE ID, which grounds only once registered. This
/// function is the single funnel for every sweep-confirmed detection — catalog
/// templates and the Rust-side ticket correlations alike — so it registers here
/// rather than relying on the catalog runner, which the correlation rules never
/// go through.
async fn record_fired(investigation_id: &str, f: &FiredDetection) -> Vec<String> {
    ares_tools::blue::evidence_validator::register_grounded_technique(&f.mitre_id);
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
                "source": format!("{SWEEP_TIMELINE_SOURCE}:{}", f.template),
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
                "source": SWEEP_TIMELINE_SOURCE,
                "confidence": confidence,
                "extra_data_json": observed_window_json(f),
            }),
        ),
    ];

    let mut rejected = Vec::new();
    for (tool, args) in calls {
        if !record_state(&f.template, tool, &args).await {
            rejected.push(format!("{}/{tool}", f.template));
        }
    }
    rejected
}

/// The span of log events this detection matched, for the timeline event's
/// structured payload.
///
/// The report scores coverage per red action, so it has to know which actions a
/// detection observed. The timeline event's single `timestamp` is the first
/// matched event and says nothing about the rest: without the span, a detection
/// that matched 44 events over 20 minutes looks like an instant, and every red
/// action after the first scores as undetected. `None` when the detection
/// carries no event times — the ticket correlations report orphaned principals
/// rather than matched log lines.
fn observed_window_json(f: &FiredDetection) -> Option<String> {
    let first = f.first_event_at?;
    let last = f.last_event_at.unwrap_or(first);
    Some(
        json!({
            "first_event_at": first.to_rfc3339(),
            "last_event_at": last.max(first).to_rfc3339(),
            "event_count": f.event_count,
        })
        .to_string(),
    )
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

pub(crate) fn sweep_refresh_secs() -> u64 {
    std::env::var("ARES_BLUE_SWEEP_REFRESH_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SWEEP_REFRESH_SECS)
}

pub(crate) fn spawn_sweep_refresh(
    investigation_id: String,
    attack_start: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !sweep_enabled() {
        return None;
    }
    let interval = sweep_refresh_secs();
    if interval == 0 {
        return None;
    }
    info!(
        investigation_id = %investigation_id,
        interval_secs = interval,
        "Sweep refresh armed"
    );
    Some(tokio::spawn(async move {
        let mut round: u32 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            round += 1;
            let outcome = run_detection_sweep(&investigation_id, attack_start).await;
            info!(
                investigation_id = %investigation_id,
                round,
                fired = outcome.fired.len(),
                failed = outcome.failed.len(),
                "Sweep refresh round completed"
            );
        }
    }))
}

/// Whether the golden-ticket correlation should run. Defaults on; set
/// `ARES_BLUE_GOLDEN_TICKET_CORRELATION=0` to disable.
fn golden_ticket_enabled() -> bool {
    correlation_enabled("ARES_BLUE_GOLDEN_TICKET_CORRELATION")
}

/// Whether the silver-ticket correlation should run. Defaults on; set
/// `ARES_BLUE_SILVER_TICKET_CORRELATION=0` to disable.
fn silver_ticket_enabled() -> bool {
    correlation_enabled("ARES_BLUE_SILVER_TICKET_CORRELATION")
}

fn correlation_enabled(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Baseline width for the golden correlation, overridable via
/// `ARES_BLUE_GOLDEN_BASELINE_HOURS`.
fn golden_baseline_hours() -> i64 {
    baseline_hours(
        "ARES_BLUE_GOLDEN_BASELINE_HOURS",
        DEFAULT_GOLDEN_BASELINE_HOURS,
    )
}

/// Baseline width for the silver correlation, overridable via
/// `ARES_BLUE_SILVER_BASELINE_HOURS`.
fn silver_baseline_hours() -> i64 {
    baseline_hours(
        "ARES_BLUE_SILVER_BASELINE_HOURS",
        DEFAULT_SILVER_BASELINE_HOURS,
    )
}

/// Resolve a baseline width, clamped to at least the candidate window.
///
/// A baseline narrower than the candidates would manufacture orphans out of
/// window-boundary artifacts rather than find forged tickets.
fn baseline_hours(var: &str, default: i64) -> i64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|h| *h >= 1)
        .unwrap_or(default)
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
    fn observed_window_carries_the_whole_matched_span() {
        let f = fired(
            Some("2026-07-26T21:41:13Z"),
            Some("2026-07-26T21:55:02Z"),
            &[],
        );
        let w: serde_json::Value =
            serde_json::from_str(&observed_window_json(&f).expect("window")).expect("valid json");

        assert_eq!(w["first_event_at"], "2026-07-26T21:41:13+00:00");
        assert_eq!(w["last_event_at"], "2026-07-26T21:55:02+00:00");
        assert_eq!(w["event_count"], 3);
    }

    #[test]
    fn observed_window_collapses_to_the_first_event_without_a_last() {
        let f = fired(Some("2026-07-26T21:41:13Z"), None, &[]);
        let w: serde_json::Value =
            serde_json::from_str(&observed_window_json(&f).expect("window")).expect("valid json");

        assert_eq!(w["last_event_at"], "2026-07-26T21:41:13+00:00");
    }

    #[test]
    fn a_detection_with_no_event_times_records_no_window() {
        // The ticket correlations report orphaned principals, not matched log
        // lines. An invented window would credit blue for observing a span it
        // never queried.
        assert_eq!(observed_window_json(&fired(None, None, &[])), None);
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
    fn sweep_refresh_defaults_and_respects_override() {
        std::env::remove_var("ARES_BLUE_SWEEP_REFRESH_SECS");
        assert_eq!(sweep_refresh_secs(), DEFAULT_SWEEP_REFRESH_SECS);
        std::env::set_var("ARES_BLUE_SWEEP_REFRESH_SECS", "300");
        assert_eq!(sweep_refresh_secs(), 300);
        std::env::set_var("ARES_BLUE_SWEEP_REFRESH_SECS", "0");
        assert_eq!(sweep_refresh_secs(), 0);
        std::env::set_var("ARES_BLUE_SWEEP_REFRESH_SECS", "not-a-number");
        assert_eq!(sweep_refresh_secs(), DEFAULT_SWEEP_REFRESH_SECS);
        std::env::remove_var("ARES_BLUE_SWEEP_REFRESH_SECS");
    }

    #[tokio::test]
    async fn sweep_refresh_is_disabled_by_the_sweep_toggle_and_by_zero() {
        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "0");
        std::env::remove_var("ARES_BLUE_SWEEP_REFRESH_SECS");
        assert!(spawn_sweep_refresh("inv-test".into(), None).is_none());

        std::env::set_var("ARES_BLUE_DETERMINISTIC_SWEEP", "1");
        std::env::set_var("ARES_BLUE_SWEEP_REFRESH_SECS", "0");
        assert!(spawn_sweep_refresh("inv-test".into(), None).is_none());

        std::env::remove_var("ARES_BLUE_DETERMINISTIC_SWEEP");
        std::env::remove_var("ARES_BLUE_SWEEP_REFRESH_SECS");
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
            out_of_window: vec![],
            no_match: vec!["detect_golden_ticket".into()],
            failed: vec![],
            not_run: vec![],
            rejected_writes: vec![],
            timed_out: false,
            golden_ticket: None,
            silver_ticket: None,
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("T1003.006"));
        assert!(s.contains("5 matching event"));
        assert!(s.contains("detect_golden_ticket"));
        assert!(s.contains("ALREADY"));
        // Clean finish → no "time cap" note.
        assert!(!s.contains("time cap"));
        // Nothing was refused, so the summary must not manufacture a warning.
        assert!(!s.contains("REJECTED"));
    }

    /// A refused state write means the detection never became coverage, while
    /// the sweep still lists it as FIRED. Saying so in the prompt is the point:
    /// the refusal is otherwise invisible to everything downstream, which is how
    /// a tightened grounding gate can delete detections with nothing failing.
    #[test]
    fn prompt_summary_flags_rejected_state_writes() {
        let outcome = SweepOutcome {
            templates_total: 1,
            rejected_writes: vec!["detect_dcsync/add_technique".into()],
            ..Default::default()
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("REJECTED"));
        assert!(s.contains("detect_dcsync/add_technique"));
    }

    #[test]
    fn prompt_summary_notes_timeout_gap() {
        let outcome = SweepOutcome {
            templates_total: 3,
            fired: vec![],
            out_of_window: vec![],
            no_match: vec![],
            failed: vec![],
            not_run: vec!["detect_esc1_attack".into()],
            rejected_writes: vec![],
            timed_out: true,
            golden_ticket: None,
            silver_ticket: None,
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("FIRED: none"));
        assert!(s.contains("time cap"));
        assert!(s.contains("detect_esc1_attack"));
    }

    /// A query that errored proves nothing. Reporting it alongside the
    /// genuinely-clean templates told the analyst a technique was cleared when
    /// it had never been checked — and under a one-attempt Loki budget that is
    /// the common case, not the rare one.
    #[test]
    fn prompt_summary_separates_failed_queries_from_clean_ones() {
        let outcome = SweepOutcome {
            templates_total: 3,
            fired: vec![],
            out_of_window: vec![],
            no_match: vec!["detect_esc1_attack".into()],
            failed: vec!["detect_secretsdump".into(), "detect_pass_the_hash".into()],
            not_run: vec![],
            rejected_writes: vec![],
            timed_out: false,
            golden_ticket: None,
            silver_ticket: None,
        };
        let s = outcome.prompt_summary();

        assert!(s.contains("UNCHECKED"), "{s}");
        assert!(s.contains("detect_secretsdump"), "{s}");
        assert!(s.contains("detect_pass_the_hash"), "{s}");

        let no_match_line = s
            .lines()
            .find(|l| l.starts_with("Ran and returned no matches"))
            .expect("clean templates still listed");
        assert!(
            !no_match_line.contains("detect_secretsdump"),
            "a failed query must never be listed as clean: {no_match_line}"
        );
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
                event_count: 9,
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
                event_count: 12,
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
        let clean = TicketCorrelation {
            candidates: 3,
            baseline: 3,
            orphans: vec![],
        };
        assert!(clean.as_fired(&GOLDEN_TICKET_RULE).is_none());

        let hit = TicketCorrelation {
            candidates: 3,
            baseline: 2,
            orphans: vec![
                OrphanAccount {
                    account: "bob".into(),
                    event_count: 9,
                },
                OrphanAccount {
                    account: "admin".into(),
                    event_count: 4,
                },
            ],
        };
        let fired = hit
            .as_fired(&GOLDEN_TICKET_RULE)
            .expect("orphans must fire");
        assert_eq!(fired.mitre_id, GOLDEN_TICKET_RULE.mitre_id);
        assert_eq!(fired.event_count, 13);
        assert_eq!(fired.severity, "critical");
    }

    #[test]
    fn summary_distinguishes_clean_from_unchecked() {
        let clean = SweepOutcome {
            golden_ticket: Some(TicketOutcome::Correlated(TicketCorrelation {
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
            golden_ticket: Some(TicketOutcome::Inconclusive("query failed".into())),
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
            golden_ticket: Some(TicketOutcome::Correlated(TicketCorrelation {
                candidates: 4,
                baseline: 19,
                orphans: vec![],
            })),
            ..Default::default()
        };
        let s = clean.golden_ticket_summary();
        assert!(
            s.contains("authoritative"),
            "clean verdict must claim authority over {}: {s}",
            GOLDEN_TICKET_RULE.mitre_id
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
                event_count: 1,
            })
            .collect();
        let outcome = SweepOutcome {
            golden_ticket: Some(TicketOutcome::Correlated(TicketCorrelation {
                candidates: 40,
                baseline: 12,
                orphans,
            })),
            ..Default::default()
        };
        let s = outcome.golden_ticket_summary();
        assert!(s.contains("svc_00"), "{s}");
        assert!(s.contains(GOLDEN_TICKET_RULE.mitre_id), "{s}");
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
        assert!(recheck_silver_tickets("inv-test").await.is_none());
        std::env::remove_var("ARES_BLUE_DETERMINISTIC_SWEEP");

        std::env::set_var("ARES_BLUE_GOLDEN_TICKET_CORRELATION", "0");
        assert!(recheck_golden_tickets("inv-test").await.is_none());
        std::env::remove_var("ARES_BLUE_GOLDEN_TICKET_CORRELATION");

        std::env::set_var("ARES_BLUE_SILVER_TICKET_CORRELATION", "0");
        assert!(recheck_silver_tickets("inv-test").await.is_none());
        std::env::remove_var("ARES_BLUE_SILVER_TICKET_CORRELATION");
    }

    /// Each correlation must be independently switchable, or turning one off to
    /// cut query load silently disables the other technique too.
    #[test]
    fn correlation_toggles_are_independent() {
        std::env::set_var("ARES_BLUE_GOLDEN_TICKET_CORRELATION", "0");
        assert!(!golden_ticket_enabled());
        assert!(silver_ticket_enabled());
        std::env::remove_var("ARES_BLUE_GOLDEN_TICKET_CORRELATION");

        std::env::set_var("ARES_BLUE_SILVER_TICKET_CORRELATION", "off");
        assert!(!silver_ticket_enabled());
        assert!(golden_ticket_enabled());
        std::env::remove_var("ARES_BLUE_SILVER_TICKET_CORRELATION");

        assert!(golden_ticket_enabled());
        assert!(silver_ticket_enabled());
    }

    #[test]
    fn every_correlation_outcome_is_distinguishable_in_the_log() {
        // "ran and found nothing" must never look like "never produced an
        // answer". A clean verdict is treated as authoritative downstream, so
        // the log has to say which one actually happened.
        assert_eq!(ticket_log_value(&None), "disabled");

        let clean = ticket_log_value(&Some(TicketOutcome::Correlated(TicketCorrelation {
            candidates: 4,
            baseline: 19,
            orphans: vec![],
        })));
        assert!(clean.starts_with("clean"), "{clean}");
        assert!(clean.contains('4') && clean.contains("19"), "{clean}");

        let hit = ticket_log_value(&Some(TicketOutcome::Correlated(TicketCorrelation {
            candidates: 5,
            baseline: 19,
            orphans: vec![OrphanAccount {
                account: "admin@contoso".into(),
                event_count: 3,
            }],
        })));
        assert!(hit.contains("1 orphan"), "{hit}");

        let broken = ticket_log_value(&Some(TicketOutcome::Inconclusive(
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

    /// Both correlation IDs must be covered by a catalog template.
    ///
    /// This is the load-bearing link between the two halves of each rule. Blue
    /// writes are gated on a MITRE ID the detection catalog can match — exact or
    /// parent/child, never siblings — so an ID with no template is refused at the
    /// write and the correlation records nothing at all. T1558.001 has
    /// `detect_golden_ticket`; T1558.002 has `detect_silver_ticket`. Deleting
    /// either template silently switches its correlation off.
    #[test]
    fn every_correlation_rule_id_is_covered_by_a_catalog_template() {
        for rule in [&GOLDEN_TICKET_RULE, &SILVER_TICKET_RULE] {
            let covered = detection_config().templates.values().any(|t| {
                ares_core::correlation::redblue::RedBlueCorrelator::techniques_match(
                    Some(rule.mitre_id),
                    Some(&t.mitre_id),
                )
            });
            assert!(
                covered,
                "{} has no catalog template, so every blue write for it is dropped",
                rule.mitre_id
            );
        }
    }

    /// The two rules must not collapse onto one ID: coverage joins never match
    /// siblings, so a shared ID would leave the other technique permanently
    /// missed.
    #[test]
    fn the_two_ticket_rules_are_distinct() {
        assert_ne!(GOLDEN_TICKET_RULE.mitre_id, SILVER_TICKET_RULE.mitre_id);
        assert_ne!(GOLDEN_TICKET_RULE.source, SILVER_TICKET_RULE.source);
        assert_eq!(SILVER_TICKET_RULE.mitre_id, "T1558.002");
    }

    /// admin completed Kerberos network logons that no DC ever issued a service
    /// ticket for — the ticket was forged with the service account's key and
    /// handed straight to the service. alice's logon has a matching 4769 and is
    /// ordinary.
    #[test]
    fn silver_correlate_flags_logon_with_no_service_ticket() {
        let result = correlate(
            &series(&[
                ("alice@CONTOSO.LOCAL", "CONTOSO.LOCAL", 3),
                ("admin@CONTOSO.LOCAL", "CONTOSO.LOCAL", 6),
            ]),
            &series(&[("alice", "CONTOSO", 4), ("bob", "CONTOSO", 2)]),
        )
        .expect("both sides populated");

        assert_eq!(
            result.orphans,
            vec![OrphanAccount {
                account: "admin@contoso".to_string(),
                event_count: 6,
            }]
        );
    }

    /// The non-matching case: every principal that authenticated to a service was
    /// issued a ticket for it, so nothing was forged. This is the state a clean
    /// domain is in, and firing here would put a false T1558.002 on every
    /// investigation.
    #[test]
    fn silver_correlate_clears_logon_backed_by_a_service_ticket() {
        let result = correlate(
            &series(&[
                ("alice@CONTOSO.LOCAL", "CONTOSO.LOCAL", 12),
                ("svc_sql@CONTOSO.LOCAL", "CONTOSO.LOCAL", 40),
            ]),
            &series(&[("alice", "CONTOSO", 2), ("svc_sql", "CONTOSO", 5)]),
        )
        .expect("both sides populated");
        assert!(
            result.orphans.is_empty(),
            "a KDC-issued ticket must clear the logon it authorised, got {:?}",
            result.orphans
        );
    }

    /// Computers re-authenticate constantly and cache their service tickets for
    /// the full ticket lifetime, so they dominate the 4624 population and would
    /// swamp the real signal with boundary artifacts.
    ///
    /// A half-identity carries no account name, so there is nothing to classify:
    /// it must not be mistaken for a machine account and dropped for the wrong
    /// reason (`correlate` drops it on the missing key instead).
    #[test]
    fn machine_accounts_are_dropped_from_silver_candidates() {
        let mut labels = BTreeMap::new();
        labels.insert(
            ACCOUNT_LABEL.to_string(),
            "SQL01$@CONTOSO.LOCAL".to_string(),
        );
        labels.insert(DOMAIN_LABEL.to_string(), "CONTOSO.LOCAL".to_string());
        assert!(is_machine_account(&labels));

        labels.insert(ACCOUNT_LABEL.to_string(), "admin@CONTOSO.LOCAL".to_string());
        assert!(!is_machine_account(&labels));

        assert!(!is_machine_account(&BTreeMap::new()));
    }

    #[test]
    fn kerberos_logon_query_narrows_to_network_logons_only() {
        let q = kerberos_logon_aggregation_query(SWEEP_HOURS_BACK);
        assert!(
            q.contains(r#"|= `"event_id":4624`"#),
            "event filter must be anchored to the event_id field, or record IDs \
             and ports containing 4624 come along too, got: {q}"
        );
        assert!(
            q.contains(r#"LogonType'\\u003e3\\u003c"#),
            "must anchor LogonType to exactly 3 — an unanchored 3 also matches \
             two-digit types, got: {q}"
        );
        assert!(
            q.contains(r#"AuthenticationPackageName'\\u003eKerberos"#),
            "must exclude NTLM logons, which are T1550.002 not a forged ticket, got: {q}"
        );
        assert!(
            q.contains(&format!("sum by ({ACCOUNT_LABEL}, {DOMAIN_LABEL})")),
            "must aggregate per account AND domain — account alone is ambiguous \
             across a forest, got: {q}"
        );
        assert!(
            q.contains(&format!("[{SWEEP_HOURS_BACK}h]")),
            "must apply the requested window, got: {q}"
        );
    }

    /// The line filters have to run before the `regexp` parsers, or Loki pays for
    /// label extraction on every 4624 in the domain before discarding it.
    #[test]
    fn kerberos_logon_query_filters_before_parsing() {
        let q = kerberos_logon_aggregation_query(SWEEP_HOURS_BACK);
        let package = q
            .find("AuthenticationPackageName")
            .expect("package filter present");
        let first_parse = q.find("| regexp").expect("parsers present");
        assert!(
            package < first_parse,
            "line filters must precede the regexp parsers, got: {q}"
        );
    }

    /// The silver baseline is the service-ticket stream, not the TGT stream: a
    /// silver ticket needs no TGT, so diffing against 4768 would clear it.
    #[test]
    fn silver_baseline_is_the_service_ticket_stream() {
        let q = account_aggregation_query(EVENT_SERVICE_TICKET, 12);
        assert!(q.contains(r#"|= `"event_id":4769`"#), "{q}");
        assert!(!q.contains("4768"), "{q}");
        assert!(q.contains("[12h]"), "{q}");
    }

    /// The silver baseline has to outlive a cached service ticket. A client with
    /// a valid TGS keeps authenticating without going back to the KDC for the
    /// domain's full 10h ticket lifetime, so a shorter baseline turns ordinary
    /// long-lived sessions into reported forgeries.
    #[test]
    fn silver_baseline_outlives_the_maximum_ticket_lifetime() {
        const MAX_TICKET_LIFETIME_HOURS: i64 = 10;
        const {
            assert!(
                DEFAULT_SILVER_BASELINE_HOURS > MAX_TICKET_LIFETIME_HOURS,
                "the silver baseline cannot vouch for a ticket that outlives it"
            )
        };
        const {
            assert!(
                DEFAULT_SILVER_BASELINE_HOURS > DEFAULT_GOLDEN_BASELINE_HOURS,
                "a cached service ticket outlives the TGT-request recency the \
                 golden baseline was tuned for"
            )
        };

        std::env::set_var("ARES_BLUE_SILVER_BASELINE_HOURS", "1");
        assert!(silver_baseline_hours() >= SWEEP_HOURS_BACK);
        std::env::set_var("ARES_BLUE_SILVER_BASELINE_HOURS", "24");
        assert_eq!(silver_baseline_hours(), 24);
        std::env::remove_var("ARES_BLUE_SILVER_BASELINE_HOURS");
        assert_eq!(silver_baseline_hours(), DEFAULT_SILVER_BASELINE_HOURS);
    }

    /// The evidence type the sweep derives from the rule's tactic must be one
    /// `validate_evidence` accepts, or the swept `add_evidence` call is silently
    /// rejected and the detection lands as a technique with no evidence behind it.
    #[test]
    fn silver_correlation_fires_under_its_own_technique_id() {
        let clean = TicketCorrelation {
            candidates: 5,
            baseline: 5,
            orphans: vec![],
        };
        assert!(clean.as_fired(&SILVER_TICKET_RULE).is_none());

        let hit = TicketCorrelation {
            candidates: 5,
            baseline: 4,
            orphans: vec![
                OrphanAccount {
                    account: "admin@contoso".into(),
                    event_count: 6,
                },
                OrphanAccount {
                    account: "svc_sql@fabrikam".into(),
                    event_count: 2,
                },
            ],
        };
        let fired = hit
            .as_fired(&SILVER_TICKET_RULE)
            .expect("orphans must fire");
        assert_eq!(fired.mitre_id, "T1558.002");
        assert_eq!(fired.template, "silver_ticket_correlation");
        assert_eq!(fired.event_count, 8);
        assert_eq!(fired.severity, "critical");
        let et = evidence_type_for_tactic(&fired.tactic);
        assert!(
            ares_tools::blue::validation::validate_evidence(et, &fired.mitre_id, "detection_sweep")
                .valid,
            "evidence_type '{et}' rejected by validation"
        );
    }

    /// The clean verdict has to name the non-signals, or the LLM re-derives
    /// T1558.002 from ordinary Kerberos traffic on top of a correlation that
    /// already answered the question — the same false positive the golden clean
    /// verdict had to be hardened against.
    #[test]
    fn silver_summary_distinguishes_clean_from_unchecked() {
        let clean = SweepOutcome {
            silver_ticket: Some(TicketOutcome::Correlated(TicketCorrelation {
                candidates: 7,
                baseline: 22,
                orphans: vec![],
            })),
            ..Default::default()
        };
        let s = clean.silver_ticket_summary();
        assert!(s.contains("CLEAN"), "{s}");
        assert!(!s.contains("NO VERDICT"), "{s}");
        assert!(s.contains("authoritative"), "{s}");
        assert!(s.contains("Do NOT record"), "{s}");
        for non_signal in ["logon type 3", "4672", "RC4 session key", "non-DC IP"] {
            assert!(
                s.contains(non_signal),
                "clean verdict must name the non-signal '{non_signal}': {s}"
            );
        }

        let broken = SweepOutcome {
            silver_ticket: Some(TicketOutcome::Inconclusive("logon query failed".into())),
            ..Default::default()
        };
        let s = broken.silver_ticket_summary();
        assert!(s.contains("NO VERDICT"), "{s}");
        assert!(s.contains("unchecked"), "{s}");
        assert!(!s.contains("CLEAN"), "{s}");
    }

    #[test]
    fn silver_summary_names_orphans_and_declares_truncation() {
        let orphans: Vec<OrphanAccount> = (0..MAX_REPORTED_ORPHANS + 3)
            .map(|i| OrphanAccount {
                account: format!("svc_{i:02}@contoso"),
                event_count: 1,
            })
            .collect();
        let outcome = SweepOutcome {
            silver_ticket: Some(TicketOutcome::Correlated(TicketCorrelation {
                candidates: 30,
                baseline: 14,
                orphans,
            })),
            ..Default::default()
        };
        let s = outcome.silver_ticket_summary();
        assert!(s.contains("svc_00@contoso"), "{s}");
        assert!(s.contains("Kerberos logon(s)"), "{s}");
        assert!(s.contains("T1558.002"), "{s}");
        assert!(s.contains("3 more"), "{s}");
        assert!(!s.contains("svc_22"), "listing must stop at the cap: {s}");
    }

    #[test]
    fn silver_summary_absent_when_correlation_disabled() {
        assert!(SweepOutcome::default().silver_ticket_summary().is_empty());
    }

    /// Both correlations have to reach the prompt. Reporting only one would tell
    /// the analyst the other technique was clean when it was never answered.
    #[test]
    fn prompt_summary_reports_both_correlations() {
        let outcome = SweepOutcome {
            templates_total: 2,
            golden_ticket: Some(TicketOutcome::Correlated(TicketCorrelation {
                candidates: 4,
                baseline: 19,
                orphans: vec![],
            })),
            silver_ticket: Some(TicketOutcome::Correlated(TicketCorrelation {
                candidates: 6,
                baseline: 19,
                orphans: vec![OrphanAccount {
                    account: "admin@contoso".into(),
                    event_count: 5,
                }],
            })),
            ..Default::default()
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("Golden ticket correlation"), "{s}");
        assert!(s.contains("Silver ticket correlation"), "{s}");
        assert!(s.contains("T1558.001"), "{s}");
        assert!(s.contains("T1558.002"), "{s}");
        assert!(s.contains("admin@contoso"), "{s}");
    }

    fn detection_at(last: Option<&str>) -> FiredDetection {
        FiredDetection {
            template: "detect_dcsync".into(),
            mitre_id: "T1003.006".into(),
            description: "DCSync Detection".into(),
            tactic: "credential_access".into(),
            severity: "critical".into(),
            event_count: 1,
            first_event_at: None,
            last_event_at: last.map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .unwrap()
                    .with_timezone(&chrono::Utc)
            }),
            hosts: Vec::new(),
        }
    }

    fn op_start(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    #[test]
    fn attack_window_start_parses_operation_context() {
        let alert = json!({
            "operation_context": { "attack_window_start": "2026-07-28T00:03:34+00:00" }
        });
        assert_eq!(
            attack_window_start(&alert),
            op_start("2026-07-28T00:03:34+00:00")
        );
        assert_eq!(attack_window_start(&json!({})), None);
        assert_eq!(
            attack_window_start(&json!({"operation_context": {"attack_window_start": "nope"}})),
            None
        );
    }

    #[test]
    fn detections_predating_the_operation_are_not_attributable() {
        let start = op_start("2026-07-28T00:03:34+00:00");
        assert!(!attributable(
            &detection_at(Some("2026-07-27T23:04:33+00:00")),
            start
        ));
        assert!(attributable(
            &detection_at(Some("2026-07-28T00:11:47+00:00")),
            start
        ));
    }

    #[test]
    fn attribution_is_inclusive_of_the_window_start() {
        let start = op_start("2026-07-28T00:03:34+00:00");
        assert!(attributable(
            &detection_at(Some("2026-07-28T00:03:34+00:00")),
            start
        ));
    }

    #[test]
    fn untimed_detections_stay_attributable() {
        // Golden-ticket correlation reports absence of a partner event and so
        // carries no event timestamps; dropping it would delete the only rule
        // that can find T1558.001 at all.
        let start = op_start("2026-07-28T00:03:34+00:00");
        assert!(attributable(&detection_at(None), start));
    }

    #[test]
    fn everything_is_attributable_without_a_window() {
        assert!(attributable(
            &detection_at(Some("2020-01-01T00:00:00+00:00")),
            None
        ));
    }

    #[test]
    fn out_of_window_detections_are_flagged_in_the_prompt() {
        let outcome = SweepOutcome {
            templates_total: 2,
            fired: vec![],
            out_of_window: vec![detection_at(Some("2026-07-27T23:04:33+00:00"))],
            no_match: vec![],
            failed: vec![],
            not_run: vec![],
            rejected_writes: vec![],
            timed_out: false,
            golden_ticket: None,
            silver_ticket: None,
        };
        let s = outcome.prompt_summary();
        assert!(s.contains("OUTSIDE"), "must warn the LLM off them: {s}");
        assert!(s.contains("T1003.006"));
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
