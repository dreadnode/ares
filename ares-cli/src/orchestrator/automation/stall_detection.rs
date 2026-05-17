//! auto_stall_detection -- detect when the operation is stuck and take action.
//!
//! When no new credentials or hashes have been discovered for a configurable
//! period (default: 5 minutes), this automation triggers fallback actions:
//!
//!   1. Re-attempt password spray with discovered users
//!   2. Re-run low-hanging-fruit discovery with all known creds
//!   3. Cold-start AS-REP enumeration when both users and creds are empty
//!
//! This prevents the operation from idling when all easy wins are exhausted.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect the set of lowercased domains that have at least one pending
/// (un-exploited) constrained-delegation or RBCD vuln. The stall-recovery
/// password spray uses this set to skip domains where a spray would lock
/// out delegation accounts before S4U gets to use them.
pub(crate) fn domains_with_pending_delegation(
    state: &StateInner,
) -> std::collections::HashSet<String> {
    state
        .discovered_vulnerabilities
        .values()
        .filter(|v| {
            let vt = v.vuln_type.to_lowercase();
            (vt == "constrained_delegation" || vt == "rbcd")
                && !state.exploited_vulnerabilities.contains(&v.vuln_id)
        })
        .filter_map(|v| {
            v.details
                .get("domain")
                .or_else(|| v.details.get("Domain"))
                .and_then(|d| d.as_str())
                .map(|d| d.to_lowercase())
        })
        .collect()
}

/// Build the stall-recovery spray dedup key. The `recovery_attempts` counter
/// is embedded so each round emits a fresh, distinct key — otherwise a single
/// stall would only ever trigger one spray dispatch.
pub(crate) fn stall_spray_dedup_key(domain: &str, recovery_attempts: u32) -> String {
    format!("stall_spray:{}:{recovery_attempts}", domain.to_lowercase())
}

/// Build the stall-recovery low-hanging-fruit dedup key.
pub(crate) fn stall_lhf_dedup_key(domain: &str, username: &str, recovery_attempts: u32) -> String {
    format!(
        "stall_lhf:{}:{}:{recovery_attempts}",
        domain.to_lowercase(),
        username.to_lowercase()
    )
}

/// Resolve a DC IP for stall-recovery LHF dispatch.
///
/// Tries exact match in `domain_controllers` first, then any child-domain
/// DC (`d.ends_with(".{cred_domain}")`). Returns `None` when no DC for
/// this cred's forest is known yet.
pub(crate) fn resolve_stall_dc_ip(state: &StateInner, cred_domain: &str) -> Option<String> {
    let cred_domain = cred_domain.to_lowercase();
    state
        .domain_controllers
        .get(&cred_domain)
        .cloned()
        .or_else(|| {
            let suffix = format!(".{cred_domain}");
            state
                .domain_controllers
                .iter()
                .find(|(d, _)| d.ends_with(&suffix))
                .map(|(_, ip)| ip.clone())
        })
}

/// Select stall-recovery password-spray work items for this tick.
///
/// Returns `(domain, dc_ip)` for each known DC whose domain has no pending
/// delegation vulns AND whose round-specific dedup key
/// (`stall_spray:{domain}:{recovery_attempts}`) is unprocessed.
pub(crate) fn select_stall_spray_work(
    state: &StateInner,
    recovery_attempts: u32,
) -> Vec<(String, String)> {
    let delegation_domains = domains_with_pending_delegation(state);
    state
        .domain_controllers
        .iter()
        .filter(|(domain, _)| !state.is_domain_dominated(domain))
        .filter(|(domain, _)| !delegation_domains.contains(&domain.to_lowercase()))
        .filter(|(domain, _)| {
            let key = stall_spray_dedup_key(domain, recovery_attempts);
            !state.is_processed(DEDUP_PASSWORD_SPRAY, &key)
        })
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Select stall-recovery low-hanging-fruit work items, capped at `max_items`.
pub(crate) fn select_stall_lhf_work(
    state: &StateInner,
    recovery_attempts: u32,
    max_items: usize,
) -> Vec<(String, String, String, ares_core::models::Credential)> {
    state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter_map(|cred| {
            let cred_domain = cred.domain.to_lowercase();
            if state.is_domain_dominated(&cred_domain) {
                return None;
            }
            let key = stall_lhf_dedup_key(&cred_domain, &cred.username, recovery_attempts);
            if state.is_processed(DEDUP_EXPANSION_CREDS, &key) {
                return None;
            }
            let dc_ip = resolve_stall_dc_ip(state, &cred_domain)?;
            Some((key, dc_ip, cred_domain, cred.clone()))
        })
        .take(max_items)
        .collect()
}

/// Build the stall-recovery cold-start dedup key.
pub(crate) fn stall_cold_start_dedup_key(domain: &str, recovery_attempts: u32) -> String {
    format!(
        "stall_cold_start:{}:{recovery_attempts}",
        domain.to_lowercase()
    )
}

/// Select stall-recovery cold-start work items: unauth user enumeration
/// against each known DC whose domain isn't already dominated AND whose
/// round-specific dedup key is unprocessed. Used when the op has zero
/// users AND zero credentials but DCs are known — initial bootstrap
/// (petitpotam unauth, anonymous SAMR, etc.) produced nothing, so we
/// fall back to seclists + kerbrute via AS-REP roast cold-start.
pub(crate) fn select_stall_cold_start_work(
    state: &StateInner,
    recovery_attempts: u32,
) -> Vec<(String, String)> {
    state
        .domain_controllers
        .iter()
        .filter(|(domain, _)| !state.is_domain_dominated(domain))
        .filter(|(domain, _)| {
            let key = stall_cold_start_dedup_key(domain, recovery_attempts);
            !state.is_processed(DEDUP_STALL_COLD_START, &key)
        })
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Build the password-spray payload for stall recovery.
pub(crate) fn build_spray_payload(domain: &str, dc_ip: &str) -> Value {
    json!({
        "technique": "password_spray",
        "target_ip": dc_ip,
        "domain": domain,
        "use_common_passwords": true,
        "acknowledge_no_policy": true,
    })
}

/// Build the cold-start AS-REP enumeration payload (delegates to
/// `credential_access::build_asrep_payload` with empty known/excluded users
/// to emit the seclists+kerbrute instructions).
pub(crate) fn build_cold_start_payload(domain: &str, dc_ip: &str) -> Value {
    super::credential_access::build_asrep_payload(domain, dc_ip, &[], &[])
}

/// What kind of recovery action a `RecoveryAction` represents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionKind {
    /// Password spray against a discovered userlist.
    Spray,
    /// Low-hanging-fruit (LAPS, gMSA) against a known credential.
    LowHanging,
    /// Cold-start unauth AS-REP enumeration against a DC.
    ColdStart,
}

/// A single recovery action produced by `plan_stall_recovery`. The dispatch
/// loop consumes these and routes each to the appropriate dispatcher call.
#[derive(Debug, Clone)]
pub(crate) struct RecoveryAction {
    pub kind: ActionKind,
    pub domain: String,
    pub dc_ip: String,
    pub dedup_key: String,
    pub dedup_set: &'static str,
    /// Only set for `ActionKind::LowHanging` — the credential to use.
    pub cred: Option<ares_core::models::Credential>,
}

/// Inputs to `plan_stall_recovery` describing what corpus the op has so far
/// and which fallback techniques are currently permissible.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StallContext {
    pub has_users: bool,
    pub has_creds: bool,
    pub has_dcs: bool,
    pub allow_password_spray: bool,
    pub allow_asrep_roast: bool,
    pub lhf_max: usize,
}

/// Build the prioritized list of stall-recovery actions for this tick.
///
/// Pure function: no I/O, no Dispatcher. Inspects state + gates and returns
/// the actions the dispatch loop should attempt.
///
/// Order: spray → low-hanging-fruit → cold-start. Cold-start only fires
/// when both `has_users` and `has_creds` are false (otherwise the other
/// two branches own the recovery).
pub(crate) fn plan_stall_recovery(
    state: &StateInner,
    recovery_attempts: u32,
    ctx: &StallContext,
) -> Vec<RecoveryAction> {
    let mut plan = Vec::new();

    if ctx.has_users && ctx.has_dcs && ctx.allow_password_spray {
        for (domain, dc_ip) in select_stall_spray_work(state, recovery_attempts) {
            let dedup_key = stall_spray_dedup_key(&domain, recovery_attempts);
            plan.push(RecoveryAction {
                kind: ActionKind::Spray,
                domain,
                dc_ip,
                dedup_key,
                dedup_set: DEDUP_PASSWORD_SPRAY,
                cred: None,
            });
        }
    }

    if ctx.has_creds && ctx.has_dcs {
        for (key, dc_ip, domain, cred) in
            select_stall_lhf_work(state, recovery_attempts, ctx.lhf_max)
        {
            plan.push(RecoveryAction {
                kind: ActionKind::LowHanging,
                domain,
                dc_ip,
                dedup_key: key,
                dedup_set: DEDUP_EXPANSION_CREDS,
                cred: Some(cred),
            });
        }
    }

    if !ctx.has_users && !ctx.has_creds && ctx.has_dcs && ctx.allow_asrep_roast {
        for (domain, dc_ip) in select_stall_cold_start_work(state, recovery_attempts) {
            let dedup_key = stall_cold_start_dedup_key(&domain, recovery_attempts);
            plan.push(RecoveryAction {
                kind: ActionKind::ColdStart,
                domain,
                dc_ip,
                dedup_key,
                dedup_set: DEDUP_STALL_COLD_START,
                cred: None,
            });
        }
    }

    plan
}

/// How long without new discoveries before we consider the op stalled.
const STALL_THRESHOLD: Duration = Duration::from_secs(180); // 3 minutes

/// Minimum interval between stall recovery actions.
const RECOVERY_COOLDOWN: Duration = Duration::from_secs(120); // 2 minutes

/// Cap on the number of recovery rounds per op (don't spam indefinitely).
const MAX_RECOVERY_ATTEMPTS: u32 = 10;

/// Mutable bookkeeping for the stall detector. Tracks observed progress
/// counters and timing gates outside the Dispatcher so the gate logic can
/// be unit-tested without async I/O or a real clock.
#[derive(Debug)]
pub(crate) struct StallTracker {
    last_cred_count: usize,
    last_hash_count: usize,
    last_change: Instant,
    last_recovery: Instant,
    recovery_attempts: u32,
}

impl StallTracker {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            last_cred_count: 0,
            last_hash_count: 0,
            last_change: now,
            last_recovery: now.checked_sub(RECOVERY_COOLDOWN).unwrap_or(now),
            recovery_attempts: 0,
        }
    }

    /// Returns true when progress (more creds or hashes) was observed since
    /// the previous tick — caller should `continue`. Updates internal state.
    pub(crate) fn observe_progress(&mut self, cred_count: usize, hash_count: usize) -> bool {
        if cred_count > self.last_cred_count || hash_count > self.last_hash_count {
            self.last_cred_count = cred_count;
            self.last_hash_count = hash_count;
            self.last_change = Instant::now();
            self.recovery_attempts = 0;
            true
        } else {
            false
        }
    }

    pub(crate) fn is_stalled(&self) -> bool {
        self.last_change.elapsed() >= STALL_THRESHOLD
    }

    pub(crate) fn cooldown_elapsed(&self) -> bool {
        self.last_recovery.elapsed() >= RECOVERY_COOLDOWN
    }

    pub(crate) fn attempts_exhausted(&self) -> bool {
        self.recovery_attempts >= MAX_RECOVERY_ATTEMPTS
    }

    /// Record a new recovery attempt: bumps the counter, resets the cooldown,
    /// and returns the new attempt number (1-indexed).
    pub(crate) fn note_recovery_attempt(&mut self) -> u32 {
        self.last_recovery = Instant::now();
        self.recovery_attempts += 1;
        self.recovery_attempts
    }

    pub(crate) fn stall_duration_secs(&self) -> u64 {
        self.last_change.elapsed().as_secs()
    }

    /// Test-only: rewind `last_change` to make `is_stalled()` true.
    #[cfg(test)]
    pub(crate) fn rewind_last_change(&mut self, by: Duration) {
        self.last_change = self
            .last_change
            .checked_sub(by)
            .expect("rewind out of range");
    }

    /// Test-only: rewind `last_recovery` to make `cooldown_elapsed()` true.
    #[cfg(test)]
    pub(crate) fn rewind_last_recovery(&mut self, by: Duration) {
        self.last_recovery = self
            .last_recovery
            .checked_sub(by)
            .expect("rewind out of range");
    }

    #[cfg(test)]
    pub(crate) fn force_attempts(&mut self, n: u32) {
        self.recovery_attempts = n;
    }
}

/// Adapter trait abstracting the dispatcher operations required by the
/// stall-recovery dispatch loop. Production wires this through
/// `DispatcherStallAdapter`; tests pin a hand-rolled fake to drive every
/// branch without a real Dispatcher.
#[async_trait]
pub(crate) trait StallRecoveryAdapter: Send + Sync {
    async fn submit_spray(&self, domain: &str, dc_ip: &str) -> Result<Option<String>>;
    async fn submit_lhf(
        &self,
        dc_ip: &str,
        domain: &str,
        cred: &ares_core::models::Credential,
    ) -> Result<Option<String>>;
    async fn submit_cold_start(&self, domain: &str, dc_ip: &str) -> Result<Option<String>>;
    async fn mark_dedup(&self, set: &'static str, key: String);
}

/// Execute a planned set of recovery actions, returning the count that
/// produced a task dispatch. Errors and `Ok(None)` outcomes are logged but
/// otherwise ignored; only successful submissions update the dedup ledger.
pub(crate) async fn execute_recovery_actions<A: StallRecoveryAdapter + ?Sized>(
    adapter: &A,
    plan: Vec<RecoveryAction>,
) -> usize {
    let mut dispatched = 0usize;

    for action in plan {
        let (result, label) = match action.kind {
            ActionKind::Spray => (
                adapter.submit_spray(&action.domain, &action.dc_ip).await,
                "password spray",
            ),
            ActionKind::LowHanging => {
                let cred = action
                    .cred
                    .as_ref()
                    .expect("LowHanging action must carry a credential");
                (
                    adapter
                        .submit_lhf(&action.dc_ip, &action.domain, cred)
                        .await,
                    "low-hanging fruit",
                )
            }
            ActionKind::ColdStart => (
                adapter
                    .submit_cold_start(&action.domain, &action.dc_ip)
                    .await,
                "cold-start user enumeration",
            ),
        };

        match result {
            Ok(Some(task_id)) => {
                info!(
                    task_id = %task_id,
                    domain = %action.domain,
                    branch = %label,
                    "Stall recovery dispatched"
                );
                dispatched += 1;
                adapter.mark_dedup(action.dedup_set, action.dedup_key).await;
            }
            Ok(None) => {}
            Err(e) => warn!(err = %e, branch = %label, "Stall recovery dispatch failed"),
        }
    }

    dispatched
}

/// Production adapter wiring `auto_stall_detection` to a live `Dispatcher`.
/// Each method is a thin delegate — the testable orchestration lives in
/// `plan_stall_recovery` and `execute_recovery_actions`.
struct DispatcherStallAdapter<'a> {
    dispatcher: &'a Arc<Dispatcher>,
}

#[async_trait]
impl<'a> StallRecoveryAdapter for DispatcherStallAdapter<'a> {
    async fn submit_spray(&self, domain: &str, dc_ip: &str) -> Result<Option<String>> {
        let payload = build_spray_payload(domain, dc_ip);
        self.dispatcher
            .throttled_submit("credential_access", "credential_access", payload, 7)
            .await
    }
    async fn submit_lhf(
        &self,
        dc_ip: &str,
        domain: &str,
        cred: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        self.dispatcher
            .request_low_hanging_fruit(dc_ip, domain, cred, 6)
            .await
    }
    async fn submit_cold_start(&self, domain: &str, dc_ip: &str) -> Result<Option<String>> {
        let payload = build_cold_start_payload(domain, dc_ip);
        self.dispatcher
            .throttled_submit("credential_access", "credential_access", payload, 7)
            .await
    }
    async fn mark_dedup(&self, set: &'static str, key: String) {
        self.dispatcher
            .state
            .write()
            .await
            .mark_processed(set, key.clone());
        let _ = self
            .dispatcher
            .state
            .persist_dedup(&self.dispatcher.queue, set, &key)
            .await;
    }
}

/// Monitors for discovery stalls and triggers fallback actions.
/// Interval: 60s.
pub async fn auto_stall_detection(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let start = Instant::now();
    let mut tracker = StallTracker::new();
    let adapter = DispatcherStallAdapter {
        dispatcher: &dispatcher,
    };

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if start.elapsed() < Duration::from_secs(180) {
            continue;
        }

        let (cred_count, hash_count, has_da, has_creds, has_users, has_dcs, all_dominated) = {
            let state = dispatcher.state.read().await;
            (
                state.credentials.len(),
                state.hashes.len(),
                state.has_domain_admin,
                !state.credentials.is_empty(),
                !state.users.is_empty(),
                !state.domain_controllers.is_empty(),
                state.all_forests_dominated(),
            )
        };

        if has_da && !dispatcher.config.strategy.should_continue_after_da() && all_dominated {
            continue;
        }

        if tracker.observe_progress(cred_count, hash_count) {
            continue;
        }
        if !tracker.is_stalled() {
            continue;
        }
        if !tracker.cooldown_elapsed() {
            continue;
        }
        if tracker.attempts_exhausted() {
            continue;
        }

        let attempt = tracker.note_recovery_attempt();

        let plan = {
            let state = dispatcher.state.read().await;
            let ctx = StallContext {
                has_users,
                has_creds,
                has_dcs,
                allow_password_spray: dispatcher.is_technique_allowed("password_spray"),
                allow_asrep_roast: dispatcher.is_technique_allowed("asrep_roast"),
                lhf_max: 2,
            };
            plan_stall_recovery(&state, attempt, &ctx)
        };

        let dispatched = execute_recovery_actions(&adapter, plan).await;

        if dispatched > 0 {
            info!(
                stall_duration_secs = tracker.stall_duration_secs(),
                cred_count,
                hash_count,
                recovery_attempt = attempt,
                dispatched,
                "Operation stall detected — fallback actions dispatched"
            );
        } else {
            warn!(
                stall_duration_secs = tracker.stall_duration_secs(),
                cred_count,
                hash_count,
                recovery_attempt = attempt,
                has_users,
                has_creds,
                has_dcs,
                "Operation stall detected — no fallback branch dispatched this round"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}-{domain}"),
            username: user.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_vuln_with_domain(
        vuln_id: &str,
        vuln_type: &str,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("domain".into(), serde_json::json!(domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    #[test]
    fn stall_spray_dedup_key_includes_recovery_attempt() {
        assert_eq!(
            stall_spray_dedup_key("contoso.local", 3),
            "stall_spray:contoso.local:3"
        );
    }

    #[test]
    fn stall_spray_dedup_key_lowercases_domain() {
        assert_eq!(
            stall_spray_dedup_key("Contoso.Local", 0),
            "stall_spray:contoso.local:0"
        );
    }

    #[test]
    fn stall_lhf_dedup_key_combines_domain_user_attempt() {
        assert_eq!(
            stall_lhf_dedup_key("contoso.local", "Administrator", 1),
            "stall_lhf:contoso.local:administrator:1"
        );
    }

    #[test]
    fn pending_delegation_empty_state() {
        let s = StateInner::new("op".into());
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_collects_constrained_delegation_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let set = domains_with_pending_delegation(&s);
        assert!(set.contains("contoso.local"));
    }

    #[test]
    fn pending_delegation_collects_rbcd_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "rbcd", "fabrikam.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let set = domains_with_pending_delegation(&s);
        assert!(set.contains("fabrikam.local"));
    }

    #[test]
    fn pending_delegation_skips_exploited_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.exploited_vulnerabilities.insert("v1".into());
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_skips_non_delegation_types() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "kerberoastable_account", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_picks_up_capitalized_domain_key_alias() {
        let mut s = StateInner::new("op".into());
        let mut details = std::collections::HashMap::new();
        details.insert("Domain".into(), serde_json::json!("contoso.local"));
        let v = ares_core::models::VulnerabilityInfo {
            vuln_id: "v1".into(),
            vuln_type: "rbcd".into(),
            target: "x".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        };
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(domains_with_pending_delegation(&s).contains("contoso.local"));
    }

    #[test]
    fn resolve_stall_dc_ip_exact_match() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert_eq!(
            resolve_stall_dc_ip(&s, "contoso.local").as_deref(),
            Some("192.168.58.10")
        );
    }

    #[test]
    fn resolve_stall_dc_ip_child_fallback() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        assert_eq!(
            resolve_stall_dc_ip(&s, "contoso.local").as_deref(),
            Some("192.168.58.11")
        );
    }

    #[test]
    fn resolve_stall_dc_ip_returns_none_for_unrelated() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(resolve_stall_dc_ip(&s, "contoso.local").is_none());
    }

    #[test]
    fn select_stall_spray_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_spray_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_spray_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_spray_work(&s, 1);
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_stall_spray_skips_delegation_domains() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(select_stall_spray_work(&s, 1).is_empty());
    }

    #[test]
    fn select_stall_spray_skips_already_processed_for_this_round() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_PASSWORD_SPRAY,
            stall_spray_dedup_key("contoso.local", 0),
        );
        assert!(select_stall_spray_work(&s, 0).is_empty());
        assert_eq!(select_stall_spray_work(&s, 1).len(), 1);
    }

    #[test]
    fn select_stall_spray_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());

        assert!(select_stall_spray_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_lhf_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_lhf_work(&s, 0, 2).is_empty());
    }

    #[test]
    fn select_stall_lhf_emits_when_cred_dc_match() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_lhf_work(&s, 0, 5);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].3.username, "alice");
        assert_eq!(work[0].1, "192.168.58.10");
    }

    #[test]
    fn select_stall_lhf_skips_empty_credential_fields() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw", ""));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_stall_lhf_work(&s, 0, 5).is_empty());
    }

    #[test]
    fn select_stall_lhf_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());

        assert!(select_stall_lhf_work(&s, 0, 5).is_empty());
    }

    #[test]
    fn select_stall_lhf_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for u in &["alice", "bob", "carol", "dave"] {
            s.credentials.push(make_cred(u, "Pw", "contoso.local"));
        }
        assert_eq!(select_stall_lhf_work(&s, 0, 2).len(), 2);
        assert_eq!(select_stall_lhf_work(&s, 0, 10).len(), 4);
    }

    #[test]
    fn select_stall_lhf_skips_already_processed_for_this_round() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let key = stall_lhf_dedup_key("contoso.local", "alice", 0);
        s.mark_processed(DEDUP_EXPANSION_CREDS, key);
        assert!(select_stall_lhf_work(&s, 0, 5).is_empty());
        assert_eq!(select_stall_lhf_work(&s, 1, 5).len(), 1);
    }

    #[test]
    fn stall_cold_start_dedup_key_includes_recovery_attempt() {
        assert_eq!(
            stall_cold_start_dedup_key("contoso.local", 4),
            "stall_cold_start:contoso.local:4"
        );
    }

    #[test]
    fn stall_cold_start_dedup_key_lowercases_domain() {
        assert_eq!(
            stall_cold_start_dedup_key("Contoso.Local", 0),
            "stall_cold_start:contoso.local:0"
        );
    }

    #[test]
    fn select_stall_cold_start_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_cold_start_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_cold_start_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_cold_start_work(&s, 1);
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_stall_cold_start_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());
        assert!(select_stall_cold_start_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_cold_start_dedup_re_arms_per_attempt() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_STALL_COLD_START,
            stall_cold_start_dedup_key("contoso.local", 0),
        );
        assert!(select_stall_cold_start_work(&s, 0).is_empty());
        assert_eq!(select_stall_cold_start_work(&s, 1).len(), 1);
    }

    #[test]
    fn select_stall_cold_start_ignores_delegation_vulns() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert_eq!(select_stall_cold_start_work(&s, 0).len(), 1);
    }

    #[test]
    fn select_stall_cold_start_emits_one_per_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert_eq!(select_stall_cold_start_work(&s, 0).len(), 2);
    }

    #[test]
    fn build_spray_payload_shape() {
        let p = build_spray_payload("contoso.local", "192.168.58.10");
        assert_eq!(p["technique"], "password_spray");
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["use_common_passwords"], true);
        assert_eq!(p["acknowledge_no_policy"], true);
    }

    #[test]
    fn build_cold_start_payload_emits_cold_start_instructions() {
        let p = build_cold_start_payload("contoso.local", "192.168.58.10");
        let techniques = p["techniques"].as_array().expect("techniques array");
        let tech_names: Vec<&str> = techniques.iter().filter_map(|v| v.as_str()).collect();
        assert!(tech_names.contains(&"asrep_roast"));
        assert!(tech_names.contains(&"kerberos_user_enum_noauth"));
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        let instructions = p["instructions"].as_str().expect("instructions");
        assert!(instructions.contains("seclists"));
        assert!(instructions.contains("kerbrute"));
    }

    fn ctx(
        has_users: bool,
        has_creds: bool,
        has_dcs: bool,
        allow_password_spray: bool,
        allow_asrep_roast: bool,
        lhf_max: usize,
    ) -> StallContext {
        StallContext {
            has_users,
            has_creds,
            has_dcs,
            allow_password_spray,
            allow_asrep_roast,
            lhf_max,
        }
    }

    #[test]
    fn plan_stall_recovery_empty_state_no_actions() {
        let s = StateInner::new("op".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(false, false, false, true, true, 2));
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_stall_recovery_emits_spray_when_users_present() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(true, false, true, true, false, 2));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, ActionKind::Spray);
        assert_eq!(plan[0].domain, "contoso.local");
        assert_eq!(plan[0].dedup_set, DEDUP_PASSWORD_SPRAY);
        assert_eq!(plan[0].dedup_key, "stall_spray:contoso.local:1");
    }

    #[test]
    fn plan_stall_recovery_emits_lhf_when_creds_present() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(false, true, true, false, false, 2));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, ActionKind::LowHanging);
        assert_eq!(plan[0].dedup_set, DEDUP_EXPANSION_CREDS);
        assert!(plan[0].cred.is_some());
    }

    #[test]
    fn plan_stall_recovery_emits_cold_start_when_empty() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 2, &ctx(false, false, true, false, true, 2));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, ActionKind::ColdStart);
        assert_eq!(plan[0].dedup_set, DEDUP_STALL_COLD_START);
        assert_eq!(plan[0].dedup_key, "stall_cold_start:contoso.local:2");
    }

    #[test]
    fn plan_stall_recovery_cold_start_suppressed_when_users_or_creds_present() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());

        let plan = plan_stall_recovery(&s, 1, &ctx(true, false, true, false, true, 2));
        assert!(plan.iter().all(|a| a.kind != ActionKind::ColdStart));

        let plan = plan_stall_recovery(&s, 1, &ctx(false, true, true, false, true, 2));
        assert!(plan.iter().all(|a| a.kind != ActionKind::ColdStart));
    }

    #[test]
    fn plan_stall_recovery_spray_gated_by_technique_flag() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(true, false, true, false, true, 2));
        assert!(plan.iter().all(|a| a.kind != ActionKind::Spray));
    }

    #[test]
    fn plan_stall_recovery_cold_start_gated_by_technique_flag() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let plan = plan_stall_recovery(&s, 1, &ctx(false, false, true, true, false, 2));
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_stall_recovery_requires_dcs() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        let plan = plan_stall_recovery(&s, 1, &ctx(true, true, false, true, true, 2));
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_stall_recovery_lhf_respects_cap() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for u in &["alice", "bob", "carol"] {
            s.credentials.push(make_cred(u, "Pw", "contoso.local"));
        }
        let plan = plan_stall_recovery(&s, 1, &ctx(false, true, true, false, false, 2));
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|a| a.kind == ActionKind::LowHanging));
    }

    #[test]
    fn stall_tracker_observe_progress_marks_change() {
        let mut t = StallTracker::new();
        assert!(t.observe_progress(1, 0));
        assert!(!t.observe_progress(1, 0));
        assert!(t.observe_progress(1, 1));
    }

    #[test]
    fn stall_tracker_observe_progress_resets_attempts() {
        let mut t = StallTracker::new();
        t.force_attempts(3);
        t.observe_progress(1, 0);
        assert!(!t.attempts_exhausted());
        t.force_attempts(MAX_RECOVERY_ATTEMPTS);
        assert!(t.attempts_exhausted());
        t.observe_progress(2, 0);
        assert!(!t.attempts_exhausted());
    }

    #[test]
    fn stall_tracker_is_stalled_after_threshold() {
        let mut t = StallTracker::new();
        assert!(!t.is_stalled());
        t.rewind_last_change(STALL_THRESHOLD + Duration::from_secs(1));
        assert!(t.is_stalled());
    }

    #[test]
    fn stall_tracker_cooldown_elapsed_on_construction() {
        let t = StallTracker::new();
        assert!(t.cooldown_elapsed());
    }

    #[test]
    fn stall_tracker_cooldown_not_elapsed_after_recovery() {
        let mut t = StallTracker::new();
        t.note_recovery_attempt();
        assert!(!t.cooldown_elapsed());
        t.rewind_last_recovery(RECOVERY_COOLDOWN + Duration::from_secs(1));
        assert!(t.cooldown_elapsed());
    }

    #[test]
    fn stall_tracker_note_recovery_increments() {
        let mut t = StallTracker::new();
        assert_eq!(t.note_recovery_attempt(), 1);
        assert_eq!(t.note_recovery_attempt(), 2);
        assert_eq!(t.note_recovery_attempt(), 3);
    }

    #[test]
    fn stall_tracker_attempts_exhausted_at_cap() {
        let mut t = StallTracker::new();
        for _ in 0..MAX_RECOVERY_ATTEMPTS {
            t.note_recovery_attempt();
        }
        assert!(t.attempts_exhausted());
    }

    #[test]
    fn stall_tracker_stall_duration_secs_increases() {
        let mut t = StallTracker::new();
        assert_eq!(t.stall_duration_secs(), 0);
        t.rewind_last_change(Duration::from_secs(42));
        assert!(t.stall_duration_secs() >= 42);
    }

    /// Hand-rolled fake adapter for testing `execute_recovery_actions`.
    /// Records every call and returns scripted outcomes per action kind.
    struct FakeAdapter {
        spray_outcome: Mutex<Result<Option<String>, String>>,
        lhf_outcome: Mutex<Result<Option<String>, String>>,
        cold_start_outcome: Mutex<Result<Option<String>, String>>,
        spray_calls: Mutex<Vec<(String, String)>>,
        lhf_calls: Mutex<Vec<(String, String, String)>>,
        cold_start_calls: Mutex<Vec<(String, String)>>,
        dedup_marks: Mutex<Vec<(&'static str, String)>>,
    }

    impl FakeAdapter {
        fn new() -> Self {
            Self {
                spray_outcome: Mutex::new(Ok(Some("spray-task".into()))),
                lhf_outcome: Mutex::new(Ok(Some("lhf-task".into()))),
                cold_start_outcome: Mutex::new(Ok(Some("cs-task".into()))),
                spray_calls: Mutex::new(Vec::new()),
                lhf_calls: Mutex::new(Vec::new()),
                cold_start_calls: Mutex::new(Vec::new()),
                dedup_marks: Mutex::new(Vec::new()),
            }
        }
        fn set_spray(&self, r: Result<Option<String>, String>) {
            *self.spray_outcome.lock().unwrap() = r;
        }
        fn set_lhf(&self, r: Result<Option<String>, String>) {
            *self.lhf_outcome.lock().unwrap() = r;
        }
        fn set_cold_start(&self, r: Result<Option<String>, String>) {
            *self.cold_start_outcome.lock().unwrap() = r;
        }
    }

    #[async_trait]
    impl StallRecoveryAdapter for FakeAdapter {
        async fn submit_spray(&self, domain: &str, dc_ip: &str) -> Result<Option<String>> {
            self.spray_calls
                .lock()
                .unwrap()
                .push((domain.to_string(), dc_ip.to_string()));
            match self.spray_outcome.lock().unwrap().clone() {
                Ok(v) => Ok(v),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        async fn submit_lhf(
            &self,
            dc_ip: &str,
            domain: &str,
            cred: &ares_core::models::Credential,
        ) -> Result<Option<String>> {
            self.lhf_calls.lock().unwrap().push((
                dc_ip.to_string(),
                domain.to_string(),
                cred.username.clone(),
            ));
            match self.lhf_outcome.lock().unwrap().clone() {
                Ok(v) => Ok(v),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        async fn submit_cold_start(&self, domain: &str, dc_ip: &str) -> Result<Option<String>> {
            self.cold_start_calls
                .lock()
                .unwrap()
                .push((domain.to_string(), dc_ip.to_string()));
            match self.cold_start_outcome.lock().unwrap().clone() {
                Ok(v) => Ok(v),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        async fn mark_dedup(&self, set: &'static str, key: String) {
            self.dedup_marks.lock().unwrap().push((set, key));
        }
    }

    fn spray_action(domain: &str, dc_ip: &str, attempt: u32) -> RecoveryAction {
        RecoveryAction {
            kind: ActionKind::Spray,
            domain: domain.to_string(),
            dc_ip: dc_ip.to_string(),
            dedup_key: stall_spray_dedup_key(domain, attempt),
            dedup_set: DEDUP_PASSWORD_SPRAY,
            cred: None,
        }
    }

    fn lhf_action(domain: &str, dc_ip: &str, user: &str, attempt: u32) -> RecoveryAction {
        RecoveryAction {
            kind: ActionKind::LowHanging,
            domain: domain.to_string(),
            dc_ip: dc_ip.to_string(),
            dedup_key: stall_lhf_dedup_key(domain, user, attempt),
            dedup_set: DEDUP_EXPANSION_CREDS,
            cred: Some(make_cred(user, "Pw", domain)),
        }
    }

    fn cold_start_action(domain: &str, dc_ip: &str, attempt: u32) -> RecoveryAction {
        RecoveryAction {
            kind: ActionKind::ColdStart,
            domain: domain.to_string(),
            dc_ip: dc_ip.to_string(),
            dedup_key: stall_cold_start_dedup_key(domain, attempt),
            dedup_set: DEDUP_STALL_COLD_START,
            cred: None,
        }
    }

    #[tokio::test]
    async fn execute_recovery_actions_empty_plan_zero_dispatched() {
        let fake = FakeAdapter::new();
        let n = execute_recovery_actions(&fake, vec![]).await;
        assert_eq!(n, 0);
        assert!(fake.dedup_marks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_spray_and_marks_dedup() {
        let fake = FakeAdapter::new();
        let plan = vec![spray_action("contoso.local", "192.168.58.10", 1)];
        let n = execute_recovery_actions(&fake, plan).await;
        assert_eq!(n, 1);
        let calls = fake.spray_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "contoso.local");
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks.len(), 1);
        assert_eq!(marks[0].0, DEDUP_PASSWORD_SPRAY);
        assert_eq!(marks[0].1, "stall_spray:contoso.local:1");
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_lhf_and_passes_cred() {
        let fake = FakeAdapter::new();
        let plan = vec![lhf_action("contoso.local", "192.168.58.10", "alice", 1)];
        let n = execute_recovery_actions(&fake, plan).await;
        assert_eq!(n, 1);
        let calls = fake.lhf_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "192.168.58.10");
        assert_eq!(calls[0].1, "contoso.local");
        assert_eq!(calls[0].2, "alice");
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks[0].0, DEDUP_EXPANSION_CREDS);
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_cold_start_and_marks_dedup() {
        let fake = FakeAdapter::new();
        let plan = vec![cold_start_action("fabrikam.local", "192.168.58.40", 3)];
        let n = execute_recovery_actions(&fake, plan).await;
        assert_eq!(n, 1);
        let calls = fake.cold_start_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "fabrikam.local");
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks[0].0, DEDUP_STALL_COLD_START);
        assert_eq!(marks[0].1, "stall_cold_start:fabrikam.local:3");
    }

    #[tokio::test]
    async fn execute_recovery_actions_skips_dedup_on_ok_none() {
        let fake = FakeAdapter::new();
        fake.set_spray(Ok(None));
        let plan = vec![spray_action("contoso.local", "192.168.58.10", 1)];
        let n = execute_recovery_actions(&fake, plan).await;
        assert_eq!(n, 0);
        assert_eq!(fake.spray_calls.lock().unwrap().len(), 1);
        assert!(fake.dedup_marks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_recovery_actions_skips_dedup_on_error() {
        let fake = FakeAdapter::new();
        fake.set_lhf(Err("dispatch boom".into()));
        let plan = vec![lhf_action("contoso.local", "192.168.58.10", "alice", 1)];
        let n = execute_recovery_actions(&fake, plan).await;
        assert_eq!(n, 0);
        assert!(fake.dedup_marks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn execute_recovery_actions_dispatches_mixed_plan() {
        let fake = FakeAdapter::new();
        let plan = vec![
            spray_action("contoso.local", "192.168.58.10", 1),
            lhf_action("contoso.local", "192.168.58.10", "alice", 1),
            cold_start_action("fabrikam.local", "192.168.58.40", 1),
        ];
        let n = execute_recovery_actions(&fake, plan).await;
        assert_eq!(n, 3);
        assert_eq!(fake.spray_calls.lock().unwrap().len(), 1);
        assert_eq!(fake.lhf_calls.lock().unwrap().len(), 1);
        assert_eq!(fake.cold_start_calls.lock().unwrap().len(), 1);
        assert_eq!(fake.dedup_marks.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn execute_recovery_actions_partial_success_counts_only_dispatched() {
        let fake = FakeAdapter::new();
        fake.set_spray(Ok(None));
        fake.set_cold_start(Err("boom".into()));
        let plan = vec![
            spray_action("contoso.local", "192.168.58.10", 1),
            lhf_action("contoso.local", "192.168.58.10", "alice", 1),
            cold_start_action("fabrikam.local", "192.168.58.40", 1),
        ];
        let n = execute_recovery_actions(&fake, plan).await;
        assert_eq!(n, 1);
        let marks = fake.dedup_marks.lock().unwrap();
        assert_eq!(marks.len(), 1);
        assert_eq!(marks[0].0, DEDUP_EXPANSION_CREDS);
    }

    #[tokio::test]
    async fn execute_recovery_actions_each_action_marks_its_own_dedup_set() {
        let fake = FakeAdapter::new();
        let plan = vec![
            spray_action("contoso.local", "192.168.58.10", 7),
            cold_start_action("fabrikam.local", "192.168.58.40", 7),
        ];
        execute_recovery_actions(&fake, plan).await;
        let marks = fake.dedup_marks.lock().unwrap();
        let sets: Vec<&str> = marks.iter().map(|(s, _)| *s).collect();
        assert!(sets.contains(&DEDUP_PASSWORD_SPRAY));
        assert!(sets.contains(&DEDUP_STALL_COLD_START));
    }
}
