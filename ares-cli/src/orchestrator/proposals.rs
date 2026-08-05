use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::{watch, RwLock};
use tracing::{debug, info, warn};

use super::deferred::DeferredTask;
use super::dispatcher::Dispatcher;

const DEFAULT_WINDOW_SECS: u64 = 180;

const VETOABLE_TASK_TYPES: &[&str] = &["exploit", "lateral", "coercion", "acl_chain_step"];

pub(crate) fn task_type_is_vetoable(task_type: &str) -> bool {
    VETOABLE_TASK_TYPES.contains(&task_type)
}

pub(crate) fn mediation_scope_is_all() -> bool {
    std::env::var("ARES_ORCHESTRATOR_MEDIATION_SCOPE")
        .map(|v| v.trim().eq_ignore_ascii_case("all"))
        .unwrap_or(false)
}
const DEFAULT_CAPACITY: usize = 200;
const DEFAULT_REJECTION_TTL_SECS: u64 = 600;
const DEFAULT_DISPATCH_TTL_SECS: u64 = 600;
const SWEEP_INTERVAL_SECS: u64 = 5;

const BEHIND_THRESHOLD: u32 = 2;

pub fn mediation_enabled() -> bool {
    match std::env::var("ARES_ORCHESTRATOR_MEDIATION") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "on" | "yes"
        ),
        Err(_) => false,
    }
}

fn secs_from_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn usize_from_env(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

pub struct Proposal {
    pub id: String,
    pub task: DeferredTask,
    pub proposed_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProposalOutcome {
    Parked,
    Duplicate,
    PreviouslyRejected,
    Full,
    ReviewerBehind,
}

struct PoolInner {
    proposals: Vec<Proposal>,
    signatures: HashSet<String>,
    rejected: HashMap<String, Instant>,
    dispatched: HashMap<String, Instant>,
    next_id: u64,
    consecutive_expiries: u32,
}

pub struct ProposalPool {
    inner: RwLock<PoolInner>,
    window: Duration,
    capacity: usize,
    rejection_ttl: Duration,
    dispatch_ttl: Duration,
}

impl ProposalPool {
    pub fn new(
        window: Duration,
        capacity: usize,
        rejection_ttl: Duration,
        dispatch_ttl: Duration,
    ) -> Self {
        Self {
            inner: RwLock::new(PoolInner {
                proposals: Vec::new(),
                signatures: HashSet::new(),
                rejected: HashMap::new(),
                dispatched: HashMap::new(),
                next_id: 1,
                consecutive_expiries: 0,
            }),
            window,
            capacity,
            rejection_ttl,
            dispatch_ttl,
        }
    }

    pub fn from_env() -> Self {
        Self::new(
            Duration::from_secs(secs_from_env(
                "ARES_ORCHESTRATOR_MEDIATION_WINDOW_SECS",
                DEFAULT_WINDOW_SECS,
            )),
            usize_from_env("ARES_ORCHESTRATOR_MEDIATION_CAPACITY", DEFAULT_CAPACITY),
            Duration::from_secs(secs_from_env(
                "ARES_ORCHESTRATOR_MEDIATION_REJECTION_TTL_SECS",
                DEFAULT_REJECTION_TTL_SECS,
            )),
            Duration::from_secs(secs_from_env(
                "ARES_ORCHESTRATOR_MEDIATION_DISPATCH_TTL_SECS",
                DEFAULT_DISPATCH_TTL_SECS,
            )),
        )
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.proposals.len()
    }

    pub async fn propose(&self, task: DeferredTask) -> ProposalOutcome {
        let signature = task.signature();
        let mut inner = self.inner.write().await;

        inner
            .rejected
            .retain(|_, at| at.elapsed() < self.rejection_ttl);

        inner
            .dispatched
            .retain(|_, at| at.elapsed() < self.dispatch_ttl);

        if inner.rejected.contains_key(&signature) {
            return ProposalOutcome::PreviouslyRejected;
        }
        if inner.signatures.contains(&signature) || inner.dispatched.contains_key(&signature) {
            return ProposalOutcome::Duplicate;
        }
        if inner.proposals.len() >= self.capacity {
            inner.dispatched.insert(signature, Instant::now());
            return ProposalOutcome::Full;
        }
        if inner.consecutive_expiries >= BEHIND_THRESHOLD {
            inner.dispatched.insert(signature, Instant::now());
            return ProposalOutcome::ReviewerBehind;
        }

        let id = format!("p{:04}", inner.next_id);
        inner.next_id += 1;
        inner.signatures.insert(signature);
        inner.proposals.push(Proposal {
            id,
            task,
            proposed_at: Instant::now(),
        });
        ProposalOutcome::Parked
    }

    pub async fn list(&self, limit: usize) -> Vec<serde_json::Value> {
        let inner = self.inner.read().await;
        let mut views: Vec<&Proposal> = inner.proposals.iter().collect();
        views.sort_by_key(|p| p.task.priority);
        views
            .iter()
            .take(limit)
            .map(|p| proposal_view(p, self.window))
            .collect()
    }

    pub async fn approve(&self, ids: &[String]) -> (Vec<DeferredTask>, Vec<String>) {
        let mut inner = self.inner.write().await;
        let mut approved = Vec::new();
        let mut unknown = Vec::new();
        for id in ids {
            match inner.proposals.iter().position(|p| &p.id == id) {
                Some(idx) => {
                    let p = inner.proposals.remove(idx);
                    let signature = p.task.signature();
                    inner.signatures.remove(&signature);
                    inner.dispatched.insert(signature, Instant::now());
                    inner.consecutive_expiries = 0;
                    approved.push(p.task);
                }
                None => unknown.push(id.clone()),
            }
        }
        (approved, unknown)
    }

    pub async fn reject(&self, id: &str) -> Option<DeferredTask> {
        let mut inner = self.inner.write().await;
        let idx = inner.proposals.iter().position(|p| p.id == id)?;
        let p = inner.proposals.remove(idx);
        let signature = p.task.signature();
        inner.signatures.remove(&signature);
        inner.rejected.insert(signature, Instant::now());
        inner.consecutive_expiries = 0;
        Some(p.task)
    }

    pub async fn take_expired(&self) -> Vec<DeferredTask> {
        let mut inner = self.inner.write().await;
        let window = self.window;
        let mut expired = Vec::new();
        let mut i = 0;
        while i < inner.proposals.len() {
            if inner.proposals[i].proposed_at.elapsed() >= window {
                let p = inner.proposals.remove(i);
                let signature = p.task.signature();
                inner.signatures.remove(&signature);
                inner.dispatched.insert(signature, Instant::now());
                expired.push(p.task);
            } else {
                i += 1;
            }
        }
        if !expired.is_empty() {
            inner.consecutive_expiries = inner.consecutive_expiries.saturating_add(1);
        } else if inner.proposals.is_empty() {
            inner.consecutive_expiries = 0;
        }
        expired
    }
}

fn payload_str(payload: &serde_json::Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = payload.get(*key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    String::new()
}

fn proposal_view(p: &Proposal, window: Duration) -> serde_json::Value {
    let payload = &p.task.payload;
    let principal = payload
        .get("credential")
        .and_then(|c| {
            let user = c.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let dom = c.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            if user.is_empty() {
                None
            } else {
                Some(format!("{user}@{dom}"))
            }
        })
        .or_else(|| {
            let user = payload_str(payload, &["username"]);
            let dom = payload_str(payload, &["domain"]);
            match (user.is_empty(), dom.is_empty()) {
                (true, _) => None,
                (false, true) => Some(user),
                (false, false) => Some(format!("{user}@{dom}")),
            }
        })
        .unwrap_or_default();
    let age = p.proposed_at.elapsed();
    json!({
        "id": p.id,
        "task_type": p.task.task_type,
        "target_role": p.task.target_role,
        "priority": p.task.priority,
        "technique": payload_str(payload, &["technique"]),
        "target": payload_str(payload, &["target_ip", "dc_ip", "target", "domain"]),
        "vuln_id": payload_str(payload, &["vuln_id"]),
        "principal": principal,
        "age_secs": age.as_secs(),
        "auto_release_in_secs": window.saturating_sub(age).as_secs(),
    })
}

pub fn spawn_proposal_sweeper(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        info!(
            window_secs = dispatcher.proposals.window().as_secs(),
            "Proposal sweeper started"
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = shutdown.changed() => break,
            }
            if *shutdown.borrow() {
                break;
            }

            let expired = dispatcher.proposals.take_expired().await;
            if expired.is_empty() {
                continue;
            }

            warn!(
                count = expired.len(),
                "Orchestrator did not rule on proposals within the window — auto-releasing"
            );
            for task in expired {
                if let Err(e) = dispatcher
                    .submit_approved(
                        &task.task_type,
                        &task.target_role,
                        task.payload.clone(),
                        task.priority,
                    )
                    .await
                {
                    debug!(err = %e, task_type = %task.task_type, "Auto-release submit failed");
                }
            }
        }

        info!("Proposal sweeper stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(task_type: &str, role: &str, target_ip: &str, priority: i32) -> DeferredTask {
        DeferredTask {
            priority,
            enqueue_time: 0.0,
            task_type: task_type.to_string(),
            target_role: role.to_string(),
            payload: json!({"target_ip": target_ip, "technique": "secretsdump"}),
            source_agent: "orchestrator".to_string(),
        }
    }

    fn pool() -> ProposalPool {
        ProposalPool::new(
            Duration::from_secs(60),
            10,
            Duration::from_secs(600),
            Duration::from_secs(600),
        )
    }

    #[test]
    fn golden_ticket_proposal_shows_its_domain_and_principal() {
        let p = Proposal {
            id: "p0112".to_string(),
            task: DeferredTask {
                priority: 1,
                enqueue_time: 0.0,
                task_type: "exploit".to_string(),
                target_role: "privesc".to_string(),
                payload: json!({
                    "technique": "golden_ticket",
                    "vuln_type": "golden_ticket",
                    "domain": "contoso.local",
                    "username": "Administrator",
                    "krbtgt_hash": "aad3b435b51404eeaad3b435b51404ee",
                }),
                source_agent: "automation".to_string(),
            },
            proposed_at: Instant::now(),
        };

        let view = proposal_view(&p, Duration::from_secs(180));

        assert_eq!(view["technique"], "golden_ticket");
        assert_eq!(view["target"], "contoso.local");
        assert_eq!(view["principal"], "Administrator@contoso.local");
        assert_eq!(view["vuln_id"], "");
    }

    #[test]
    fn a_principal_without_a_domain_is_not_suffixed() {
        let p = Proposal {
            id: "p0113".to_string(),
            task: DeferredTask {
                priority: 1,
                enqueue_time: 0.0,
                task_type: "exploit".to_string(),
                target_role: "privesc".to_string(),
                payload: json!({
                    "technique": "shadow_credentials",
                    "username": "svc_backup",
                }),
                source_agent: "automation".to_string(),
            },
            proposed_at: Instant::now(),
        };

        let view = proposal_view(&p, Duration::from_secs(180));

        assert_eq!(view["principal"], "svc_backup");
    }

    #[tokio::test]
    async fn parks_and_lists_a_proposal() {
        let p = pool();
        assert_eq!(
            p.propose(task(
                "credential_access",
                "credential_access",
                "192.168.58.10",
                3
            ))
            .await,
            ProposalOutcome::Parked
        );
        let listed = p.list(10).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["target"], "192.168.58.10");
        assert_eq!(listed[0]["target_role"], "credential_access");
    }

    #[tokio::test]
    async fn identical_work_proposed_twice_is_deduped() {
        let p = pool();
        let first = p
            .propose(task(
                "credential_access",
                "credential_access",
                "192.168.58.10",
                3,
            ))
            .await;
        let second = p
            .propose(task(
                "credential_access",
                "credential_access",
                "192.168.58.10",
                3,
            ))
            .await;
        assert_eq!(first, ProposalOutcome::Parked);
        assert_eq!(second, ProposalOutcome::Duplicate);
        assert_eq!(p.len().await, 1);
    }

    #[tokio::test]
    async fn distinct_targets_are_separate_proposals() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        p.propose(task("recon", "recon", "192.168.58.11", 1)).await;
        assert_eq!(p.len().await, 2);
    }

    #[tokio::test]
    async fn approve_removes_and_returns_the_task() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        let id = p.list(10).await[0]["id"].as_str().unwrap().to_string();

        let (approved, unknown) = p.approve(&[id]).await;
        assert_eq!(approved.len(), 1);
        assert!(unknown.is_empty());
        assert_eq!(approved[0].target_role, "recon");
        assert_eq!(p.len().await, 0);
    }

    #[tokio::test]
    async fn approving_an_unknown_id_is_reported_not_silently_dropped() {
        let p = pool();
        let (approved, unknown) = p.approve(&["p9999".to_string()]).await;
        assert!(approved.is_empty());
        assert_eq!(unknown, vec!["p9999".to_string()]);
    }

    #[tokio::test]
    async fn rejected_work_is_not_reproposed_within_the_ttl() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        let id = p.list(10).await[0]["id"].as_str().unwrap().to_string();

        assert!(p.reject(&id).await.is_some());
        assert_eq!(p.len().await, 0);

        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.10", 1)).await,
            ProposalOutcome::PreviouslyRejected
        );
        assert_eq!(p.len().await, 0);
    }

    #[tokio::test]
    async fn rejection_expires_after_the_ttl() {
        let p = ProposalPool::new(
            Duration::from_secs(60),
            10,
            Duration::from_millis(1),
            Duration::from_secs(600),
        );
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        let id = p.list(10).await[0]["id"].as_str().unwrap().to_string();
        p.reject(&id).await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.10", 1)).await,
            ProposalOutcome::Parked
        );
    }

    #[tokio::test]
    async fn repeated_expiry_stops_parking_so_review_latency_cannot_stall_red() {
        let p = ProposalPool::new(
            Duration::from_millis(1),
            10,
            Duration::from_secs(600),
            Duration::from_secs(600),
        );
        for i in 0..BEHIND_THRESHOLD {
            p.propose(task("exploit", "privesc", &format!("192.168.58.2{i}"), 1))
                .await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(p.take_expired().await.len(), 1);
        }
        assert_eq!(
            p.propose(task("exploit", "privesc", "192.168.58.11", 1))
                .await,
            ProposalOutcome::ReviewerBehind
        );
    }

    #[tokio::test]
    async fn parking_resumes_once_the_backlog_drains() {
        let p = ProposalPool::new(
            Duration::from_millis(1),
            10,
            Duration::from_secs(600),
            Duration::from_secs(600),
        );
        for i in 0..BEHIND_THRESHOLD {
            p.propose(task("exploit", "privesc", &format!("192.168.58.2{i}"), 1))
                .await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            p.take_expired().await;
        }
        assert_eq!(
            p.propose(task("exploit", "privesc", "192.168.58.11", 1))
                .await,
            ProposalOutcome::ReviewerBehind
        );

        assert!(p.take_expired().await.is_empty());

        assert_eq!(
            p.propose(task("exploit", "privesc", "192.168.58.12", 1))
                .await,
            ProposalOutcome::Parked
        );
    }

    #[tokio::test]
    async fn ruling_on_work_clears_the_behind_counter() {
        let p = ProposalPool::new(
            Duration::from_millis(1),
            10,
            Duration::from_secs(600),
            Duration::from_secs(600),
        );
        p.propose(task("exploit", "privesc", "192.168.58.10", 1))
            .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        p.take_expired().await;

        p.propose(task("exploit", "privesc", "192.168.58.11", 1))
            .await;
        let (approved, _) = p.approve(&["p0002".to_string()]).await;
        assert_eq!(approved.len(), 1);

        p.propose(task("exploit", "privesc", "192.168.58.12", 1))
            .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        p.take_expired().await;
        assert_eq!(
            p.propose(task("exploit", "privesc", "192.168.58.13", 1))
                .await,
            ProposalOutcome::Parked
        );
    }

    #[tokio::test]
    async fn unreviewed_work_expires_for_auto_release() {
        let p = ProposalPool::new(
            Duration::from_millis(1),
            10,
            Duration::from_secs(600),
            Duration::from_secs(600),
        );
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        let expired = p.take_expired().await;
        assert_eq!(expired.len(), 1);
        assert_eq!(p.len().await, 0);
    }

    #[tokio::test]
    async fn fresh_work_is_not_swept_early() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        assert!(p.take_expired().await.is_empty());
        assert_eq!(p.len().await, 1);
    }

    #[tokio::test]
    async fn auto_released_work_is_not_reproposed_within_the_cooldown() {
        let p = ProposalPool::new(
            Duration::from_millis(1),
            10,
            Duration::from_secs(600),
            Duration::from_secs(600),
        );
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(p.take_expired().await.len(), 1);

        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.10", 1)).await,
            ProposalOutcome::Duplicate,
            "auto-release must not free the signature, or every automation tick redispatches the same work"
        );
    }

    #[tokio::test]
    async fn dispatch_cooldown_expires_so_work_can_be_retried_later() {
        let p = ProposalPool::new(
            Duration::from_millis(1),
            10,
            Duration::from_secs(600),
            Duration::from_millis(5),
        );
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        p.take_expired().await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.10", 1)).await,
            ProposalOutcome::Parked
        );
    }

    #[tokio::test]
    async fn fail_open_dispatch_also_holds_the_cooldown() {
        let p = ProposalPool::new(
            Duration::from_millis(1),
            10,
            Duration::from_secs(600),
            Duration::from_secs(600),
        );
        for i in 0..BEHIND_THRESHOLD {
            p.propose(task("exploit", "privesc", &format!("192.168.58.2{i}"), 1))
                .await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            p.take_expired().await;
        }
        assert_eq!(
            p.propose(task("exploit", "privesc", "192.168.58.10", 1))
                .await,
            ProposalOutcome::ReviewerBehind
        );
        assert_eq!(
            p.propose(task("exploit", "privesc", "192.168.58.10", 1))
                .await,
            ProposalOutcome::Duplicate,
            "a fail-open dispatch must be remembered, or the behind state becomes an unbounded redispatch loop"
        );
    }

    #[tokio::test]
    async fn capacity_is_bounded() {
        let p = ProposalPool::new(
            Duration::from_secs(60),
            2,
            Duration::from_secs(600),
            Duration::from_secs(600),
        );
        p.propose(task("recon", "recon", "192.168.58.10", 1)).await;
        p.propose(task("recon", "recon", "192.168.58.11", 1)).await;
        assert_eq!(
            p.propose(task("recon", "recon", "192.168.58.12", 1)).await,
            ProposalOutcome::Full
        );
    }

    #[tokio::test]
    async fn listing_is_ordered_by_priority() {
        let p = pool();
        p.propose(task("recon", "recon", "192.168.58.10", 7)).await;
        p.propose(task("recon", "recon", "192.168.58.11", 1)).await;
        let listed = p.list(10).await;
        assert_eq!(listed[0]["target"], "192.168.58.11");
        assert_eq!(listed[0]["priority"], 1);
    }

    #[test]
    fn mediation_defaults_off_so_it_cannot_ship_enabled_by_accident() {
        std::env::remove_var("ARES_ORCHESTRATOR_MEDIATION");
        assert!(
            !mediation_enabled(),
            "mediation must be opt-in, or an unreviewed pool silently gates every exploit"
        );
        for off in ["0", "false", "off", "no", "OFF", " No "] {
            std::env::set_var("ARES_ORCHESTRATOR_MEDIATION", off);
            assert!(!mediation_enabled(), "{off} must disable mediation");
        }
        for on in ["1", "true", "on", "yes"] {
            std::env::set_var("ARES_ORCHESTRATOR_MEDIATION", on);
            assert!(mediation_enabled(), "{on} must leave mediation enabled");
        }
        std::env::remove_var("ARES_ORCHESTRATOR_MEDIATION");
    }
}
