//! auto_acl_chain_follow -- dispatch ACL chain steps using available creds.
//!
//! `state.acl_chains` is rebuilt from the ACL graph at the top of every tick
//! ([`crate::orchestrator::acl_graph::refresh_acl_chains`]). Before that
//! producer existed nothing in the tree ever wrote the field, so this whole
//! module was spawned and idle for the life of every operation.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::acl_graph::{self, MAX_ACL_DISPATCH_PER_TICK};
use crate::orchestrator::automation::dacl_abuse::{holds_target_material, is_destructive_acl_type};
use crate::orchestrator::dispatcher::{Dispatcher, SubmissionOutcome};
use crate::orchestrator::state::*;

/// Extract steps from an ACL chain JSON value.
/// The chain can be a direct array or an object with a "steps" field.
fn extract_chain_steps(chain: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    chain
        .as_array()
        .or_else(|| chain.get("steps").and_then(|v| v.as_array()))
}

/// Extract the `vuln_id` an ACL chain step exploits, if the producer set one.
///
/// Shared with `auto_dacl_abuse` via the `dacl:{vuln_id}` dedup key: both
/// drivers submit the same `acl_chain_step` work for the same edge, so
/// whichever fires first retires it for the other.
fn extract_step_vuln_id(step: &serde_json::Value) -> &str {
    step.get("vuln_id").and_then(|v| v.as_str()).unwrap_or("")
}

/// Extract source user from an ACL chain step.
/// Tries "source", "source_user", "from" keys in order.
fn extract_source_user(step: &serde_json::Value) -> &str {
    step.get("source")
        .or_else(|| step.get("source_user"))
        .or_else(|| step.get("from"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// Extract source domain from an ACL chain step.
/// Tries "source_domain", "domain" keys.
fn extract_source_domain(step: &serde_json::Value) -> &str {
    step.get("source_domain")
        .or_else(|| step.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn extract_target_user(step: &serde_json::Value) -> &str {
    step.get("target")
        .or_else(|| step.get("target_user"))
        .or_else(|| step.get("to"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn extract_edge_domain<'a>(step: &'a serde_json::Value, fallback: &'a str) -> &'a str {
    let domain = step
        .get("domain")
        .or_else(|| step.get("source_domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if domain.is_empty() {
        fallback
    } else {
        domain
    }
}

fn extract_acl_type(step: &serde_json::Value) -> String {
    let declared = step
        .get("acl_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    if declared.is_empty() {
        extract_step_vuln_id(step).to_lowercase()
    } else {
        declared
    }
}

/// Build ACL chain step dedup key.
fn acl_step_dedup_key(chain_idx: usize, step_idx: usize) -> String {
    format!("chain:{}:step:{}", chain_idx, step_idx)
}

/// Dedup key for a step, preferring the chain's stable `chain_id`.
///
/// The chain list is re-ranked every tick, so a positional key would drift
/// onto a different edge (and silently unblock or re-block work) whenever a
/// new ACL edge landed. Falls back to the positional form for chains from an
/// external producer that carry no id.
fn acl_step_key(chain: &serde_json::Value, chain_idx: usize, step_idx: usize) -> String {
    match chain.get("chain_id").and_then(|v| v.as_str()) {
        Some(id) if !id.is_empty() => format!("chain:{id}:step:{step_idx}"),
        _ => acl_step_dedup_key(chain_idx, step_idx),
    }
}

/// Resolve the principal that authenticates for `source_user`.
///
/// A password-bearing credential wins; otherwise any NTLM hash we hold for the
/// principal stands in. The payload's credential block is identity-only — the
/// prompt renders `username`/`domain` and forbids the agent from passing
/// secrets, because the worker injects whichever material state holds by
/// `(username, domain)` immediately before the tool runs. So a hash-only
/// foothold dispatches exactly like a password one, where before it produced
/// no dispatch at all.
///
/// A step whose source is a group falls back to
/// [`acl_graph::resolve_group_source`], which answers with a member — a group
/// name matches no credential and previously ended the chain.
fn resolve_step_principal(
    state: &StateInner,
    source_user: &str,
    source_domain: &str,
) -> Result<ares_core::models::Credential, acl_graph::UnresolvedSource> {
    let user_l = source_user.to_lowercase();
    let domain_l = source_domain.to_lowercase();
    let domain_matches = |d: &str| domain_l.is_empty() || d.to_lowercase() == domain_l;

    if let Some(cred) = state
        .credentials
        .iter()
        .find(|c| c.username.to_lowercase() == user_l && domain_matches(&c.domain))
    {
        return Ok(cred.clone());
    }

    if let Some(hash) = state.hashes.iter().find(|h| {
        h.username.to_lowercase() == user_l
            && domain_matches(&h.domain)
            && acl_graph::is_usable_hash(h)
    }) {
        return Ok(credential_for_hash(hash));
    }

    match acl_graph::resolve_group_source(state, source_user, source_domain)? {
        acl_graph::SourceMaterial::Credential(cred) => Ok(cred),
        acl_graph::SourceMaterial::Hash(hash) => Ok(credential_for_hash(&hash)),
    }
}

fn credential_for_hash(hash: &ares_core::models::Hash) -> ares_core::models::Credential {
    ares_core::models::Credential {
        id: format!("acl-step-{}", hash.id),
        username: hash.username.clone(),
        password: String::new(),
        domain: hash.domain.clone(),
        source: hash.source.clone(),
        discovered_at: None,
        is_admin: false,
        parent_id: None,
        attack_step: hash.attack_step,
    }
}

/// Build the dispatch payload for one resolved chain step.
///
/// `source_user` is the principal the worker will authenticate as, not the
/// trustee the ACE names: the task template renders it as "we authenticate as
/// this", and a group-sourced edge whose trustee reached that line had the
/// agent trying to log in as a group. The trustee is preserved as `via_group`
/// so the record of *why* this principal was chosen survives.
fn step_payload(
    vuln_id: &str,
    step: &serde_json::Value,
    cred: &ares_core::models::Credential,
) -> serde_json::Value {
    let trustee = extract_source_user(step);
    let via_group = (!cred.username.eq_ignore_ascii_case(trustee)).then(|| trustee.to_string());

    let mut payload = json!({
        "technique": "acl_chain_step",
        "vuln_id": vuln_id,
        "acl_type": step.get("acl_type").and_then(|v| v.as_str()).unwrap_or(""),
        "source_user": cred.username,
        "target_user": step.get("target").and_then(|v| v.as_str()).unwrap_or(""),
        "target_ip": step.get("target_ip").and_then(|v| v.as_str()).unwrap_or(""),
        "step": step,
        "credential": {
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        },
    });
    if let Some(group) = via_group {
        payload["via_group"] = json!(group);
    }
    payload
}

/// One ACL chain step ready to dispatch.
pub(crate) struct AclStepWork {
    pub dedup_key: String,
    pub vuln_id: String,
    pub step: serde_json::Value,
    pub credential: ares_core::models::Credential,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct AclChainTickCensus {
    pub post_domination_stop: bool,
    pub chains: usize,
    pub no_chains: bool,
    pub malformed_chains: usize,
    pub already_dispatched: usize,
    pub already_exploited: usize,
    pub no_source_principal: usize,
    pub unresolvable_principal: usize,
    pub group_no_owned_member: usize,
    pub group_unmapped: usize,
    pub non_principal_source: usize,
    pub domain_dominated: usize,
    pub target_material_held: usize,
    pub over_tick_cap: usize,
    pub eligible: usize,
}

impl AclChainTickCensus {
    pub(crate) fn post_domination() -> Self {
        Self {
            post_domination_stop: true,
            ..Self::default()
        }
    }

    /// Book an unresolved source against the reason it failed.
    pub(crate) fn record_unresolved(&mut self, reason: acl_graph::UnresolvedSource) {
        match reason {
            acl_graph::UnresolvedSource::GroupNoOwnedMember => self.group_no_owned_member += 1,
            acl_graph::UnresolvedSource::GroupUnmapped => self.group_unmapped += 1,
            acl_graph::UnresolvedSource::NonPrincipal => self.non_principal_source += 1,
            acl_graph::UnresolvedSource::NoMaterial => self.unresolvable_principal += 1,
        }
    }

    pub(crate) fn emit(&self) {
        info!(
            post_domination_stop = self.post_domination_stop,
            chains = self.chains,
            no_chains = self.no_chains,
            malformed_chains = self.malformed_chains,
            already_dispatched = self.already_dispatched,
            already_exploited = self.already_exploited,
            no_source_principal = self.no_source_principal,
            unresolvable_principal = self.unresolvable_principal,
            group_no_owned_member = self.group_no_owned_member,
            group_unmapped = self.group_unmapped,
            non_principal_source = self.non_principal_source,
            domain_dominated = self.domain_dominated,
            target_material_held = self.target_material_held,
            over_tick_cap = self.over_tick_cap,
            eligible = self.eligible,
            "ACL chain tick census"
        );
    }
}

/// Collect the chain steps dispatchable this tick.
///
/// At most one step per chain: the first that is neither already dispatched
/// nor already exploited. A later step only becomes eligible once its
/// predecessor is marked, which is exactly the sequencing an ACL chain needs —
/// step 1 authenticates as the principal step 0 takes over, so it cannot run
/// until step 0 has run and published that principal's material.
///
/// Extracted from the driver loop so that sequencing is testable without a
/// Dispatcher.
#[cfg(test)]
pub(crate) fn collect_acl_chain_work(state: &StateInner) -> Vec<AclStepWork> {
    collect_acl_chain_work_census(state, &mut AclChainTickCensus::default())
}

pub(crate) fn collect_acl_chain_work_census(
    state: &StateInner,
    census: &mut AclChainTickCensus,
) -> Vec<AclStepWork> {
    let mut items = Vec::new();
    census.chains = state.acl_chains.len();

    for (chain_idx, chain) in state.acl_chains.iter().enumerate() {
        let Some(steps) = extract_chain_steps(chain) else {
            census.malformed_chains += 1;
            continue;
        };

        for (step_idx, step) in steps.iter().enumerate() {
            let dedup_key = acl_step_key(chain, chain_idx, step_idx);

            if state.dispatched_acl_steps.contains(&dedup_key) {
                census.already_dispatched += 1;
                continue;
            }
            if state.is_processed(DEDUP_ACL_STEPS, &dedup_key) {
                census.already_dispatched += 1;
                continue;
            }

            let vuln_id = extract_step_vuln_id(step).to_string();
            if !vuln_id.is_empty()
                && (state.exploited_vulnerabilities.contains(&vuln_id)
                    || state.is_processed(DEDUP_DACL_ABUSE, &format!("dacl:{vuln_id}")))
            {
                census.already_exploited += 1;
                continue;
            }

            let source_user = extract_source_user(step);
            let source_domain = extract_source_domain(step);

            if source_user.is_empty() {
                census.no_source_principal += 1;
                continue;
            }

            let credential = match resolve_step_principal(state, source_user, source_domain) {
                Ok(credential) => credential,
                Err(reason) => {
                    census.record_unresolved(reason);
                    break;
                }
            };

            let edge_domain = extract_edge_domain(step, &credential.domain).to_lowercase();
            if state.dominated_domains.contains(&edge_domain) {
                census.domain_dominated += 1;
                debug!(vuln_id = %vuln_id, domain = %edge_domain, "ACL chain skipped: domain already dominated");
                break;
            }

            let target_user = extract_target_user(step);
            if is_destructive_acl_type(&extract_acl_type(step))
                && !target_user.is_empty()
                && holds_target_material(state, target_user, &edge_domain)
            {
                census.target_material_held += 1;
                debug!(vuln_id = %vuln_id, target = %target_user, "ACL chain step skipped: destructive ACL, target material already in state");
                continue;
            }

            items.push(AclStepWork {
                dedup_key,
                vuln_id,
                step: step.clone(),
                credential,
            });

            // Only dispatch the first undispatched step per chain
            break;
        }
    }

    census.over_tick_cap = items.len().saturating_sub(MAX_ACL_DISPATCH_PER_TICK);
    let items = acl_graph::take_diverse_by(items, MAX_ACL_DISPATCH_PER_TICK, |w: &AclStepWork| {
        (
            w.credential.username.to_lowercase(),
            w.credential.domain.to_lowercase(),
        )
    });
    census.eligible = items.len();
    items
}

/// Follows ACL chains from BloodHound results, dispatching each step when we
/// hold auth material for the source principal.
/// Interval: 30s. Each chain is a JSON array of steps; we find the first
/// undispatched step whose source principal we can authenticate as — password
/// or NTLM hash — and dispatch it.
pub async fn auto_acl_chain_follow(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_census: Option<AclChainTickCensus> = None;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Skip only when ALL forests are dominated AND strategy says to stop.
        // When continue_after_da is true, keep following ACL chains for path diversity.
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                let census = AclChainTickCensus::post_domination();
                if last_census.as_ref() != Some(&census) {
                    census.emit();
                    last_census = Some(census);
                }
                continue;
            }
        }

        {
            let mut state = dispatcher.state.write().await;
            let count = acl_graph::refresh_acl_chains(&mut state);
            debug!(chains = count, "ACL graph refreshed");
        }

        let mut census = AclChainTickCensus::default();
        let work: Vec<AclStepWork> = {
            let state = dispatcher.state.read().await;

            if state.acl_chains.is_empty() {
                census.no_chains = true;
                if last_census.as_ref() != Some(&census) {
                    census.emit();
                    last_census = Some(census);
                }
                continue;
            }

            collect_acl_chain_work_census(&state, &mut census)
        };
        if last_census.as_ref() != Some(&census) {
            census.emit();
            last_census = Some(census);
        }

        for AclStepWork {
            dedup_key,
            vuln_id,
            step,
            credential: cred,
        } in work
        {
            let payload = step_payload(&vuln_id, &step, &cred);

            let priority = dispatcher.effective_priority("acl_abuse");
            // Mark dedup on Submitted OR Deferred — Deferred means the task is
            // safely in the deferred ZSET and the drain will retry it. Without
            // this, the next 30s tick re-emits the same step and the deferred
            // ZSET hits its per-type cap, silently dropping work.
            let mark_dedup = match dispatcher
                .throttled_submit_outcome("acl_chain_step", "acl", payload, priority)
                .await
            {
                Ok(SubmissionOutcome::Submitted(task_id)) => {
                    info!(
                        task_id = %task_id,
                        step_key = %dedup_key,
                        "ACL chain step dispatched"
                    );
                    true
                }
                Ok(SubmissionOutcome::Deferred) => {
                    debug!(step_key = %dedup_key, "ACL chain step deferred (will retry via deferred drain)");
                    true
                }
                Ok(SubmissionOutcome::Dropped) => {
                    debug!(step_key = %dedup_key, "ACL chain step dropped (will reconsider next tick)");
                    false
                }
                Err(e) => {
                    warn!(err = %e, "Failed to dispatch ACL chain step");
                    false
                }
            };
            if mark_dedup {
                let dacl_key = (!vuln_id.is_empty()).then(|| format!("dacl:{vuln_id}"));
                {
                    let mut state = dispatcher.state.write().await;
                    state.dispatched_acl_steps.insert(dedup_key.clone());
                    state.mark_processed(DEDUP_ACL_STEPS, dedup_key.clone());
                    if let Some(ref k) = dacl_key {
                        state.mark_processed(DEDUP_DACL_ABUSE, k.clone());
                    }
                }
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_ACL_STEPS, &dedup_key)
                    .await;
                if let Some(ref k) = dacl_key {
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DACL_ABUSE, k)
                        .await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_chain_steps_from_array() {
        let chain = json!([{"source": "a"}, {"source": "b"}]);
        let steps = extract_chain_steps(&chain).unwrap();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn extract_chain_steps_from_object_with_steps_field() {
        let chain = json!({"steps": [{"source": "a"}]});
        let steps = extract_chain_steps(&chain).unwrap();
        assert_eq!(steps.len(), 1);
    }

    #[test]
    fn extract_chain_steps_empty_array() {
        let chain = json!([]);
        let steps = extract_chain_steps(&chain).unwrap();
        assert!(steps.is_empty());
    }

    #[test]
    fn extract_chain_steps_invalid_returns_none() {
        let chain = json!({"other": "value"});
        assert!(extract_chain_steps(&chain).is_none());
    }

    #[test]
    fn extract_chain_steps_null_returns_none() {
        let chain = json!(null);
        assert!(extract_chain_steps(&chain).is_none());
    }

    #[test]
    fn extract_chain_steps_string_returns_none() {
        let chain = json!("not a chain");
        assert!(extract_chain_steps(&chain).is_none());
    }

    #[test]
    fn extract_source_user_from_source_key() {
        let step = json!({"source": "admin"});
        assert_eq!(extract_source_user(&step), "admin");
    }

    #[test]
    fn extract_source_user_from_source_user_key() {
        let step = json!({"source_user": "jdoe"});
        assert_eq!(extract_source_user(&step), "jdoe");
    }

    #[test]
    fn extract_source_user_from_from_key() {
        let step = json!({"from": "svc_account"});
        assert_eq!(extract_source_user(&step), "svc_account");
    }

    #[test]
    fn extract_source_user_prefers_source_over_from() {
        let step = json!({"source": "admin", "from": "other"});
        assert_eq!(extract_source_user(&step), "admin");
    }

    #[test]
    fn extract_source_user_missing_returns_empty() {
        let step = json!({"target": "dc01"});
        assert_eq!(extract_source_user(&step), "");
    }

    #[test]
    fn extract_source_user_non_string_returns_empty() {
        let step = json!({"source": 42});
        assert_eq!(extract_source_user(&step), "");
    }

    #[test]
    fn extract_source_domain_from_source_domain_key() {
        let step = json!({"source_domain": "contoso.local"});
        assert_eq!(extract_source_domain(&step), "contoso.local");
    }

    #[test]
    fn extract_source_domain_from_domain_key() {
        let step = json!({"domain": "corp.net"});
        assert_eq!(extract_source_domain(&step), "corp.net");
    }

    #[test]
    fn extract_source_domain_prefers_source_domain() {
        let step = json!({"source_domain": "contoso.local", "domain": "other.local"});
        assert_eq!(extract_source_domain(&step), "contoso.local");
    }

    #[test]
    fn extract_source_domain_missing_returns_empty() {
        let step = json!({"source": "admin"});
        assert_eq!(extract_source_domain(&step), "");
    }

    #[test]
    fn extract_source_domain_non_string_returns_empty() {
        let step = json!({"source_domain": 123});
        assert_eq!(extract_source_domain(&step), "");
    }

    #[test]
    fn acl_step_dedup_key_basic() {
        assert_eq!(acl_step_dedup_key(0, 0), "chain:0:step:0");
    }

    #[test]
    fn acl_step_dedup_key_large_indices() {
        assert_eq!(acl_step_dedup_key(42, 7), "chain:42:step:7");
    }

    #[test]
    fn acl_step_key_prefers_chain_id() {
        let chain = json!({"chain_id": "deadbeef", "steps": [{"source": "alice"}]});
        assert_eq!(acl_step_key(&chain, 3, 0), "chain:deadbeef:step:0");
    }

    #[test]
    fn acl_step_key_is_stable_when_the_chain_is_reranked() {
        let chain = json!({"chain_id": "deadbeef", "steps": [{"source": "alice"}]});
        assert_eq!(acl_step_key(&chain, 0, 1), acl_step_key(&chain, 9, 1));
    }

    #[test]
    fn acl_step_key_falls_back_to_position_without_an_id() {
        let chain = json!([{"source": "alice"}]);
        assert_eq!(acl_step_key(&chain, 2, 1), "chain:2:step:1");
    }

    #[test]
    fn acl_step_key_falls_back_on_empty_id() {
        let chain = json!({"chain_id": "", "steps": []});
        assert_eq!(acl_step_key(&chain, 2, 1), "chain:2:step:1");
    }

    #[test]
    fn extract_step_vuln_id_reads_the_field() {
        let step = json!({"vuln_id": "acl_genericall_alice_bob"});
        assert_eq!(extract_step_vuln_id(&step), "acl_genericall_alice_bob");
    }

    #[test]
    fn extract_step_vuln_id_missing_returns_empty() {
        assert_eq!(extract_step_vuln_id(&json!({"source": "alice"})), "");
    }

    fn cred(username: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("cred-{username}"),
            username: username.into(),
            password: password.into(),
            domain: domain.into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn hash(username: &str, domain: &str, hash_type: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("hash-{username}"),
            username: username.into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            hash_type: hash_type.into(),
            domain: domain.into(),
            cracked_password: None,
            source: "secretsdump".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn two_step_chain() -> serde_json::Value {
        json!({
            "chain_id": "deadbeef",
            "steps": [
                {
                    "vuln_id": "acl_genericall_alice_bob",
                    "acl_type": "genericall",
                    "source": "alice",
                    "source_domain": "contoso.local",
                    "target": "bob",
                    "target_ip": "192.168.58.10",
                    "domain": "contoso.local",
                },
                {
                    "vuln_id": "acl_addmember_bob_da",
                    "acl_type": "addmember",
                    "source": "bob",
                    "source_domain": "contoso.local",
                    "target": "Domain Admins",
                    "target_ip": "192.168.58.10",
                    "domain": "contoso.local",
                },
            ],
        })
    }

    fn state_with_chain() -> StateInner {
        let mut state = StateInner::new("op".into());
        state.acl_chains = vec![two_step_chain()];
        state
    }

    #[test]
    fn collect_refuses_a_source_known_only_by_roast_ciphertext() {
        let mut state = state_with_chain();
        let mut roast = hash("alice", "contoso.local", "kerberoast");
        roast.hash_value = "$krb5tgs$23$*alice$CONTOSO.LOCAL*".into();
        state.hashes.push(roast);

        assert!(
            collect_acl_chain_work(&state).is_empty(),
            "a chain seeded speculatively must wait for the crack, not dispatch"
        );
    }

    #[test]
    fn collect_dispatches_once_the_roast_ciphertext_is_cracked() {
        let mut state = state_with_chain();
        let mut roast = hash("alice", "contoso.local", "kerberoast");
        roast.hash_value = "$krb5tgs$23$*alice$CONTOSO.LOCAL*".into();
        state.hashes.push(roast);
        state.credentials.push(ares_core::models::Credential {
            id: "c-alice".into(),
            username: "alice".into(),
            password: "P@ssw0rd!".into(),
            domain: "contoso.local".into(),
            source: "cracked:hashcat".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        });

        let work = collect_acl_chain_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_id, "acl_genericall_alice_bob");
    }

    #[test]
    fn collect_dispatches_a_hash_only_source() {
        let mut state = state_with_chain();
        state.hashes.push(hash("alice", "contoso.local", "ntlm"));
        let work = collect_acl_chain_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_id, "acl_genericall_alice_bob");
        assert_eq!(work[0].credential.username, "alice");
        assert_eq!(work[0].credential.domain, "contoso.local");
        assert!(work[0].credential.password.is_empty());
    }

    #[test]
    fn collect_prefers_a_password_over_a_hash() {
        let mut state = state_with_chain();
        state.hashes.push(hash("alice", "contoso.local", "ntlm"));
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));
        let work = collect_acl_chain_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.password, "P@ssw0rd!");
    }

    #[test]
    fn collect_skips_a_source_with_no_material() {
        let mut state = state_with_chain();
        state
            .credentials
            .push(cred("carol", "P@ssw0rd!", "contoso.local"));
        assert!(collect_acl_chain_work(&state).is_empty());
    }

    #[test]
    fn collect_skips_a_source_we_only_hold_roastable_ciphertext_for() {
        let mut state = state_with_chain();
        state
            .hashes
            .push(hash("alice", "contoso.local", "kerberoast"));
        assert!(collect_acl_chain_work(&state).is_empty());
    }

    #[test]
    fn collect_skips_a_hash_from_another_realm() {
        let mut state = state_with_chain();
        state.hashes.push(hash("alice", "fabrikam.local", "ntlm"));
        assert!(collect_acl_chain_work(&state).is_empty());
    }

    #[test]
    fn census_attributes_an_unresolvable_source_principal() {
        let state = state_with_chain();
        let mut census = AclChainTickCensus::default();
        let work = collect_acl_chain_work_census(&state, &mut census);

        assert!(work.is_empty());
        assert_eq!(census.chains, 1);
        assert_eq!(census.unresolvable_principal, 1);
        assert_eq!(census.eligible, 0);
        assert!(!census.no_chains);
        assert_ne!(census, AclChainTickCensus::default());
    }

    fn group_sourced_chain() -> serde_json::Value {
        json!({
            "chain_id": "cafebabe",
            "steps": [{
                "vuln_id": "acl_genericwrite_certpublishers_web01",
                "acl_type": "genericwrite",
                "source": "Cert Publishers",
                "source_domain": "contoso.local",
                "target": "web01",
                "target_ip": "192.168.58.10",
                "domain": "contoso.local",
            }],
        })
    }

    fn user_in(username: &str, groups: &[&str]) -> ares_core::models::User {
        ares_core::models::User {
            username: username.into(),
            domain: "contoso.local".into(),
            description: String::new(),
            is_admin: false,
            source: "ldap_enumeration".into(),
            member_of: groups.iter().map(|g| (*g).to_string()).collect(),
        }
    }

    #[test]
    fn collect_dispatches_a_group_sourced_step_as_a_member() {
        let mut state = StateInner::new("op".into());
        state.acl_chains = vec![group_sourced_chain()];
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));
        state.users.push(user_in("alice", &["Cert Publishers"]));

        let work = collect_acl_chain_work(&state);
        assert_eq!(work.len(), 1, "a group source is no longer a dead end");
        assert_eq!(work[0].credential.username, "alice");
    }

    #[test]
    fn census_separates_a_group_with_no_owned_member_from_an_unmapped_one() {
        let mut state = StateInner::new("op".into());
        state.acl_chains = vec![group_sourced_chain()];
        state
            .credentials
            .push(cred("carol", "P@ssw0rd!", "contoso.local"));
        state.users.push(user_in("carol", &["Domain Users"]));

        let mut unmapped = AclChainTickCensus::default();
        assert!(collect_acl_chain_work_census(&state, &mut unmapped).is_empty());
        assert_eq!(unmapped.group_unmapped, 1);
        assert_eq!(unmapped.group_no_owned_member, 0);
        assert_eq!(unmapped.unresolvable_principal, 0);

        state.users.push(user_in("alice", &["Cert Publishers"]));
        let mut no_member = AclChainTickCensus::default();
        assert!(collect_acl_chain_work_census(&state, &mut no_member).is_empty());
        assert_eq!(no_member.group_no_owned_member, 1);
        assert_eq!(no_member.group_unmapped, 0);
    }

    #[test]
    fn payload_authenticates_as_the_member_not_the_group() {
        let step = group_sourced_chain()["steps"][0].clone();
        let payload = step_payload(
            "acl_genericwrite_certpublishers_web01",
            &step,
            &cred("alice", "P@ssw0rd!", "contoso.local"),
        );

        assert_eq!(payload["source_user"], "alice");
        assert_eq!(payload["via_group"], "Cert Publishers");
        assert_eq!(payload["step"]["source"], "Cert Publishers");
    }

    #[test]
    fn payload_omits_via_group_for_a_directly_sourced_step() {
        let step = two_step_chain()["steps"][0].clone();
        let payload = step_payload(
            "acl_genericall_alice_bob",
            &step,
            &cred("alice", "P@ssw0rd!", "contoso.local"),
        );

        assert_eq!(payload["source_user"], "alice");
        assert!(payload.get("via_group").is_none());
    }

    #[test]
    fn census_attributes_a_non_principal_source() {
        let mut state = StateInner::new("op".into());
        let mut chain = group_sourced_chain();
        chain["steps"][0]["source"] = json!("S-1-3-0");
        state.acl_chains = vec![chain];
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));

        let mut census = AclChainTickCensus::default();
        assert!(collect_acl_chain_work_census(&state, &mut census).is_empty());
        assert_eq!(census.non_principal_source, 1);
        assert_eq!(census.unresolvable_principal, 0);
    }

    #[test]
    fn census_attributes_an_already_dispatched_step() {
        let mut state = state_with_chain();
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));
        let first = collect_acl_chain_work(&state);
        state
            .dispatched_acl_steps
            .insert(first[0].dedup_key.clone());

        let mut census = AclChainTickCensus::default();
        let work = collect_acl_chain_work_census(&state, &mut census);

        assert!(work.is_empty());
        assert_eq!(census.already_dispatched, 1);
        assert_eq!(census.eligible, 0);
    }

    #[test]
    fn census_counts_an_eligible_step() {
        let mut state = state_with_chain();
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));

        let mut census = AclChainTickCensus::default();
        let work = collect_acl_chain_work_census(&state, &mut census);

        assert_eq!(work.len(), 1);
        assert_eq!(census.chains, 1);
        assert_eq!(census.eligible, 1);
        assert_eq!(census.unresolvable_principal, 0);
        assert_eq!(census.over_tick_cap, 0);
    }

    #[test]
    fn post_domination_census_is_distinguishable_from_a_silent_tick() {
        assert_ne!(
            AclChainTickCensus::post_domination(),
            AclChainTickCensus::default()
        );
        assert!(AclChainTickCensus::post_domination().post_domination_stop);
    }

    #[test]
    fn chain_advances_one_step_per_tick() {
        let mut state = state_with_chain();
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));

        let first = collect_acl_chain_work(&state);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].dedup_key, "chain:deadbeef:step:0");

        assert_eq!(
            collect_acl_chain_work(&state)[0].dedup_key,
            "chain:deadbeef:step:0"
        );

        state
            .dispatched_acl_steps
            .insert(first[0].dedup_key.clone());

        assert!(collect_acl_chain_work(&state).is_empty());

        state
            .credentials
            .push(cred("bob", "P@ssw0rd!", "contoso.local"));

        let second = collect_acl_chain_work(&state);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].dedup_key, "chain:deadbeef:step:1");
        assert_eq!(second[0].vuln_id, "acl_addmember_bob_da");
        assert_eq!(second[0].credential.username, "bob");
    }

    #[test]
    fn collect_takes_at_most_one_step_from_each_chain() {
        let mut state = StateInner::new("op".into());
        state.acl_chains = vec![two_step_chain(), two_step_chain()];
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));
        state
            .credentials
            .push(cred("bob", "P@ssw0rd!", "contoso.local"));
        let work = collect_acl_chain_work(&state);
        assert_eq!(work.len(), 2);
        assert!(work.iter().all(|w| w.dedup_key.ends_with(":step:1")));
    }

    #[test]
    fn collect_skips_destructive_step_when_target_password_already_held() {
        let mut state = StateInner::new("op".into());
        state.acl_chains = vec![two_step_chain()];
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));
        state
            .credentials
            .push(cred("bob", "P@ssw0rd!", "contoso.local"));

        let work = collect_acl_chain_work(&state);

        assert!(
            work.iter().all(|w| w.vuln_id != "acl_genericall_alice_bob"),
            "destructive ACL must not overwrite a principal we already hold"
        );
    }

    #[test]
    fn collect_skips_destructive_step_when_target_hash_already_held() {
        let mut state = StateInner::new("op".into());
        state.acl_chains = vec![two_step_chain()];
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));
        state.hashes.push(hash("bob", "contoso.local", "ntlm"));

        let work = collect_acl_chain_work(&state);

        assert!(
            work.iter().all(|w| w.vuln_id != "acl_genericall_alice_bob"),
            "destructive ACL must not overwrite a principal whose hash we already dumped"
        );
    }

    #[test]
    fn collect_skips_chain_whose_domain_is_already_dominated() {
        let mut state = state_with_chain();
        state.dominated_domains.insert("contoso.local".to_string());

        assert!(collect_acl_chain_work(&state).is_empty());
    }

    #[test]
    fn collect_skips_a_step_whose_edge_is_already_exploited() {
        let mut state = state_with_chain();
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local"));
        state
            .exploited_vulnerabilities
            .insert("acl_genericall_alice_bob".into());
        assert!(collect_acl_chain_work(&state).is_empty());

        state
            .credentials
            .push(cred("bob", "P@ssw0rd!", "contoso.local"));
        let work = collect_acl_chain_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "chain:deadbeef:step:1");
    }
}
