//! auto_crack_dispatch -- submit crack tasks for new hashes.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

use super::crack_dedup_key;

/// Cracking-priority bucket for a hash type. Lower is higher priority.
///
/// Kerberoast and AS-REP hashes are the high-leverage crack targets in any
/// op: a cracked SPN often exposes a service account the orchestrator
/// already knows how to abuse (linked-server pivots, MSSQL impersonation,
/// cross-forest reuse), and AS-REP plaintext lets us swap an LLM-blind
/// password into the credential pool. NTLM hashes from secretsdump are
/// already usable as-is via PtH, so cracking them is the lowest-payoff
/// work and should never block roastable hashes from the single hashcat
/// slot.
fn crack_priority(hash_type: &str) -> u8 {
    // Strip '-'/'_' before matching so the hyphenated canonical spelling emitted
    // by `dedup::normalize_hash_type` ("AS-REP") collapses onto the bare "asrep"
    // token. Without this, "AS-REP" lowercases to "as-rep" which never matched
    // "asrep", so AS-REP tickets were misclassified as priority-1 (NTLM-class),
    // dropped from the roastable batch, and starved behind the secretsdump NTLM
    // flood — a genuinely crackable AS-REP could sit forever. (Kerberoast is
    // stored as "Kerberoast", which already matches after lowercasing.) Mirrors
    // `credential_resolver::is_authenticating_hash_type`.
    let t: String = hash_type
        .to_ascii_lowercase()
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .collect();
    match t.as_str() {
        "kerberoast" | "asrep" | "asreproast" => 0,
        "dcc2" | "mscachev2" => 1,
        _ => 2,
    }
}

/// Whether a hash can never be recovered by wordlist cracking and so must be
/// kept out of the hashcat pool. All three cases share the property
/// that the secret is machine-generated (not a human password) and that
/// *possessing the hash is already the win*, so a crack attempt only burns
/// `MAX_CRACK_ATTEMPTS` runs apiece and starves genuinely crackable user
/// hashes:
///
/// * **Computer accounts** (`username` ends in `$`): AD assigns 120-char random
///   passwords — hopeless for any wordlist — and the NTLM hash is already
///   pass-the-hash-usable straight from secretsdump. A kerberoast/AS-REP ticket
///   for such an account is encrypted with that same un-crackable key.
/// * **Inter-realm trust keys** (`is_trust_key`): consumed directly to forge
///   inter-realm TGTs, never cracked.
/// * **krbtgt** (and RODC `krbtgt_NNNNN`): the domain key account. Its password
///   is machine-generated and uncrackable; capturing the NT hash *is* the
///   objective. `auto_golden_ticket` forges straight from `state.hashes` using
///   `krbtgt.hash_value` (see `golden_ticket.rs`) and never needs a plaintext.
///
/// This predicate only shapes the crack *work list* — it never removes a hash
/// from `state.hashes`, so downstream forging (golden ticket, trust-key
/// inter-realm forge) still sees every one of these hashes.
fn is_uncrackable(hash: &ares_core::models::Hash) -> bool {
    let username = hash.username.trim_end();
    hash.is_trust_key
        || username.ends_with('$')
        || is_krbtgt(username)
        || hash
            .hash_type
            .eq_ignore_ascii_case(ares_tools::parsers::DPAPI_SYSTEM_HASH_TYPE)
}

/// Whether `username` names a krbtgt account: the domain krbtgt or an RODC
/// per-DC krbtgt (`krbtgt_NNNNN`). Case-insensitive.
fn is_krbtgt(username: &str) -> bool {
    let lower = username.trim().to_ascii_lowercase();
    lower == "krbtgt" || lower.starts_with("krbtgt_")
}

/// True for an NTLM hash whose domain we already fully own (it's in
/// `dominated_domains` — we hold the domain's krbtgt). We already have the hash
/// itself (PtH-usable), so cracking its plaintext buys no new access. Crucially,
/// these secretsdump NTLM hashes flood the tiny (2-slot, ~8-min-per-run) crack
/// queue and delay the AS-REP/kerberoast footholds that unlock the forests we do
/// NOT own yet. Measured live: a foreign-forest AS-REP foothold sat ~38 min
/// behind ~12 such already-owned NTLM jobs, then cracked in <1 min the moment it
/// reached a slot. Roastables (priority 0) are never dropped here — only NTLM of
/// an already-dominated domain. `dominated` is expected lowercased.
pub(crate) fn is_owned_domain_ntlm(
    hash: &ares_core::models::Hash,
    dominated: &HashSet<String>,
) -> bool {
    let domain = hash.domain.trim().to_lowercase();
    crack_priority(&hash.hash_type) > 0 && !domain.is_empty() && dominated.contains(&domain)
}

/// Max times a single hash gets dispatched to hashcat before the dispatcher
/// permanently marks it `DEDUP_CRACK_REQUESTS` and gives up. Bounded retry
/// covers the common failure modes (missing wordlist on the worker pod, a
/// transient hashcat crash, the password not in the current wordlist but
/// added later) without burning the cracker slot forever on impossible
/// hashes. Operationally, three attempts costs at most ~3× the hashcat
/// runtime per hash, which is the same overhead as restarting the op.
pub(crate) const MAX_CRACK_ATTEMPTS: u32 = 3;

/// Number of consecutive roastable (kerberoast/AS-REP) dispatches after
/// which the next eligible NTLM hash takes a turn. Without this, a steady
/// inflow of roastables — produced as each new domain/host gets owned —
/// permanently starves NTLM hashes from secretsdump, leaving DCSync output
/// uncracked and downstream scoreboard credit unclaimed.
const NTLM_TURN_AFTER_ROASTABLE_STREAK: u32 = 2;

const CRACK_TASK_STALL_TTL: Duration = Duration::from_secs(30 * 60);

/// Slot-time cost class for a hash's hashcat mode. Lower cracks fast; higher
/// can grind for the whole budget. The two AES kerberoast modes (19600/19700)
/// are ~1000x slower per candidate than RC4/NTLM, so a single AES batch can
/// hold the AES-exclusive hashcat slot for its full budget; every other mode
/// exhausts rockyou in seconds.
///
/// Used only as a *secondary* sort key inside the roastable priority bucket, so
/// a fast, high-crack-probability RC4 AS-REP (mode 18200) or RC4 kerberoast
/// (13100) is dispatched before a slow, usually-uncrackable AES kerberoast
/// ticket. AS-REP roast in particular is the classic cross-forest foothold: its
/// plaintext is a human password (near-certain rockyou hit) that unlocks
/// authenticated action in a far domain. Losing that race to a slow AES ticket
/// has cost a whole second forest — a far-domain AS-REP hash cracked ~46 min
/// after capture, stuck behind other crack work, with no time left to DCSync
/// that domain's krbtgt before the op ended.
fn crack_mode_cost(hash_value: &str) -> u8 {
    match ares_tools::cracker::hashcat_mode_for(hash_value) {
        19600 | 19700 | 2100 => 1, // AES kerberoast / DCC2 — hashcat "Slow.Hash: Yes"
        _ => 0,                    // RC4 AS-REP / RC4 kerberoast / NTLM — crack fast
    }
}

/// Order the crack work list breadth-first: by crack priority, then by cheapest
/// hashcat mode, then by fewest prior attempts on that exact hash. Ensures every
/// uncracked roastable hash gets attempt #1 before any hash gets attempt #2, and
/// that a fast RC4 AS-REP/kerberoast is never queued behind a slow AES ticket.
///
/// Without the attempts tiebreak the priority sort is stable, so `work.first()`
/// stays pinned to the same hash every tick. That hash is then re-dispatched on
/// each tick until it either cracks or exhausts `MAX_CRACK_ATTEMPTS` — so an
/// AES-only kerberoast ticket (etype 18, mode 19700) whose password isn't in the
/// wordlist burns all three ~10-min crack slots back-to-back before the next
/// hash is ever tried, starving a genuinely crackable ticket queued behind it
/// (e.g. an SPN account whose password *is* in rockyou) until the op ends.
/// Cycling through every hash once before any retry also makes the retries worth
/// more: by attempt #2 the op has usually harvested more cleartext, so the
/// known-password seed list fed to hashcat has grown.
///
/// The mode-cost tiebreak sits *between* priority and attempts: it never lets an
/// NTLM hash jump ahead of a roastable (priority dominates), but within the
/// roastable bucket it puts the fast, high-value RC4 modes first so the single
/// hashcat pool recovers the likely cross-forest foothold before spending the
/// AES budget on a ticket that probably isn't in the wordlist at all.
fn sort_crack_work(
    work: &mut [(String, ares_core::models::Hash)],
    attempts: &std::collections::HashMap<String, u32>,
) {
    work.sort_by_key(|(dedup, h)| {
        (
            crack_priority(&h.hash_type),
            crack_mode_cost(&h.hash_value),
            *attempts.get(dedup).unwrap_or(&0),
        )
    });
}

/// Pick the next hash to dispatch given a priority-sorted work list and the
/// current roastable streak. Pure function — exercised directly by the unit
/// tests so the fairness invariant doesn't drift back into starvation.
fn select_next_crack(
    work: &[(String, ares_core::models::Hash)],
    roastable_streak: u32,
) -> Option<&(String, ares_core::models::Hash)> {
    if roastable_streak >= NTLM_TURN_AFTER_ROASTABLE_STREAK {
        if let Some(ntlm) = work.iter().find(|(_, h)| crack_priority(&h.hash_type) > 0) {
            return Some(ntlm);
        }
    }
    work.first()
}

/// Scans for uncracked hashes and submits crack tasks.
/// Interval: 15s.
pub async fn auto_crack_dispatch(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Tracks consecutive roastable dispatches so NTLM hashes from
    // secretsdump aren't starved by a continuous roastable inflow.
    let mut roastable_streak: u32 = 0;
    let crack_inflight = dispatcher.crack_inflight.clone();

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Age out inflight guards by TTL only. The direct dispatch path
        // (tokio::spawn → tool_dispatcher::dispatch_tool) is not registered with
        // `dispatcher.tracker`, so any tracker-derived count is blind to this
        // tick's own hashcat runs. Using such a count as a "clear inflight"
        // trigger deleted the guard every tick, letting the same hash be
        // re-selected, re-dispatched, and burn all MAX_CRACK_ATTEMPTS retries in
        // ~45s before the first hashcat run had a chance to finish.
        crack_inflight.expire_stale().await;
        let active_crack_tasks = crack_inflight.active().await;
        let inflight_keys = crack_inflight.live_keys().await;

        // Collect unprocessed hashes, then sort by crack priority so the
        // hashcat pool serves roastable hashes first. Without this,
        // a backlog of NTLM machine-account hashes from secretsdump (already
        // PtH-usable) would starve the lone kerberoast/asrep hash that
        // unlocks a service-account password.
        let mut work: Vec<(String, ares_core::models::Hash)> = Vec::new();
        let mut uncracked_hashes = 0usize;
        let mut crackable_hashes = 0usize;
        let mut dropped_reasons: Vec<String> = Vec::new();
        let (attempts, total_hashes) = {
            let state = dispatcher.state.read().await;
            let total_hashes = state.hashes.len();
            let dominated: HashSet<String> = state
                .dominated_domains
                .iter()
                .map(|d| d.trim().to_lowercase())
                .collect();
            for h in state.hashes.iter() {
                if h.cracked_password.is_some() {
                    continue;
                }
                uncracked_hashes += 1;
                if is_uncrackable(h) {
                    continue;
                }
                crackable_hashes += 1;
                // Don't spend a scarce crack slot on NTLM of a domain we already
                // fully own — it buys no new access and starves the AS-REP /
                // kerberoast footholds for the forests we don't own yet.
                if is_owned_domain_ntlm(h, &dominated) {
                    dropped_reasons
                        .push(format!("{}:{}:owned_domain_ntlm", h.username, h.hash_type));
                    continue;
                }
                let dedup = crack_dedup_key(h);
                if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                    dropped_reasons.push(format!("{}:{}:dedup_processed", h.username, h.hash_type));
                    continue;
                }
                if inflight_keys.contains(&dedup) {
                    dropped_reasons.push(format!("{}:{}:inflight", h.username, h.hash_type));
                    continue;
                }
                work.push((dedup, h.clone()));
            }
            (state.crack_attempts.clone(), total_hashes)
        };
        sort_crack_work(&mut work, &attempts);
        info!(
            state_hashes_total = total_hashes,
            state_hashes_uncracked = uncracked_hashes,
            state_hashes_crackable = crackable_hashes,
            dropped = ?dropped_reasons,
            "crack_tick: filter stats"
        );

        // Allow multiple distinct crack tasks up to the configured cap. Same-mode
        // roastables are still batched into one task, and in-flight dedup keys
        // above prevent the next tick from re-submitting the same hash while an
        // earlier batch is still running.
        let max_active = crack_inflight.max_active();
        if active_crack_tasks >= max_active {
            warn!(
                active = active_crack_tasks,
                max_active,
                crackable = crackable_hashes,
                "crack_tick: cap reached, skipping dispatch this tick"
            );
            continue;
        }

        // Dispatch one crack task per tick (hashcat is a single serialized
        // slot). The `select_next_crack` pick is the primary hash; a roastable
        // pick then pulls in every other uncracked roastable of the same hashcat
        // mode so they crack together in one run (see `batch_same_mode_roastable`).
        let next = select_next_crack(&work, roastable_streak).cloned();
        if let Some((_primary_dedup, primary)) = next {
            let is_roastable = crack_priority(&primary.hash_type) == 0;
            let candidates = if is_roastable {
                batch_same_mode_roastable(&work, &primary)
            } else {
                // NTLM: never batched — its cracked line (`<32hex>:pw`) carries
                // no principal, so attribution needs the per-task username, which
                // only holds for one hash.
                vec![(crack_dedup_key(&primary), primary.clone())]
            };

            let task_id = format!(
                "crack_direct_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            );
            let candidate_keys: Vec<String> =
                candidates.iter().map(|(dedup, _)| dedup.clone()).collect();
            let Some(reserved) = crack_inflight.try_reserve(&task_id, &candidate_keys).await else {
                continue;
            };
            let batch: Vec<(String, ares_core::models::Hash)> = candidates
                .into_iter()
                .filter(|(dedup, _)| reserved.iter().any(|k| k == dedup))
                .collect();
            roastable_streak = if is_roastable {
                roastable_streak.saturating_add(1)
            } else {
                0
            };

            // Direct-tool dispatch: the LLM cracker path (gpt-5-mini) hits
            // MaxTokens on step 1 when a $krb5tgs$18 hash (2000+ chars) sits
            // in the prompt — the model runs out of output budget before it
            // can emit the crack_with_hashcat tool call, so kerberoast AES
            // TGS never actually reaches hashcat. crack_with_hashcat's
            // `resolve_hashcat_mode` auto-detects the mode from the hash
            // value; no LLM reasoning is required. Dispatch straight to the
            // worker.
            let joined = batch
                .iter()
                .map(|(_, h)| h.hash_value.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let (known_usernames, known_passwords) = {
                let state = dispatcher.state.read().await;
                super::super::dispatcher::task_builders::collect_crack_seed(&state)
            };
            let call = ares_llm::ToolCall {
                id: format!("crack_with_hashcat_{}", uuid::Uuid::new_v4().simple()),
                name: "crack_with_hashcat".to_string(),
                arguments: serde_json::json!({
                    "hash_value": joined,
                    "username": primary.username,
                    "known_usernames": known_usernames,
                    "known_passwords": known_passwords,
                }),
            };
            info!(
                task_id = %task_id,
                hash_type = %primary.hash_type,
                pick_user = %primary.username,
                batch = batch.len(),
                "crack_tick: dispatching crack_with_hashcat directly (bypass LLM)"
            );
            let dispatcher_bg = dispatcher.clone();
            let batch_bg = batch.clone();
            let call_args = call.arguments.clone();
            let primary_domain = primary.domain.clone();
            tokio::spawn(async move {
                let inflight = dispatcher_bg.crack_inflight.clone();
                let Ok(dispatch_result) = tokio::time::timeout(
                    CRACK_TASK_STALL_TTL,
                    dispatcher_bg
                        .llm_runner
                        .tool_dispatcher()
                        .dispatch_tool("cracker", &task_id, &call),
                )
                .await
                else {
                    warn!(
                        task_id = %task_id,
                        stall_secs = CRACK_TASK_STALL_TTL.as_secs(),
                        "crack_tick: direct crack dispatch stalled — reclaiming slot"
                    );
                    inflight.release(&task_id).await;
                    return;
                };
                match dispatch_result {
                    Ok(result) => {
                        info!(
                            task_id = %task_id,
                            batch = batch_bg.len(),
                            "crack_tick: direct crack task completed"
                        );
                        process_direct_crack_result(
                            &dispatcher_bg,
                            &task_id,
                            &call_args,
                            &primary_domain,
                            result,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(err = %e, task_id = %task_id, "crack_tick: direct crack dispatch failed");
                    }
                }
                // Count attempts against completed hashcat runs, not tick
                // re-selections. `record_crack_attempt` only marks
                // DEDUP_CRACK_REQUESTS when a hash has actually taken
                // MAX_CRACK_ATTEMPTS full runs and still isn't cracked; a hash
                // that cracked on this run drops out of `work` naturally via
                // `cracked_password.is_some()` on the next tick, so the counter
                // bump here is harmless for the success case.
                for (dedup, hash) in &batch_bg {
                    let still_uncracked = {
                        let state = dispatcher_bg.state.read().await;
                        state
                            .hashes
                            .iter()
                            .any(|h| crack_dedup_key(h) == *dedup && h.cracked_password.is_none())
                    };
                    if still_uncracked {
                        record_crack_attempt(&dispatcher_bg, dedup, &hash.hash_type).await;
                    }
                }
                inflight.release(&task_id).await;
            });
        }
    }
}

/// Fold a direct-dispatch `crack_with_hashcat` result back into state.
///
/// The LLM cracker path pushes tool discoveries + raw stdout through
/// `submission::execute_task` → result queue → `process_completed_task`, which
/// runs `extract_discoveries` and `extract_from_raw_text` to publish cracked
/// credentials and stamp the source hashes cracked. The direct path bypasses
/// that pipeline, so replay the same two extractors inline: without this the
/// worker cracks the ticket, prints the plaintext, and the orchestrator never
/// notices — leaving `state.hashes[<user>].cracked_password` at `None`.
async fn process_direct_crack_result(
    dispatcher: &Arc<Dispatcher>,
    task_id: &str,
    call_args: &serde_json::Value,
    primary_domain: &str,
    result: ares_llm::ToolExecResult,
) {
    use crate::orchestrator::result_processing;

    if let Some(ref disc) = result.discoveries {
        if let Err(e) = result_processing::extract_discoveries(disc, dispatcher, None, None).await {
            warn!(task_id = %task_id, err = %e, "crack_tick: extract_discoveries failed");
        }
    }

    let default_domain = if !primary_domain.is_empty() {
        primary_domain.to_string()
    } else {
        dispatcher
            .state
            .read()
            .await
            .domains
            .first()
            .cloned()
            .unwrap_or_default()
    };

    // Wrap in the `{tool_outputs: [{name, arguments, output}]}` shape
    // `extract_from_raw_text` expects — the same shape submission.rs builds
    // from `outcome.tool_outputs` on the LLM path.
    let payload = serde_json::json!({
        "tool_outputs": [{
            "name": "crack_with_hashcat",
            "arguments": call_args,
            "output": result.output,
        }],
    });
    result_processing::extract_from_raw_text(&payload, dispatcher, &default_domain, None, None)
        .await;
}

/// All uncracked roastable hashes in `work` that share `primary`'s hashcat mode
/// (including `primary`). These crack together in one hashcat run: a crackable
/// ticket is recovered in the first wordlist pass instead of waiting out every
/// other ticket's full crack budget one task at a time. Grouping by
/// [`ares_tools::cracker::hashcat_mode_for`] keeps the batch to a single `-m`
/// mode, which is required — hashcat runs one mode per invocation.
fn batch_same_mode_roastable(
    work: &[(String, ares_core::models::Hash)],
    primary: &ares_core::models::Hash,
) -> Vec<(String, ares_core::models::Hash)> {
    let mode = ares_tools::cracker::hashcat_mode_for(&primary.hash_value);
    work.iter()
        .filter(|(_, h)| {
            crack_priority(&h.hash_type) == 0
                && ares_tools::cracker::hashcat_mode_for(&h.hash_value) == mode
        })
        .cloned()
        .collect()
}

/// Record one crack attempt against `dedup_key`: bump the per-hash counter and,
/// at `MAX_CRACK_ATTEMPTS`, write the permanent dedup marker (in-memory +
/// persisted) so the hash is never re-dispatched, even after the op restarts.
async fn record_crack_attempt(
    dispatcher: &Arc<crate::orchestrator::dispatcher::Dispatcher>,
    dedup_key: &str,
    hash_type: &str,
) {
    let attempts = {
        let mut state = dispatcher.state.write().await;
        let entry = state
            .crack_attempts
            .entry(dedup_key.to_string())
            .or_insert(0);
        *entry += 1;
        *entry
    };
    if attempts >= MAX_CRACK_ATTEMPTS {
        warn!(
            dedup_key = %dedup_key,
            hash_type = %hash_type,
            attempts,
            "Crack attempts exhausted; giving up on hash"
        );
        dispatcher
            .state
            .write()
            .await
            .mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.to_string());
        let _ = dispatcher
            .state
            .persist_dedup(&dispatcher.queue, DEDUP_CRACK_REQUESTS, dedup_key)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        batch_same_mode_roastable, crack_mode_cost, crack_priority, is_krbtgt,
        is_owned_domain_ntlm, is_uncrackable, select_next_crack, sort_crack_work,
        MAX_CRACK_ATTEMPTS, NTLM_TURN_AFTER_ROASTABLE_STREAK,
    };
    use crate::orchestrator::state::{StateInner, DEDUP_CRACK_REQUESTS};
    use ares_core::models::Hash;
    use std::collections::{HashMap, HashSet};

    fn mk(hash_type: &str) -> (String, Hash) {
        (
            format!("dedup-{hash_type}"),
            Hash {
                id: format!("h-{hash_type}"),
                username: "u".into(),
                hash_type: hash_type.into(),
                hash_value: "x".into(),
                domain: "contoso.local".into(),
                source: "test".into(),
                cracked_password: None,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
                aes_key: None,
                is_previous: false,
                source_host: None,
                is_trust_key: false,
                trust_pair_label: None,
            },
        )
    }

    fn dominated(domains: &[&str]) -> HashSet<String> {
        domains.iter().map(|d| d.to_string()).collect()
    }

    #[test]
    fn owned_domain_ntlm_is_skipped() {
        // NTLM of a domain we already own → skip (no new access, and it starves
        // the crack queue). Case-insensitive on the hash's domain.
        let dom = dominated(&["contoso.local"]);
        let mut h = mk_hash("alice", "ntlm", false);
        h.domain = "contoso.local".into();
        assert!(is_owned_domain_ntlm(&h, &dom));
        h.domain = "CONTOSO.LOCAL".into();
        assert!(is_owned_domain_ntlm(&h, &dom));
    }

    #[test]
    fn unowned_or_empty_domain_ntlm_is_kept() {
        let dom = dominated(&["contoso.local"]);
        let mut h = mk_hash("bob", "ntlm", false);
        // Un-owned forest: plaintext may unlock it — keep it crackable.
        h.domain = "fabrikam.local".into();
        assert!(!is_owned_domain_ntlm(&h, &dom));
        // Empty domain: can't attribute to a dominated domain — keep.
        h.domain = String::new();
        assert!(!is_owned_domain_ntlm(&h, &dom));
    }

    #[test]
    fn roastable_in_owned_domain_is_never_skipped() {
        // Footholds (AS-REP / kerberoast, priority 0) are never dropped here —
        // even in an already-dominated domain — since the whole point is to keep
        // the queue clear FOR them.
        let dom = dominated(&["contoso.local"]);
        let mut a = mk_hash("svc_sql", "asrep", false);
        a.domain = "contoso.local".into();
        assert!(!is_owned_domain_ntlm(&a, &dom));
        let mut k = mk_hash("svc_sql", "kerberoast", false);
        k.domain = "contoso.local".into();
        assert!(!is_owned_domain_ntlm(&k, &dom));
    }

    fn mk_hash(username: &str, hash_type: &str, is_trust_key: bool) -> Hash {
        Hash {
            id: format!("h-{username}"),
            username: username.into(),
            hash_type: hash_type.into(),
            hash_value: "x".into(),
            domain: "contoso.local".into(),
            source: "test".into(),
            cracked_password: None,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key,
            trust_pair_label: None,
        }
    }

    #[test]
    fn machine_account_ntlm_is_uncrackable() {
        // Computer-account NTLM from secretsdump: 120-char random password,
        // hopeless for any wordlist, already PtH-usable — never dispatch it.
        assert!(is_uncrackable(&mk_hash("dc01$", "ntlm", false)));
        assert!(is_uncrackable(&mk_hash("ws01$", "ntlm", false)));
    }

    #[test]
    fn machine_account_roastable_is_uncrackable() {
        // A kerberoast/AS-REP ticket for a machine account is encrypted with
        // that same un-crackable key, so it is skipped regardless of type.
        assert!(is_uncrackable(&mk_hash("sql01$", "kerberoast", false)));
    }

    #[test]
    fn trust_key_is_uncrackable() {
        // Inter-realm trust keys are used directly for forging, never cracked.
        assert!(is_uncrackable(&mk_hash("contoso", "ntlm", true)));
    }

    #[test]
    fn user_hashes_remain_crackable() {
        assert!(!is_uncrackable(&mk_hash("alice", "ntlm", false)));
        assert!(!is_uncrackable(&mk_hash("svc_sql", "kerberoast", false)));
    }

    #[test]
    fn crack_priority_normalizes_canonical_roast_spellings() {
        // dedup::normalize_hash_type stores AS-REP tickets as the hyphenated
        // canonical form "AS-REP" and kerberoast tickets as "Kerberoast" (never
        // "TGS-REP"). crack_priority must rank both as top-priority roastables
        // (0). Before the fix, plain lowercase "as-rep" missed the "asrep" arm
        // and fell to priority 1, starving a crackable ticket behind the
        // secretsdump NTLM flood.
        assert_eq!(crack_priority("AS-REP"), 0);
        assert_eq!(crack_priority("as-rep"), 0);
        assert_eq!(crack_priority("Kerberoast"), 0);
        assert!(crack_priority("NTLM") > crack_priority("dcc2"));
        assert!(crack_priority("dcc2") > crack_priority("AS-REP"));
        assert_eq!(crack_priority("NTLM"), crack_priority("ntlm"));
    }

    #[test]
    fn dcc2_outranks_ntlm_but_never_roastables() {
        assert!(crack_priority("dcc2") > crack_priority("Kerberoast"));
        assert!(crack_priority("dcc2") < crack_priority("NTLM"));
        assert!(
            crack_priority("dcc2") > 0,
            "dcc2 is never batched as roastable"
        );
    }

    #[test]
    fn dcc2_is_crackable_but_dpapi_system_is_not() {
        assert!(!is_uncrackable(&mk_hash("alice", "dcc2", false)));
        assert!(is_uncrackable(&mk_hash(
            "DPAPI_SYSTEM",
            "dpapi_system",
            false
        )));
    }

    #[test]
    fn dcc2_mode_is_charged_as_a_slow_hash() {
        assert_eq!(
            crack_mode_cost("$DCC2$10240#alice#e2829c8af2232fa53797e2f0e35e4626"),
            1
        );
        assert_eq!(crack_mode_cost("aad3b435b51404eeaad3b435b51404ee"), 0);
    }

    #[test]
    fn krbtgt_is_uncrackable() {
        // krbtgt's password is machine-generated and never crackable; cracking
        // it only burns the hashcat slot. Excluding it from the crack work list
        // does not remove it from state.hashes, so auto_golden_ticket still
        // forges from krbtgt.hash_value (see golden_ticket.rs).
        assert!(is_uncrackable(&mk_hash("krbtgt", "ntlm", false)));
        assert!(is_uncrackable(&mk_hash("KRBTGT", "ntlm", false)));
        // AS-REP/kerberoast material for krbtgt is just as uncrackable.
        assert!(is_uncrackable(&mk_hash("krbtgt", "asrep", false)));
        // RODC per-DC krbtgt accounts follow the krbtgt_NNNNN convention.
        assert!(is_uncrackable(&mk_hash("krbtgt_31415", "ntlm", false)));
    }

    #[test]
    fn is_krbtgt_matches_domain_and_rodc_variants() {
        assert!(is_krbtgt("krbtgt"));
        assert!(is_krbtgt("KrbTgt"));
        assert!(is_krbtgt("krbtgt_20001"));
        assert!(!is_krbtgt("alice"));
        assert!(!is_krbtgt("krbtgtx"));
    }

    #[test]
    fn roastable_hashes_outrank_ntlm() {
        assert!(crack_priority("kerberoast") < crack_priority("ntlm"));
        assert!(crack_priority("asrep") < crack_priority("ntlm"));
        assert!(crack_priority("asreproast") < crack_priority("ntlm"));
    }

    #[test]
    fn roastable_priority_case_insensitive() {
        assert_eq!(crack_priority("KERBEROAST"), crack_priority("kerberoast"));
        assert_eq!(crack_priority("AsRep"), crack_priority("asrep"));
    }

    #[test]
    fn unknown_hash_types_share_ntlm_bucket() {
        assert_eq!(crack_priority("ntlm"), crack_priority("netntlmv2"));
        assert_eq!(crack_priority("ntlm"), crack_priority(""));
    }

    #[test]
    fn breadth_first_prefers_unattempted_hash_over_retry() {
        // Two roastable hashes at equal priority: `starved` (a slow, so-far
        // uncrackable AES kerberoast ticket) has already burned attempts;
        // `fresh` has none. The un-attempted hash must sort first so it isn't
        // starved behind the other's back-to-back retries. Regression guard for
        // an AES-only kerberoast ticket (mode 19700, ~10 min/attempt) whose
        // password isn't in the wordlist monopolizing the AES hashcat slot
        // for all MAX_CRACK_ATTEMPTS runs while a rockyou-crackable ticket
        // queued behind it never gets a turn before the op ends.
        let starved = (
            "k:starved".to_string(),
            mk_hash("svc_web", "kerberoast", false),
        );
        let fresh = ("k:fresh".to_string(), mk_hash("carol", "kerberoast", false));
        let mut work = vec![starved, fresh];
        let mut attempts = HashMap::new();
        attempts.insert("k:starved".to_string(), MAX_CRACK_ATTEMPTS - 1);
        sort_crack_work(&mut work, &attempts);
        assert_eq!(
            work[0].0, "k:fresh",
            "an un-attempted hash must be dispatched before another hash's retry"
        );
        // And the picker chooses it (streak below the NTLM-turn threshold).
        let chosen = select_next_crack(&work, 0).unwrap();
        assert_eq!(chosen.1.username, "carol");
    }

    #[test]
    fn batch_groups_same_mode_roastables_only() {
        // A batch pulls in every uncracked roastable sharing the primary's
        // hashcat mode — and nothing else: not a different-mode roastable (an
        // AS-REP ticket is mode 18200, AES kerberoast is 19700), not an NTLM
        // hash (mode 1000, and NTLM can't be batched anyway). So every etype-18
        // kerberoast ticket cracks in one run; the AS-REP one waits its own turn.
        fn roast(dedup: &str, user: &str, hv: &str) -> (String, Hash) {
            let mut h = mk_hash(user, "kerberoast", false);
            h.hash_value = hv.into();
            (dedup.into(), h)
        }
        let aes1 = roast(
            "k:aes1",
            "carol",
            "$krb5tgs$18$carol$CONTOSO.LOCAL$*HTTP/web01*$aa$bb",
        );
        let aes2 = roast(
            "k:aes2",
            "svc_sql",
            "$krb5tgs$18$svc_sql$CONTOSO.LOCAL$*MSSQLSvc/sql01*$cc$dd",
        );
        let mut asrep_h = mk_hash("bob", "asrep", false);
        asrep_h.hash_value = "$krb5asrep$23$bob@CONTOSO.LOCAL:aa$bb".into();
        let asrep = ("a:bob".to_string(), asrep_h);
        let ntlm = ("n:alice".to_string(), mk_hash("alice", "ntlm", false));

        let work = vec![aes1.clone(), asrep, ntlm, aes2];
        let batch = batch_same_mode_roastable(&work, &aes1.1);
        let users: Vec<&str> = batch.iter().map(|(_, h)| h.username.as_str()).collect();
        assert_eq!(
            batch.len(),
            2,
            "only the two etype-18 kerberoast tickets batch together, got {users:?}"
        );
        assert!(users.contains(&"carol") && users.contains(&"svc_sql"));
    }

    #[test]
    fn breadth_first_keeps_roastable_ahead_of_never_tried_ntlm() {
        // Priority still dominates the attempts tiebreak: a roastable hash that
        // has already been retried outranks a never-tried NTLM hash, so the
        // fairness fix doesn't let cheap PtH-usable NTLM starve roastables.
        let roast = (
            "k:roast".to_string(),
            mk_hash("svc_sql", "kerberoast", false),
        );
        let ntlm = ("n:ntlm".to_string(), mk_hash("alice", "ntlm", false));
        let mut work = vec![ntlm, roast];
        let mut attempts = HashMap::new();
        attempts.insert("k:roast".to_string(), MAX_CRACK_ATTEMPTS - 1);
        sort_crack_work(&mut work, &attempts);
        assert_eq!(work[0].1.hash_type, "kerberoast");
    }

    #[test]
    fn cheap_rc4_asrep_sorts_ahead_of_slow_aes_kerberoast() {
        // Within the roastable bucket, a fast RC4 AS-REP (mode 18200) must be
        // dispatched before a slow AES kerberoast ticket (etype 18, mode 19700).
        // The AS-REP is the likely cross-forest foothold — its plaintext is a
        // human password that cracks in seconds and unlocks a far domain —
        // whereas the AES ticket can hold the AES hashcat slot for its whole
        // budget and usually isn't in the wordlist at all. Regression guard for
        // a far-domain AS-REP foothold losing the crack-slot race to an AES
        // ticket (which cost a whole second forest).
        let mut aes = mk_hash("svc_sql", "kerberoast", false);
        aes.hash_value = "$krb5tgs$18$svc_sql$FABRIKAM.LOCAL$*MSSQLSvc/sql01*$aa$bb".into();
        let mut asrep = mk_hash("carol", "asrep", false);
        asrep.hash_value = "$krb5asrep$23$carol@FABRIKAM.LOCAL:aa$bb".into();
        // AES appears first and has no more attempts, so only the mode-cost
        // tiebreak can float the AS-REP ahead of it.
        let mut work = vec![("k:aes".to_string(), aes), ("a:carol".to_string(), asrep)];
        let attempts = HashMap::new();
        sort_crack_work(&mut work, &attempts);
        assert_eq!(
            work[0].1.hash_type, "asrep",
            "a fast RC4 AS-REP must sort ahead of a slow AES kerberoast ticket"
        );
        // And the picker chooses it (streak below the NTLM-turn threshold).
        let chosen = select_next_crack(&work, 0).unwrap();
        assert_eq!(chosen.1.username, "carol");
    }

    #[test]
    fn sort_places_roastable_first() {
        let mut v = ["ntlm", "kerberoast", "ntlm", "asrep"];
        v.sort_by_key(|t| crack_priority(t));
        // First two slots are the roastable ones in some order; last two are ntlm.
        assert!(matches!(v[0], "kerberoast" | "asrep"));
        assert!(matches!(v[1], "kerberoast" | "asrep"));
        assert_eq!(v[2], "ntlm");
        assert_eq!(v[3], "ntlm");
    }

    // Crack retry-cap logic. The dispatch path itself takes a Dispatcher
    // (network + Redis), so these tests pin the state-side invariants:
    //   - First N-1 attempts increment the counter without writing the
    //     permanent dedup, so a failed crack can retry on the next tick.
    //   - The Nth attempt writes the permanent dedup, so the hash is
    //     never re-dispatched even after the operation restarts.

    fn simulate_attempt(state: &mut StateInner, dedup_key: &str) {
        let entry = state
            .crack_attempts
            .entry(dedup_key.to_string())
            .or_insert(0);
        *entry += 1;
        if *entry >= MAX_CRACK_ATTEMPTS {
            state.mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.to_string());
        }
    }

    #[test]
    fn crack_retry_below_cap_does_not_write_dedup() {
        // A hash whose crack failed once (e.g. wordlist miss) must remain
        // eligible for retry: the dedup marker must NOT be written before
        // the attempt cap.
        let mut state = StateInner::new("op-test".into());
        let key = "child.contoso.local:svc_sql:abcdef0123456789abcdef0123456789";
        for _ in 0..(MAX_CRACK_ATTEMPTS - 1) {
            simulate_attempt(&mut state, key);
        }
        assert!(
            !state.is_processed(DEDUP_CRACK_REQUESTS, key),
            "dedup must not be written before the attempt cap"
        );
        assert_eq!(
            state.crack_attempts.get(key).copied().unwrap_or(0),
            MAX_CRACK_ATTEMPTS - 1
        );
    }

    #[test]
    fn crack_retry_at_cap_writes_dedup_permanently() {
        // Cap reached → dedup written → next ticks (and post-restart
        // ticks, once persisted) skip this hash forever.
        let mut state = StateInner::new("op-test".into());
        let key = "contoso.local:alice:00112233445566778899aabbccddeeff";
        for _ in 0..MAX_CRACK_ATTEMPTS {
            simulate_attempt(&mut state, key);
        }
        assert!(
            state.is_processed(DEDUP_CRACK_REQUESTS, key),
            "dedup must be written once attempts reach MAX_CRACK_ATTEMPTS"
        );
    }

    #[test]
    fn select_returns_none_when_empty() {
        assert!(select_next_crack(&[], 0).is_none());
        assert!(select_next_crack(&[], 100).is_none());
    }

    #[test]
    fn select_prefers_roastable_below_streak_threshold() {
        let work = vec![mk("kerberoast"), mk("ntlm")];
        let chosen = select_next_crack(&work, 0).unwrap();
        assert_eq!(chosen.1.hash_type, "kerberoast");
    }

    #[test]
    fn select_forces_ntlm_turn_at_streak_threshold() {
        let work = vec![mk("kerberoast"), mk("kerberoast"), mk("ntlm")];
        let chosen = select_next_crack(&work, NTLM_TURN_AFTER_ROASTABLE_STREAK).unwrap();
        assert_eq!(chosen.1.hash_type, "ntlm");
    }

    #[test]
    fn select_falls_back_to_roastable_when_no_ntlm_at_threshold() {
        let work = vec![mk("kerberoast"), mk("asrep")];
        let chosen = select_next_crack(&work, NTLM_TURN_AFTER_ROASTABLE_STREAK + 5).unwrap();
        assert_eq!(chosen.1.hash_type, "kerberoast");
    }

    #[test]
    fn select_picks_ntlm_when_only_ntlm_present() {
        let work = vec![mk("ntlm"), mk("ntlm")];
        let chosen = select_next_crack(&work, 0).unwrap();
        assert_eq!(chosen.1.hash_type, "ntlm");
    }

    #[test]
    fn ntlm_eventually_serviced_under_continuous_roastable_inflow() {
        // Steady roastable inflow must not starve NTLM. Walk 100 ticks
        // and verify NTLM dispatches at least once per (threshold+1).
        let work = vec![mk("kerberoast"), mk("ntlm")];
        let mut streak: u32 = 0;
        let mut ntlm_dispatches = 0u32;
        let mut roastable_dispatches = 0u32;
        for _ in 0..100 {
            let chosen = select_next_crack(&work, streak).unwrap();
            if crack_priority(&chosen.1.hash_type) == 0 {
                streak = streak.saturating_add(1);
                roastable_dispatches += 1;
            } else {
                streak = 0;
                ntlm_dispatches += 1;
            }
        }
        let expected_floor = 100 / (NTLM_TURN_AFTER_ROASTABLE_STREAK + 1);
        assert!(
            ntlm_dispatches >= expected_floor,
            "NTLM starved: {ntlm_dispatches} dispatches in 100 ticks (floor {expected_floor})"
        );
        assert!(
            roastable_dispatches > 0,
            "roastable bucket should still be served"
        );
    }

    #[test]
    fn crack_retry_independent_per_hash() {
        // Each hash gets its own attempt budget — exhausting one must not
        // dedup another. Without this, a single perma-failing hash would
        // appear to "use up" everyone else's slot from the dispatcher's
        // perspective if the state key collision is wrong.
        let mut state = StateInner::new("op-test".into());
        let stuck = "contoso.local:stuck:00000000000000000000000000000000";
        let fresh = "contoso.local:fresh:11111111111111111111111111111111";
        for _ in 0..MAX_CRACK_ATTEMPTS {
            simulate_attempt(&mut state, stuck);
        }
        assert!(state.is_processed(DEDUP_CRACK_REQUESTS, stuck));
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, fresh));
        assert_eq!(state.crack_attempts.get(fresh).copied(), None);
    }
}
