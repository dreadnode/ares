//! auto_crack_dispatch -- submit crack tasks for new hashes.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

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
    match hash_type.to_ascii_lowercase().as_str() {
        "kerberoast" | "asrep" | "asreproast" => 0,
        _ => 1,
    }
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
/// Interval: 15s. Matches Python `_auto_crack_dispatch`.
pub async fn auto_crack_dispatch(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Tracks consecutive roastable dispatches so NTLM hashes from
    // secretsdump aren't starved by a continuous roastable inflow.
    let mut roastable_streak: u32 = 0;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Collect unprocessed hashes, then sort by crack priority so the
        // single hashcat slot serves roastable hashes first. Without this,
        // a backlog of NTLM machine-account hashes from secretsdump (already
        // PtH-usable) starves the lone kerberoast/asrep hash that would
        // unlock a service-account password — exactly the failure mode that
        // left a kerberoasted sql_svc untouched for hours in op-20260510.
        let mut work: Vec<(String, ares_core::models::Hash)> = {
            let state = dispatcher.state.read().await;
            state
                .hashes
                .iter()
                .filter(|h| h.cracked_password.is_none())
                .filter_map(|h| {
                    let dedup = crack_dedup_key(h);
                    if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                        None
                    } else {
                        Some((dedup, h.clone()))
                    }
                })
                .collect()
        };
        work.sort_by_key(|(_, h)| crack_priority(&h.hash_type));

        // Serialize crack tasks: hashcat only allows one instance at a time.
        // Skip this tick if a cracker task is already running.
        if dispatcher.tracker.count_for_role("cracker").await > 0 {
            debug!("Crack task already active, skipping dispatch this tick");
            continue;
        }

        // Only dispatch one crack task per tick to avoid hashcat PID conflicts.
        // Remaining hashes will be picked up on subsequent ticks.
        let next = select_next_crack(&work, roastable_streak).cloned();
        if let Some((dedup_key, hash)) = next {
            if crack_priority(&hash.hash_type) == 0 {
                roastable_streak = roastable_streak.saturating_add(1);
            } else {
                roastable_streak = 0;
            }
            match dispatcher.request_crack(&hash).await {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, hash_type = %hash.hash_type, "Crack task dispatched");
                    // Increment the per-hash attempt counter. Cap reached
                    // → write the dedup marker (persisted) so future ticks
                    // and post-restart ticks skip this hash permanently.
                    // Before the cap, do NOT write the dedup — that lets a
                    // failed crack (cracked_password still None when the
                    // task finishes) be retried on the next tick, which is
                    // the bug this PR fixes.
                    let attempts = {
                        let mut state = dispatcher.state.write().await;
                        let entry = state.crack_attempts.entry(dedup_key.clone()).or_insert(0);
                        *entry += 1;
                        *entry
                    };
                    if attempts >= MAX_CRACK_ATTEMPTS {
                        warn!(
                            dedup_key = %dedup_key,
                            hash_type = %hash.hash_type,
                            attempts,
                            "Crack attempts exhausted; giving up on hash"
                        );
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_CRACK_REQUESTS, &dedup_key)
                            .await;
                    }
                }
                Ok(None) => {} // deferred or throttled
                Err(e) => warn!(err = %e, "Failed to dispatch crack task"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        crack_priority, select_next_crack, MAX_CRACK_ATTEMPTS, NTLM_TURN_AFTER_ROASTABLE_STREAK,
    };
    use crate::orchestrator::state::{StateInner, DEDUP_CRACK_REQUESTS};
    use ares_core::models::Hash;

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
        // eligible for retry — this was the bug. Confirm that the dedup
        // marker is NOT written before the cap.
        let mut state = StateInner::new("op-test".into());
        let key = "north.contoso.local:svc_sql:abcdef0123456789abcdef0123456789";
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
