//! auto_dacl_abuse -- direct ACL abuse for known attack paths.
//!
//! Unlike acl_chain_follow (which requires BloodHound to populate acl_chains),
//! this module proactively dispatches known ACL abuse techniques when:
//!   - A credential is available for a user known to have dangerous permissions
//!   - The target object exists in the domain
//!
//! Covers: ForceChangePassword, GenericWrite (targeted Kerberoast), WriteDacl,
//! WriteOwner, GenericAll. Each abuse type maps to a specific tool invocation
//! (e.g., net rpc password for ForceChangePassword, bloodyAD for GenericWrite).

use std::sync::Arc;
use std::time::Duration;

use ares_core::ldap::domain_to_base_dn;
use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dedup::is_ghost_machine_account;
use crate::orchestrator::acl_graph::{self, MAX_ACL_DISPATCH_PER_TICK};
use crate::orchestrator::dispatcher::{Dispatcher, SubmissionOutcome};
use crate::orchestrator::state::*;

pub(crate) fn is_destructive_acl_type(vuln_type: &str) -> bool {
    let t = vuln_type.to_lowercase();
    t.contains("forcechangepassword") || t.contains("genericall")
}

/// True when the ACL edge's target is a Group Policy Object.
///
/// `ldap_acl_enumeration` prefixes the vuln type (`gpo_writeowner`); the
/// BloodHound path keeps the bare right and marks the object class in
/// `target_type`. Either is authoritative.
pub(crate) fn is_gpo_acl_target(vuln_type: &str, target_type: &str) -> bool {
    vuln_type.to_lowercase().starts_with("gpo_") || target_type.eq_ignore_ascii_case("gpo")
}

fn brace_wrapped_guid(raw: &str) -> Option<String> {
    let inner = raw.trim().trim_start_matches('{').trim_end_matches('}');
    let mut groups = inner.split('-');
    for len in [8usize, 4, 4, 4, 12] {
        let group = groups.next()?;
        if group.len() != len || !group.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
    }
    if groups.next().is_some() {
        return None;
    }
    Some(format!("{{{inner}}}"))
}

/// Build the distinguished name of a Group Policy container.
///
/// Every GPO lives at `CN={GUID},CN=Policies,CN=System,<domain base DN>`; the
/// GUID alone resolves to nothing, and `dacledit.py` / `owneredit.py` bind by
/// DN.
pub(crate) fn gpo_container_dn(gpo_id: &str, domain: &str) -> Option<String> {
    let guid = brace_wrapped_guid(gpo_id)?;
    let base = domain_to_base_dn(domain);
    if base.is_empty() {
        return None;
    }
    Some(format!("CN={guid},CN=Policies,CN=System,{base}"))
}

/// Resolve the distinguished name the impacket ACL tools have to be given for
/// this edge's target.
///
/// Prefers the DN the discovery parser captured verbatim. Falls back, for GPO
/// targets only, to reconstructing it from the container GUID — vulnerabilities
/// replayed out of Redis from before the parsers emitted `target_dn` carry
/// `gpo_id` but no DN, and their `target` is the bare GUID, which resolves to
/// nothing.
pub(crate) fn resolve_acl_target_dn(
    details: &std::collections::HashMap<String, serde_json::Value>,
    vuln_type: &str,
    target_type: &str,
    target_name: &str,
    domain: &str,
) -> String {
    let detail_str = |key: &str| {
        details
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };

    if let Some(dn) = detail_str("target_dn").filter(|s| s.contains('=')) {
        return dn.to_string();
    }
    if !is_gpo_acl_target(vuln_type, target_type) {
        return String::new();
    }
    let gpo_id = detail_str("gpo_id")
        .or_else(|| detail_str("gpo_guid"))
        .unwrap_or(target_name);
    let dn_domain = detail_str("domain").unwrap_or(domain);
    gpo_container_dn(gpo_id, dn_domain).unwrap_or_default()
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DaclTickCensus {
    pub technique_gated: bool,
    pub no_auth_material: bool,
    pub acl_vulns: usize,
    pub already_exploited: usize,
    pub deduped: usize,
    pub ghost_target: usize,
    pub no_source_principal: usize,
    pub unresolvable_principal: usize,
    pub privileged_group_no_member: usize,
    pub group_no_owned_member: usize,
    pub group_unmapped: usize,
    pub non_principal_source: usize,
    pub domain_dominated: usize,
    pub capture_in_flight: usize,
    pub target_material_held: usize,
    pub no_target_dn: usize,
    pub over_tick_cap: usize,
    pub eligible: usize,
}

impl DaclTickCensus {
    pub(crate) fn gated() -> Self {
        Self {
            technique_gated: true,
            ..Self::default()
        }
    }

    /// Book an unresolved edge source against the reason it failed.
    ///
    /// One `unresolvable_principal` count cannot be acted on: a group ares
    /// never enumerated, a privileged group it owns no member of, and an ACE
    /// trustee that is not a principal at all want three different responses,
    /// and the first census to report this loss put 197 of 200 edges in the
    /// single bucket.
    pub(crate) fn record_unresolved(&mut self, reason: acl_graph::UnresolvedSource, source: &str) {
        match reason {
            acl_graph::UnresolvedSource::GroupNoOwnedMember => self.group_no_owned_member += 1,
            acl_graph::UnresolvedSource::GroupUnmapped => self.group_unmapped += 1,
            acl_graph::UnresolvedSource::NonPrincipal => self.non_principal_source += 1,
            acl_graph::UnresolvedSource::NoMaterial => {
                if names_well_known_privileged_group(source) {
                    self.privileged_group_no_member += 1;
                } else {
                    self.unresolvable_principal += 1;
                }
            }
        }
    }

    pub(crate) fn emit(&self) {
        info!(
            technique_gated = self.technique_gated,
            no_auth_material = self.no_auth_material,
            acl_vulns = self.acl_vulns,
            already_exploited = self.already_exploited,
            deduped = self.deduped,
            ghost_target = self.ghost_target,
            no_source_principal = self.no_source_principal,
            unresolvable_principal = self.unresolvable_principal,
            privileged_group_no_member = self.privileged_group_no_member,
            group_no_owned_member = self.group_no_owned_member,
            group_unmapped = self.group_unmapped,
            non_principal_source = self.non_principal_source,
            domain_dominated = self.domain_dominated,
            capture_in_flight = self.capture_in_flight,
            target_material_held = self.target_material_held,
            no_target_dn = self.no_target_dn,
            over_tick_cap = self.over_tick_cap,
            eligible = self.eligible,
            "DACL abuse tick census"
        );
    }
}

pub(crate) fn holds_target_material(state: &StateInner, target_user: &str, domain: &str) -> bool {
    let target = target_user.to_lowercase();
    let domain = domain.to_lowercase();
    state.credentials.iter().any(|c| {
        !c.password.is_empty()
            && c.username.to_lowercase() == target
            && c.domain.to_lowercase() == domain
    }) || state
        .hashes
        .iter()
        .any(|h| h.username.to_lowercase() == target && h.domain.to_lowercase() == domain)
}

/// Dispatches ACL abuse when matching credentials + bloodhound paths exist.
/// Interval: 30s.
pub async fn auto_dacl_abuse(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_census: Option<DaclTickCensus> = None;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("acl_abuse") {
            let census = DaclTickCensus::gated();
            if last_census.as_ref() != Some(&census) {
                census.emit();
                last_census = Some(census);
            }
            continue;
        }

        let mut census = DaclTickCensus::default();
        let work: Vec<DaclWork> = {
            let state = dispatcher.state.read().await;
            collect_dacl_work_census(&state, &mut census)
        };
        if last_census.as_ref() != Some(&census) {
            census.emit();
            last_census = Some(census);
        }

        for item in work {
            let payload = build_dacl_payload(&item);

            let priority = dispatcher.effective_priority("acl_abuse");
            // Mark dedup on Submitted OR Deferred to prevent the 30s tick from
            // re-emitting identical work each cycle and bloating the deferred
            // ZSET past its per-type cap (which silently drops entries). Only
            // skip dedup on Dropped — those need to be reconsidered next tick.
            let mark_dedup = match dispatcher
                .throttled_submit_outcome("acl_chain_step", "acl", payload, priority)
                .await
            {
                Ok(SubmissionOutcome::Submitted(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        acl_type = %item.vuln_type,
                        source = %item.source_user,
                        target = %item.target_user,
                        "DACL abuse dispatched"
                    );
                    true
                }
                Ok(SubmissionOutcome::Deferred) => {
                    debug!(vuln_id = %item.vuln_id, "DACL abuse deferred (will retry via deferred drain)");
                    true
                }
                Ok(SubmissionOutcome::Dropped) => {
                    debug!(vuln_id = %item.vuln_id, "DACL abuse dropped (will reconsider next tick)");
                    false
                }
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch DACL abuse");
                    false
                }
            };
            if mark_dedup {
                {
                    let mut state = dispatcher.state.write().await;
                    state.mark_processed(DEDUP_DACL_ABUSE, item.dedup_key.clone());
                }
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_DACL_ABUSE, &item.dedup_key)
                    .await;
            }
        }
    }
}

/// Build the JSON payload for a DACL-abuse dispatch. Pure construction.
///
/// Used by `auto_dacl_abuse` and exposed `pub(crate)` so the payload shape
/// can be unit-tested without standing up a Dispatcher.
pub(crate) fn build_dacl_payload(item: &DaclWork) -> serde_json::Value {
    let mut payload = json!({
        "technique": "dacl_abuse",
        "acl_type": item.vuln_type,
        "vuln_id": item.vuln_id,
        "source_user": item.source_user,
        "target_user": item.target_user,
        "target_ip": item.dc_ip,
        "domain": item.domain,
    });
    if !item.target_dn.is_empty() {
        payload["target_dn"] = json!(item.target_dn);
    }
    if !item.target_type.is_empty() {
        payload["target_type"] = json!(item.target_type);
    }
    if let Some(ref group) = item.via_group {
        payload["via_group"] = json!(group);
    }
    if let Some(ref cred) = item.credential {
        payload["username"] = json!(cred.username);
        payload["password"] = json!(cred.password);
        payload["credential"] = json!({
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        });
    } else if let Some(ref hash) = item.hash {
        payload["username"] = json!(hash.username);
        payload["hash"] = json!(hash.hash_value);
    }
    payload
}

/// Collect DACL abuse work items from state without holding async locks.
///
/// Extracted for testability: scans `discovered_vulnerabilities` for ACL-type
/// vulns that have a matching credential and haven't been processed yet.
///
/// The result is ordered by the ACL graph's hop distance to a high-value
/// terminal and truncated to [`MAX_ACL_DISPATCH_PER_TICK`]. Edges that reach
/// nothing privileged sort last but are not dropped — they surface once the
/// privileged ones have been dispatched and dedup'd. Both ACL drivers share
/// one 50-slot `acl_chain_step` deferred bucket, so an unbounded 310-path
/// enumeration would otherwise starve every other technique.
#[cfg(test)]
pub(crate) fn collect_dacl_work(state: &StateInner) -> Vec<DaclWork> {
    collect_dacl_work_census(state, &mut DaclTickCensus::default())
}

pub(crate) fn collect_dacl_work_census(
    state: &StateInner,
    census: &mut DaclTickCensus,
) -> Vec<DaclWork> {
    if state.credentials.is_empty() && state.hashes.is_empty() {
        census.no_auth_material = true;
        return Vec::new();
    }

    let mut items = Vec::new();

    // Check discovered_vulnerabilities for ACL-related vulns
    // (populated by BloodHound analysis or recon agents)
    for vuln in state.discovered_vulnerabilities.values() {
        let vtype = vuln.vuln_type.to_lowercase();

        if !acl_graph::is_acl_vuln_type(&vtype) {
            continue;
        }
        census.acl_vulns += 1;

        if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
            census.already_exploited += 1;
            continue;
        }

        let dedup_key = format!("dacl:{}", vuln.vuln_id);
        if state.is_processed(DEDUP_DACL_ABUSE, &dedup_key) {
            census.deduped += 1;
            continue;
        }

        let target_name = vuln
            .details
            .get("target")
            .or_else(|| vuln.details.get("target_user"))
            .or_else(|| vuln.details.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_ghost_machine_account(target_name) {
            census.ghost_target += 1;
            debug!(
                vuln_id = %vuln.vuln_id,
                target = %target_name,
                "Skipping ACL abuse for ghost machine account target"
            );
            continue;
        }

        // Extract source user from vuln details
        let source_user = vuln
            .details
            .get("source")
            .or_else(|| vuln.details.get("source_user"))
            .or_else(|| vuln.details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let source_domain = vuln
            .details
            .get("source_domain")
            .or_else(|| vuln.details.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if source_user.is_empty() {
            census.no_source_principal += 1;
            continue;
        }

        // Find matching credential.
        //
        // BloodHound often emits ACL edges with SID principals (e.g. for
        // well-known groups like Enterprise Admins). When `source` is a SID,
        // resolve to any privileged credential in the source's domain so the
        // ACL chain can still be exercised.
        let cred = state
            .credentials
            .iter()
            .find(|c| {
                c.username.to_lowercase() == source_user.to_lowercase()
                    && (source_domain.is_empty()
                        || c.domain.to_lowercase() == source_domain.to_lowercase())
            })
            .cloned()
            .or_else(|| resolve_sid_principal(state, source_user, source_domain));

        let hash = if cred.is_none() {
            state.find_source_hash(source_user, source_domain)
        } else {
            None
        };

        let (cred, hash) = if cred.is_none() && hash.is_none() {
            match acl_graph::resolve_group_source(state, source_user, source_domain) {
                Ok(acl_graph::SourceMaterial::Credential(c)) => (Some(c), None),
                Ok(acl_graph::SourceMaterial::Hash(h)) => (None, Some(h)),
                Err(reason) => {
                    census.record_unresolved(reason, source_user);
                    debug!(
                        vuln_id = %vuln.vuln_id,
                        source = %source_user,
                        reason = ?reason,
                        "DACL abuse skipped: no owned principal for the edge source"
                    );
                    continue;
                }
            }
        } else {
            (cred, hash)
        };

        let Some((auth_username, auth_domain)) = cred
            .as_ref()
            .map(|c| (c.username.clone(), c.domain.clone()))
            .or_else(|| {
                hash.as_ref()
                    .map(|h| (h.username.clone(), h.domain.clone()))
            })
        else {
            census.unresolvable_principal += 1;
            continue;
        };

        let target_user = vuln
            .details
            .get("target")
            .or_else(|| vuln.details.get("target_user"))
            .or_else(|| vuln.details.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let dispatch_domain = auth_domain.to_lowercase();

        if state.dominated_domains.contains(&dispatch_domain) {
            census.domain_dominated += 1;
            debug!(vuln_id = %vuln.vuln_id, domain = %auth_domain, "DACL abuse skipped: domain dominated");
            continue;
        }

        // Defer (don't mark dedup) so the next tick re-evaluates once
        // DCSync either finishes (domain becomes dominated above) or its
        // in-flight TTL expires and the chain runs as fallback.
        if state.credential_capture_in_flight_for(&dispatch_domain) {
            census.capture_in_flight += 1;
            debug!(vuln_id = %vuln.vuln_id, domain = %auth_domain, "DACL abuse deferred: credential capture in flight");
            continue;
        }

        // ForceChangePassword / GenericAll overwrite the target's
        // plaintext via `bloodyad_set_password`. Skip when we already
        // have material so the scoreboard's back-verification against
        // the original lab-provisioned password still holds.
        if is_destructive_acl_type(&vtype)
            && !target_user.is_empty()
            && holds_target_material(state, &target_user, &dispatch_domain)
        {
            census.target_material_held += 1;
            debug!(vuln_id = %vuln.vuln_id, target = %target_user, "Destructive ACL skipped: target material already in state");
            continue;
        }

        let dc_ip = state
            .domain_controllers
            .get(&dispatch_domain)
            .cloned()
            .unwrap_or_default();

        // When BloodHound emitted the source as a raw SID and we resolved
        // it via `resolve_sid_principal`, surface the resolved credential's
        // SAM account name as `source_user` — not the SID. Tool schemas
        // require a username for credential injection by `(user, domain)`,
        // and the LLM otherwise echoes the SID as the auth principal.
        let resolved_from_trustee = !auth_username.eq_ignore_ascii_case(source_user);
        let dispatched_source_user = if resolved_from_trustee {
            auth_username
        } else {
            source_user.to_string()
        };

        let target_type = vuln
            .details
            .get("target_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target_dn = resolve_acl_target_dn(
            &vuln.details,
            &vtype,
            &target_type,
            &target_user,
            &auth_domain,
        );

        if target_dn.is_empty() && is_gpo_acl_target(&vtype, &target_type) {
            census.no_target_dn += 1;
            debug!(
                vuln_id = %vuln.vuln_id,
                target = %target_user,
                "GPO ACL edge skipped: no distinguished name — the container GUID alone \
                 resolves to nothing and every impacket ACL tool binds by DN"
            );
            continue;
        }

        items.push(DaclWork {
            dedup_key,
            vuln_id: vuln.vuln_id.clone(),
            vuln_type: vtype,
            source_user: dispatched_source_user,
            via_group: resolved_from_trustee.then(|| source_user.to_string()),
            target_user,
            target_type,
            target_dn,
            domain: auth_domain,
            dc_ip,
            credential: cred,
            hash,
        });
    }

    let analysis = acl_graph::analyze(state);
    items.sort_by(|a, b| {
        analysis
            .rank_of(&a.vuln_id)
            .cmp(&analysis.rank_of(&b.vuln_id))
            .then_with(|| a.vuln_id.cmp(&b.vuln_id))
    });
    census.over_tick_cap = items.len().saturating_sub(MAX_ACL_DISPATCH_PER_TICK);
    let items = acl_graph::take_diverse_by(items, MAX_ACL_DISPATCH_PER_TICK, |w: &DaclWork| {
        (w.source_user.to_lowercase(), w.domain.to_lowercase())
    });
    census.eligible = items.len();
    items
}

pub(crate) struct DaclWork {
    pub dedup_key: String,
    pub vuln_id: String,
    pub vuln_type: String,
    pub source_user: String,
    /// The ACE trustee, when `source_user` is a member ares resolved it to.
    pub via_group: Option<String>,
    pub target_user: String,
    pub target_type: String,
    pub target_dn: String,
    pub domain: String,
    pub dc_ip: String,
    pub credential: Option<ares_core::models::Credential>,
    pub hash: Option<ares_core::models::Hash>,
}

/// Group name for the well-known privileged RIDs whose membership a SID-typed
/// ACL source may be resolved through. Resolving such a source to a credential
/// is only correct when that credential belongs to *a* member of the group —
/// the RID names which group membership has to be established against.
/// True when `source` is a domain SID whose RID names one of those groups.
///
/// Separates "we own no member of Enterprise Admins" from "we hold no material
/// for this principal" in the tick census — the first is a forest-root
/// membership problem, the second is a looting one.
fn names_well_known_privileged_group(source: &str) -> bool {
    if !source.starts_with("S-1-5-21-") {
        return false;
    }
    source
        .rsplit_once('-')
        .and_then(|(_, rid)| rid.parse::<u32>().ok())
        .and_then(well_known_privileged_group)
        .is_some()
}

fn well_known_privileged_group(rid: u32) -> Option<&'static str> {
    match rid {
        512 => Some("Domain Admins"),
        518 => Some("Schema Admins"),
        519 => Some("Enterprise Admins"),
        520 => Some("Group Policy Creator Owners"),
        526 => Some("Key Admins"),
        527 => Some("Enterprise Key Admins"),
        _ => None,
    }
}

/// When the ACL edge source is a SID (typically a well-known group), resolve
/// it to a credential of an actual member.
///
/// Strategy:
///   1. Parse `S-1-5-21-X-Y-Z-RID` and extract the domain SID prefix and RID.
///   2. Reverse-look up the domain via `state.domain_sids` (or fall back to
///      `source_domain` from the vuln details).
///   3. For privileged well-known RIDs, return an `is_admin` credential in that
///      domain, else a credential whose principal LDAP `memberOf` places in the
///      group the RID names.
///
/// Returns `None` when neither holds. There is deliberately no "any credential
/// in the domain" fallback: an ACL edge granted to Enterprise Admins cannot be
/// exercised as a non-member, and dispatching one anyway spends a queue slot, an
/// LLM turn, and a dedup entry that then suppresses the edge from being retried
/// once a real member *is* owned.
fn resolve_sid_principal(
    state: &StateInner,
    source: &str,
    source_domain: &str,
) -> Option<ares_core::models::Credential> {
    if !source.starts_with("S-1-5-21-") {
        return None;
    }
    let (prefix, rid_str) = source.rsplit_once('-')?;
    let rid: u32 = rid_str.parse().ok()?;

    let resolved_domain = state
        .domain_sids
        .iter()
        .find(|(_, sid)| sid.eq_ignore_ascii_case(prefix))
        .map(|(d, _)| d.to_lowercase())
        .or_else(|| {
            if source_domain.is_empty() {
                None
            } else {
                Some(source_domain.to_lowercase())
            }
        })?;

    let group = well_known_privileged_group(rid)?;

    let admin = state
        .credentials
        .iter()
        .find(|c| c.is_admin && c.domain.to_lowercase() == resolved_domain)
        .cloned();
    if admin.is_some() {
        return admin;
    }

    let members = acl_graph::members_from_ldap(state, group);
    state
        .credentials
        .iter()
        .find(|c| {
            c.domain.to_lowercase() == resolved_domain
                && members.contains(&c.username.to_lowercase())
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTOSO_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    fn cred(username: &str, is_admin: bool) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{username}"),
            username: username.into(),
            password: "P@ssw0rd!".into(),
            domain: "contoso.local".into(),
            source: "test".into(),
            discovered_at: None,
            is_admin,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn user_in(username: &str, groups: &[&str]) -> ares_core::models::User {
        ares_core::models::User {
            username: username.into(),
            domain: "contoso.local".into(),
            description: String::new(),
            is_admin: false,
            source: "ldap".into(),
            member_of: groups.iter().map(|g| (*g).to_string()).collect(),
        }
    }

    fn sid_state() -> StateInner {
        let mut state = StateInner::new("op-1".into());
        state
            .domain_sids
            .insert("contoso.local".into(), CONTOSO_SID.into());
        state
    }

    #[test]
    fn sid_source_resolves_to_an_admin_credential() {
        let mut state = sid_state();
        state.credentials.push(cred("alice", false));
        state.credentials.push(cred("admin", true));

        let resolved =
            resolve_sid_principal(&state, &format!("{CONTOSO_SID}-519"), "contoso.local");
        assert_eq!(resolved.map(|c| c.username), Some("admin".to_string()));
    }

    #[test]
    fn sid_source_never_resolves_to_a_non_member() {
        let mut state = sid_state();
        state.credentials.push(cred("alice", false));

        assert!(
            resolve_sid_principal(&state, &format!("{CONTOSO_SID}-519"), "contoso.local").is_none(),
            "an Enterprise Admins edge must not dispatch as an ordinary user"
        );
    }

    #[test]
    fn sid_source_resolves_through_ldap_membership_without_an_admin_flag() {
        let mut state = sid_state();
        state.credentials.push(cred("alice", false));
        state.credentials.push(cred("bob", false));
        state.users.push(user_in("alice", &["Domain Users"]));
        state.users.push(user_in(
            "bob",
            &["CN=Enterprise Admins,CN=Users,DC=contoso,DC=local"],
        ));

        let resolved =
            resolve_sid_principal(&state, &format!("{CONTOSO_SID}-519"), "contoso.local");
        assert_eq!(resolved.map(|c| c.username), Some("bob".to_string()));
    }

    #[test]
    fn sid_source_membership_is_matched_against_the_rids_own_group() {
        let mut state = sid_state();
        state.credentials.push(cred("bob", false));
        state.users.push(user_in(
            "bob",
            &["CN=Enterprise Admins,CN=Users,DC=contoso,DC=local"],
        ));

        assert!(
            resolve_sid_principal(&state, &format!("{CONTOSO_SID}-526"), "contoso.local").is_none(),
            "membership in Enterprise Admins must not satisfy a Key Admins edge"
        );
    }

    #[test]
    fn sid_source_with_an_unprivileged_rid_is_not_resolved() {
        let mut state = sid_state();
        state.credentials.push(cred("admin", true));

        assert!(
            resolve_sid_principal(&state, &format!("{CONTOSO_SID}-1105"), "contoso.local")
                .is_none()
        );
    }

    #[test]
    fn sid_source_membership_does_not_cross_domains() {
        let mut state = sid_state();
        let mut bob = cred("bob", false);
        bob.domain = "fabrikam.local".into();
        state.credentials.push(bob);
        let mut bob_user = user_in(
            "bob",
            &["CN=Enterprise Admins,CN=Users,DC=contoso,DC=local"],
        );
        bob_user.domain = "fabrikam.local".into();
        state.users.push(bob_user);

        assert!(
            resolve_sid_principal(&state, &format!("{CONTOSO_SID}-519"), "contoso.local").is_none(),
            "a fabrikam.local credential cannot exercise a contoso.local group edge"
        );
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("dacl:{}", "vuln-acl-001");
        assert_eq!(key, "dacl:vuln-acl-001");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_DACL_ABUSE, "dacl_abuse");
    }

    #[test]
    fn acl_vuln_type_matching() {
        let positives = [
            "ForceChangePassword",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "GenericAll",
            "self_membership",
            "write_membership",
            "WriteProperty",
            "AllExtendedRights",
            "AddMember",
            "AddSelf",
            "SomePrefix_forcechangepassword_suffix",
        ];
        for t in &positives {
            let vtype = t.to_lowercase();
            let is_acl_vuln = vtype.contains("forcechangepassword")
                || vtype.contains("genericwrite")
                || vtype.contains("writedacl")
                || vtype.contains("writeowner")
                || vtype.contains("genericall")
                || vtype.contains("self_membership")
                || vtype.contains("write_membership")
                || vtype.contains("writeproperty")
                || vtype.contains("allextendedrights")
                || vtype.contains("addmember")
                || vtype.contains("addself");
            assert!(is_acl_vuln, "{t} should match as ACL vuln");
        }
    }

    #[test]
    fn non_acl_vuln_types_rejected() {
        let negatives = [
            "smb_signing_disabled",
            "mssql_access",
            "zerologon",
            "esc1",
            "kerberoast",
        ];
        for t in &negatives {
            let vtype = t.to_lowercase();
            let is_acl_vuln = vtype.contains("forcechangepassword")
                || vtype.contains("genericwrite")
                || vtype.contains("writedacl")
                || vtype.contains("writeowner")
                || vtype.contains("genericall")
                || vtype.contains("self_membership")
                || vtype.contains("write_membership");
            assert!(!is_acl_vuln, "{t} should NOT match as ACL vuln");
        }
    }

    #[test]
    fn source_user_extraction_keys() {
        // Verify the fallback chain for source user extraction
        let details = serde_json::json!({
            "source": "admin",
            "source_user": "admin2",
            "from": "admin3",
        });
        let source = details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source, "admin");

        // Fallback to source_user
        let details2 = serde_json::json!({
            "source_user": "admin2",
        });
        let source2 = details2
            .get("source")
            .or_else(|| details2.get("source_user"))
            .or_else(|| details2.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source2, "admin2");

        // No source returns empty
        let details3 = serde_json::json!({});
        let source3 = details3
            .get("source")
            .or_else(|| details3.get("source_user"))
            .or_else(|| details3.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source3, "");
    }

    #[test]
    fn source_domain_extraction_keys() {
        let details = serde_json::json!({"source_domain": "contoso.local"});
        let source_domain = details
            .get("source_domain")
            .or_else(|| details.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain, "contoso.local");

        let details2 = serde_json::json!({"domain": "fabrikam.local"});
        let source_domain2 = details2
            .get("source_domain")
            .or_else(|| details2.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain2, "fabrikam.local");

        let details3 = serde_json::json!({});
        let source_domain3 = details3
            .get("source_domain")
            .or_else(|| details3.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain3, "");
    }

    #[test]
    fn target_user_extraction_keys() {
        let details = serde_json::json!({"target": "victim", "target_user": "v2", "to": "v3"});
        let target = details
            .get("target")
            .or_else(|| details.get("target_user"))
            .or_else(|| details.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target, "victim");

        let details2 = serde_json::json!({"target_user": "v2"});
        let target2 = details2
            .get("target")
            .or_else(|| details2.get("target_user"))
            .or_else(|| details2.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target2, "v2");

        let details3 = serde_json::json!({"to": "v3"});
        let target3 = details3
            .get("target")
            .or_else(|| details3.get("target_user"))
            .or_else(|| details3.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target3, "v3");
    }

    #[test]
    fn ghost_machine_targets_rejected() {
        assert!(is_ghost_machine_account("WIN-DPPJMLU3XS6$"));
    }

    #[test]
    fn credential_matching_with_domain() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "Admin";
        let cred_domain = "CONTOSO.LOCAL";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(matches);
    }

    #[test]
    fn credential_matching_without_domain() {
        let source_user = "admin";
        let source_domain = "";
        let cred_username = "admin";
        let cred_domain = "contoso.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(matches);
    }

    #[test]
    fn credential_matching_wrong_user() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "jdoe";
        let cred_domain = "contoso.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(!matches);
    }

    #[test]
    fn credential_matching_wrong_domain() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "admin";
        let cred_domain = "fabrikam.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(!matches);
    }

    #[test]
    fn dacl_payload_structure() {
        let payload = serde_json::json!({
            "technique": "dacl_abuse",
            "acl_type": "forcechangepassword",
            "vuln_id": "vuln-acl-001",
            "source_user": "admin",
            "target_user": "victim",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "dacl_abuse");
        assert_eq!(payload["acl_type"], "forcechangepassword");
        assert_eq!(payload["source_user"], "admin");
        assert_eq!(payload["target_user"], "victim");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn acl_vuln_type_case_insensitive() {
        for t in [
            "ForceChangePassword",
            "FORCECHANGEPASSWORD",
            "forcechangepassword",
        ] {
            let vtype = t.to_lowercase();
            assert!(vtype.contains("forcechangepassword"), "{t} should match");
        }
    }

    #[test]
    fn source_user_from_key() {
        let details = serde_json::json!({"from": "svc_account"});
        let source = details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source, "svc_account");
    }

    use crate::orchestrator::state::SharedState;
    use ares_core::models::{Credential, VulnerabilityInfo};
    use std::collections::HashMap;

    fn make_credential(username: &str, domain: &str) -> Credential {
        Credential {
            id: format!("cred-{username}"),
            username: username.to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_vuln(
        vuln_id: &str,
        vuln_type: &str,
        details: HashMap<String, serde_json::Value>,
    ) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "bloodhound".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn acl_details(source: &str, target: &str, domain: &str) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert("source".to_string(), serde_json::json!(source));
        m.insert("target".to_string(), serde_json::json!(target));
        m.insert("source_domain".to_string(), serde_json::json!(domain));
        m
    }

    #[tokio::test]
    async fn collect_empty_state_no_work() {
        let shared = SharedState::new("test".into());
        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_credentials_no_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }
        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_forcechangepassword_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "forcechangepassword");
        assert_eq!(work[0].source_user, "admin");
        assert_eq!(work[0].target_user, "victim");
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[tokio::test]
    async fn census_reports_no_auth_material_when_state_is_bare() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }
        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        let work = collect_dacl_work_census(&state, &mut census);

        assert!(work.is_empty());
        assert!(census.no_auth_material);
        assert_eq!(census.acl_vulns, 0);
        assert_ne!(census, DaclTickCensus::default());
    }

    #[tokio::test]
    async fn census_attributes_a_dominated_domain_decline() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state.dominated_domains.insert("contoso.local".into());
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-dom-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        let work = collect_dacl_work_census(&state, &mut census);

        assert!(work.is_empty());
        assert_eq!(census.acl_vulns, 1);
        assert_eq!(census.domain_dominated, 1);
        assert_eq!(census.eligible, 0);
        assert!(!census.no_auth_material);
    }

    #[tokio::test]
    async fn census_attributes_an_unresolvable_principal_decline() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            let details = acl_details("bob", "victim", "contoso.local");
            let vuln = make_vuln("vuln-nop-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        let work = collect_dacl_work_census(&state, &mut census);

        assert!(work.is_empty());
        assert_eq!(census.acl_vulns, 1);
        assert_eq!(census.unresolvable_principal, 1);
        assert_eq!(census.domain_dominated, 0);
    }

    fn ldap_user(username: &str, domain: &str, groups: &[&str]) -> ares_core::models::User {
        ares_core::models::User {
            username: username.into(),
            domain: domain.into(),
            description: String::new(),
            is_admin: false,
            source: "ldap_enumeration".into(),
            member_of: groups.iter().map(|g| (*g).to_string()).collect(),
        }
    }

    async fn group_sourced_state(source: &str) -> SharedState {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let details = acl_details(source, "web01", "contoso.local");
            let vuln = make_vuln("vuln-gw-group-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }
        shared
    }

    #[tokio::test]
    async fn group_sourced_edge_dispatches_as_an_owned_member() {
        let shared = group_sourced_state("Cert Publishers").await;
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            state
                .users
                .push(ldap_user("alice", "contoso.local", &["Cert Publishers"]));
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        let work = collect_dacl_work_census(&state, &mut census);

        assert_eq!(work.len(), 1, "a group trustee is no longer discarded");
        assert_eq!(work[0].source_user, "alice");
        assert_eq!(work[0].via_group.as_deref(), Some("Cert Publishers"));
        assert_eq!(census.group_no_owned_member, 0);
        assert_eq!(census.unresolvable_principal, 0);

        let payload = build_dacl_payload(&work[0]);
        assert_eq!(payload["source_user"], "alice");
        assert_eq!(payload["via_group"], "Cert Publishers");
    }

    #[tokio::test]
    async fn group_sourced_edge_is_refused_when_no_member_is_owned() {
        let shared = group_sourced_state("Cert Publishers").await;
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("carol", "contoso.local"));
            state
                .users
                .push(ldap_user("alice", "contoso.local", &["Cert Publishers"]));
            state
                .users
                .push(ldap_user("carol", "contoso.local", &["Domain Users"]));
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        let work = collect_dacl_work_census(&state, &mut census);

        assert!(
            work.is_empty(),
            "a non-member must not be handed the group's right"
        );
        assert_eq!(census.group_no_owned_member, 1);
        assert_eq!(census.unresolvable_principal, 0);
        assert_eq!(census.group_unmapped, 0);
    }

    #[tokio::test]
    async fn census_separates_an_unmapped_group_from_an_unowned_one() {
        let shared = group_sourced_state("Terminal Server License Servers").await;
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("carol", "contoso.local"));
            state
                .users
                .push(ldap_user("carol", "contoso.local", &["Domain Users"]));
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        assert!(collect_dacl_work_census(&state, &mut census).is_empty());
        assert_eq!(census.group_unmapped, 1);
        assert_eq!(census.group_no_owned_member, 0);
        assert_eq!(census.unresolvable_principal, 0);
    }

    #[tokio::test]
    async fn census_separates_a_privileged_rid_with_no_owned_member() {
        let shared = group_sourced_state(&format!("{CONTOSO_SID}-519")).await;
        {
            let mut state = shared.write().await;
            state
                .domain_sids
                .insert("contoso.local".into(), CONTOSO_SID.into());
            state
                .credentials
                .push(make_credential("carol", "contoso.local"));
            state
                .users
                .push(ldap_user("carol", "contoso.local", &["Domain Users"]));
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        assert!(collect_dacl_work_census(&state, &mut census).is_empty());
        assert_eq!(census.privileged_group_no_member, 1);
        assert_eq!(census.unresolvable_principal, 0);
        assert_eq!(census.group_unmapped, 0);
    }

    #[tokio::test]
    async fn census_counts_a_non_principal_trustee() {
        let shared = group_sourced_state("S-1-3-0").await;
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("carol", "contoso.local"));
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        assert!(collect_dacl_work_census(&state, &mut census).is_empty());
        assert_eq!(census.non_principal_source, 1);
        assert_eq!(census.unresolvable_principal, 0);
    }

    #[tokio::test]
    async fn group_sourced_edge_dispatches_a_hash_only_member() {
        let shared = group_sourced_state("Cert Publishers").await;
        {
            let mut state = shared.write().await;
            state
                .users
                .push(ldap_user("bob", "contoso.local", &["Cert Publishers"]));
            state.hashes.push(ares_core::models::Hash {
                id: "h-bob".into(),
                username: "bob".into(),
                hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
                    .into(),
                hash_type: "ntlm".into(),
                domain: "contoso.local".into(),
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
            });
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].source_user, "bob");
        assert!(work[0].credential.is_none());
        assert!(work[0].hash.is_some());
    }

    #[tokio::test]
    async fn census_counts_an_eligible_edge() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-ok-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        let work = collect_dacl_work_census(&state, &mut census);

        assert_eq!(work.len(), 1);
        assert_eq!(census.acl_vulns, 1);
        assert_eq!(census.eligible, 1);
        assert_eq!(census.over_tick_cap, 0);
    }

    #[test]
    fn gated_census_is_distinguishable_from_a_silent_tick() {
        assert_ne!(DaclTickCensus::gated(), DaclTickCensus::default());
        assert!(DaclTickCensus::gated().technique_gated);
    }

    #[tokio::test]
    async fn collect_genericwrite_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("svc_sql", "contoso.local"));
            let details = acl_details("svc_sql", "targetuser", "contoso.local");
            let vuln = make_vuln("vuln-gw-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "genericwrite");
    }

    #[tokio::test]
    async fn collect_writedacl_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("operator", "contoso.local"));
            let details = acl_details("operator", "targetobj", "contoso.local");
            let vuln = make_vuln("vuln-wd-001", "WriteDacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "writedacl");
    }

    #[tokio::test]
    async fn collect_writeowner_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("operator", "contoso.local"));
            let details = acl_details("operator", "targetobj", "contoso.local");
            let vuln = make_vuln("vuln-wo-001", "WriteOwner", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "writeowner");
    }

    #[tokio::test]
    async fn collect_genericall_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-ga-001", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "genericall");
    }

    #[tokio::test]
    async fn collect_self_membership_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("user1", "contoso.local"));
            let details = acl_details("user1", "Domain Admins", "contoso.local");
            let vuln = make_vuln("vuln-sm-001", "self_membership", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "self_membership");
    }

    #[tokio::test]
    async fn collect_sid_source_resolves_via_domain_admin() {
        // BloodHound emits ACL edges where the source is a SID for a
        // well-known group (e.g. Enterprise Admins ending in -519). The
        // resolver should pick any DA-marked credential in the same domain.
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let mut da = make_credential("admin", "contoso.local");
            da.is_admin = true;
            state.credentials.push(da);
            state.domain_sids.insert(
                "contoso.local".to_string(),
                "S-1-5-21-111-222-333".to_string(),
            );
            let details = acl_details("S-1-5-21-111-222-333-519", "victim", "contoso.local");
            let vuln = make_vuln("vuln-sid-001", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.as_ref().unwrap().username, "admin");
        assert_eq!(work[0].vuln_type, "genericall");
        // source_user must be the resolved cred's SAM, not the raw SID — the
        // credential_resolver looks up password by `(username, domain)`, and
        // a SID never matches a credential record.
        assert_eq!(work[0].source_user, "admin");
    }

    #[tokio::test]
    async fn collect_dispatches_source_holding_only_an_ntlm_hash() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state.hashes.push(make_hash("bob", "contoso.local"));
            let details = acl_details("bob", "carol", "contoso.local");
            let vuln = make_vuln("vuln-hash-001", "WriteDacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);

        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "writedacl");
        assert_eq!(work[0].source_user, "bob");
        assert_eq!(work[0].domain, "contoso.local");
        assert!(work[0].credential.is_none());
        assert_eq!(work[0].hash.as_ref().unwrap().username, "bob");
    }

    #[tokio::test]
    async fn collect_prefers_credential_over_hash_for_same_principal() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("bob", "contoso.local"));
            state.hashes.push(make_hash("bob", "contoso.local"));
            let details = acl_details("bob", "carol", "contoso.local");
            let vuln = make_vuln("vuln-both-001", "WriteDacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);

        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.as_ref().unwrap().username, "bob");
        assert!(work[0].hash.is_none());
    }

    #[tokio::test]
    async fn collect_sid_source_non_privileged_rid_skipped() {
        // Only well-known privileged RIDs are auto-resolved; an arbitrary
        // user SID (RID >= 1000) requires an exact match.
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let mut da = make_credential("admin", "contoso.local");
            da.is_admin = true;
            state.credentials.push(da);
            state.domain_sids.insert(
                "contoso.local".to_string(),
                "S-1-5-21-111-222-333".to_string(),
            );
            let details = acl_details("S-1-5-21-111-222-333-1105", "victim", "contoso.local");
            let vuln = make_vuln("vuln-sid-002", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_write_membership_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("user1", "contoso.local"));
            let details = acl_details("user1", "Domain Admins", "contoso.local");
            let vuln = make_vuln("vuln-wm-001", "write_membership", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "write_membership");
    }

    #[tokio::test]
    async fn collect_non_acl_vuln_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "dc01", "contoso.local");
            let vuln = make_vuln("vuln-smb-001", "smb_signing_disabled", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_already_exploited_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-002", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state
                .exploited_vulnerabilities
                .insert("vuln-fcp-002".to_string());
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_already_processed_dedup_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-003", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state.mark_processed(DEDUP_DACL_ABUSE, "dacl:vuln-fcp-003".to_string());
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_source_user_empty_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let mut details = HashMap::new();
            details.insert("target".to_string(), serde_json::json!("victim"));
            let vuln = make_vuln("vuln-fcp-004", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_matching_credential_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("otheruser", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-005", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_case_insensitive_credential_match() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("Admin", "CONTOSO.LOCAL"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-006", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].source_user, "admin");
    }

    const GPO_GUID: &str = "{34034095-875D-4230-9232-2611A167C9E1}";
    const GPO_DN: &str =
        "CN={34034095-875D-4230-9232-2611A167C9E1},CN=Policies,CN=System,DC=contoso,DC=local";

    fn gpo_details(source: &str, domain: &str) -> HashMap<String, serde_json::Value> {
        let mut m = acl_details(source, GPO_GUID, domain);
        m.insert("domain".to_string(), serde_json::json!(domain));
        m.insert("target_type".to_string(), serde_json::json!("GPO"));
        m.insert("gpo_id".to_string(), serde_json::json!(GPO_GUID));
        m
    }

    #[test]
    fn gpo_container_dn_builds_the_policies_container_path() {
        assert_eq!(
            gpo_container_dn(GPO_GUID, "contoso.local").as_deref(),
            Some(GPO_DN)
        );
    }

    #[test]
    fn gpo_container_dn_accepts_an_unbraced_guid_and_a_child_domain() {
        assert_eq!(
            gpo_container_dn(
                "34034095-875D-4230-9232-2611A167C9E1",
                "child.contoso.local"
            )
            .as_deref(),
            Some(
                "CN={34034095-875D-4230-9232-2611A167C9E1},CN=Policies,CN=System,\
                 DC=child,DC=contoso,DC=local"
            )
        );
    }

    #[test]
    fn gpo_container_dn_refuses_to_fabricate_a_dn_from_a_non_guid() {
        assert_eq!(
            gpo_container_dn("Default Domain Policy", "contoso.local"),
            None
        );
        assert_eq!(gpo_container_dn("{not-a-guid}", "contoso.local"), None);
        assert_eq!(gpo_container_dn(GPO_GUID, ""), None);
    }

    #[test]
    fn gpo_dn_builds_a_dn_bound_command_for_both_impacket_tools() {
        let dn = gpo_container_dn(GPO_GUID, "contoso.local").expect("GPO DN must build");

        let owner = ares_tools::acl::build_owner_edit(&serde_json::json!({
            "domain": "contoso.local",
            "username": "alice",
            "password": "P@ssw0rd!", // pragma: allowlist secret
            "dc_ip": "192.168.58.10",
            "target": dn,
            "new_owner": "alice",
        }))
        .expect("owner_edit must accept a GPO DN through its `target` argument");
        let owner_argv = owner.args_for_test();
        assert!(
            owner_argv.iter().any(|a| a == "-target-dn"),
            "a DN handed to owner_edit must reach owneredit.py's -target-dn flag, \
             not -target: {owner_argv:?}"
        );
        assert!(owner_argv.iter().any(|a| a == &dn));
        assert!(
            !owner_argv.iter().any(|a| a == GPO_GUID),
            "the bare container GUID resolves to nothing: {owner_argv:?}"
        );

        let dacl = ares_tools::acl::build_dacl_edit(&serde_json::json!({
            "domain": "contoso.local",
            "username": "alice",
            "password": "P@ssw0rd!", // pragma: allowlist secret
            "dc_ip": "192.168.58.10",
            "target_dn": dn,
            "principal": "alice",
            "rights": "GenericAll",
        }))
        .expect("dacl_edit must accept a GPO DN");
        let dacl_argv = dacl.args_for_test();
        assert!(dacl_argv.iter().any(|a| a == "-target-dn"));
        assert!(dacl_argv.iter().any(|a| a == &dn));
    }

    #[test]
    fn resolve_acl_target_dn_prefers_the_dn_the_parser_captured() {
        let mut details = gpo_details("alice", "contoso.local");
        details.insert("target_dn".to_string(), serde_json::json!(GPO_DN));
        assert_eq!(
            resolve_acl_target_dn(&details, "gpo_writeowner", "GPO", GPO_GUID, "contoso.local"),
            GPO_DN
        );
    }

    #[test]
    fn resolve_acl_target_dn_reconstructs_a_gpo_dn_when_the_parser_dropped_it() {
        let details = gpo_details("alice", "contoso.local");
        assert_eq!(
            resolve_acl_target_dn(&details, "gpo_writeowner", "GPO", GPO_GUID, "contoso.local"),
            GPO_DN,
            "vulns replayed from Redis predate the parser emitting target_dn"
        );
    }

    #[test]
    fn resolve_acl_target_dn_leaves_sam_bearing_targets_alone() {
        let details = acl_details("alice", "victim", "contoso.local");
        assert_eq!(
            resolve_acl_target_dn(&details, "writeowner", "User", "victim", "contoso.local"),
            "",
            "a user/group/computer target still resolves by sAMAccountName"
        );
    }

    #[tokio::test]
    async fn collect_gpo_edge_dispatches_a_dn_not_the_container_guid() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            state
                .domain_controllers
                .insert("contoso.local".to_string(), "192.168.58.10".to_string());
            let vuln = make_vuln(
                "gpo_writeowner_alice__34034095_875d_4230_9232_2611a167c9e1_",
                "gpo_writeowner",
                gpo_details("alice", "contoso.local"),
            );
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1, "GPO ACL edges are still dispatchable");
        assert_eq!(work[0].target_dn, GPO_DN);
        assert_eq!(work[0].target_type, "GPO");

        let payload = build_dacl_payload(&work[0]);
        assert_eq!(payload["target_dn"], GPO_DN);
        assert_eq!(payload["target_type"], "GPO");
        assert_eq!(
            payload["target_user"], GPO_GUID,
            "the GUID stays available for pygpoabuse; the DN is what the ACL tools bind on"
        );
    }

    #[tokio::test]
    async fn collect_gpo_edge_without_a_resolvable_dn_is_not_dispatched() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            let mut details = acl_details("alice", "Workstation Lockdown", "contoso.local");
            details.insert("domain".to_string(), serde_json::json!("contoso.local"));
            details.insert("target_type".to_string(), serde_json::json!("GPO"));
            let vuln = make_vuln("gpo_writedacl_alice_x", "gpo_writedacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let mut census = DaclTickCensus::default();
        let work = collect_dacl_work_census(&state, &mut census);
        assert!(
            work.is_empty(),
            "dispatching a GPO edge with no DN burns an LLM turn on a guaranteed failure"
        );
        assert_eq!(census.no_target_dn, 1);
    }

    #[tokio::test]
    async fn collect_non_gpo_edge_carries_the_parser_dn_when_present() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            let mut details = acl_details("alice", "victim", "contoso.local");
            details.insert(
                "target_dn".to_string(),
                serde_json::json!("CN=victim,CN=Users,DC=contoso,DC=local"),
            );
            let vuln = make_vuln("acl_writedacl_alice_victim", "writedacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_dn, "CN=victim,CN=Users,DC=contoso,DC=local");
    }

    #[tokio::test]
    async fn collect_dc_ip_resolved_from_domain_controllers() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state
                .domain_controllers
                .insert("contoso.local".to_string(), "192.168.58.10".to_string());
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-007", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_ip, "192.168.58.10");
    }

    #[tokio::test]
    async fn collect_dc_ip_empty_when_no_dc_mapping() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-008", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_ip, "");
    }

    #[tokio::test]
    async fn collect_credential_domain_mismatch_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "fabrikam.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-009", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_empty_source_domain_matches_any_cred_domain() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "fabrikam.local"));
            let mut details = HashMap::new();
            details.insert("source".to_string(), serde_json::json!("admin"));
            details.insert("target".to_string(), serde_json::json!("victim"));
            let vuln = make_vuln("vuln-fcp-010", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[tokio::test]
    async fn collect_orders_privileged_reaching_edges_first() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));

            let mut dead_end = acl_details("alice", "carol", "contoso.local");
            dead_end.insert("target_type".to_string(), serde_json::json!("User"));
            state.discovered_vulnerabilities.insert(
                "aaa_dead_end".to_string(),
                make_vuln("aaa_dead_end", "WriteDacl", dead_end),
            );

            let mut to_da = acl_details("alice", "Domain Admins", "contoso.local");
            to_da.insert("target_type".to_string(), serde_json::json!("Group"));
            state.discovered_vulnerabilities.insert(
                "zzz_to_da".to_string(),
                make_vuln("zzz_to_da", "AddMember", to_da),
            );
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 2);
        assert_eq!(
            work[0].vuln_id, "zzz_to_da",
            "the edge that reaches Domain Admins must dispatch before the dead end"
        );
        assert_eq!(work[1].vuln_id, "aaa_dead_end");
    }

    #[tokio::test]
    async fn collect_caps_dispatch_at_the_per_tick_budget() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            for i in 0..(MAX_ACL_DISPATCH_PER_TICK * 4) {
                let details = acl_details("alice", &format!("target{i}"), "contoso.local");
                let vuln = make_vuln(&format!("vuln-flood-{i:03}"), "WriteDacl", details);
                state
                    .discovered_vulnerabilities
                    .insert(vuln.vuln_id.clone(), vuln);
            }
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), MAX_ACL_DISPATCH_PER_TICK);
    }

    #[tokio::test]
    async fn the_tick_budget_is_spread_across_distinct_source_principals() {
        let shared = SharedState::new("test".into());
        let owners = 40usize;
        {
            let mut state = shared.write().await;
            for p in 0..owners {
                state
                    .credentials
                    .push(make_credential(&format!("svc_{p:03}"), "contoso.local"));
            }
            for p in 0..owners {
                for e in 0..60 {
                    let details = acl_details(
                        &format!("svc_{p:03}"),
                        &format!("host{p:03}_{e:03}"),
                        "contoso.local",
                    );
                    let vuln = make_vuln(
                        &format!("acl_writedacl_{p:03}_{e:03}"),
                        "WriteDacl",
                        details,
                    );
                    state
                        .discovered_vulnerabilities
                        .insert(vuln.vuln_id.clone(), vuln);
                }
            }
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), MAX_ACL_DISPATCH_PER_TICK);

        let sources: std::collections::HashSet<String> =
            work.iter().map(|w| w.source_user.to_lowercase()).collect();
        assert_eq!(
            sources.len(),
            MAX_ACL_DISPATCH_PER_TICK,
            "2400 edges over {owners} owned principals produced {} distinct sources; the tick \
             budget was spent re-walking one principal instead of covering the graph",
            sources.len()
        );

        let targets: std::collections::HashSet<String> =
            work.iter().map(|w| w.target_user.to_lowercase()).collect();
        assert_eq!(targets.len(), MAX_ACL_DISPATCH_PER_TICK);
    }

    #[tokio::test]
    async fn diverse_selection_still_leads_with_the_best_ranked_edge() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            state
                .credentials
                .push(make_credential("bob", "contoso.local"));
            for e in 0..40 {
                let details = acl_details("alice", &format!("host{e:03}"), "contoso.local");
                let vuln = make_vuln(&format!("acl_aaa_{e:03}"), "WriteDacl", details);
                state
                    .discovered_vulnerabilities
                    .insert(vuln.vuln_id.clone(), vuln);
            }
            let mut details = acl_details("bob", "Domain Admins", "contoso.local");
            details.insert("target_type".to_string(), serde_json::json!("Group"));
            let vuln = make_vuln("acl_zzz_bob_da", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(
            work[0].vuln_id, "acl_zzz_bob_da",
            "diversity must not displace the edge that actually reaches Domain Admins"
        );
    }

    #[tokio::test]
    async fn collect_is_deterministic_across_calls() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("alice", "contoso.local"));
            for i in 0..20 {
                let details = acl_details("alice", &format!("target{i}"), "contoso.local");
                let vuln = make_vuln(&format!("vuln-det-{i:03}"), "WriteDacl", details);
                state
                    .discovered_vulnerabilities
                    .insert(vuln.vuln_id.clone(), vuln);
            }
        }

        let state = shared.read().await;
        let first: Vec<String> = collect_dacl_work(&state)
            .iter()
            .map(|w| w.vuln_id.clone())
            .collect();
        let second: Vec<String> = collect_dacl_work(&state)
            .iter()
            .map(|w| w.vuln_id.clone())
            .collect();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn collect_multiple_vulns_produces_multiple_work_items() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));

            for (i, vtype) in ["ForceChangePassword", "GenericAll", "WriteDacl"]
                .iter()
                .enumerate()
            {
                let details = acl_details("admin", &format!("target{i}"), "contoso.local");
                let vuln = make_vuln(&format!("vuln-multi-{i}"), vtype, details);
                state
                    .discovered_vulnerabilities
                    .insert(vuln.vuln_id.clone(), vuln);
            }
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 3);
    }

    #[tokio::test]
    async fn collect_dedup_key_format_matches() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-dk-001", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "dacl:vuln-dk-001");
    }

    #[tokio::test]
    async fn collect_source_user_fallback_to_from_key() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("svc_account", "contoso.local"));
            let mut details = HashMap::new();
            details.insert("from".to_string(), serde_json::json!("svc_account"));
            details.insert("target".to_string(), serde_json::json!("victim"));
            details.insert(
                "source_domain".to_string(),
                serde_json::json!("contoso.local"),
            );
            let vuln = make_vuln("vuln-from-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].source_user, "svc_account");
    }

    fn make_hash(username: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("hash-{username}"),
            username: username.to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(), // pragma: allowlist secret
            hash_type: "NTLM".into(),
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

    #[tokio::test]
    async fn collect_skips_when_domain_already_dominated() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-dom-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state.dominated_domains.insert("contoso.local".to_string());
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "ACL chain must be suppressed once domain is dominated"
        );
    }

    #[tokio::test]
    async fn collect_defers_when_credential_capture_in_flight() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-flight-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state.mark_credential_capture_in_flight("contoso.local");
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "ACL chain must defer while DCSync is in flight"
        );
    }

    #[tokio::test]
    async fn collect_skips_destructive_when_target_hash_already_present() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state.hashes.push(make_hash("victim", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-mat-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "ForceChangePassword must be suppressed when target hash is in state"
        );
    }

    #[tokio::test]
    async fn collect_skips_destructive_when_target_credential_already_present() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state
                .credentials
                .push(make_credential("victim", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-mat-002", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "GenericAll must be suppressed when target credential is in state"
        );
    }

    #[tokio::test]
    async fn collect_allows_non_destructive_acl_when_target_material_present() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state.hashes.push(make_hash("victim", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-gw-002", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(
            work.len(),
            1,
            "Non-destructive ACL types must still dispatch"
        );
    }

    #[tokio::test]
    async fn collect_target_user_fallback_to_target_user_key() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let mut details = HashMap::new();
            details.insert("source".to_string(), serde_json::json!("admin"));
            details.insert(
                "target_user".to_string(),
                serde_json::json!("fallback_target"),
            );
            details.insert(
                "source_domain".to_string(),
                serde_json::json!("contoso.local"),
            );
            let vuln = make_vuln("vuln-tu-001", "WriteDacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_user, "fallback_target");
    }

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

    fn baseline_dacl_work() -> DaclWork {
        DaclWork {
            dedup_key: "dacl:v1".into(),
            vuln_id: "v1".into(),
            vuln_type: "genericall".into(),
            source_user: "alice".into(),
            via_group: None,
            target_user: "victim".into(),
            target_type: String::new(),
            target_dn: String::new(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: Some(make_cred("alice", "P@ssw0rd!", "contoso.local")),
            hash: None,
        }
    }

    #[test]
    fn build_dacl_payload_emits_expected_fields() {
        let p = build_dacl_payload(&baseline_dacl_work());
        assert_eq!(p["technique"], "dacl_abuse");
        assert_eq!(p["acl_type"], "genericall");
        assert_eq!(p["vuln_id"], "v1");
        assert_eq!(p["source_user"], "alice");
        assert_eq!(p["target_user"], "victim");
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["credential"]["username"], "alice");
        assert_eq!(p["credential"]["password"], "P@ssw0rd!");
        assert_eq!(p["credential"]["domain"], "contoso.local");
        assert_eq!(p["username"], "alice");
        assert!(p.get("hash").is_none());
    }

    #[test]
    fn build_dacl_payload_falls_back_to_hash_when_no_credential() {
        let mut item = baseline_dacl_work();
        item.credential = None;
        item.hash = Some(make_hash("alice", "contoso.local"));

        let p = build_dacl_payload(&item);

        assert_eq!(p["username"], "alice");
        assert_eq!(
            p["hash"],
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        );
        assert!(p.get("credential").is_none());
        assert!(p.get("password").is_none());
    }

    #[test]
    fn build_dacl_payload_propagates_acl_type_verbatim() {
        let mut w = baseline_dacl_work();
        w.vuln_type = "writeproperty".into();
        assert_eq!(build_dacl_payload(&w)["acl_type"], "writeproperty");

        w.vuln_type = "forcechangepassword".into();
        assert_eq!(build_dacl_payload(&w)["acl_type"], "forcechangepassword");
    }
}
