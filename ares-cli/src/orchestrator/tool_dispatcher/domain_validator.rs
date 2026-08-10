//! Validate `domain` arguments on outgoing LLM tool calls.
//!
//! The LLM occasionally fat-fingers domain names in tool arguments
//! (e.g. `child.contossso.local` instead of `child.contoso.local`).
//! Tools accept the typo silently, then auth fails, credential lineage breaks,
//! and downstream consumers (cross-forest forge, ADCS enum, credential_resolver)
//! get misdirected. The publishing-side guard already keeps these typos out of
//! `state.domains`, but the typo'd value still rides on credential records and
//! pollutes per-credential routing.
//!
//! This module rejects tool calls whose `domain` argument doesn't match any
//! domain that authoritative recon has discovered. The LLM gets a synchronous
//! error listing valid domains and retries with the right spelling.

use tracing::warn;

use ares_core::state::RedisStateReader;
use ares_llm::{ToolCall, ToolExecResult};

use crate::orchestrator::task_queue::TaskQueue;

/// Inspect a tool call's `domain` argument; return a synthetic error result
/// if it looks like a hallucinated FQDN. Returns `None` to allow the call.
///
/// Allow rules:
/// - No `domain` arg, or empty → allow.
/// - Domain has no dot (workgroup-style label like `WORKGROUP`) → allow.
/// - Domain matches `state.domains` ∪ DC-map keys ∪ trusted-domain keys
///   (case-insensitive) → allow.
/// - Known-domain set is empty (early in the op, no recon yet) → allow.
///
/// Otherwise: reject with an error listing the known domains.
pub(super) async fn check_domain_arg(
    queue: &TaskQueue,
    operation_id: &str,
    call: &ToolCall,
) -> Option<ToolExecResult> {
    let supplied = call.arguments.get("domain").and_then(|v| v.as_str())?;
    let supplied = supplied.trim();
    if supplied.is_empty() || !supplied.contains('.') {
        return None;
    }
    let supplied_lc = supplied.to_lowercase();

    let mut conn = queue.connection();
    let reader = RedisStateReader::new(operation_id.to_string());

    let domains = reader.get_domains(&mut conn).await.unwrap_or_default();
    let dc_keys: Vec<String> = reader
        .get_dc_map(&mut conn)
        .await
        .unwrap_or_default()
        .into_keys()
        .collect();
    let trusted: Vec<String> = reader
        .get_trusted_domains(&mut conn)
        .await
        .unwrap_or_default()
        .into_keys()
        .collect();

    let mut known: Vec<String> = domains
        .into_iter()
        .chain(dc_keys)
        .chain(trusted)
        .map(|d| d.to_lowercase())
        .collect();
    known.sort();
    known.dedup();

    if known.is_empty() {
        return None;
    }
    if known.iter().any(|d| d == &supplied_lc) {
        return None;
    }

    // Also consult cred/hash records: their `domain` field may legitimately
    // carry NetBIOS-style or freshly-discovered values that haven't yet been
    // promoted into the canonical domains set. Only reject if the supplied
    // value is foreign to every channel.
    if let Ok(creds) = reader.get_credentials(&mut conn).await {
        if creds
            .iter()
            .any(|c| c.domain.eq_ignore_ascii_case(supplied))
        {
            return None;
        }
    }

    warn!(
        tool = %call.name,
        supplied = %supplied,
        known = ?known,
        "Rejecting tool call: domain argument not in known domains"
    );

    let suggestion = closest_match(&supplied_lc, &known);
    let message = match suggestion {
        Some(s) => format!(
            "Unknown domain '{}'. Known domains: [{}]. Did you mean '{}'?",
            supplied,
            known.join(", "),
            s
        ),
        None => format!(
            "Unknown domain '{}'. Known domains: [{}]. Use one of these exactly, or call a recon tool first to discover the correct FQDN.",
            supplied,
            known.join(", ")
        ),
    };

    Some(ToolExecResult {
        output: String::new(),
        error: Some(message),
        discoveries: None,
        // Pre-dispatch rejection — no spawn attempted, so no spawn kind.
        failure_kind: None,
    })
}

/// Intercept native-credential auth aimed across a *forest* trust boundary.
///
/// Native NTLM/Kerberos auth cannot cross a forest boundary: a home-realm
/// ticket presented to a foreign forest's KDC fails with `KDC_ERR_WRONG_REALM`,
/// and cross-realm NTLM pass-through is rejected. The only working path is an
/// inter-realm TGT forged with the trust key, which `auto_trust_follow`
/// produces automatically and publishes as a ccache;
/// `credential_resolver::resolve_cross_forest_ticket` then flips these tools
/// into Kerberos mode. Left unguarded, the LLM re-issues `secretsdump` against
/// a foreign-forest DC with home-realm creds every turn — eating
/// `KDC_ERR_WRONG_REALM` and burning tokens while objective state stays flat
/// (the op-20260703-141802 wedge).
///
/// Returns a synthetic error (steering the agent off the doomed mechanic) when
/// ALL hold:
/// - the tool has a native auth mode with a Kerberos alternative
///   (`KerberosCoercion::InPlace` / `Redirect` — `*_kerberos` variants and
///   non-auth tools are never blocked),
/// - no `ticket_path` is already supplied (a supplied ticket is the legit path),
/// - the credential realm (`domain` arg) and the resolved target-host realm are
///   in different forests, and
/// - no forged inter-realm ccache for the target realm exists yet.
///
/// Any unknown — no `domain` arg, unresolvable target realm, same forest, or a
/// forge already landed — returns `None` (allow), so the guard never blocks a
/// legitimate or same-realm call.
pub(super) async fn check_cross_realm_auth(
    queue: &TaskQueue,
    operation_id: &str,
    call: &ToolCall,
) -> Option<ToolExecResult> {
    // Only native-cred impacket auth tools that have a Kerberos alternative.
    if !blocks_native_cross_realm_auth(&call.name) {
        return None;
    }

    // A supplied ticket means the caller is already on the Kerberos path.
    if call
        .arguments
        .get("ticket_path")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty())
    {
        return None;
    }

    // Credential realm the LLM is authenticating as. Needs a dot to be a realm;
    // a bare workgroup label carries no forest, so leave it alone.
    let cred_realm = call
        .arguments
        .get("domain")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.contains('.'))?
        .to_lowercase();

    let mut conn = queue.connection();
    let reader = RedisStateReader::new(operation_id.to_string());

    // Resolve the target host's realm. Unknown target → don't over-block.
    let dc_map = reader.get_dc_map(&mut conn).await.unwrap_or_default();
    let target_realm = infer_target_realm_from_args(&call.arguments, &dc_map)?;

    // If a forged inter-realm ccache for the target realm already exists, the
    // worker's resolve_cross_forest_ticket will inject it and flip to Kerberos.
    let has_forged_ticket = reader
        .get_kerberos_tickets(&mut conn)
        .await
        .unwrap_or_default()
        .iter()
        .any(|t| {
            t.target_domain.eq_ignore_ascii_case(&target_realm) && !t.ticket_path.trim().is_empty()
        });

    // Only block a genuine forest boundary (disjoint namespaces) with no forge
    // yet; same-domain, parent/child, and post-forge calls take the normal path.
    if !cross_realm_auth_is_doomed(&cred_realm, &target_realm, has_forged_ticket) {
        return None;
    }

    warn!(
        tool = %call.name,
        cred_realm = %cred_realm,
        target_realm = %target_realm,
        "Rejecting native-credential auth across a forest boundary — no forged inter-realm ticket yet"
    );

    let message = format!(
        "Cross-forest authentication blocked: '{tool}' is targeting a domain controller in forest \
         '{target}' using '{cred}' credentials. Native NTLM/Kerberos auth cannot cross a forest \
         trust boundary — a home-realm ticket presented to the foreign KDC fails with \
         KDC_ERR_WRONG_REALM, and cross-realm NTLM pass-through is rejected. The cross-forest dump \
         requires an inter-realm TGT forged with the trust key; the orchestrator does this \
         automatically once the target domain SID, trust key, and AES key are in state, then \
         publishes a forged ccache that flips secretsdump/psexec/wmiexec/smbexec into Kerberos \
         mode. No forged ticket for '{target}' exists yet. Do NOT retry native-credential auth \
         against this DC — it will keep failing the same way. Pursue other objectives (ACL or \
         certificate escalation, or enumeration that captures the trust key and target SID) while \
         the inter-realm forge completes.",
        tool = call.name,
        target = target_realm,
        cred = cred_realm,
    );

    Some(ToolExecResult {
        output: String::new(),
        error: Some(message),
        discoveries: None,
        // Pre-dispatch rejection — no spawn attempted, so no spawn kind.
        failure_kind: None,
    })
}

/// True when the tool authenticates with a native credential and has a Kerberos
/// alternative — exactly the set that fails across a forest boundary but works
/// once a forged inter-realm ccache flips it into Kerberos mode. Derived from
/// `kerberos_coercion` so the guard stays in lock-step with the resolver's
/// notion of a Kerberos-capable tool; `*_kerberos` variants (`AlreadyKerberos`,
/// the correct mechanic) and non-auth tools are excluded.
fn blocks_native_cross_realm_auth(tool_name: &str) -> bool {
    use crate::worker::credential_resolver::{kerberos_coercion, KerberosCoercion};
    matches!(
        kerberos_coercion(tool_name),
        KerberosCoercion::InPlace | KerberosCoercion::Redirect(_)
    )
}

/// A native cross-realm auth call is doomed when the credential realm and target
/// realm are in different forests and no forged inter-realm ticket exists yet.
/// Same-domain and parent/child (same-forest) pairs auth normally, and a landed
/// forge flips the tool into Kerberos mode — neither is blocked.
fn cross_realm_auth_is_doomed(
    cred_realm: &str,
    target_realm: &str,
    has_forged_ticket: bool,
) -> bool {
    use crate::orchestrator::automation::is_cross_forest;
    is_cross_forest(cred_realm, target_realm) && !has_forged_ticket
}

/// Best-effort target-realm inference for [`check_cross_realm_auth`]. Mirrors
/// `credential_resolver::infer_domain_from_target`: an IP target is matched
/// against the DC map (`domain → dc_ip`); an FQDN target yields its suffix.
/// Returns `None` for bare hostnames or IPs absent from the DC map — the guard
/// treats "unknown target realm" as allow, never block.
fn infer_target_realm_from_args(
    arguments: &serde_json::Value,
    dc_map: &std::collections::HashMap<String, String>,
) -> Option<String> {
    const TARGET_KEYS: &[&str] = &[
        "target",
        "target_ip",
        "dc_ip",
        "target_host",
        "target_hostname",
        "hostname",
        "host",
    ];

    for key in TARGET_KEYS {
        let Some(value) = arguments.get(*key).and_then(|v| v.as_str()) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if looks_like_ip(value) {
            for (domain, ip) in dc_map {
                if ip.trim() == value {
                    let d = domain.trim().to_lowercase();
                    if !d.is_empty() {
                        return Some(d);
                    }
                }
            }
        } else if let Some((_, suffix)) = value.split_once('.') {
            let s = suffix.trim().to_lowercase();
            if !s.is_empty() && s.contains('.') {
                return Some(s);
            }
        }
    }
    None
}

fn looks_like_ip(s: &str) -> bool {
    let octets: Vec<&str> = s.trim().split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
}

/// Return the known domain with the smallest edit distance to `supplied`,
/// if any are within distance 3. Used only to nudge the LLM in the error.
fn closest_match(supplied: &str, known: &[String]) -> Option<String> {
    known
        .iter()
        .map(|d| (d.clone(), edit_distance(supplied, d)))
        .filter(|(_, dist)| *dist <= 3)
        .min_by_key(|(_, dist)| *dist)
        .map(|(d, _)| d)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance("contoso.local", "contoso.local"), 0);
        assert_eq!(
            edit_distance("child.contossso.local", "child.contoso.local"),
            2
        );
        assert_eq!(
            edit_distance("child.contosssso.local", "child.contoso.local"),
            3
        );
        assert!(edit_distance("foo.bar", "completely.different") > 5);
    }

    #[test]
    fn closest_match_picks_nearest() {
        let known = vec![
            "fabrikam.local".to_string(),
            "child.contoso.local".to_string(),
            "contoso.local".to_string(),
        ];
        let picked = closest_match("child.contossso.local", &known);
        assert_eq!(picked.as_deref(), Some("child.contoso.local"));
    }

    #[test]
    fn closest_match_returns_none_when_far() {
        let known = vec!["fabrikam.local".to_string()];
        assert!(closest_match("totally.unrelated.domain", &known).is_none());
    }

    #[test]
    fn native_auth_tools_are_guarded() {
        // Native impacket auth tools with a Kerberos alternative → guarded.
        assert!(blocks_native_cross_realm_auth("secretsdump"));
        assert!(blocks_native_cross_realm_auth("psexec"));
        assert!(blocks_native_cross_realm_auth("wmiexec"));
        assert!(blocks_native_cross_realm_auth("smbexec"));
    }

    #[test]
    fn kerberos_and_nonauth_tools_are_not_guarded() {
        // *_kerberos variants are the correct cross-forest mechanic — never block.
        assert!(!blocks_native_cross_realm_auth("secretsdump_kerberos"));
        assert!(!blocks_native_cross_realm_auth("psexec_kerberos"));
        // Recon / non-auth tools have no native cross-realm auth to block.
        assert!(!blocks_native_cross_realm_auth("ldap_search"));
        assert!(!blocks_native_cross_realm_auth("nmap_scan"));
    }

    #[test]
    fn doomed_only_for_cross_forest_without_ticket() {
        // Cross-forest, no forged ticket → doomed (block).
        assert!(cross_realm_auth_is_doomed(
            "contoso.local",
            "fabrikam.local",
            false
        ));
        // Cross-forest but a forge already landed → allow (worker flips to Kerberos).
        assert!(!cross_realm_auth_is_doomed(
            "contoso.local",
            "fabrikam.local",
            true
        ));
        // Same forest (parent/child) → allow, regardless of ticket state.
        assert!(!cross_realm_auth_is_doomed(
            "child.contoso.local",
            "contoso.local",
            false
        ));
        // Same domain → allow.
        assert!(!cross_realm_auth_is_doomed(
            "contoso.local",
            "contoso.local",
            false
        ));
    }

    #[test]
    fn infer_target_realm_from_fqdn_suffix() {
        let dc_map = std::collections::HashMap::new();
        let args = serde_json::json!({ "target": "dc01.fabrikam.local" });
        assert_eq!(
            infer_target_realm_from_args(&args, &dc_map).as_deref(),
            Some("fabrikam.local")
        );
    }

    #[test]
    fn infer_target_realm_from_ip_via_dc_map() {
        let mut dc_map = std::collections::HashMap::new();
        dc_map.insert("fabrikam.local".to_string(), "192.168.58.20".to_string());
        let args = serde_json::json!({ "target_ip": "192.168.58.20" });
        assert_eq!(
            infer_target_realm_from_args(&args, &dc_map).as_deref(),
            Some("fabrikam.local")
        );
    }

    #[test]
    fn infer_target_realm_none_for_unknown_ip_or_bare_host() {
        let dc_map = std::collections::HashMap::new();
        // IP not in the DC map → unknown realm.
        let ip_args = serde_json::json!({ "target": "192.168.58.99" });
        assert!(infer_target_realm_from_args(&ip_args, &dc_map).is_none());
        // Bare hostname (no dotted suffix) → unknown realm.
        let host_args = serde_json::json!({ "target": "dc01" });
        assert!(infer_target_realm_from_args(&host_args, &dc_map).is_none());
    }

    #[test]
    fn looks_like_ip_distinguishes_ip_from_fqdn() {
        assert!(looks_like_ip("192.168.58.20"));
        assert!(!looks_like_ip("dc01.fabrikam.local"));
        assert!(!looks_like_ip("999.1.1.1"));
        assert!(!looks_like_ip("192.168.58"));
    }
}
