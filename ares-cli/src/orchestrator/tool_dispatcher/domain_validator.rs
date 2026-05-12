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
    })
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
}
