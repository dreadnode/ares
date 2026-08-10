//! Domain-name canonicalization helpers.
//!
//! Tool output mixes NetBIOS flat names (`NORTH`) and FQDNs
//! (`north.contoso.local`); state-keyed lookups (`domain_sids`,
//! `domain_controllers`, etc.) always key on the FQDN. Callers that touch a
//! domain coming straight out of a hash or work-item must run it through
//! [`resolve_flat_to_fqdn`] first, otherwise FQDN-keyed maps miss for flat
//! inputs and the loop defers forever.

use super::StateInner;

/// Resolve a NetBIOS/flat domain name (e.g. `FABRIKAM`) to a known FQDN.
///
/// Checks three sources, in order:
/// 1. `state.trusted_domains`: each `TrustInfo` carries an explicit `flat_name`.
/// 2. `state.netbios_to_fqdn`: published mappings from host short names; useful
///    when the flat name happens to match a hostname mapping.
/// 3. `state.domains`: derive each FQDN's first label and compare. Catches the
///    primary domain (which is rarely in `trusted_domains`).
///
/// Returns `None` when the flat name does not correspond to any known domain.
/// Callers must treat that as "skip caching" — guessing risks attributing the
/// SID to the wrong domain.
pub(crate) fn resolve_flat_to_fqdn(flat: &str, state: &StateInner) -> Option<String> {
    let target = flat.to_uppercase();

    if let Some(t) = state
        .trusted_domains
        .values()
        .find(|t| !t.flat_name.is_empty() && t.flat_name.to_uppercase() == target)
    {
        return Some(t.domain.to_lowercase());
    }

    if let Some(fqdn) = state
        .netbios_to_fqdn
        .get(&target)
        .or_else(|| state.netbios_to_fqdn.get(flat))
    {
        // Only accept the mapping if it looks like a domain FQDN, not a host
        // FQDN (e.g. "DC02" → "dc02.contoso.local" should NOT yield "dc02…").
        let lower = fqdn.to_lowercase();
        if is_valid_domain_fqdn(&lower) && state.domains.iter().any(|d| d.to_lowercase() == lower) {
            return Some(lower);
        }
    }

    state
        .domains
        .iter()
        .find(|d| {
            d.split('.')
                .next()
                .map(|first| first.eq_ignore_ascii_case(flat))
                .unwrap_or(false)
        })
        .map(|d| d.to_lowercase())
}

/// Resolve a domain FQDN (e.g. `child.contoso.local`) to its NetBIOS/flat
/// name (e.g. `CHILD`), when Ares has authoritatively captured it.
///
/// The only trusted source is `state.trusted_domains`, whose `TrustInfo`
/// entries carry a `flat_name` observed via LDAP `trustedDomain` enumeration.
/// We deliberately do NOT guess the flat name from the FQDN's first label:
/// callers use this to qualify `-just-dc-user` in a multi-domain forest, and a
/// wrong guess turns a working bare-`krbtgt` dump into a hard "name not found"
/// failure. `None` means "flat name unknown" — the caller should fall back to
/// the bare account name (and, for `-just-dc-user`, a full-dump retry).
pub(crate) fn resolve_fqdn_to_flat(fqdn: &str, state: &StateInner) -> Option<String> {
    let target = fqdn.to_lowercase();
    if target.is_empty() {
        return None;
    }
    state
        .trusted_domains
        .values()
        .find(|t| t.domain.to_lowercase() == target && !t.flat_name.is_empty())
        .map(|t| t.flat_name.to_uppercase())
}

/// Validate that a string looks like a domain FQDN.
///
/// Rejects empty strings, IP-like patterns, strings with whitespace, and strings
/// without at least one dot. Used to filter out malformed domain values that
/// occasionally appear in tool payloads (e.g. `"192.168.58.30 - dc01"`).
pub(crate) fn is_valid_domain_fqdn(s: &str) -> bool {
    if s.is_empty() || s.contains(' ') || s.contains(':') || s.contains('/') {
        return false;
    }
    if !s.contains('.') {
        return false;
    }
    let first_label = s.split('.').next().unwrap_or("");
    if first_label.is_empty() || first_label.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Canonicalize a domain label to FQDN form for state lookups.
///
/// Idempotent on already-valid FQDNs. Falls back to `resolve_flat_to_fqdn`
/// when the input is a flat NetBIOS name. Returns `None` when the label is
/// unknown to `state` (no trust metadata, no netbios mapping, no matching
/// `domains` entry) — callers should treat that as "skip this candidate"
/// rather than guessing.
pub(crate) fn canonicalize_domain_label(label: &str, state: &StateInner) -> Option<String> {
    if label.is_empty() {
        return None;
    }
    if is_valid_domain_fqdn(label) {
        return Some(label.to_lowercase());
    }
    resolve_flat_to_fqdn(label, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::TrustInfo;

    fn make_trust(domain: &str, flat: &str) -> TrustInfo {
        TrustInfo {
            domain: domain.to_string(),
            flat_name: flat.to_string(),
            direction: "bidirectional".to_string(),
            trust_type: "forest".to_string(),
            sid_filtering: true,
            security_identifier: None,
        }
    }

    #[test]
    fn resolve_flat_uses_trusted_domain_metadata() {
        let mut state = StateInner::new("op-test".into());
        state.trusted_domains.insert(
            "fabrikam.local".into(),
            make_trust("fabrikam.local", "FABRIKAM"),
        );
        assert_eq!(
            resolve_flat_to_fqdn("FABRIKAM", &state).as_deref(),
            Some("fabrikam.local")
        );
    }

    #[test]
    fn resolve_flat_falls_back_to_primary_domain_label() {
        let mut state = StateInner::new("op-test".into());
        state.domains.push("contoso.local".into());
        assert_eq!(
            resolve_flat_to_fqdn("CONTOSO", &state).as_deref(),
            Some("contoso.local")
        );
    }

    #[test]
    fn resolve_flat_unknown_returns_none() {
        let state = StateInner::new("op-test".into());
        assert_eq!(resolve_flat_to_fqdn("UNKNOWN", &state), None);
    }

    #[test]
    fn resolve_flat_does_not_match_host_short_name() {
        // netbios_to_fqdn maps DC02 → dc02.contoso.local (a host, not domain).
        // resolve_flat_to_fqdn must reject this — dc02.contoso.local is not in
        // state.domains, so it cannot be a domain FQDN.
        let mut state = StateInner::new("op-test".into());
        state.domains.push("contoso.local".into());
        state
            .netbios_to_fqdn
            .insert("DC02".into(), "dc02.contoso.local".into());
        assert_eq!(resolve_flat_to_fqdn("DC02", &state), None);
    }

    #[test]
    fn resolve_flat_prefers_trust_metadata_over_primary_label() {
        // Both child.contoso.local and contoso.local are known.
        // Flat "CONTOSO" should resolve to the parent FQDN even when
        // both could plausibly match by first-label heuristic.
        let mut state = StateInner::new("op-test".into());
        state.domains.push("child.contoso.local".into());
        state.domains.push("contoso.local".into());
        state.trusted_domains.insert(
            "contoso.local".into(),
            make_trust("contoso.local", "CONTOSO"),
        );
        assert_eq!(
            resolve_flat_to_fqdn("CONTOSO", &state).as_deref(),
            Some("contoso.local")
        );
    }

    #[test]
    fn resolve_fqdn_to_flat_uses_trusted_domain_metadata() {
        let mut state = StateInner::new("op-test".into());
        state.trusted_domains.insert(
            "child.contoso.local".into(),
            make_trust("child.contoso.local", "CHILD"),
        );
        assert_eq!(
            resolve_fqdn_to_flat("child.contoso.local", &state).as_deref(),
            Some("CHILD")
        );
    }

    #[test]
    fn resolve_fqdn_to_flat_is_case_insensitive_and_uppercases() {
        let mut state = StateInner::new("op-test".into());
        state.trusted_domains.insert(
            "fabrikam.local".into(),
            make_trust("fabrikam.local", "fabrikam"),
        );
        assert_eq!(
            resolve_fqdn_to_flat("FABRIKAM.LOCAL", &state).as_deref(),
            Some("FABRIKAM")
        );
    }

    #[test]
    fn resolve_fqdn_to_flat_unknown_returns_none() {
        // No trust metadata → we must NOT guess "CHILD" from the first label.
        let mut state = StateInner::new("op-test".into());
        state.domains.push("child.contoso.local".into());
        assert_eq!(resolve_fqdn_to_flat("child.contoso.local", &state), None);
    }

    #[test]
    fn resolve_fqdn_to_flat_skips_empty_flat_name() {
        let mut state = StateInner::new("op-test".into());
        state.trusted_domains.insert(
            "child.contoso.local".into(),
            make_trust("child.contoso.local", ""),
        );
        assert_eq!(resolve_fqdn_to_flat("child.contoso.local", &state), None);
    }

    #[test]
    fn resolve_fqdn_to_flat_empty_input_returns_none() {
        let state = StateInner::new("op-test".into());
        assert_eq!(resolve_fqdn_to_flat("", &state), None);
    }

    #[test]
    fn valid_fqdn_accepts_standard_domain() {
        assert!(is_valid_domain_fqdn("contoso.local"));
        assert!(is_valid_domain_fqdn("fabrikam.local"));
        assert!(is_valid_domain_fqdn("child.contoso.local"));
    }

    #[test]
    fn valid_fqdn_rejects_empty_string() {
        assert!(!is_valid_domain_fqdn(""));
    }

    #[test]
    fn valid_fqdn_rejects_no_dot() {
        // A flat name (e.g. "CONTOSO") has no dot — not a valid FQDN.
        assert!(!is_valid_domain_fqdn("CONTOSO"));
        assert!(!is_valid_domain_fqdn("localonly"));
    }

    #[test]
    fn valid_fqdn_rejects_strings_with_spaces() {
        assert!(!is_valid_domain_fqdn("contoso .local"));
        assert!(!is_valid_domain_fqdn("192.168.58.30 - dc01"));
    }

    #[test]
    fn valid_fqdn_rejects_strings_with_colons_or_slashes() {
        assert!(!is_valid_domain_fqdn("http://contoso.local"));
        assert!(!is_valid_domain_fqdn("contoso:local"));
    }

    #[test]
    fn valid_fqdn_rejects_ip_like_strings() {
        // First label is all digits → looks like an IP, not a domain.
        assert!(!is_valid_domain_fqdn("192.168.58.10"));
        assert!(!is_valid_domain_fqdn("192.168.58.1"));
    }

    #[test]
    fn valid_fqdn_rejects_leading_dot() {
        // First label is empty → ".contoso.local" is malformed.
        assert!(!is_valid_domain_fqdn(".contoso.local"));
    }

    #[test]
    fn valid_fqdn_accepts_domain_with_hyphens_and_underscores() {
        assert!(is_valid_domain_fqdn("hr-team.contoso.local"));
        assert!(is_valid_domain_fqdn("_kerberos.contoso.local"));
    }

    #[test]
    fn canonicalize_passes_through_valid_fqdn() {
        let state = StateInner::new("op-test".into());
        assert_eq!(
            canonicalize_domain_label("contoso.local", &state).as_deref(),
            Some("contoso.local")
        );
    }

    #[test]
    fn canonicalize_lowercases_valid_fqdn() {
        let state = StateInner::new("op-test".into());
        assert_eq!(
            canonicalize_domain_label("CONTOSO.LOCAL", &state).as_deref(),
            Some("contoso.local")
        );
    }

    #[test]
    fn canonicalize_resolves_flat_to_known_fqdn() {
        // The failure mode this whole module exists to prevent:
        // hash.domain = "NORTH" arrives from secretsdump,
        // state.domains has "north.contoso.local",
        // lookup against domain_sids["north"] misses → forge defers forever.
        let mut state = StateInner::new("op-test".into());
        state.domains.push("north.contoso.local".into());
        state.domains.push("contoso.local".into());
        assert_eq!(
            canonicalize_domain_label("NORTH", &state).as_deref(),
            Some("north.contoso.local")
        );
    }

    #[test]
    fn canonicalize_returns_none_for_unknown_flat() {
        let state = StateInner::new("op-test".into());
        assert_eq!(canonicalize_domain_label("MYSTERY", &state), None);
    }

    #[test]
    fn canonicalize_returns_none_for_empty() {
        let state = StateInner::new("op-test".into());
        assert_eq!(canonicalize_domain_label("", &state), None);
    }
}
