pub(crate) mod credentials;
pub(crate) mod domains;
pub(crate) mod hashes;
pub(crate) mod labels;
pub(crate) mod users;

#[cfg(test)]
mod tests;

use regex::Regex;
use std::sync::LazyLock;

/// Strip trailing DNS root dot and NetExec "0." artifact from domain strings
/// (e.g. `child.contoso.local.` → `child.contoso.local`,
/// `contoso.local0` → `contoso.local`).
pub(super) fn strip_trailing_dot(s: &str) -> &str {
    let s = s.trim_end_matches('.');
    // NetExec sometimes appends "0" to domain TLDs. Strip if the char
    // before the trailing 0 is alphabetic (i.e. TLD-like, not "host10").
    match s.strip_suffix('0') {
        Some(clean) if clean.ends_with(|c: char| c.is_ascii_alphabetic()) => clean,
        _ => s,
    }
}

/// Auto-generated Windows hostname pattern (`WIN-` + 11 alphanumerics + optional `$`),
/// the name noPAC gives the machine account it creates.
static GHOST_MACHINE_ACCOUNT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^WIN-[A-Z0-9]{11}\$?$").unwrap());

/// True if `username` is a machine account this operation created — either
/// noPAC's auto-generated name (`WIN-G9FWV8ZNSCL$`) or one minted by
/// `add_computer` (`ARES-1A2B3C4D$`).
///
/// Callers use it to keep our own residue out of loot and to avoid re-attacking
/// an account we control as though it were a lab target.
pub(crate) fn is_ghost_machine_account(username: &str) -> bool {
    let username = username.trim();
    GHOST_MACHINE_ACCOUNT_RE.is_match(username)
        || ares_tools::privesc::is_minted_machine_account(username)
}

pub(crate) use credentials::{dedup_credentials, sanitize_credentials};
pub(crate) use domains::{looks_like_workgroup_pseudo_domain, normalize_state_domains};
pub(crate) use hashes::dedup_hashes;
pub(crate) use labels::normalize_source_label;
pub(crate) use users::dedup_users;
