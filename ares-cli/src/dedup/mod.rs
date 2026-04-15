pub(crate) mod credentials;
pub(crate) mod domains;
pub(crate) mod hashes;
pub(crate) mod labels;
pub(crate) mod users;

#[cfg(test)]
mod tests;

/// Strip trailing DNS root dot from domain strings (e.g. `child.contoso.local.` → `child.contoso.local`).
pub(super) fn strip_trailing_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

pub(crate) use credentials::{dedup_credentials, sanitize_credentials};
pub(crate) use domains::normalize_state_domains;
pub(crate) use hashes::dedup_hashes;
pub(crate) use labels::normalize_source_label;
pub(crate) use users::dedup_users;
