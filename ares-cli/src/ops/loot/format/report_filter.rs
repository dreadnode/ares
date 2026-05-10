//! Filters that decide which credentials and hashes are surfaced in the loot
//! JSON output consumed by external scoreboards (e.g. DreadGOAD).
//!
//! These are *report-boundary* filters, not state filters — internal logic
//! (Golden Ticket detection, dedup, etc.) still sees every credential and hash.
//! We drop entries here that would pollute the scoreboard with non-objective
//! noise: machine account hashes from NTDS dumps, local-SAM built-ins,
//! krbtgt (used internally as a Golden-Ticket signal, not a cred objective),
//! and Kerberoast/AS-REP hash blobs that have already been cracked into a
//! Credential row (the same user otherwise shows up twice — once verified
//! via the cracked password, once unmatched via the raw ticket blob).

use ares_core::models::{Credential, Hash};

/// Built-in / system accounts that aren't credit-worthy AD-user findings.
///
/// `krbtgt` is included because it's consumed internally by Golden Ticket
/// detection rather than tracked as a cred objective.
const NOISE_USERNAMES: &[&str] = &[
    "krbtgt",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
    "ssm-user",
    "ansible",
];

fn is_machine_account(username: &str) -> bool {
    username.ends_with('$')
}

fn is_noise_username(username: &str) -> bool {
    let lower = username.to_lowercase();
    NOISE_USERNAMES.iter().any(|n| *n == lower)
}

/// Local SAM accounts arrive with no domain (or a synthetic hostname) and
/// match a small set of well-known names. The bare `Administrator` account
/// is local-SAM-only when domain is empty; the actual Domain Admin always
/// carries a real FQDN, so this won't drop credit-worthy DA findings.
fn is_local_sam_builtin(username: &str, domain: &str) -> bool {
    if !domain.trim().is_empty() {
        return false;
    }
    matches!(
        username.to_lowercase().as_str(),
        "administrator" | "guest" | "defaultaccount" | "wdagutilityaccount"
    )
}

/// True if a credential should be surfaced in the loot JSON output.
pub(super) fn is_reportable_credential(c: &Credential) -> bool {
    let username = c.username.trim();
    if username.is_empty() {
        return false;
    }
    if is_machine_account(username) {
        return false;
    }
    if is_noise_username(username) {
        return false;
    }
    if is_local_sam_builtin(username, &c.domain) {
        return false;
    }
    true
}

/// True if a hash should be surfaced in the loot JSON output.
///
/// Hashes whose `cracked_password` is set are dropped because the cracked
/// form is already emitted as a Credential — keeping the hash too produces
/// a duplicate finding under the same `target` with a different `evidence`
/// string, which scoreboards count as a separate (unmatched) finding.
pub(super) fn is_reportable_hash(h: &Hash) -> bool {
    let username = h.username.trim();
    if username.is_empty() {
        return false;
    }
    if is_machine_account(username) {
        return false;
    }
    if is_noise_username(username) {
        return false;
    }
    if is_local_sam_builtin(username, &h.domain) {
        return false;
    }
    if h.cracked_password.is_some() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(username: &str, domain: &str) -> Credential {
        Credential {
            id: "id".into(),
            username: username.into(),
            password: "P@ssw0rd!".into(),
            domain: domain.into(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn hash(username: &str, domain: &str, cracked: Option<&str>) -> Hash {
        Hash {
            id: "id".into(),
            username: username.into(),
            hash_value: "deadbeef".into(),
            hash_type: "NTLM".into(),
            domain: domain.into(),
            cracked_password: cracked.map(String::from),
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }
    }

    #[test]
    fn keeps_real_user() {
        assert!(is_reportable_credential(&cred("alice", "contoso.local")));
        assert!(is_reportable_hash(&hash("alice", "contoso.local", None)));
    }

    #[test]
    fn drops_machine_accounts() {
        assert!(!is_reportable_credential(&cred("DC01$", "contoso.local")));
        assert!(!is_reportable_hash(&hash("DC01$", "contoso.local", None)));
        // Even with a domain attached — secretsdump tags machine accounts to
        // their host's FQDN, which is how the cross-domain duplicate appears.
        assert!(!is_reportable_hash(&hash(
            "DC02$",
            "child.contoso.local",
            None
        )));
    }

    #[test]
    fn drops_krbtgt() {
        assert!(!is_reportable_hash(&hash("krbtgt", "contoso.local", None)));
        assert!(!is_reportable_hash(&hash("KRBTGT", "contoso.local", None)));
    }

    #[test]
    fn drops_local_sam_builtins() {
        assert!(!is_reportable_credential(&cred("Guest", "")));
        assert!(!is_reportable_credential(&cred("DefaultAccount", "")));
        assert!(!is_reportable_credential(&cred("WDAGUtilityAccount", "")));
        // Empty-domain Administrator is local SAM, not Domain Admin.
        assert!(!is_reportable_credential(&cred("Administrator", "")));
    }

    #[test]
    fn keeps_domain_administrator() {
        // Real DA always carries the FQDN — must not be dropped.
        assert!(is_reportable_credential(&cred(
            "Administrator",
            "contoso.local"
        )));
    }

    #[test]
    fn drops_system_service_accounts() {
        assert!(!is_reportable_credential(&cred("ssm-user", "")));
        assert!(!is_reportable_credential(&cred(
            "ansible",
            "fabrikam.local"
        )));
    }

    #[test]
    fn drops_cracked_hash_to_avoid_double_count() {
        // Kerberoast/AS-REP blob whose password has been recovered: the cracked
        // form is already emitted as a Credential; keep it from showing up
        // twice in the loot report.
        assert!(!is_reportable_hash(&hash(
            "sql_svc",
            "fabrikam.local",
            Some("CrackedPW!")
        )));
        assert!(is_reportable_hash(&hash("sql_svc", "fabrikam.local", None)));
    }

    #[test]
    fn drops_empty_username() {
        assert!(!is_reportable_credential(&cred("", "contoso.local")));
        assert!(!is_reportable_hash(&hash("", "contoso.local", None)));
    }
}
