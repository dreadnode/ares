//! Teardown engine — reads an operation's mutation journal and reverses it.
//!
//! Order is LIFO (last mutation undone first), which is the safe default when
//! later mutations depend on earlier ones (e.g. an RBCD write onto a computer
//! this op created). Each inverse is executed in-process via
//! [`ares_tools::dispatch`] rather than the Redis worker queue, so teardown
//! works as a standalone command long after the operation's workers are gone.
//!
//! The authenticating secret is not journaled; it is re-resolved here from the
//! operation's credential store and hash store (both ride the same 24h TTL as
//! the journal) and injected into the inverse call. Plaintext is not required:
//! a domain is frequently owned only by pass-the-hash, and requiring a password
//! stranded every mutation made in one — observed live, where all three
//! cleanly-revertible mutations were skipped because the operation held 19 NTLM
//! hashes for that domain and zero passwords.

use anyhow::Result;
use redis::AsyncCommands;
use serde_json::Value;
use tracing::{info, warn};

use ares_core::models::{Credential, Hash};
use ares_core::state::RedisStateReader;

use super::journal;
use super::registry::{undo_plan, Reversibility, ValidateProbe};

/// Options controlling a teardown run.
#[derive(Debug, Clone, Default)]
pub struct TeardownOptions {
    /// Plan and print only; perform no target changes.
    pub dry_run: bool,
    /// Restrict to a single tool name (e.g. only revert `rbcd_write`).
    pub only: Option<String>,
}

/// What happened to one journaled mutation during teardown.
#[derive(Debug, Clone)]
enum EntryStatus {
    /// Dry-run: this is what would be done.
    Planned,
    /// Inverse dispatched and the tool reported success (no read-back probe).
    Reverted,
    /// Inverse succeeded AND an independent read-back confirmed the mutation
    /// is gone. This is the "proven" state.
    Verified,
    /// Inverse succeeded but the read-back could not confirm it (mutation still
    /// visible, or the probe errored). Carries the reason.
    Unverified(String),
    /// No automatic inverse (needs-capture / hard / impossible / unsupported),
    /// or a prerequisite (credential) was unavailable. Carries the reason.
    Skipped(String),
    /// Inverse was attempted and failed. Carries the error.
    Failed(String),
}

struct EntryResult {
    tool: String,
    target: String,
    class: Reversibility,
    note: String,
    status: EntryStatus,
}

/// Summary counts for a teardown run.
#[derive(Debug, Default)]
pub struct TeardownReport {
    pub total: usize,
    /// Reverted with no read-back probe available.
    pub reverted: usize,
    /// Reverted and independently proven gone.
    pub verified: usize,
    /// Reverted but the read-back could not confirm it.
    pub unverified: usize,
    pub skipped: usize,
    pub failed: usize,
    pub planned: usize,
}

impl TeardownReport {
    /// True when nothing was left un-reverted that we *could* have reverted —
    /// i.e. no failures. Callers map this to the process exit code.
    pub fn is_clean(&self) -> bool {
        self.failed == 0
    }
}

/// Read the journal and reverse it (or, with `dry_run`, print the plan).
pub async fn run_teardown(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    opts: &TeardownOptions,
) -> Result<TeardownReport> {
    let mut records = journal::read_all(conn, operation_id).await?;
    // LIFO: undo the most recent mutation first.
    records.reverse();
    if let Some(only) = &opts.only {
        records.retain(|r| &r.tool == only);
    }

    if records.is_empty() {
        println!("No journaled mutations for operation {operation_id} — nothing to revert.");
        return Ok(TeardownReport::default());
    }

    // Auth material is only needed for real reverts. Hashes count: a domain
    // owned purely by pass-the-hash is the common case, not the exception.
    let (credentials, hashes) = if opts.dry_run {
        (Vec::new(), Vec::new())
    } else {
        let reader = RedisStateReader::new(operation_id.to_string());
        let credentials = reader.get_credentials(conn).await.unwrap_or_default();
        let hashes = reader.get_hashes(conn).await.unwrap_or_default();
        (credentials, hashes)
    };

    let mode = if opts.dry_run { "DRY-RUN" } else { "TEARDOWN" };
    println!(
        "\n{mode}: {n} journaled mutation(s) for {operation_id} (reverse order)\n",
        n = records.len()
    );

    let mut results = Vec::with_capacity(records.len());
    for record in &records {
        let plan = undo_plan(record);
        let target = record.target.clone().unwrap_or_else(|| "?".into());

        let status = if opts.dry_run {
            EntryStatus::Planned
        } else {
            match plan.inverse.clone() {
                None => EntryStatus::Skipped(format!("{}: {}", plan.class.label(), plan.note)),
                Some((tool, args)) => {
                    match execute_inverse(record, &tool, args, &credentials, &hashes).await {
                        // Revert succeeded — try to prove it with a read-back.
                        EntryStatus::Reverted => match &plan.validate {
                            Some(probe) => {
                                validate_revert(record, probe, &credentials, &hashes).await
                            }
                            None => EntryStatus::Reverted,
                        },
                        other => other,
                    }
                }
            }
        };

        print_entry(&record.tool, &target, plan.class, &plan.note, &status);
        results.push(EntryResult {
            tool: record.tool.clone(),
            target,
            class: plan.class,
            note: plan.note,
            status,
        });
    }

    let report = summarize(&results);
    print_summary(&results, &report, opts.dry_run);
    Ok(report)
}

/// Resolve a credential and dispatch the inverse tool in-process.
async fn execute_inverse(
    record: &journal::MutationRecord,
    tool: &str,
    mut args: Value,
    credentials: &[Credential],
    hashes: &[Hash],
) -> EntryStatus {
    let username = record.username.as_deref().unwrap_or("");
    let domain = record.domain.as_deref().unwrap_or("");
    let Some(auth) = resolve_auth(credentials, hashes, username, domain) else {
        return EntryStatus::Skipped(format!(
            "no usable password or hash for {domain} in the operation store"
        ));
    };
    inject_auth(&mut args, &auth);

    match ares_tools::dispatch(tool, &args).await {
        Ok(out) if out.success => {
            info!(tool, "teardown: inverse succeeded");
            EntryStatus::Reverted
        }
        Ok(out) => EntryStatus::Failed(failure_reason(&out.combined())),
        Err(e) => EntryStatus::Failed(e.to_string()),
    }
}

/// Independent read-back: dispatch the probe and confirm the mutation is gone.
///
/// Verified when the probe's `expect_absent` needle is NOT present in a
/// successful read (attribute no longer lists it), or the read fails to return
/// the object at all (object deleted). Unverified when the needle is still
/// visible in a successful read, or the probe itself errored.
async fn validate_revert(
    record: &journal::MutationRecord,
    probe: &ValidateProbe,
    credentials: &[Credential],
    hashes: &[Hash],
) -> EntryStatus {
    let mut args = probe.args.clone();
    let username = record.username.as_deref().unwrap_or("");
    let domain = record.domain.as_deref().unwrap_or("");
    if let Some(auth) = resolve_auth(credentials, hashes, username, domain) {
        inject_auth(&mut args, &auth);
    }

    match ares_tools::dispatch(&probe.tool, &args).await {
        Ok(out) => match &probe.expect_absent {
            Some(needle) if out.success && out.combined().contains(needle.as_str()) => {
                EntryStatus::Unverified(format!("read-back still shows '{needle}'"))
            }
            _ => EntryStatus::Verified,
        },
        Err(e) => EntryStatus::Unverified(format!("probe failed: {e}")),
    }
}

/// Auth material teardown can present for a revert.
///
/// The ACL/privesc tools accept `ticket_path` > `hash` > `password` (see
/// `ares_tools::credentials`), so a hash-only foothold authenticates exactly
/// like a plaintext one.
enum TeardownAuth<'a> {
    Password(&'a Credential),
    Hash(&'a Hash),
}

impl TeardownAuth<'_> {
    fn username(&self) -> &str {
        match self {
            TeardownAuth::Password(c) => &c.username,
            TeardownAuth::Hash(h) => &h.username,
        }
    }

    fn domain(&self) -> &str {
        match self {
            TeardownAuth::Password(c) => &c.domain,
            TeardownAuth::Hash(h) => &h.domain,
        }
    }
}

/// Resolve auth material able to perform a revert in `domain`.
///
/// Privileged material in the domain is preferred over the mutating principal's
/// own. Reverting needs *rights*, not the original identity, and the forward
/// principal frequently lacks them: impacket refused three machine-account
/// deletions with `User <u> doesn't have right to delete <c>$!` because the
/// account that created them could not remove them. A domain admin can always
/// undo what the operation did, so teardown reaches for one first and falls
/// back to the mutating principal only when none is held.
///
/// The domain filter is never relaxed. Authenticating into one domain with
/// another's credential is not a fallback, it is a different operation.
fn resolve_auth<'a>(
    credentials: &'a [Credential],
    hashes: &'a [Hash],
    username: &str,
    domain: &str,
) -> Option<TeardownAuth<'a>> {
    let user_l = username.to_lowercase();
    let domain_l = domain.to_lowercase();

    let cred_in_domain =
        |c: &&Credential| domain_l.is_empty() || c.domain.to_lowercase() == domain_l;
    let cred_usable = |c: &&Credential| !c.password.trim().is_empty();
    let hash_in_domain = |h: &&Hash| domain_l.is_empty() || h.domain.to_lowercase() == domain_l;
    let hash_usable = |h: &&Hash| {
        crate::orchestrator::acl_graph::is_usable_hash(h) && !h.is_trust_key && !h.is_previous
    };

    // A hash we hold for the domain's built-in Administrator is the most
    // reliable revert identity available; krbtgt is excluded because it cannot
    // be used to authenticate.
    let privileged_password = || {
        credentials
            .iter()
            .filter(cred_usable)
            .filter(cred_in_domain)
            .filter(|c| c.is_admin)
            .max_by_key(|c| c.attack_step)
            .map(TeardownAuth::Password)
    };
    let privileged_hash = || {
        hashes
            .iter()
            .filter(hash_usable)
            .filter(hash_in_domain)
            .filter(|h| h.username.eq_ignore_ascii_case("administrator"))
            .max_by_key(|h| h.attack_step)
            .map(TeardownAuth::Hash)
    };
    let own_password = || {
        credentials
            .iter()
            .filter(cred_usable)
            .filter(|c| c.username.to_lowercase() == user_l)
            .filter(cred_in_domain)
            .max_by_key(|c| c.attack_step)
            .map(TeardownAuth::Password)
    };
    let own_hash = || {
        hashes
            .iter()
            .filter(hash_usable)
            .filter(|h| h.username.to_lowercase() == user_l)
            .filter(hash_in_domain)
            .max_by_key(|h| h.attack_step)
            .map(TeardownAuth::Hash)
    };
    let any_password = || {
        credentials
            .iter()
            .filter(cred_usable)
            .filter(cred_in_domain)
            .max_by_key(|c| (c.is_admin, c.attack_step))
            .map(TeardownAuth::Password)
    };
    let any_hash = || {
        hashes
            .iter()
            .filter(hash_usable)
            .filter(hash_in_domain)
            .max_by_key(|h| h.attack_step)
            .map(TeardownAuth::Hash)
    };

    privileged_password()
        .or_else(privileged_hash)
        .or_else(own_password)
        .or_else(own_hash)
        .or_else(any_password)
        .or_else(any_hash)
}

/// Inject the resolved secret so `ares_tools::dispatch` can authenticate.
///
/// `username` is overwritten, not defaulted: when the mutating principal is
/// unavailable the resolved material belongs to a *different* account, and
/// leaving the forward call's username in place would authenticate one
/// identity's secret against another's name.
fn inject_auth(args: &mut Value, auth: &TeardownAuth<'_>) {
    let Some(obj) = args.as_object_mut() else {
        return;
    };
    obj.insert(
        "username".into(),
        Value::String(auth.username().to_string()),
    );
    if !auth.domain().is_empty() {
        obj.insert("domain".into(), Value::String(auth.domain().to_string()));
    }
    match auth {
        TeardownAuth::Password(c) => {
            obj.remove("hash");
            obj.insert("password".into(), Value::String(c.password.clone()));
        }
        TeardownAuth::Hash(h) => {
            obj.remove("password");
            obj.insert("hash".into(), Value::String(h.hash_value.clone()));
        }
    }
}

fn summarize(results: &[EntryResult]) -> TeardownReport {
    let mut r = TeardownReport {
        total: results.len(),
        ..Default::default()
    };
    for e in results {
        match e.status {
            EntryStatus::Planned => r.planned += 1,
            EntryStatus::Reverted => r.reverted += 1,
            EntryStatus::Verified => r.verified += 1,
            EntryStatus::Unverified(_) => r.unverified += 1,
            EntryStatus::Skipped(_) => r.skipped += 1,
            EntryStatus::Failed(_) => r.failed += 1,
        }
    }
    r
}

fn print_entry(tool: &str, target: &str, class: Reversibility, note: &str, status: &EntryStatus) {
    let (marker, detail) = match status {
        EntryStatus::Planned => ("plan", note.to_string()),
        EntryStatus::Reverted => ("ok  ", "reverted (no read-back probe)".to_string()),
        EntryStatus::Verified => ("ok  ", "reverted + verified".to_string()),
        EntryStatus::Unverified(why) => ("warn", format!("reverted, UNVERIFIED: {why}")),
        EntryStatus::Skipped(why) => ("skip", why.clone()),
        EntryStatus::Failed(why) => ("FAIL", why.clone()),
    };
    println!(
        "  [{marker}] {tool:<28} {class:<14} {target:<22} {detail}",
        class = class.label()
    );
}

fn print_summary(results: &[EntryResult], report: &TeardownReport, dry_run: bool) {
    println!();
    if dry_run {
        println!(
            "Plan: {} mutation(s). Re-run without --dry-run to revert.",
            report.planned
        );
        return;
    }

    println!(
        "Teardown complete: {} verified, {} reverted (unprobed), {} unverified, {} skipped, {} failed (of {}).",
        report.verified,
        report.reverted,
        report.unverified,
        report.skipped,
        report.failed,
        report.total
    );

    // Surface everything that was NOT cleanly proven-reverted so the operator
    // knows exactly what still needs a manual scrub or a range rebuild.
    let attention: Vec<&EntryResult> = results
        .iter()
        .filter(|e| {
            matches!(
                e.status,
                EntryStatus::Failed(_) | EntryStatus::Skipped(_) | EntryStatus::Unverified(_)
            ) || matches!(e.class, Reversibility::Hard | Reversibility::Impossible)
        })
        .collect();
    if !attention.is_empty() {
        println!("\nNeeds attention (not auto-reverted):");
        for e in attention {
            println!(
                "  - {tool} [{class}] on {target}: {note}",
                tool = e.tool,
                class = e.class.label(),
                target = e.target,
                note = e.note
            );
        }
    }

    if report.failed > 0 {
        warn!(
            failed = report.failed,
            "teardown left un-reverted mutations — review FAIL entries above"
        );
    }
}

/// Best-effort one-line reason for a failed revert.
///
/// Not simply the first line: the tools we drive lead with boilerplate that
/// hides the diagnosis. impacket prints its version banner, and argparse prints
/// a multi-line `usage:` block whose actual complaint is the *last* line. A
/// teardown failure reported as `usage: pywhisker [-h] (-t TARGET_SAMNAME …` is
/// indistinguishable from a missing argument, when the real cause was
/// "argument --no-pass: not allowed with -H/--hashes".
///
/// So prefer a line that looks like a diagnosis — impacket's `[-]` marker or an
/// explicit error/failure word — then fall back to the last non-empty line, and
/// only then to the first.
fn failure_reason(s: &str) -> String {
    let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();

    let is_boilerplate = |l: &str| {
        let lower = l.to_lowercase();
        lower.starts_with("impacket v")
            || lower.starts_with("usage:")
            || lower.starts_with("copyright")
            || lower.starts_with("options:")
            || lower.starts_with("positional arguments")
    };
    let is_diagnosis = |l: &str| {
        let lower = l.to_lowercase();
        l.starts_with("[-]")
            || lower.contains("error")
            || lower.contains("not allowed with")
            || lower.contains("failed")
            || lower.contains("denied")
            || lower.contains("doesn't have right")
    };

    let pick = lines
        .iter()
        .find(|l| is_diagnosis(l))
        .or_else(|| lines.iter().rev().find(|l| !is_boilerplate(l)))
        .or_else(|| lines.first())
        .copied()
        .unwrap_or("");

    pick.chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cred(user: &str, domain: &str, pw: &str, step: i32) -> Credential {
        Credential {
            id: "id".into(),
            username: user.into(),
            password: pw.into(),
            domain: domain.into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: step,
        }
    }

    fn nthash(user: &str, domain: &str, step: i32) -> Hash {
        Hash {
            id: format!("h-{user}"),
            username: user.into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            hash_type: "ntlm".into(),
            domain: domain.into(),
            cracked_password: None,
            source: "secretsdump".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: step,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn pw_of(auth: &TeardownAuth<'_>) -> Option<String> {
        match auth {
            TeardownAuth::Password(c) => Some(c.password.clone()),
            TeardownAuth::Hash(_) => None,
        }
    }

    #[test]
    fn resolve_prefers_latest_attack_step() {
        let creds = vec![
            cred("alice", "contoso.local", "old", 1),
            cred("alice", "contoso.local", "new", 5),
        ];
        let got = resolve_auth(&creds, &[], "alice", "contoso.local").unwrap();
        assert_eq!(pw_of(&got).as_deref(), Some("new"));
    }

    #[test]
    fn resolve_is_case_insensitive() {
        let creds = vec![cred("Alice", "CONTOSO.LOCAL", "pw", 1)];
        assert!(resolve_auth(&creds, &[], "alice", "contoso.local").is_some());
    }

    #[test]
    fn resolve_falls_back_to_another_principal_in_the_same_domain() {
        let creds = vec![cred("bob", "contoso.local", "pw", 1)];
        let got = resolve_auth(&creds, &[], "alice", "contoso.local")
            .expect("must fall back rather than skip the revert");
        assert_eq!(got.username(), "bob");
    }

    #[test]
    fn resolve_fallback_prefers_an_admin() {
        let mut admin = cred("carol", "contoso.local", "pw-admin", 1);
        admin.is_admin = true;
        let creds = vec![cred("bob", "contoso.local", "pw-user", 9), admin];
        let got = resolve_auth(&creds, &[], "alice", "contoso.local").unwrap();
        assert_eq!(pw_of(&got).as_deref(), Some("pw-admin"));
    }

    #[test]
    fn resolve_never_crosses_domains_even_for_a_hash() {
        let creds = vec![cred("bob", "fabrikam.local", "pw", 1)];
        let hashes = vec![nthash("carol", "fabrikam.local", 3)];
        assert!(
            resolve_auth(&creds, &hashes, "alice", "contoso.local").is_none(),
            "material from another domain must never be used to revert"
        );
    }

    /// The live failure this exists for: the operation owned the domain by
    /// pass-the-hash only, so a password-only resolver skipped every revert.
    #[test]
    fn resolve_uses_a_hash_when_the_domain_has_no_plaintext() {
        let hashes = vec![nthash("administrator", "contoso.local", 4)];
        let got = resolve_auth(&[], &hashes, "alice", "contoso.local")
            .expect("a hash-only domain must still be revertible");
        assert_eq!(got.username(), "administrator");
        assert!(matches!(got, TeardownAuth::Hash(_)));
    }

    /// The live failure: impacket refused three machine-account deletions with
    /// "doesn't have right to delete" because teardown authenticated as the
    /// principal that made the mutation rather than one that could undo it.
    #[test]
    fn failure_reason_skips_impacket_and_argparse_boilerplate() {
        // The exact shape teardown reported as a pywhisker failure: argparse
        // leads with usage and states the real complaint last.
        let out = "usage: pywhisker [-h] (-t TARGET_SAMNAME | -tl TARGET_SAMNAME_LIST)\n\
                   [-td TARGET_DOMAIN] [--no-pass | -p PASSWORD]\n\
                   pywhisker: error: argument --no-pass: not allowed with -H/--hashes";
        let got = failure_reason(out);
        assert!(got.contains("not allowed with"), "got: {got}");
        assert!(!got.starts_with("usage:"), "got: {got}");
    }

    #[test]
    fn failure_reason_prefers_impacket_diagnosis_over_version_banner() {
        let out = "Impacket v0.13.0.dev0 - Copyright Fortra, LLC\n\n\
                   [-] User alice doesn\'t have right to delete WS01$!";
        let got = failure_reason(out);
        assert!(got.starts_with("[-]"), "got: {got}");
    }

    #[test]
    fn failure_reason_falls_back_to_the_last_meaningful_line() {
        let out = "Impacket v0.13.0 - Copyright Fortra\nsomething unhelpful happened";
        assert_eq!(failure_reason(out), "something unhelpful happened");
    }

    #[test]
    fn resolve_prefers_a_domain_admin_over_the_mutating_principal() {
        let mut admin = cred("administrator", "contoso.local", "pw-admin", 1);
        admin.is_admin = true;
        let creds = vec![cred("alice", "contoso.local", "pw-alice", 9), admin];
        let got = resolve_auth(&creds, &[], "alice", "contoso.local").unwrap();
        assert_eq!(got.username(), "administrator");
    }

    #[test]
    fn resolve_prefers_an_administrator_hash_over_a_plain_users_password() {
        let creds = vec![cred("alice", "contoso.local", "pw-alice", 9)];
        let hashes = vec![nthash("Administrator", "contoso.local", 1)];
        let got = resolve_auth(&creds, &hashes, "alice", "contoso.local").unwrap();
        assert!(matches!(got, TeardownAuth::Hash(_)));
        assert_eq!(got.username(), "Administrator");
    }

    #[test]
    fn resolve_prefers_the_principals_own_password_over_any_hash() {
        let creds = vec![cred("alice", "contoso.local", "pw-alice", 1)];
        let hashes = vec![nthash("alice", "contoso.local", 9)];
        let got = resolve_auth(&creds, &hashes, "alice", "contoso.local").unwrap();
        assert_eq!(pw_of(&got).as_deref(), Some("pw-alice"));
    }

    #[test]
    fn resolve_prefers_own_hash_over_another_principals_password() {
        let creds = vec![cred("bob", "contoso.local", "pw-bob", 9)];
        let hashes = vec![nthash("alice", "contoso.local", 1)];
        let got = resolve_auth(&creds, &hashes, "alice", "contoso.local").unwrap();
        assert_eq!(got.username(), "alice");
    }

    #[test]
    fn resolve_skips_trust_keys_and_previous_hashes() {
        let mut trust = nthash("contoso$", "contoso.local", 5);
        trust.is_trust_key = true;
        let mut previous = nthash("alice", "contoso.local", 5);
        previous.is_previous = true;
        assert!(resolve_auth(&[], &[trust, previous], "alice", "contoso.local").is_none());
    }

    #[test]
    fn inject_auth_overwrites_the_username_it_authenticates_as() {
        // The fallback resolves a different principal; leaving the forward
        // call's username would send one identity's secret under another's name.
        let mut args = json!({ "username": "alice", "domain": "contoso.local" });
        let bob = cred("bob", "contoso.local", "pw", 1);
        inject_auth(&mut args, &TeardownAuth::Password(&bob));
        assert_eq!(args["username"], json!("bob"));
        assert_eq!(args["password"], json!("pw"));
    }

    #[test]
    fn inject_auth_uses_the_hash_key_and_clears_any_password() {
        let mut args = json!({ "username": "alice", "password": "stale" });
        let h = nthash("administrator", "contoso.local", 1);
        inject_auth(&mut args, &TeardownAuth::Hash(&h));
        assert_eq!(args["username"], json!("administrator"));
        assert_eq!(args["hash"], json!(h.hash_value));
        assert!(
            args.get("password").is_none(),
            "a stale password must not ride along with a hash"
        );
    }

    #[test]
    fn inject_auth_sets_the_authenticating_principals_own_domain() {
        // resolve_auth never crosses domains, so the resolved material's domain
        // is the record's. Writing it rather than preserving whatever the
        // forward args carried keeps the injected triple internally consistent.
        let mut args = json!({ "username": "alice", "domain": "stale.local" });
        let alice = cred("alice", "contoso.local", "pw", 1);
        inject_auth(&mut args, &TeardownAuth::Password(&alice));
        assert_eq!(args["password"], json!("pw"));
        assert_eq!(args["domain"], json!("contoso.local"));
    }
}
