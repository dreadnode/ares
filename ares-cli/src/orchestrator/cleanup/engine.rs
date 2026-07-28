//! Teardown engine — reads an operation's mutation journal and reverses it.
//!
//! Order is LIFO (last mutation undone first), which is the safe default when
//! later mutations depend on earlier ones (e.g. an RBCD write onto a computer
//! this op created). Each inverse is executed in-process via
//! [`ares_tools::dispatch`] rather than the Redis worker queue, so teardown
//! works as a standalone command long after the operation's workers are gone.
//!
//! The authenticating secret is not journaled; it is re-resolved here from the
//! operation's credential store (which rides the same 24h TTL as the journal)
//! and injected into the inverse call — [`ares_tools::dispatch`] rejects
//! placeholder secrets, so a real password is required.

use anyhow::Result;
use redis::AsyncCommands;
use serde_json::Value;
use tracing::{info, warn};

use ares_core::models::Credential;
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

    // Credentials are only needed for real reverts.
    let credentials = if opts.dry_run {
        Vec::new()
    } else {
        RedisStateReader::new(operation_id.to_string())
            .get_credentials(conn)
            .await
            .unwrap_or_default()
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
                    match execute_inverse(record, &tool, args, &credentials).await {
                        // Revert succeeded — try to prove it with a read-back.
                        EntryStatus::Reverted => match &plan.validate {
                            Some(probe) => validate_revert(record, probe, &credentials).await,
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
) -> EntryStatus {
    let username = record.username.as_deref().unwrap_or("");
    let domain = record.domain.as_deref().unwrap_or("");
    let Some(cred) = resolve_credential(credentials, username, domain) else {
        return EntryStatus::Skipped(format!(
            "no usable credential for {username}@{domain} in the operation store"
        ));
    };
    inject_auth(&mut args, cred);

    match ares_tools::dispatch(tool, &args).await {
        Ok(out) if out.success => {
            info!(tool, "teardown: inverse succeeded");
            EntryStatus::Reverted
        }
        Ok(out) => EntryStatus::Failed(first_line(&out.combined())),
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
) -> EntryStatus {
    let mut args = probe.args.clone();
    let username = record.username.as_deref().unwrap_or("");
    let domain = record.domain.as_deref().unwrap_or("");
    if let Some(cred) = resolve_credential(credentials, username, domain) {
        inject_auth(&mut args, cred);
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

/// Case-insensitive username+domain match over the operation's credentials,
/// skipping empty/placeholder passwords, preferring the latest attack step.
///
/// Falls back to any usable credential in the same domain when the original
/// principal's secret is not in the store. Reverting needs *rights*, not the
/// original identity, and the forward principal is frequently unavailable at
/// teardown: it was reached by hash or ticket, or its plaintext was never
/// recovered. Without the fallback those mutations are skipped and left on the
/// target — observed live, where a machine account survived teardown because
/// the account that created it had no password in the store.
fn resolve_credential<'a>(
    credentials: &'a [Credential],
    username: &str,
    domain: &str,
) -> Option<&'a Credential> {
    let user_l = username.to_lowercase();
    let domain_l = domain.to_lowercase();
    let in_domain = |c: &&Credential| domain_l.is_empty() || c.domain.to_lowercase() == domain_l;
    let usable = |c: &&Credential| !c.password.trim().is_empty();

    credentials
        .iter()
        .filter(usable)
        .filter(|c| c.username.to_lowercase() == user_l)
        .filter(in_domain)
        .max_by_key(|c| c.attack_step)
        .or_else(|| {
            credentials
                .iter()
                .filter(usable)
                .filter(in_domain)
                .max_by_key(|c| (c.is_admin, c.attack_step))
        })
}

/// Inject the resolved secret so `ares_tools::dispatch` can authenticate.
fn inject_auth(args: &mut Value, cred: &Credential) {
    if let Some(obj) = args.as_object_mut() {
        obj.insert("password".into(), Value::String(cred.password.clone()));
        if !cred.domain.is_empty() {
            obj.entry("domain".to_string())
                .or_insert_with(|| Value::String(cred.domain.clone()));
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

fn first_line(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(160)
        .collect()
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

    #[test]
    fn resolve_prefers_latest_attack_step() {
        let creds = vec![
            cred("alice", "contoso.local", "old", 1),
            cred("alice", "contoso.local", "new", 5),
        ];
        let got = resolve_credential(&creds, "alice", "contoso.local").unwrap();
        assert_eq!(got.password, "new");
    }

    #[test]
    fn resolve_skips_empty_password() {
        let creds = vec![cred("alice", "contoso.local", "", 9)];
        assert!(resolve_credential(&creds, "alice", "contoso.local").is_none());
    }

    #[test]
    fn resolve_is_case_insensitive() {
        let creds = vec![cred("Alice", "CONTOSO.LOCAL", "pw", 1)];
        assert!(resolve_credential(&creds, "alice", "contoso.local").is_some());
    }

    #[test]
    fn resolve_falls_back_to_another_principal_in_the_same_domain() {
        // The account that made the mutation is often unreachable at teardown
        // (owned by hash or ticket, never by plaintext). Reverting needs
        // rights, not that identity.
        let creds = vec![cred("bob", "contoso.local", "pw", 1)];
        let got = resolve_credential(&creds, "alice", "contoso.local")
            .expect("must fall back rather than skip the revert");
        assert_eq!(got.username, "bob");
    }

    #[test]
    fn resolve_fallback_prefers_an_admin() {
        let mut admin = cred("carol", "contoso.local", "pw-admin", 1);
        admin.is_admin = true;
        let creds = vec![cred("bob", "contoso.local", "pw-user", 9), admin];
        let got = resolve_credential(&creds, "alice", "contoso.local").unwrap();
        assert_eq!(got.password, "pw-admin");
    }

    #[test]
    fn resolve_fallback_never_crosses_domains() {
        let creds = vec![cred("bob", "fabrikam.local", "pw", 1)];
        assert!(
            resolve_credential(&creds, "alice", "contoso.local").is_none(),
            "a credential from another domain must not be used to revert"
        );
    }

    #[test]
    fn resolve_exact_principal_still_wins_over_fallback() {
        let creds = vec![
            cred("bob", "contoso.local", "pw-bob", 9),
            cred("alice", "contoso.local", "pw-alice", 1),
        ];
        let got = resolve_credential(&creds, "alice", "contoso.local").unwrap();
        assert_eq!(got.password, "pw-alice");
    }

    #[test]
    fn inject_auth_sets_password_and_preserves_domain() {
        let mut args = json!({ "username": "alice", "domain": "contoso.local" });
        inject_auth(&mut args, &cred("alice", "other.local", "pw", 1));
        assert_eq!(args["password"], json!("pw"));
        // existing domain not overwritten
        assert_eq!(args["domain"], json!("contoso.local"));
    }
}
