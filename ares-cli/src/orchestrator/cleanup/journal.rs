//! Mutation journal — a durable, per-operation record of every tool call that
//! left persistent state on a target (a new computer object, an RBCD write, a
//! reset password, an enabled `xp_cmdshell`, …).
//!
//! The journal is the source of truth for teardown: [`crate::orchestrator::cleanup`]
//! reads it back (LIFO) and dispatches the inverse of each entry. Entries are
//! appended by [`JournalingToolDispatcher`](super::dispatcher::JournalingToolDispatcher),
//! a decorator that wraps the operation's `ToolDispatcher` so BOTH LLM-driven
//! and deterministic tool calls are captured through the one choke point.
//!
//! Storage: `ares:op:{op_id}:mutation_journal`, a Redis LIST of JSON records,
//! one RPUSH per successful mutation. It rides the same 24h retention TTL
//! [`ares_core::state::finalize_operation`] applies to every `ares:op:{id}:*`
//! key, so a standalone `ares ops teardown <op-id>` still works long after the
//! orchestrator process is gone (including after a SIGKILL that skipped the
//! in-process post-op pass).

use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use ares_core::state::build_key;

/// Redis key suffix (see module docs). Distinct from `ops cleanup`, which is
/// unrelated Redis-key retention GC.
pub const KEY_MUTATION_JOURNAL: &str = "mutation_journal";

/// Tools known to leave persistent state on a target. Only these are journaled;
/// read-only enumeration and offline forges (golden ticket, certipy find,
/// secretsdump) are not. Every name here is classified by
/// [`super::registry::undo_plan`] — CLEAN ones auto-revert, the rest are
/// surfaced in the teardown report even when they can't be reversed yet.
const MUTATING_TOOLS: &[&str] = &[
    "add_computer",
    "rbcd_write",
    "dacl_edit",
    "bloodyad_add_group_member",
    "bloodyad_add_genericall",
    "bloodyad_set_password",
    "bloodyad_set_object_attr",
    "adminsd_holder_add_ace",
    "addspn",
    "pywhisker",
    "certipy_ca",
    "certipy_template_esc4",
    "certipy_account_update",
    "mssql_enable_xp_cmdshell",
    "pygpoabuse_immediate_task",
    "sharpgpoabuse",
    "nopac",
    "krbrelayup",
];

/// Whether a tool call should be recorded in the mutation journal.
pub fn is_mutating(tool: &str) -> bool {
    MUTATING_TOOLS.contains(&tool)
}

/// One persistent mutation performed against a target during an operation.
///
/// Records *intent* (the forward tool + its arguments + who/where), not the
/// authenticating secret. Secrets are stripped at record time via
/// [`ares_tools::credentials::CREDENTIAL_KEYS`]: LLM-issued calls never carry
/// them, but deterministic automation builds its own argument objects above the
/// journaling decorator and does. Teardown re-resolves a usable secret from the
/// operation's credential store at revert time, so nothing depends on them
/// surviving here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationRecord {
    /// RFC3339 timestamp of when the mutation succeeded.
    pub ts: String,
    /// Tool name as dispatched (e.g. `rbcd_write`, `bloodyad_set_password`).
    pub tool: String,
    /// Agent role that issued the call, for provenance.
    #[serde(default)]
    pub role: String,
    /// Parent task id, for provenance.
    #[serde(default)]
    pub task_id: String,
    /// Best-effort target extracted from the forward arguments
    /// (`target` / `target_ip` / `dc_ip` / `host`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Principal that performed the mutation, from the forward arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Domain of the performing principal, from the forward arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Forward arguments with every credential-bearing key removed.
    pub args: Value,
    /// Prior-state captured at forward time to enable a faithful revert
    /// (pywhisker DeviceID, original UPN/attribute value, saved-template path).
    /// Populated in the capture-required phase; `None` for CLEAN tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<Value>,
}

impl MutationRecord {
    /// Build a record from a dispatched tool call, pulling target/principal
    /// hints out of the argument object.
    pub fn from_call(role: &str, task_id: &str, tool: &str, args: &Value) -> Self {
        Self {
            ts: Utc::now().to_rfc3339(),
            tool: tool.to_string(),
            role: role.to_string(),
            task_id: task_id.to_string(),
            target: extract_first(args, &["target", "target_ip", "dc_ip", "host", "hostname"]),
            username: extract_first(args, &["username", "user"]),
            domain: extract_first(args, &["domain", "target_domain"]),
            args: strip_credentials(args),
            hint: None,
        }
    }
}

/// Drop every credential-bearing key from a forward argument object.
///
/// No `undo_plan` reads any of them — teardown's `inject_auth` supplies fresh
/// material at revert time. Stripping `ticket_path` also closes a latent bug:
/// the tools resolve auth `ticket_path` > `hash` > `password`, so a stale
/// journalled ccache path would outrank the secret teardown just resolved.
fn strip_credentials(args: &Value) -> Value {
    let Some(obj) = args.as_object() else {
        return args.clone();
    };
    Value::Object(
        obj.iter()
            .filter(|(k, _)| {
                !ares_tools::credentials::CREDENTIAL_KEYS
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(k))
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

/// Pull the first present, non-empty string value among `keys` from a JSON object.
fn extract_first(args: &Value, keys: &[&str]) -> Option<String> {
    let obj = args.as_object()?;
    for k in keys {
        if let Some(s) = obj.get(*k).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Append a mutation to the operation's journal. Best-effort: a Redis failure
/// is logged and swallowed so journaling can never fail the tool call it
/// observes. Cloning the multiplexed connection is cheap (shared pipe).
pub async fn append(
    conn: &redis::aio::ConnectionManager,
    operation_id: &str,
    record: &MutationRecord,
) {
    let key = build_key(operation_id, KEY_MUTATION_JOURNAL);
    let data = match serde_json::to_string(record) {
        Ok(d) => d,
        Err(e) => {
            warn!(tool = %record.tool, error = %e, "mutation-journal: serialize failed");
            return;
        }
    };
    let mut c = conn.clone();
    if let Err(e) = c.rpush::<_, _, ()>(&key, data).await {
        warn!(tool = %record.tool, error = %e, "mutation-journal: append failed");
    }
}

/// Read the full journal for an operation in chronological (append) order.
pub async fn read_all(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> anyhow::Result<Vec<MutationRecord>> {
    let key = build_key(operation_id, KEY_MUTATION_JOURNAL);
    let raw: Vec<String> = conn.lrange(&key, 0, -1).await?;
    Ok(raw
        .iter()
        .filter_map(|s| match serde_json::from_str::<MutationRecord>(s) {
            Ok(r) => Some(r),
            Err(e) => {
                warn!(error = %e, "mutation-journal: skipping unparsable entry");
                None
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_call_extracts_target_and_principal() {
        let args = json!({
            "target_ip": "192.168.58.10",
            "username": "alice",
            "domain": "contoso.local",
            "delegate_to": "dc01$",
        });
        let r = MutationRecord::from_call("privesc", "task-1", "rbcd_write", &args);
        assert_eq!(r.tool, "rbcd_write");
        assert_eq!(r.target.as_deref(), Some("192.168.58.10"));
        assert_eq!(r.username.as_deref(), Some("alice"));
        assert_eq!(r.domain.as_deref(), Some("contoso.local"));
        assert!(r.hint.is_none());
    }

    #[test]
    fn from_call_prefers_target_over_target_ip() {
        let args = json!({ "target": "dc01.contoso.local", "target_ip": "192.168.58.10" });
        let r = MutationRecord::from_call("acl", "t", "dacl_edit", &args);
        assert_eq!(r.target.as_deref(), Some("dc01.contoso.local"));
    }

    #[test]
    fn extract_first_skips_empty() {
        let args = json!({ "target": "", "target_ip": "192.168.58.10" });
        assert_eq!(
            extract_first(&args, &["target", "target_ip"]).as_deref(),
            Some("192.168.58.10")
        );
    }

    #[test]
    fn record_roundtrips_through_json() {
        let args = json!({ "target_ip": "192.168.58.10", "username": "bob" });
        let r = MutationRecord::from_call("privesc", "t", "add_computer", &args);
        let s = serde_json::to_string(&r).unwrap();
        let back: MutationRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back.tool, "add_computer");
        assert_eq!(back.target.as_deref(), Some("192.168.58.10"));
    }

    /// Deterministic automation builds its own argument objects above the
    /// journaling decorator and puts real cleartext in them, so the journal
    /// would otherwise hold domain credentials in Redis for the full retention
    /// window, outside redaction.
    #[test]
    fn from_call_strips_every_credential_key() {
        let mut args = serde_json::Map::new();
        args.insert("domain".into(), json!("contoso.local"));
        for key in ares_tools::credentials::CREDENTIAL_KEYS {
            args.insert((*key).to_string(), json!("P@ssw0rd!"));
        }

        let r = MutationRecord::from_call(
            "acl",
            "t",
            "pygpoabuse_immediate_task",
            &Value::Object(args),
        );

        let obj = r.args.as_object().expect("args stay an object");
        for key in ares_tools::credentials::CREDENTIAL_KEYS {
            assert!(!obj.contains_key(*key), "{key} survived into the journal");
        }
        assert_eq!(obj["domain"], json!("contoso.local"));
    }

    /// The strip must never take a key an `undo_plan` reads, or teardown goes
    /// blind. This fails the build if a targeting key joins CREDENTIAL_KEYS.
    #[test]
    fn stripping_keeps_every_key_an_undo_plan_reads() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.240",
            "username": "alice",
            "password": "P@ssw0rd!",
            "ticket_path": "/tmp/ares-tickets/alice.ccache",
            "computer_name": "ws01",
            "target_computer": "dc01$",
            "attacker_sid": "S-1-5-21-1-2-3-1105",
            "group": "Domain Admins",
            "target_user": "bob",
            "action": "write",
        });

        let r = MutationRecord::from_call("privesc", "t", "rbcd_write", &args);
        let obj = r.args.as_object().unwrap();

        for key in [
            "domain",
            "dc_ip",
            "username",
            "computer_name",
            "target_computer",
            "attacker_sid",
            "group",
            "target_user",
            "action",
        ] {
            assert!(
                obj.contains_key(key),
                "{key} is undo-plan input and must survive"
            );
        }
        assert!(!obj.contains_key("password"));
        assert!(!obj.contains_key("ticket_path"));
    }
}
