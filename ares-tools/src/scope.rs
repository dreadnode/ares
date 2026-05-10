//! Operation scope enforcement.
//!
//! The orchestrator launches each operation with a fixed set of target IPs
//! (the engagement scope). Without enforcement, an LLM agent that runs a
//! discovery sweep can pull in extra hosts on the same subnet — including the
//! attacker's own management box, lab infrastructure, or unrelated standalones
//! — and then run secretsdump/psexec/etc. against them. The resulting loot is
//! pollution at best and unauthorized access at worst.
//!
//! This module rejects single-target tool invocations whose `target` /
//! `target_ip` field is a literal IPv4 address that doesn't appear in the
//! operation's configured target list. Sweep-style invocations (CIDR, comma
//! lists, hostnames) are passed through — they're discovery, not attack — and
//! the validation kicks in again on whatever single-target tool the agent runs
//! against the discovered hosts.

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use serde_json::Value;

/// In-scope target IPs for the active operation. Empty = unrestricted (test
/// mode, ad-hoc tool runs, single-binary deployments without an operation).
#[derive(Debug, Clone, Default)]
pub struct OperationScope {
    target_ips: Vec<String>,
}

impl OperationScope {
    pub fn new(target_ips: Vec<String>) -> Self {
        Self { target_ips }
    }

    /// Build a scope from `ARES_OPERATION_ID`, mirroring the parse used by
    /// `OrchestratorConfig::from_env_with_yaml`. Returns an empty (=
    /// unrestricted) scope when the env var is unset, plain-text, or
    /// missing a `target_ips` array — none of those cases are an error here.
    pub fn from_env() -> Self {
        Self::from_raw(&std::env::var("ARES_OPERATION_ID").unwrap_or_default())
    }

    /// Pure parse of the same payload format `OrchestratorConfig` consumes:
    /// either a plain operation-id string or a JSON envelope with
    /// `target_ips`. Public so callers (and tests) can exercise the parse
    /// without touching the process environment.
    pub fn from_raw(raw: &str) -> Self {
        let Some(json_start) = raw.find('{') else {
            return Self::default();
        };
        let json: serde_json::Value = match serde_json::from_str(&raw[json_start..]) {
            Ok(v) => v,
            Err(_) => return Self::default(),
        };
        let ips = json["target_ips"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Self::new(ips)
    }

    pub fn is_unrestricted(&self) -> bool {
        self.target_ips.is_empty()
    }

    pub fn contains(&self, ip: &str) -> bool {
        self.target_ips.iter().any(|t| t == ip)
    }

    pub fn target_ips(&self) -> &[String] {
        &self.target_ips
    }
}

static SCOPE: OnceLock<OperationScope> = OnceLock::new();

/// Install the process-wide operation scope. First call wins; subsequent calls
/// are no-ops so re-initialization (e.g. test setup, hot-reload) is safe.
pub fn init_scope(scope: OperationScope) {
    let _ = SCOPE.set(scope);
}

fn current_scope() -> &'static OperationScope {
    SCOPE.get_or_init(OperationScope::default)
}

/// Read the operation scope from the environment and install it. Intended to
/// be called once at orchestrator/worker startup. Returns the installed scope
/// so the caller can log the configured target list (and so the call is
/// directly unit-testable instead of relying on a process-wide side effect).
pub fn install_from_env() -> OperationScope {
    let scope = OperationScope::from_env();
    init_scope(scope.clone());
    scope
}

/// Validate that `arguments` only targets in-scope hosts.
///
/// Only checked when the field is a literal IPv4 address — CIDRs, comma-
/// separated lists, hostnames, and `localhost` pass through. The agent stays
/// free to do legitimate discovery; the gate fires when it tries to run a
/// single-target attack tool against a host nobody authorized.
pub fn validate_in_scope(tool: &str, arguments: &Value) -> Result<()> {
    validate_against(tool, arguments, current_scope())
}

/// Pure validation against an arbitrary scope. Splitting this out from the
/// `OnceLock`-backed [`validate_in_scope`] makes the gate fully unit-testable
/// without polluting global state across tests.
pub fn validate_against(tool: &str, arguments: &Value, scope: &OperationScope) -> Result<()> {
    if scope.is_unrestricted() {
        return Ok(());
    }
    for field in ["target", "target_ip"] {
        let Some(val) = arguments.get(field).and_then(|v| v.as_str()) else {
            continue;
        };
        // Only enforce on literal IPv4 — sweeps pass a CIDR or list, single
        // attacks pass a single IP. Hostnames are caught by the parser-side
        // attribution fixes; we don't try to resolve them here.
        if val.parse::<Ipv4Addr>().is_err() {
            continue;
        }
        if val == "127.0.0.1" {
            continue;
        }
        if !scope.contains(val) {
            return Err(anyhow!(
                "tool '{tool}' rejected: target {val} is not in operation scope ({})",
                scope.target_ips.join(",")
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scoped(ips: &[&str]) -> OperationScope {
        OperationScope::new(ips.iter().map(|s| (*s).to_string()).collect())
    }

    #[test]
    fn unrestricted_scope_marks_empty() {
        let scope = OperationScope::default();
        assert!(scope.is_unrestricted());
        assert_eq!(scope.target_ips(), &[] as &[String]);
        assert!(!scope.contains("192.168.58.10"));
    }

    #[test]
    fn scoped_membership_and_accessors() {
        let scope = scoped(&["192.168.58.10", "192.168.58.20"]);
        assert!(!scope.is_unrestricted());
        assert!(scope.contains("192.168.58.10"));
        assert!(scope.contains("192.168.58.20"));
        assert!(!scope.contains("192.168.58.30"));
        assert_eq!(scope.target_ips().len(), 2);
    }

    #[test]
    fn validate_against_unrestricted_passes_anything() {
        let scope = OperationScope::default();
        let args = json!({"target": "192.168.58.99"});
        assert!(validate_against("nmap_scan", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_passes_in_scope_target() {
        let scope = scoped(&["192.168.58.10", "192.168.58.20"]);
        let args = json!({"target": "192.168.58.10", "domain": "contoso.local"});
        assert!(validate_against("secretsdump", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_passes_in_scope_target_ip_field() {
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target_ip": "192.168.58.10"});
        assert!(validate_against("psexec", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_rejects_out_of_scope_ip() {
        let scope = scoped(&["192.168.58.10", "192.168.58.20"]);
        let args = json!({"target": "192.168.58.99"});
        let err = validate_against("secretsdump", &args, &scope).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("secretsdump"));
        assert!(msg.contains("192.168.58.99"));
        assert!(msg.contains("192.168.58.10"));
    }

    #[test]
    fn validate_against_rejects_out_of_scope_target_ip_field() {
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target_ip": "192.168.58.99"});
        assert!(validate_against("psexec", &args, &scope).is_err());
    }

    #[test]
    fn validate_against_passes_cidr_through() {
        // Sweeps pass — CIDR doesn't parse as Ipv4Addr.
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target": "192.168.58.0/24"});
        assert!(validate_against("smb_sweep", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_passes_comma_list_through() {
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target": "192.168.58.10,192.168.58.20"});
        assert!(validate_against("smb_sweep", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_passes_hostname_through() {
        // Hostnames aren't resolved here — parser-side attribution fixes catch
        // hostname mis-attribution. A real AD hostname won't parse as IPv4.
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target": "dc01.contoso.local"});
        assert!(validate_against("nmap_scan", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_passes_loopback() {
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target": "127.0.0.1"});
        assert!(validate_against("get_tgt", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_no_target_field_passes() {
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"username": "alice", "domain": "contoso.local"});
        assert!(validate_against("ldap_search", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_non_string_target_passes() {
        // A target that isn't a string (e.g. number, null) shouldn't crash —
        // it just fails the IPv4 parse and falls through.
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target": 12345});
        assert!(validate_against("nmap_scan", &args, &scope).is_ok());
    }

    #[test]
    fn validate_against_checks_both_target_fields() {
        // If either `target` or `target_ip` is out of scope, reject. Some
        // tools accept both names for backwards compat.
        let scope = scoped(&["192.168.58.10"]);
        let args = json!({"target": "192.168.58.10", "target_ip": "192.168.58.99"});
        assert!(validate_against("psexec", &args, &scope).is_err());
    }

    #[test]
    fn from_raw_empty_string_is_unrestricted() {
        assert!(OperationScope::from_raw("").is_unrestricted());
    }

    #[test]
    fn from_raw_plain_op_id_is_unrestricted() {
        // Plain operation-id (no JSON envelope) → no target_ips → unrestricted.
        assert!(OperationScope::from_raw("op-20260509-204128").is_unrestricted());
    }

    #[test]
    fn from_raw_json_without_target_ips_is_unrestricted() {
        let raw = r#"{"operation_id":"op-x","target_domain":"contoso.local"}"#;
        assert!(OperationScope::from_raw(raw).is_unrestricted());
    }

    #[test]
    fn from_raw_json_empty_target_ips_is_unrestricted() {
        let raw = r#"{"operation_id":"op-x","target_ips":[]}"#;
        assert!(OperationScope::from_raw(raw).is_unrestricted());
    }

    #[test]
    fn from_raw_json_with_target_ips_populates_scope() {
        let raw = r#"{"operation_id":"op-x","target_ips":["192.168.58.10","192.168.58.20"]}"#;
        let scope = OperationScope::from_raw(raw);
        assert!(!scope.is_unrestricted());
        assert!(scope.contains("192.168.58.10"));
        assert!(scope.contains("192.168.58.20"));
        assert_eq!(scope.target_ips().len(), 2);
    }

    #[test]
    fn from_raw_skips_telemetry_prefix_before_json() {
        // Wrapper script may prefix the env var with log lines — the parser
        // searches for the first `{` and parses from there.
        let raw = "2026-04-17T21:35:33Z INFO telemetry initialized\n\
                   {\"operation_id\":\"op-x\",\"target_ips\":[\"192.168.58.10\"]}";
        let scope = OperationScope::from_raw(raw);
        assert!(scope.contains("192.168.58.10"));
    }

    #[test]
    fn from_raw_invalid_json_is_unrestricted() {
        // Garbage after the `{` shouldn't crash — falls back to empty scope.
        let scope = OperationScope::from_raw("op-id {not valid json");
        assert!(scope.is_unrestricted());
    }

    #[test]
    fn from_raw_filters_non_string_target_ips() {
        // If target_ips contains non-string entries, those are skipped silently
        // rather than producing junk scope entries.
        let raw = r#"{"target_ips":["192.168.58.10",42,null,"192.168.58.20"]}"#;
        let scope = OperationScope::from_raw(raw);
        assert_eq!(scope.target_ips().len(), 2);
        assert!(scope.contains("192.168.58.10"));
        assert!(scope.contains("192.168.58.20"));
    }

    #[test]
    fn init_scope_first_call_wins() {
        // OnceLock means subsequent init_scope calls are no-ops — the first
        // installed scope persists for the process lifetime. We can't assert
        // exact contents (other tests may have initialized it), but the
        // read path must not panic.
        init_scope(OperationScope::new(vec!["192.168.58.99".into()]));
        let scope = current_scope();
        let _ = scope.is_unrestricted();
    }

    #[test]
    fn validate_in_scope_uses_global_scope() {
        // Smoke test the global path: whatever scope is installed (possibly
        // unrestricted in test environment), validate_in_scope shouldn't
        // panic and should agree with validate_against on the same scope.
        let args = json!({"target": "192.168.58.10"});
        let result = validate_in_scope("nmap_scan", &args);
        let same_scope = current_scope();
        let direct = validate_against("nmap_scan", &args, same_scope);
        assert_eq!(result.is_ok(), direct.is_ok());
    }

    #[test]
    fn install_from_env_returns_parsed_scope() {
        // Drives the orchestrator/worker startup helper. The function
        // installs the global scope (no-op if already set) and returns the
        // parsed scope so callers can log it. With ARES_OPERATION_ID unset
        // or plain, the returned scope is unrestricted; either way the call
        // must not panic.
        let returned = install_from_env();
        // The returned scope should be readable
        let _ = returned.is_unrestricted();
        let _ = returned.target_ips();
    }
}
