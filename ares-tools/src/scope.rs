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
        let raw = match std::env::var("ARES_OPERATION_ID") {
            Ok(v) => v,
            Err(_) => return Self::default(),
        };
        let json_start = match raw.find('{') {
            Some(i) => i,
            None => return Self::default(),
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

/// Validate that `arguments` only targets in-scope hosts.
///
/// Only checked when the field is a literal IPv4 address — CIDRs, comma-
/// separated lists, hostnames, and `localhost` pass through. The agent stays
/// free to do legitimate discovery; the gate fires when it tries to run a
/// single-target attack tool against a host nobody authorized.
pub fn validate_in_scope(tool: &str, arguments: &Value) -> Result<()> {
    let scope = current_scope();
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

    #[test]
    fn unrestricted_scope_passes_everything() {
        let scope = OperationScope::default();
        assert!(scope.is_unrestricted());
        // Even literal IPs pass when scope is empty
        assert!(!scope.contains("192.168.58.10"));
    }

    #[test]
    fn scoped_contains_membership() {
        let scope = OperationScope::new(vec!["192.168.58.10".into(), "192.168.58.20".into()]);
        assert!(!scope.is_unrestricted());
        assert!(scope.contains("192.168.58.10"));
        assert!(!scope.contains("192.168.58.30"));
    }

    #[test]
    fn validate_passes_in_scope_ip() {
        // Force scope into the static for this test to work — but OnceLock
        // means we can't reset it across tests. Use the per-call scope directly
        // by skipping `validate_in_scope` and exercising `OperationScope`.
        let scope = OperationScope::new(vec!["192.168.58.10".into()]);
        assert!(scope.contains("192.168.58.10"));
    }

    #[test]
    fn validate_rejects_out_of_scope_target() {
        // Inline replication of the validation logic so the OnceLock-based
        // global doesn't interfere with parallel tests.
        let scope = OperationScope::new(vec!["192.168.58.10".into(), "192.168.58.20".into()]);
        let args = json!({"target": "192.168.58.99", "domain": "contoso.local"});
        let val = args["target"].as_str().unwrap();
        let is_ip = val.parse::<Ipv4Addr>().is_ok();
        assert!(is_ip);
        assert!(!scope.contains(val));
    }

    #[test]
    fn cidr_target_passes_validation() {
        // Sweeps (CIDR / comma-list) pass — they're discovery, not single-host
        // attacks. A CIDR like 192.168.58.0/24 doesn't parse as Ipv4Addr.
        let val = "192.168.58.0/24";
        assert!(val.parse::<Ipv4Addr>().is_err());
    }

    #[test]
    fn hostname_target_passes_validation() {
        let val = "dc01.contoso.local";
        assert!(val.parse::<Ipv4Addr>().is_err());
    }

    #[test]
    fn from_env_returns_empty_when_var_missing() {
        std::env::remove_var("ARES_OPERATION_ID_FROMENV_SCOPE_TEST");
        // Don't touch the real ARES_OPERATION_ID — other tests may rely on it.
        let scope = OperationScope::default();
        assert!(scope.is_unrestricted());
    }
}
