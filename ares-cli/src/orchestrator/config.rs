//! Configuration loaded from environment variables.

use std::env;
use std::time::Duration;

use crate::orchestrator::strategy::Strategy;

/// All tunables for the orchestrator, loaded once at startup.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Redis connection URL (supports `redis://` and `redis+sentinel://`).
    pub redis_url: String,

    /// NATS connection URL for the work-queue/result broker.
    pub nats_url: String,

    /// Operation ID this orchestrator instance manages.
    pub operation_id: String,

    /// Maximum number of concurrent LLM-consuming tasks across all roles.
    pub max_concurrent_tasks: usize,

    /// Interval between heartbeat sweeps.
    pub heartbeat_interval: Duration,

    /// How long before an agent with no heartbeat is considered dead.
    pub heartbeat_timeout: Duration,

    /// How often the result consumer polls Redis for completed tasks.
    pub result_poll_interval: Duration,

    /// TTL for the operation lock key (`ares:lock:{op_id}`).
    pub lock_ttl: Duration,

    /// How often the deferred-queue processor wakes up.
    pub deferred_poll_interval: Duration,

    /// Maximum number of tasks a single role can have in-flight.
    pub max_tasks_per_role: usize,

    /// Global rate-limit: minimum delay between consecutive task dispatches.
    pub dispatch_delay: Duration,

    /// How long before an in-progress task with no activity is considered stale.
    pub stale_task_timeout: Duration,

    /// Maximum age for deferred tasks before eviction (seconds).
    pub deferred_task_max_age: Duration,

    /// Maximum number of deferred tasks per task type.
    pub max_deferred_per_type: usize,

    /// Maximum total deferred tasks across all types.
    pub max_deferred_total: usize,

    /// Target domain for the operation (e.g. "contoso.local").
    pub target_domain: String,

    /// Target IPs for the operation (comma-separated in env, parsed to vec).
    pub target_ips: Vec<String>,

    /// Initial credential to seed at startup (optional).
    /// Format: `user:pass@domain` or from JSON payload.
    pub initial_credential: Option<InitialCredential>,

    /// Strategy controlling technique weights, filtering, and path diversity.
    pub strategy: Strategy,

    /// Local IP of the attacker machine (for NTLM relay listeners, coercion, etc.).
    /// Resolved from `ARES_LISTENER_IP` env var, or auto-detected via UDP socket
    /// probe toward the first target IP.
    pub listener_ip: Option<String>,
}

/// A credential provided at operation launch time.
#[derive(Debug, Clone)]
pub struct InitialCredential {
    pub username: String,
    pub password: String,
    pub domain: String,
}

impl OrchestratorConfig {
    /// Load configuration from environment variables, merging strategy
    /// settings from the optional YAML config.
    pub fn from_env_with_yaml(
        yaml: Option<&ares_core::config::AresConfig>,
    ) -> anyhow::Result<Self> {
        let redis_url = env::var("ARES_REDIS_URL")
            .or_else(|_| env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());

        let nats_url = ares_core::nats::NatsBroker::url_from_env();

        let raw_op = env::var("ARES_OPERATION_ID")
            .map_err(|_| anyhow::anyhow!("ARES_OPERATION_ID is required"))?;

        // ARES_OPERATION_ID may be a plain operation-id string OR a full JSON
        // payload (the queue dispatcher passes the entire operation request JSON).
        // The value may also be prefixed with log/telemetry output from the
        // wrapper script, so we search for the first `{` in the string.
        let json_start = raw_op.find('{');
        let (operation_id, target_domain, target_ips, json_cred, json_value) = if let Some(pos) =
            json_start
        {
            let json_str = &raw_op[pos..];
            let v: serde_json::Value = serde_json::from_str(json_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse ARES_OPERATION_ID JSON: {e}"))?;
            let op_id = v["operation_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing operation_id in JSON payload"))?
                .to_string();
            let domain = v["target_domain"].as_str().unwrap_or("").to_string();
            let ips: Vec<String> = v["target_ips"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            // Extract initial credential from JSON payload.
            // Preferred shape: nested {"initial_credential": {"username", "password", "domain"}}.
            // Also support flat fields for backwards compatibility: {"initial_username", "initial_password"}.
            let cred = if let Some(ic) = v.get("initial_credential").and_then(|v| v.as_object()) {
                match (
                    ic.get("username").and_then(|v| v.as_str()),
                    ic.get("password").and_then(|v| v.as_str()),
                ) {
                    (Some(user), Some(pass)) => Some(InitialCredential {
                        username: user.to_string(),
                        password: pass.to_string(),
                        domain: ic
                            .get("domain")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&domain)
                            .to_string(),
                    }),
                    _ => None,
                }
            } else {
                // Flat field fallback
                match (
                    v["initial_username"].as_str(),
                    v["initial_password"].as_str(),
                ) {
                    (Some(user), Some(pass)) => Some(InitialCredential {
                        username: user.to_string(),
                        password: pass.to_string(),
                        domain: v["initial_domain"].as_str().unwrap_or(&domain).to_string(),
                    }),
                    _ => None,
                }
            };
            (op_id, domain, ips, cred, Some(v))
        } else {
            // Plain operation ID — read target info from separate env vars
            let domain = env::var("ARES_TARGET_DOMAIN").unwrap_or_default();
            let ips: Vec<String> = env::var("ARES_TARGET_IPS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            (raw_op, domain, ips, None, None)
        };

        // Initial credential: JSON payload takes precedence, then env var.
        // Format: user:pass@domain
        let initial_credential = json_cred.or_else(|| {
            env::var("ARES_INITIAL_CREDENTIAL")
                .ok()
                .and_then(|raw| parse_credential_spec(&raw, &target_domain))
        });

        // Resolve strategy from env vars + JSON payload + YAML config
        let strategy = Strategy::resolve(json_value.as_ref(), yaml);

        // Listener IP: explicit env var, or auto-detect from first target IP.
        let listener_ip = env::var("ARES_LISTENER_IP")
            .ok()
            .or_else(|| detect_local_ip(target_ips.first().map(|s| s.as_str())));

        let max_concurrent_tasks = parse_env("ARES_MAX_CONCURRENT_TASKS", 12);
        let heartbeat_interval_secs = parse_env("ARES_HEARTBEAT_INTERVAL_SECS", 30);
        let heartbeat_timeout_secs = parse_env("ARES_HEARTBEAT_TIMEOUT_SECS", 120);
        let result_poll_interval_ms = parse_env("ARES_RESULT_POLL_INTERVAL_MS", 500);
        let lock_ttl_secs = parse_env("ARES_LOCK_TTL_SECS", 300);
        let deferred_poll_interval_secs = parse_env("ARES_DEFERRED_POLL_INTERVAL_SECS", 10);
        let max_tasks_per_role = parse_env("ARES_MAX_TASKS_PER_ROLE", 3);
        let dispatch_delay_ms = parse_env("ARES_DISPATCH_DELAY_MS", 200);
        let stale_task_timeout_secs = parse_env("ARES_STALE_TASK_TIMEOUT_SECS", 300);
        let deferred_task_max_age_secs = parse_env("ARES_DEFERRED_TASK_MAX_AGE_SECS", 300);
        let max_deferred_per_type = parse_env("ARES_MAX_DEFERRED_PER_TYPE", 50);
        let max_deferred_total = parse_env("ARES_MAX_DEFERRED_TOTAL", 200);

        Ok(Self {
            redis_url,
            nats_url,
            operation_id,
            max_concurrent_tasks,
            heartbeat_interval: Duration::from_secs(heartbeat_interval_secs),
            heartbeat_timeout: Duration::from_secs(heartbeat_timeout_secs),
            result_poll_interval: Duration::from_millis(result_poll_interval_ms),
            lock_ttl: Duration::from_secs(lock_ttl_secs),
            deferred_poll_interval: Duration::from_secs(deferred_poll_interval_secs),
            max_tasks_per_role,
            dispatch_delay: Duration::from_millis(dispatch_delay_ms),
            stale_task_timeout: Duration::from_secs(stale_task_timeout_secs),
            deferred_task_max_age: Duration::from_secs(deferred_task_max_age_secs),
            max_deferred_per_type,
            max_deferred_total,
            target_domain,
            target_ips,
            initial_credential,
            strategy,
            listener_ip,
        })
    }

    /// Hard cap = 1.5x the soft concurrency limit. Tasks above this are deferred.
    pub fn hard_cap(&self) -> usize {
        (self.max_concurrent_tasks as f64 * 1.5) as usize
    }
}

/// Parse a credential spec in `user:pass@domain` format.
/// If no `@domain` is given, falls back to `default_domain`.
///
/// The `@` that separates password from domain must look like a domain
/// (contains a dot). This avoids misinterpreting `@` characters within
/// passwords (e.g., `admin:P@ssw0rd` stays intact).
fn parse_credential_spec(spec: &str, default_domain: &str) -> Option<InitialCredential> {
    let colon_pos = spec.find(':')?;
    let username = &spec[..colon_pos];
    let rest = &spec[colon_pos + 1..]; // password[@domain]

    // Only treat text after the last '@' as a domain if it contains a dot,
    // to avoid misinterpreting '@' in passwords (e.g. P@ssw0rd).
    let (password, domain) = if let Some(at_pos) = rest.rfind('@') {
        let candidate = &rest[at_pos + 1..];
        if candidate.contains('.') {
            (&rest[..at_pos], candidate)
        } else {
            (rest, default_domain)
        }
    } else {
        (rest, default_domain)
    };

    if username.is_empty() || password.is_empty() {
        return None;
    }
    Some(InitialCredential {
        username: username.to_string(),
        password: password.to_string(),
        domain: domain.to_string(),
    })
}

/// Auto-detect the local IP by opening a UDP socket aimed at the first target.
/// This never sends traffic — the OS resolves which interface would route to the
/// target and we read the bound local address.
fn detect_local_ip(target: Option<&str>) -> Option<String> {
    let dest = target.unwrap_or("8.8.8.8");
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(format!("{dest}:53")).ok()?;
    let addr = socket.local_addr().ok()?;
    let ip = addr.ip().to_string();
    // Reject loopback — not useful as a relay listener
    if ip.starts_with("127.") {
        return None;
    }
    Some(ip)
}

/// Parse an environment variable into a numeric type, falling back to `default`.
fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
impl OrchestratorConfig {
    /// Test-only convenience: load from env vars without YAML config.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_with_yaml(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a config without env vars.
    pub(crate) fn make_config(max_tasks: usize) -> OrchestratorConfig {
        OrchestratorConfig {
            redis_url: "redis://localhost".into(),
            nats_url: "nats://localhost:4222".into(),
            operation_id: "test-op".into(),
            max_concurrent_tasks: max_tasks,
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(120),
            result_poll_interval: Duration::from_millis(500),
            lock_ttl: Duration::from_secs(300),
            deferred_poll_interval: Duration::from_secs(10),
            max_tasks_per_role: 3,
            dispatch_delay: Duration::from_millis(0),
            stale_task_timeout: Duration::from_secs(900),
            deferred_task_max_age: Duration::from_secs(300),
            max_deferred_per_type: 50,
            max_deferred_total: 200,
            target_domain: String::new(),
            target_ips: Vec::new(),
            initial_credential: None,
            strategy: Strategy::default(),
            listener_ip: None,
        }
    }

    #[test]
    fn hard_cap_is_1_5x() {
        assert_eq!(make_config(8).hard_cap(), 12);
        assert_eq!(make_config(10).hard_cap(), 15);
        assert_eq!(make_config(1).hard_cap(), 1);
    }

    #[test]
    fn from_env_plain_and_json_and_missing() {
        // Single test to avoid env var race conditions between parallel tests.
        std::env::remove_var("ARES_INITIAL_CREDENTIAL");

        // Missing → error
        std::env::remove_var("ARES_OPERATION_ID");
        assert!(OrchestratorConfig::from_env().is_err());

        // Plain string → operation_id, empty targets
        std::env::set_var("ARES_OPERATION_ID", "test-op-1");
        let c = OrchestratorConfig::from_env().unwrap();
        assert_eq!(c.operation_id, "test-op-1");
        assert_eq!(c.max_concurrent_tasks, 12);
        assert_eq!(c.heartbeat_interval, Duration::from_secs(30));
        assert!(c.target_ips.is_empty());
        assert!(c.initial_credential.is_none());

        // JSON payload → parsed operation_id, target_domain, target_ips
        let payload = r#"{"operation_id":"op-json-test","target_domain":"contoso.local","target_ips":["192.168.58.1","192.168.58.2"],"model":"gpt-4"}"#;
        std::env::set_var("ARES_OPERATION_ID", payload);
        let c = OrchestratorConfig::from_env().unwrap();
        assert_eq!(c.operation_id, "op-json-test");
        assert_eq!(c.target_domain, "contoso.local");
        assert_eq!(c.target_ips, vec!["192.168.58.1", "192.168.58.2"]);

        // JSON payload prefixed with telemetry output (wrapper script noise)
        let noisy = format!("2026-04-17T21:35:33Z INFO telemetry initialized\n{payload}");
        std::env::set_var("ARES_OPERATION_ID", &noisy);
        let c = OrchestratorConfig::from_env().unwrap();
        assert_eq!(c.operation_id, "op-json-test");
        assert_eq!(c.target_domain, "contoso.local");
        assert_eq!(c.target_ips, vec!["192.168.58.1", "192.168.58.2"]);

        // JSON payload with nested initial_credential
        let payload = r#"{"operation_id":"op-cred","target_domain":"contoso.local","target_ips":[],"initial_credential":{"username":"admin","password":"Pass123","domain":"contoso.local"}}"#;
        std::env::set_var("ARES_OPERATION_ID", payload);
        let c = OrchestratorConfig::from_env().unwrap();
        let cred = c.initial_credential.unwrap();
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "Pass123");
        assert_eq!(cred.domain, "contoso.local");

        // JSON payload with flat initial credential (backwards compat)
        let payload = r#"{"operation_id":"op-cred2","target_domain":"contoso.local","target_ips":[],"initial_username":"admin2","initial_password":"Pass456"}"#;
        std::env::set_var("ARES_OPERATION_ID", payload);
        let c = OrchestratorConfig::from_env().unwrap();
        let cred = c.initial_credential.unwrap();
        assert_eq!(cred.username, "admin2");
        assert_eq!(cred.password, "Pass456");
        assert_eq!(cred.domain, "contoso.local");

        // Env var credential (ARES_INITIAL_CREDENTIAL)
        std::env::set_var("ARES_OPERATION_ID", "test-op-2");
        std::env::set_var("ARES_INITIAL_CREDENTIAL", "user1:secret@fabrikam.local");
        let c = OrchestratorConfig::from_env().unwrap();
        let cred = c.initial_credential.unwrap();
        assert_eq!(cred.username, "user1");
        assert_eq!(cred.password, "secret");
        assert_eq!(cred.domain, "fabrikam.local");

        // Listener IP from env
        std::env::set_var("ARES_LISTENER_IP", "192.168.58.50");
        std::env::set_var("ARES_OPERATION_ID", "test-listener");
        let c = OrchestratorConfig::from_env().unwrap();
        assert_eq!(c.listener_ip, Some("192.168.58.50".to_string()));
        std::env::remove_var("ARES_LISTENER_IP");

        // JSON payload with strategy
        std::env::remove_var("ARES_STRATEGY");
        let payload = r#"{"operation_id":"op-strat","target_domain":"contoso.local","target_ips":[],"strategy":"comprehensive"}"#;
        std::env::set_var("ARES_OPERATION_ID", payload);
        let c = OrchestratorConfig::from_env().unwrap();
        assert!(c.strategy.should_continue_after_da());
        assert!(c.strategy.is_comprehensive());

        std::env::remove_var("ARES_OPERATION_ID");
        std::env::remove_var("ARES_INITIAL_CREDENTIAL");
    }

    #[test]
    fn parse_credential_spec_full() {
        let cred = parse_credential_spec("admin:P@ssw0rd@contoso.local", "").unwrap();
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "P@ssw0rd");
        assert_eq!(cred.domain, "contoso.local");
    }

    #[test]
    fn parse_credential_spec_no_domain() {
        let cred = parse_credential_spec("admin:P@ssw0rd", "fallback.local").unwrap();
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "P@ssw0rd");
        assert_eq!(cred.domain, "fallback.local");
    }

    #[test]
    fn parse_credential_spec_at_in_password() {
        // rfind('@') splits at the last @, so user:p@ss@domain works
        let cred = parse_credential_spec("admin:p@ss@contoso.local", "").unwrap();
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "p@ss");
        assert_eq!(cred.domain, "contoso.local");
    }

    #[test]
    fn parse_credential_spec_invalid() {
        // No colon
        assert!(parse_credential_spec("admin", "").is_none());
        // Empty username
        assert!(parse_credential_spec(":pass@contoso.local", "").is_none());
        // Empty password
        assert!(parse_credential_spec("admin:@contoso.local", "").is_none());
        // Empty password without domain
        assert!(parse_credential_spec("admin:", "").is_none());
    }

    #[test]
    fn detect_local_ip_returns_some() {
        // Uses 8.8.8.8 as default destination — should resolve to a local interface
        // unless we're running in a network-less sandbox.
        let ip = detect_local_ip(None);
        if let Some(ref addr) = ip {
            assert!(!addr.starts_with("127."), "Should reject loopback: {addr}");
        }
        // Also test with an explicit target
        let ip2 = detect_local_ip(Some("192.168.58.10"));
        if let Some(ref addr) = ip2 {
            assert!(!addr.starts_with("127."));
        }
    }

    #[test]
    fn make_config_has_strategy() {
        let cfg = make_config(8);
        assert!(cfg.listener_ip.is_none());
        assert!(cfg.initial_credential.is_none());
        // Default strategy should be Fast
        assert!(!cfg.strategy.should_continue_after_da());
    }
}
