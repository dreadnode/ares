//! Pre-parse credential loading from .env files and 1Password.
//!
//! This module runs **before** `Cli::parse()` so that clap's `env = "..."`
//! attributes and `collect_env_vars()` see the injected values.

use std::path::Path;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

/// 1Password item mappings: (env_var, item_name, field_name)
const OP_SECRETS: &[(&str, &str, &str)] = &[
    ("ANTHROPIC_API_KEY", "Dreadnode Claude", "api-key"),
    ("DREADNODE_API_KEY", "Dreadnode Dev Platform", "api-key"),
    (
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
        "Ares Grafana MCP",
        "grafana-token",
    ),
    (
        "OPENAI_API_KEY",
        "Dreadnode Openai",
        "dreadnode-ares-api-key",
    ),
];

/// Pre-scan argv for `--env-file` and `--secrets-from` before clap runs.
///
/// Returns the values found (if any) so the caller can act on them.
pub(crate) fn prescan_secrets_args() -> (Option<String>, Option<String>) {
    let args: Vec<String> = std::env::args().collect();
    let mut env_file: Option<String> = None;
    let mut secrets_from: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--env-file" {
            if let Some(val) = args.get(i + 1) {
                env_file = Some(val.clone());
                i += 2;
                continue;
            }
        } else if let Some(val) = args[i].strip_prefix("--env-file=") {
            env_file = Some(val.to_string());
        } else if args[i] == "--secrets-from" {
            if let Some(val) = args.get(i + 1) {
                secrets_from = Some(val.clone());
                i += 2;
                continue;
            }
        } else if let Some(val) = args[i].strip_prefix("--secrets-from=") {
            secrets_from = Some(val.to_string());
        }
        i += 1;
    }

    (env_file, secrets_from)
}

/// Load environment variables from a .env file.
///
/// Variables already set in the environment are NOT overwritten (env takes precedence).
pub(crate) fn load_env_file(path: &str) -> Result<usize> {
    let p = Path::new(path);
    if !p.exists() {
        anyhow::bail!("env file not found: {path}");
    }

    let mut count = 0;
    for item in
        dotenvy::from_path_iter(p).with_context(|| format!("failed to read env file: {path}"))?
    {
        let (key, value) = item.with_context(|| format!("malformed line in {path}"))?;
        // Don't overwrite existing env vars — explicit env always wins
        if std::env::var(&key).is_err() {
            debug!("env-file: setting {key}");
            // SAFETY: we're single-threaded at this point (before tokio runtime starts)
            unsafe { std::env::set_var(&key, &value) };
            count += 1;
        } else {
            debug!("env-file: skipping {key} (already set)");
        }
    }
    Ok(count)
}

/// Load the default `.env` file if it exists (silent, best-effort).
///
/// This mirrors the common convention of auto-loading `.env` from the cwd.
pub(crate) fn try_load_default_env() -> usize {
    let path = Path::new(".env");
    if !path.exists() {
        return 0;
    }
    match load_env_file(".env") {
        Ok(n) => n,
        Err(e) => {
            warn!("failed to load .env: {e:#}");
            0
        }
    }
}

/// Fetch secrets from 1Password CLI and inject them as environment variables.
///
/// Only fetches secrets that are not already set in the environment.
pub(crate) fn load_1password_secrets() -> Result<usize> {
    // Check that `op` is available
    let check = std::process::Command::new("op").arg("--version").output();

    match check {
        Ok(output) if output.status.success() => {}
        _ => {
            anyhow::bail!(
                "1Password CLI (op) not found or not working. \
                 Install from: https://developer.1password.com/docs/cli/get-started/"
            );
        }
    }

    let mut count = 0;
    for (env_var, item_name, field_name) in OP_SECRETS {
        // Skip if already set
        if std::env::var(env_var).is_ok() {
            debug!("1password: skipping {env_var} (already set)");
            continue;
        }

        debug!("1password: fetching {env_var} from '{item_name}' field '{field_name}'");
        let output = std::process::Command::new("op")
            .args(["item", "get", item_name, "--fields", field_name, "--reveal"])
            .output()
            .with_context(|| format!("failed to run op for {env_var}"))?;

        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                // SAFETY: single-threaded at this point
                unsafe { std::env::set_var(env_var, &value) };
                info!("1password: loaded {env_var}");
                count += 1;
            }
        } else {
            warn!(
                "1password: failed to fetch {env_var} from '{item_name}': {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    Ok(count)
}
