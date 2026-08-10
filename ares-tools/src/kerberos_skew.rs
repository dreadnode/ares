//! Workaround for Kerberos clock skew between agent hosts and target DCs.
//!
//! Kerberos clients encrypt the current time into AS/TGS requests; the KDC
//! rejects anything outside a ±5min window with `KRB_AP_ERR_SKEW`. In labs
//! where the DC's BIOS / NTP isn't synced to the agent host, every
//! impacket / certipy invocation that opens a Kerberos session fails before
//! protocol logic even runs. The lab fix (sync the DCs) is out of scope here;
//! this module provides an in-process fallback so authenticated chains —
//! notably certipy PKINIT for ESC1/ESC4 — actually complete.
//!
//! Mechanism: a Python `sitecustomize.py` shipped in `ares-tools/python/`
//! patches `datetime.datetime.now`, `datetime.datetime.utcnow`, and
//! `time.time` to subtract a fixed offset (env `ARES_KERBEROS_TIME_OFFSET_SECS`).
//! The CommandBuilder method `with_kerberos_skew_shim()` extracts the shim
//! to a stable temp dir on first call and prepends its directory to
//! `PYTHONPATH` for the subprocess. Inert when the env var is unset or 0,
//! so leaving the shim plumbed in is safe.

use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::{Context, Result};

/// The embedded sitecustomize shim source. `include_str!` at compile time so
/// the runtime install is a single self-contained file write — no separate
/// ansible / Dockerfile change needed for the shim itself.
const SITECUSTOMIZE_PY: &str = include_str!("../python/ares_krb_skew/sitecustomize.py");

/// Env variable consumed by the Python shim. A positive integer means the
/// local clock is AHEAD of the DC by this many seconds (and we subtract).
pub const SKEW_ENV_VAR: &str = "ARES_KERBEROS_TIME_OFFSET_SECS";

/// Extract the shim to a stable temp path on first use and return its parent
/// directory (suitable for prepending to `PYTHONPATH`).
///
/// Caches the path in a `OnceLock` so subsequent calls are free. The shim is
/// idempotent — overwriting a stale copy from a previous binary is fine.
pub fn ensure_shim_installed() -> Result<&'static str> {
    static SHIM_DIR: OnceLock<String> = OnceLock::new();
    if let Some(p) = SHIM_DIR.get() {
        return Ok(p.as_str());
    }
    let dir: PathBuf = std::env::temp_dir().join("ares-krb-skew");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("ensure_shim_installed: mkdir {}", dir.display()))?;
    let file = dir.join("sitecustomize.py");
    std::fs::write(&file, SITECUSTOMIZE_PY)
        .with_context(|| format!("ensure_shim_installed: write {}", file.display()))?;
    let s = dir.to_string_lossy().into_owned();
    let _ = SHIM_DIR.set(s);
    Ok(SHIM_DIR.get().unwrap().as_str())
}

/// Return the PYTHONPATH value the subprocess should see (existing dirs
/// preserved, shim dir prepended). When the env var is unset locally, the
/// shim is still installed but inert at runtime (no offset applied).
pub fn build_pythonpath_with_shim() -> Result<String> {
    let shim_dir = ensure_shim_installed()?;
    let existing = std::env::var("PYTHONPATH").unwrap_or_default();
    if existing.is_empty() {
        Ok(shim_dir.to_string())
    } else {
        Ok(format!("{shim_dir}:{existing}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_installs_idempotently() {
        let p1 = ensure_shim_installed().unwrap();
        let p2 = ensure_shim_installed().unwrap();
        assert_eq!(p1, p2);
        let f = std::path::Path::new(p1).join("sitecustomize.py");
        assert!(f.exists());
        let body = std::fs::read_to_string(&f).unwrap();
        assert!(body.contains("ARES_KERBEROS_TIME_OFFSET_SECS"));
    }

    #[test]
    fn pythonpath_prepends_shim_dir() {
        let pp = build_pythonpath_with_shim().unwrap();
        let shim = ensure_shim_installed().unwrap();
        assert!(pp.starts_with(shim));
    }

    #[test]
    fn env_var_constant_is_what_shim_reads() {
        assert_eq!(SKEW_ENV_VAR, "ARES_KERBEROS_TIME_OFFSET_SECS");
        let body = SITECUSTOMIZE_PY;
        assert!(body.contains(SKEW_ENV_VAR));
    }
}
