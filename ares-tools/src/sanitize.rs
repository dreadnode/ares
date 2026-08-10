//! Cross-op attacker-workspace sanitation — ensures every operation starts
//! FRESH from the attacker's perspective, so a later op cannot shortcut ("cheat")
//! off a prior op's residue. Left unchecked, that residue silently inflates
//! benchmark compromise numbers with earlier ops' work.
//!
//! This is the attacker-side complement to the target-side mutation teardown
//! (`orchestrator::cleanup`): teardown reverses what an op did to the *target
//! DC*; this wipes what an op left on the *attacker box*.
//!
//! Sanitized (at op start, before any tool runs — so wiping ccaches is safe):
//! - **hashcat potfile** — cracked plaintexts would seed the next op's
//!   known-password wordlist for free.
//! - **netexec `~/.nxc`** — its SQLite host/cred/share DBs, `spider_plus` file
//!   downloads, and captured artifacts (`screenshots`, `obfuscated_scripts`,
//!   `tmp`) persist every prior op's enumeration and loot (`nxc.conf` is kept).
//! - **Kerberos ccaches** in `/tmp/ares-tickets` — a still-valid TGT would let
//!   a later op skip re-authentication / re-compromise.
//!
//! Opt out with `ARES_KEEP_WORKSPACE=1` (carry state between engagements / dev
//! loop), mirroring `ARES_KEEP_POTFILE`.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

/// Shared, non-op-scoped directory where the credential resolver writes
/// inter-realm ccaches (see `acl.rs`). Because the filenames key off
/// domain/user, not op-id, tickets leak across ops unless wiped here.
const ARES_TICKETS_DIR: &str = "/tmp/ares-tickets";

/// `ARES_KEEP_WORKSPACE=1|true` opts out of all workspace sanitation.
fn keep_workspace_env() -> bool {
    matches!(
        std::env::var("ARES_KEEP_WORKSPACE").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

/// What a sanitize pass cleared, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SanitizeReport {
    pub potfile_reset: bool,
    pub nxc_paths_removed: usize,
    pub ccaches_removed: usize,
}

/// Wipe all cross-op attacker-side contamination so the next op is fresh.
/// Best-effort: individual failures are logged, never fatal.
pub fn sanitize_workspace() -> SanitizeReport {
    if keep_workspace_env() {
        info!(target: "sanitize", "workspace sanitation skipped (ARES_KEEP_WORKSPACE set)");
        return SanitizeReport::default();
    }

    let report = SanitizeReport {
        potfile_reset: crate::cracker::reset_hashcat_potfile(),
        nxc_paths_removed: reset_nxc_workspace(nxc_home().as_deref()),
        ccaches_removed: reset_ccaches(Path::new(ARES_TICKETS_DIR)),
    };

    info!(
        target: "sanitize",
        potfile = report.potfile_reset,
        nxc_removed = report.nxc_paths_removed,
        ccaches_removed = report.ccaches_removed,
        "attacker workspace sanitized — fresh op",
    );
    report
}

/// netexec's per-user state root (`~/.nxc`, `/root/.nxc` under systemd).
fn nxc_home() -> Option<PathBuf> {
    home::home_dir().map(|h| h.join(".nxc"))
}

/// Remove netexec's cross-op state — workspace SQLite DBs, top-level proto DBs,
/// `spider_plus` file downloads, and captured artifacts (RDP screenshots,
/// obfuscated payload scripts, scratch tmp) — while preserving `nxc.conf`.
fn reset_nxc_workspace(nxc: Option<&Path>) -> usize {
    let Some(nxc) = nxc else {
        return 0;
    };
    if !nxc.is_dir() {
        return 0;
    }
    let mut removed = 0;
    // Cross-op state/artifact dirs (the dir and nxc.conf are preserved).
    for sub in ["workspaces", "screenshots", "obfuscated_scripts", "tmp"] {
        removed += remove_path(&nxc.join(sub));
    }
    removed += remove_path(&nxc.join("modules").join("nxc_spider_plus"));
    // Older nxc layout stores proto DBs at the top level (smb.db, ldap.db, …).
    if let Ok(entries) = std::fs::read_dir(nxc) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("db") {
                removed += remove_path(&p);
            }
        }
    }
    removed
}

/// Remove ticket artifacts (`X.ccache` and its `X.ccache.krb5.conf` companion)
/// from the shared ares tickets dir, keeping the dir and any helper scripts the
/// forging path writes there (e.g. `cross_realm_tgs.py`).
fn reset_ccaches(dir: &Path) -> usize {
    if !dir.is_dir() {
        return 0;
    }
    let mut removed = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let is_ticket = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".ccache"));
            if is_ticket {
                removed += remove_path(&p);
            }
        }
    }
    removed
}

/// Remove a file or directory tree; returns 1 if something was removed, 0 if it
/// was absent or removal failed (logged).
fn remove_path(p: &Path) -> usize {
    if p.is_dir() {
        match std::fs::remove_dir_all(p) {
            Ok(_) => 1,
            Err(e) => {
                warn!(path = %p.display(), err = %e, "sanitize: failed to remove directory");
                0
            }
        }
    } else if p.exists() {
        match std::fs::remove_file(p) {
            Ok(_) => 1,
            Err(e) => {
                warn!(path = %p.display(), err = %e, "sanitize: failed to remove file");
                0
            }
        }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ares-san-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reset_ccaches_removes_tickets_keeps_helpers_and_dir() {
        let d = tmp("cc");
        fs::write(d.join("contoso_local__fabrikam_local__admin.ccache"), "x").unwrap();
        fs::write(
            d.join("contoso_local__fabrikam_local__admin.ccache.krb5.conf"),
            "c",
        )
        .unwrap();
        fs::write(d.join("cross_realm_tgs.py"), "script").unwrap();
        assert_eq!(reset_ccaches(&d), 2, "ccache + its krb5.conf, not the .py");
        assert!(d.is_dir(), "tickets dir preserved");
        assert!(
            d.join("cross_realm_tgs.py").exists(),
            "helper script preserved"
        );
        assert!(!d
            .join("contoso_local__fabrikam_local__admin.ccache")
            .exists());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn reset_ccaches_noop_when_dir_absent() {
        assert_eq!(reset_ccaches(Path::new("/nonexistent/ares-tickets-xyz")), 0);
    }

    #[test]
    fn reset_nxc_removes_dbs_and_spider_but_keeps_conf() {
        let nxc = tmp("nxc");
        fs::write(nxc.join("nxc.conf"), "cfg").unwrap();
        fs::write(nxc.join("smb.db"), "db").unwrap();
        fs::create_dir_all(nxc.join("workspaces/default")).unwrap();
        fs::write(nxc.join("workspaces/default/ldap.db"), "db").unwrap();
        fs::create_dir_all(nxc.join("modules/nxc_spider_plus/192.168.58.10")).unwrap();
        fs::write(
            nxc.join("modules/nxc_spider_plus/192.168.58.10/loot.txt"),
            "loot",
        )
        .unwrap();
        // Captured-artifact dirs the sanitizer must also wipe.
        for sub in ["screenshots", "obfuscated_scripts", "tmp"] {
            fs::create_dir_all(nxc.join(sub)).unwrap();
            fs::write(nxc.join(sub).join("artifact"), "x").unwrap();
        }

        let removed = reset_nxc_workspace(Some(&nxc));
        // workspaces + spider_plus + smb.db + screenshots + obfuscated_scripts + tmp
        assert_eq!(removed, 6);
        assert!(nxc.join("nxc.conf").exists(), "config must be preserved");
        assert!(!nxc.join("smb.db").exists());
        assert!(!nxc.join("workspaces").exists());
        assert!(!nxc.join("modules/nxc_spider_plus").exists());
        assert!(!nxc.join("screenshots").exists());
        assert!(!nxc.join("obfuscated_scripts").exists());
        assert!(!nxc.join("tmp").exists());
        fs::remove_dir_all(&nxc).ok();
    }

    #[test]
    fn reset_nxc_noop_when_absent() {
        assert_eq!(reset_nxc_workspace(None), 0);
        assert_eq!(reset_nxc_workspace(Some(Path::new("/nonexistent/.nxc"))), 0);
    }

    #[test]
    fn remove_path_absent_is_zero() {
        assert_eq!(remove_path(Path::new("/nonexistent/thing")), 0);
    }
}
