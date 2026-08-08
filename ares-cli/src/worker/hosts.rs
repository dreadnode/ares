//! Background `/etc/hosts` management for AD hostname resolution.
//!
//! In Active Directory environments, Kerberos authentication requires hostname
//! resolution. Workers read discovered hosts from Redis and reflect them into
//! `/etc/hosts` so FQDN- and realm-based tooling can resolve DC and member
//! names.
//!
//! Rather than appending, the sync owns a single marker-delimited block
//! (`ares managed hosts`) that it **rewrites** from the current operation's
//! host set each tick. This keeps the file correct across operations on a
//! long-lived box: a prior op's entries are purged instead of shadowing the
//! current op's (`/etc/hosts` resolves first-match-wins, so a stale
//! `dc01.contoso.local` line would otherwise win). The seven role-workers
//! share one file, so the rewrite is serialized with an advisory `flock` and
//! published via an atomic temp-write + rename so a concurrent `getaddrinfo`
//! never sees a torn file.
//!
//! For domain controllers, the bare domain name is also added as an alias to
//! enable Kerberos realm resolution (e.g., `192.168.58.10  dc01.contoso.local dc01 contoso.local`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tracing::{debug, info, warn};

use ares_core::models::Host;

/// Interval between host sync cycles.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Path to the system hosts file.
const HOSTS_PATH: &str = "/etc/hosts";
/// Staging path for the atomic rewrite (same filesystem as `HOSTS_PATH` so the
/// rename is atomic).
const HOSTS_TMP_PATH: &str = "/etc/hosts.ares.tmp";
/// Stable lock file the role-workers flock to serialize `/etc/hosts` rewrites.
/// Deliberately NOT `/etc/hosts` itself — the atomic rename swaps that inode,
/// which would defeat an flock held on it.
const HOSTS_LOCK_PATH: &str = "/tmp/.ares-etchosts.lock";
/// Opening delimiter of the ares-managed block within `/etc/hosts`.
const ARES_BLOCK_BEGIN: &str = "# >>> ares managed hosts (auto-generated per operation) >>>";
/// Closing delimiter of the ares-managed block within `/etc/hosts`.
const ARES_BLOCK_END: &str = "# <<< ares managed hosts <<<";

/// Build the `/etc/hosts` entries for a list of discovered hosts.
///
/// Emits one line per host (`IP  fqdn short [bare-domain-if-dc]`), skipping
/// records missing an IP or hostname, any IP already in `already_written`, and
/// repeat IPs within this call (the Redis list can, defensively, still carry a
/// duplicate).
pub fn build_host_entries(hosts: &[Host], already_written: &HashSet<String>) -> Vec<String> {
    let mut entries = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for host in hosts {
        if host.ip.is_empty() || host.hostname.is_empty() {
            continue;
        }
        if already_written.contains(&host.ip) {
            continue;
        }
        if !seen.insert(host.ip.clone()) {
            continue;
        }

        let hostname = host.hostname.to_lowercase();
        let parts: Vec<&str> = hostname.split('.').collect();
        let short_name = parts.first().copied().unwrap_or(&hostname);

        // Build aliases: FQDN, short name, and bare domain for DCs
        let mut aliases = vec![hostname.clone()];
        if short_name != hostname {
            aliases.push(short_name.to_string());
        }

        // For domain controllers, add bare domain for Kerberos realm resolution
        if host.is_dc && parts.len() >= 2 {
            let domain = parts[1..].join(".");
            if !domain.is_empty() {
                aliases.push(domain);
            }
        }

        entries.push(format!("{}  {}", host.ip, aliases.join(" ")));
    }

    entries
}

/// Render the full `/etc/hosts` content: everything in `existing` outside the
/// ares-managed block, followed by a freshly-built block containing `entries`.
///
/// Pure and filesystem-free so the block accounting is unit-testable. Any
/// prior ares block (including an unterminated one left by a crash mid-write)
/// is stripped, so a stale operation's entries never survive into the next.
/// When `entries` is empty the block is dropped entirely — the caller uses
/// this to purge the previous op on rebind.
fn render_hosts_file(existing: &str, entries: &[String]) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut in_block = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == ARES_BLOCK_BEGIN {
            in_block = true;
            continue;
        }
        if trimmed == ARES_BLOCK_END {
            in_block = false;
            continue;
        }
        if !in_block {
            kept.push(line);
        }
    }
    // Normalize away trailing blank lines the old block may have left behind so
    // the file doesn't accrete blank lines across rewrites.
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }

    let mut out = kept.join("\n");
    if !entries.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(ARES_BLOCK_BEGIN);
        out.push('\n');
        for entry in entries {
            out.push_str(entry);
            out.push('\n');
        }
        out.push_str(ARES_BLOCK_END);
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Rewrite the ares-managed `/etc/hosts` block to exactly `entries`.
///
/// Blocking (fs + advisory lock); call from `spawn_blocking`. Serializes the
/// role-workers via a non-blocking `flock` on a stable lock file — if another
/// worker holds it we skip this tick (it writes identical content, so nothing
/// is lost). Publishes via temp-write + atomic rename so `getaddrinfo` readers
/// never observe a partial file, and no-ops when the rendered file already
/// matches on disk.
fn sync_managed_block(entries: &[String]) {
    let lock = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(HOSTS_LOCK_PATH)
    {
        Ok(f) => f,
        Err(e) => {
            warn!("hosts_sync: cannot open lock file {HOSTS_LOCK_PATH}: {e}");
            return;
        }
    };
    if let Err(e) = rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        // WouldBlock → another worker is mid-rewrite; anything else → treat as
        // transient. Either way skip this tick; the next one retries.
        debug!("hosts_sync: skipping tick, could not lock /etc/hosts ({e})");
        return;
    }

    let existing = std::fs::read_to_string(HOSTS_PATH).unwrap_or_default();
    // Nothing managed and nothing to purge — avoid touching the file at all.
    if entries.is_empty() && !existing.contains(ARES_BLOCK_BEGIN) {
        return;
    }
    let rendered = render_hosts_file(&existing, entries);
    if rendered == existing {
        return; // already current; lock releases on drop
    }

    if let Err(e) = std::fs::write(HOSTS_TMP_PATH, rendered.as_bytes()) {
        warn!("hosts_sync: cannot write staging hosts file: {e}");
        return;
    }
    if let Err(e) = std::fs::rename(HOSTS_TMP_PATH, HOSTS_PATH) {
        warn!("hosts_sync: cannot replace /etc/hosts: {e}");
        let _ = std::fs::remove_file(HOSTS_TMP_PATH);
        return;
    }
    info!(
        count = entries.len(),
        "Rewrote ares-managed /etc/hosts block"
    );
    // `lock` drops here, releasing the flock.
}

/// Lazily binds the `/etc/hosts` sync to the operation a worker is currently
/// serving.
///
/// Long-lived workers (EC2 systemd units) start *before* any operation and
/// come up with `operation_id = None`, so the startup spawn in
/// [`crate::worker`] never fires — they only learn the operation ID when the
/// first task/tool-exec request for an op arrives over NATS. Without this the
/// sync never runs on EC2 and `/etc/hosts` stays empty, so every Kerberos /
/// FQDN-based tool (secretsdump, lsassy, S4U, cross-forest DCSync) fails with
/// `getaddrinfo: Name or service not known`.
///
/// [`Self::ensure`] is cheap to call on every request: it no-ops once the
/// sync is bound to the active op, and respawns (aborting the previous task)
/// when the op changes across a worker's lifetime.
#[derive(Default)]
pub struct HostsSyncGuard {
    current_op: Option<String>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl HostsSyncGuard {
    /// Seed the guard with the op known at process start (K8s path, where the
    /// startup spawn already covers it) so the lazy path doesn't double-spawn
    /// the same op.
    pub fn seeded(operation_id: Option<String>) -> Self {
        Self {
            current_op: operation_id,
            handle: None,
        }
    }

    /// Ensure the sync is running for `operation_id`, spawning it if the guard
    /// is not already bound to that op. Empty IDs are ignored.
    pub fn ensure(
        &mut self,
        conn: &ConnectionManager,
        operation_id: &str,
        agent_name: &str,
        shutdown: Arc<tokio::sync::Notify>,
    ) {
        if !needs_respawn(self.current_op.as_deref(), operation_id) {
            return;
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        self.handle = Some(spawn_hosts_sync(
            conn.clone(),
            operation_id.to_string(),
            agent_name.to_string(),
            shutdown,
        ));
        self.current_op = Some(operation_id.to_string());
    }
}

/// Decide whether the `/etc/hosts` sync must be (re)spawned for `incoming`.
/// A blank operation ID is never worth spawning for; otherwise respawn only
/// when the worker starts serving a different op than the one already bound.
fn needs_respawn(current: Option<&str>, incoming: &str) -> bool {
    !incoming.is_empty() && current != Some(incoming)
}

/// Spawn a background task that periodically syncs hosts from Redis to `/etc/hosts`.
///
/// Requires an operation ID to know which Redis key to read from.
/// Returns the join handle.
pub fn spawn_hosts_sync(
    conn: ConnectionManager,
    operation_id: String,
    agent_name: String,
    shutdown: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut conn = conn;
        let hosts_key = format!("ares:op:{operation_id}:hosts");
        info!(key = %hosts_key, agent = %agent_name, "Starting /etc/hosts sync background task");

        loop {
            // Rebuild the managed block from the CURRENT op's host set each tick
            // (no incremental `written` tracking) so a rebind to a new op purges
            // the prior op's entries. On op change the guard aborts this task and
            // spawns one bound to the new key, so we always reflect one op.
            let hosts_json: Vec<String> = match conn.lrange(&hosts_key, 0, -1).await {
                Ok(h) => h,
                Err(e) => {
                    debug!("hosts_sync: Redis read failed: {e}");
                    Vec::new()
                }
            };
            let hosts: Vec<Host> = hosts_json
                .iter()
                .filter_map(|json| serde_json::from_str(json).ok())
                .collect();
            let entries = build_host_entries(&hosts, &HashSet::new());

            // fs + flock are blocking — keep them off the async runtime.
            if let Err(e) = tokio::task::spawn_blocking(move || sync_managed_block(&entries)).await
            {
                debug!("hosts_sync: rewrite task join error: {e}");
            }

            tokio::select! {
                _ = tokio::time::sleep(SYNC_INTERVAL) => {}
                _ = shutdown.notified() => {
                    debug!("hosts_sync: shutdown signalled");
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc,
            owned: false,
        }
    }

    #[test]
    fn build_host_entries_basic() {
        let hosts = vec![
            make_host("192.168.58.10", "dc01.contoso.local", true),
            make_host("192.168.58.22", "ws01.contoso.local", false),
        ];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 2);
        // DC entry should have FQDN, short name, and domain
        assert_eq!(
            entries[0],
            "192.168.58.10  dc01.contoso.local dc01 contoso.local"
        );
        // Non-DC entry should have FQDN and short name only
        assert_eq!(entries[1], "192.168.58.22  ws01.contoso.local ws01");
    }

    #[test]
    fn build_host_entries_dedup() {
        let hosts = vec![make_host("192.168.58.10", "dc01.contoso.local", true)];
        let mut already_written = HashSet::new();
        already_written.insert("192.168.58.10".to_string());
        let entries = build_host_entries(&hosts, &already_written);
        assert!(entries.is_empty()); // Already written
    }

    #[test]
    fn build_host_entries_collapses_repeat_ip_within_call() {
        // Defensive intra-call dedup: a duplicate IP in the Redis list must not
        // emit two lines for the same address.
        let hosts = vec![
            make_host("192.168.58.10", "dc01.contoso.local", true),
            make_host("192.168.58.10", "dc01.contoso.local", true),
        ];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn render_hosts_file_appends_block_to_base() {
        let base = "127.0.0.1 localhost\n";
        let out = render_hosts_file(
            base,
            &["192.168.58.10  dc01.contoso.local dc01".to_string()],
        );
        assert!(out.starts_with("127.0.0.1 localhost\n"));
        assert!(out.contains(ARES_BLOCK_BEGIN));
        assert!(out.contains("192.168.58.10  dc01.contoso.local dc01"));
        assert!(out.contains(ARES_BLOCK_END));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn render_hosts_file_replaces_prior_block_and_purges_stale() {
        // A previous op's entry must NOT survive the rewrite — that's the whole
        // point: first-match-wins resolution would otherwise let a stale line
        // shadow the current op.
        let prior = format!(
            "127.0.0.1 localhost\n{ARES_BLOCK_BEGIN}\n10.9.9.9  dc01.contoso.local dc01\n{ARES_BLOCK_END}\n"
        );
        let out = render_hosts_file(
            &prior,
            &["192.168.58.10  dc01.contoso.local dc01".to_string()],
        );
        assert!(out.contains("192.168.58.10  dc01.contoso.local dc01"));
        assert!(
            !out.contains("10.9.9.9"),
            "stale prior-op entry survived: {out}"
        );
        // The base line is preserved and the block appears exactly once.
        assert!(out.contains("127.0.0.1 localhost"));
        assert_eq!(out.matches(ARES_BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn render_hosts_file_empty_entries_drops_block() {
        // Rebinding to an op with no hosts yet must purge the prior block
        // entirely, leaving only the base file.
        let prior = format!(
            "127.0.0.1 localhost\n{ARES_BLOCK_BEGIN}\n10.9.9.9  dc01.contoso.local\n{ARES_BLOCK_END}\n"
        );
        let out = render_hosts_file(&prior, &[]);
        assert!(!out.contains(ARES_BLOCK_BEGIN));
        assert!(!out.contains("10.9.9.9"));
        assert_eq!(out, "127.0.0.1 localhost\n");
    }

    #[test]
    fn render_hosts_file_strips_unterminated_block_from_crash() {
        // A crash mid-write can leave a BEGIN with no END. Everything from BEGIN
        // onward is dropped so the partial block can't poison resolution.
        let broken =
            format!("127.0.0.1 localhost\n{ARES_BLOCK_BEGIN}\n10.9.9.9  partial.contoso.local\n");
        let out = render_hosts_file(&broken, &["192.168.58.10  dc01.contoso.local".to_string()]);
        assert!(!out.contains("10.9.9.9"));
        assert!(out.contains("192.168.58.10  dc01.contoso.local"));
        assert_eq!(out.matches(ARES_BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn render_hosts_file_is_idempotent() {
        // Re-rendering the output of a prior render must be a fixed point, so
        // the sync's skip-if-unchanged guard actually holds and the file isn't
        // churned every tick.
        let base = "127.0.0.1 localhost\n";
        let entries = vec!["192.168.58.10  dc01.contoso.local dc01".to_string()];
        let once = render_hosts_file(base, &entries);
        let twice = render_hosts_file(&once, &entries);
        assert_eq!(once, twice);
    }

    #[test]
    fn build_host_entries_skip_incomplete() {
        let hosts = vec![
            make_host("", "dc01.contoso.local", true),
            make_host("192.168.58.10", "", true),
        ];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert!(entries.is_empty()); // Both missing required fields
    }

    #[test]
    fn build_host_entries_short_hostname() {
        let hosts = vec![make_host("192.168.58.99", "fileserver", false)];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 1);
        // Short hostname without domain — no alias needed
        assert_eq!(entries[0], "192.168.58.99  fileserver");
    }

    #[test]
    fn build_host_entries_dc_subdomain() {
        let hosts = vec![make_host("192.168.58.15", "dc02.child.contoso.local", true)];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0],
            "192.168.58.15  dc02.child.contoso.local dc02 child.contoso.local"
        );
    }

    #[test]
    fn build_host_entries_lowercase() {
        let hosts = vec![make_host("192.168.58.10", "DC01.CONTOSO.LOCAL", true)];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("dc01.contoso.local")); // Lowercased
    }

    #[test]
    fn needs_respawn_spawns_first_op_for_unbound_worker() {
        // EC2 worker started with operation_id=None: the first request that
        // carries an op must trigger the sync.
        assert!(needs_respawn(None, "op-20260704-225459"));
    }

    #[test]
    fn needs_respawn_skips_when_already_bound_to_same_op() {
        // Idempotent: called on every tool-exec request, must not respawn for
        // the op the sync is already serving.
        assert!(!needs_respawn(
            Some("op-20260704-225459"),
            "op-20260704-225459"
        ));
    }

    #[test]
    fn needs_respawn_respawns_when_op_changes() {
        // A long-lived worker reused across ops must rebind to the new op's
        // hosts key.
        assert!(needs_respawn(Some("op-old"), "op-new"));
    }

    #[test]
    fn needs_respawn_ignores_blank_incoming_op() {
        // A request without an operation_id must never spawn a sync against
        // the `ares:op::hosts` empty-id key.
        assert!(!needs_respawn(None, ""));
        assert!(!needs_respawn(Some("op-live"), ""));
    }

    #[test]
    fn hosts_sync_guard_seeded_reports_startup_op() {
        // Seeding with the startup op (K8s path) must suppress a redundant
        // lazy respawn for that same op.
        let guard = HostsSyncGuard::seeded(Some("op-startup".to_string()));
        assert!(!needs_respawn(guard.current_op.as_deref(), "op-startup"));
        assert!(needs_respawn(guard.current_op.as_deref(), "op-later"));
    }
}
