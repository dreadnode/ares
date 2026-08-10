//! Global concurrency caps for memory-heavy tools.
//!
//! Two layered caps live here:
//!
//! 1. `TOOL_PERMITS` — global ceiling on total concurrent subprocess spawns
//!    from `CommandBuilder::execute`. Backstop against pentest-tool fork-storms
//!    that OOM-killed the orchestrator when ~110 concurrent netexec/nxc/hashcat
//!    processes accumulated in a 10 GiB cgroup. Applied to every tool.
//!
//! 2. `SPIDER_PLUS_PERMITS` — tighter cap on `netexec spider_plus` specifically
//!    (`smbclient_spider`, `sysvol_script_search`). Each spider_plus invocation
//!    holds ~100–150 MB across a recursive share walk; without a specific cap,
//!    60+ concurrent dispatches blow the cgroup to 6–9 GB on their own even
//!    when the global cap is generous.
//!
//! Both caps are process-wide. Both the worker `tool_executor` path and the
//! orchestrator's `LocalToolDispatcher` route through `ares_tools::dispatch`,
//! so a single cap here covers both. Acquisition order is outer-to-inner:
//! `dispatch()` acquires the spider_plus permit (if applicable), then calls
//! the tool wrapper, which calls `CommandBuilder::execute()`, which acquires
//! the global tool permit — consistent order avoids deadlock.

use std::sync::LazyLock;

use tokio::sync::{Semaphore, SemaphorePermit};
use tracing::debug;

/// Default number of concurrent spider_plus dispatches before subsequent calls
/// queue. Picked to keep peak RSS under ~1 GB (4 × ~150 MB) on a t3.medium
/// while still allowing parallelism across multiple SMB targets.
pub const DEFAULT_SPIDER_PLUS_CONCURRENCY: usize = 4;

/// Override via `ARES_SPIDER_PLUS_CONCURRENCY=<n>`. Values <1 are ignored.
const SPIDER_PLUS_ENV: &str = "ARES_SPIDER_PLUS_CONCURRENCY";

static SPIDER_PLUS_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| {
    let cap = std::env::var(SPIDER_PLUS_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_SPIDER_PLUS_CONCURRENCY);
    Semaphore::new(cap)
});

/// Tools whose implementation invokes `netexec ... -M spider_plus`. Adding a
/// new spider_plus-backed tool? List it here so it shares the cap.
pub fn is_spider_plus_tool(tool_name: &str) -> bool {
    matches!(tool_name, "smbclient_spider" | "sysvol_script_search")
}

/// Acquire a permit for a spider_plus dispatch. The returned permit is held
/// for the lifetime of the tool execution; drop releases it for the next
/// queued call.
///
/// `acquire()` only fails if the semaphore is closed, which never happens in
/// our static initialization, so we treat it as fatal if observed.
pub async fn acquire_spider_plus_permit() -> SemaphorePermit<'static> {
    if SPIDER_PLUS_PERMITS.available_permits() == 0 {
        debug!("spider_plus concurrency cap reached, queueing dispatch");
    }
    SPIDER_PLUS_PERMITS
        .acquire()
        .await
        .expect("spider_plus semaphore unexpectedly closed")
}

/// Default global cap on concurrent subprocess spawns from
/// `CommandBuilder::execute`. Backstop against the pentest-tool fork-storm
/// that OOM-killed the orchestrator when ~110 concurrent
/// netexec/nxc/hashcat processes accumulated in a 10 GiB cgroup (each
/// netexec 90–345 MB, hashcat 500+ MB). At ~250 MB average, 20 concurrent
/// tools peak around 5 GB — well below the observed 10 GiB ceiling.
pub const DEFAULT_TOOL_CONCURRENCY: usize = 20;

/// Override via `ARES_MAX_CONCURRENT_TOOLS=<n>`. Values <1 are ignored.
const TOOL_CONCURRENCY_ENV: &str = "ARES_MAX_CONCURRENT_TOOLS";

static TOOL_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| {
    let cap = std::env::var(TOOL_CONCURRENCY_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_TOOL_CONCURRENCY);
    Semaphore::new(cap)
});

/// Acquire a permit for a subprocess spawn. Held for the lifetime of the
/// executing tool; drop releases it for the next queued call. Called from
/// `CommandBuilder::execute` on the hot spawn path — every subprocess is
/// gated by this cap.
///
/// Composes with the spider_plus cap: `dispatch()` acquires the spider_plus
/// permit first (outer), then the tool wrapper calls `execute()` which
/// acquires this permit (inner). Consistent acquisition order avoids
/// deadlock even when both caps are contended.
pub async fn acquire_tool_permit() -> SemaphorePermit<'static> {
    if TOOL_PERMITS.available_permits() == 0 {
        debug!("global tool concurrency cap reached, queueing spawn");
    }
    TOOL_PERMITS
        .acquire()
        .await
        .expect("tool semaphore unexpectedly closed")
}

/// Default number of concurrent hashcat crack jobs. Per-job session names keep
/// hashcat instances from colliding on restore/potfile state, so cheaper modes
/// can run beside an expensive one. AES Kerberoast has its own exclusive cap
/// below because two mode 19600/19700 kernels can exhaust a single T4's memory.
///
/// The orchestrator's `auto_crack_dispatch` already serializes at the *task*
/// layer, but that guard is per-task: the agent loop dispatches every tool
/// call in a single LLM turn concurrently, so a cracker that emits two
/// `crack_with_hashcat` calls in one turn would otherwise run two hashcats
/// under one task. This cap is the process-layer backstop that makes the
/// documented hashcat pool actually hold, on every path that reaches
/// `crack_with_hashcat`. Override with `ARES_MAX_CONCURRENT_HASHCAT=<n>`.
pub const DEFAULT_HASHCAT_CONCURRENCY: usize = 2;

/// Override via `ARES_MAX_CONCURRENT_HASHCAT=<n>`. Values <1 are ignored.
const HASHCAT_CONCURRENCY_ENV: &str = "ARES_MAX_CONCURRENT_HASHCAT";

static HASHCAT_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| {
    let cap = std::env::var(HASHCAT_CONCURRENCY_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_HASHCAT_CONCURRENCY);
    Semaphore::new(cap)
});

/// Acquire a hashcat crack-job permit. Held for the full crack sequence
/// (every wordlist/rules phase plus the final `--show`), so each submitted
/// crack job occupies one slot until completion.
///
/// Composes with the global tool permit: the crack wrapper acquires this
/// permit first (outer), then each hashcat spawn inside the job acquires the
/// tool permit (inner) via `CommandBuilder::execute`. Consistent outer→inner
/// order (matching the spider_plus cap) avoids deadlock; the inner tool
/// permit is always released after each spawn, so holding this outer permit
/// across several spawns can never starve itself.
pub async fn acquire_hashcat_permit() -> SemaphorePermit<'static> {
    if HASHCAT_PERMITS.available_permits() == 0 {
        debug!("hashcat crack-job cap reached, queueing crack job");
    }
    HASHCAT_PERMITS
        .acquire()
        .await
        .expect("hashcat semaphore unexpectedly closed")
}

static AES_KERBEROAST_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1));

/// Acquire the exclusive AES Kerberoast permit. Modes 19600/19700 are
/// memory-heavy enough that two concurrent jobs on the current T4 profile can
/// fail or throttle each other harder than a serialized run. Same-mode
/// roastable hashes are batched upstream, so this preserves useful parallelism
/// without duplicating the most expensive kernel.
pub async fn acquire_aes_kerberoast_permit() -> SemaphorePermit<'static> {
    if AES_KERBEROAST_PERMITS.available_permits() == 0 {
        debug!("AES Kerberoast cap reached, queueing crack job");
    }
    AES_KERBEROAST_PERMITS
        .acquire()
        .await
        .expect("AES Kerberoast semaphore unexpectedly closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_spider_plus_tools() {
        assert!(is_spider_plus_tool("smbclient_spider"));
        assert!(is_spider_plus_tool("sysvol_script_search"));
    }

    #[test]
    fn ignores_non_spider_tools() {
        assert!(!is_spider_plus_tool("nmap_scan"));
        assert!(!is_spider_plus_tool("secretsdump"));
        assert!(!is_spider_plus_tool(""));
    }

    #[tokio::test]
    async fn permit_serializes_excess_callers() {
        // Sanity check that the global semaphore actually blocks past the cap.
        // We can't override the singleton mid-test, but we can verify that
        // available_permits decreases when we hold one.
        let initial = SPIDER_PLUS_PERMITS.available_permits();
        let permit = acquire_spider_plus_permit().await;
        let after_acquire = SPIDER_PLUS_PERMITS.available_permits();
        assert_eq!(after_acquire, initial.saturating_sub(1));
        drop(permit);
        let after_drop = SPIDER_PLUS_PERMITS.available_permits();
        assert_eq!(after_drop, initial);
    }

    #[tokio::test]
    async fn tool_permit_reduces_available_count() {
        // Mirrors the spider_plus sanity check: holding a permit reduces
        // available_permits by one, dropping restores it.
        let initial = TOOL_PERMITS.available_permits();
        let permit = acquire_tool_permit().await;
        assert_eq!(TOOL_PERMITS.available_permits(), initial.saturating_sub(1));
        drop(permit);
        assert_eq!(TOOL_PERMITS.available_permits(), initial);
    }

    #[tokio::test]
    async fn hashcat_permit_uses_default_pool() {
        // The crack path relies on a bounded hashcat pool. Holding one permit
        // drains one slot; dropping restores it.
        assert_eq!(DEFAULT_HASHCAT_CONCURRENCY, 2);
        let initial = HASHCAT_PERMITS.available_permits();
        let permit = acquire_hashcat_permit().await;
        assert_eq!(
            HASHCAT_PERMITS.available_permits(),
            initial.saturating_sub(1)
        );
        drop(permit);
        assert_eq!(HASHCAT_PERMITS.available_permits(), initial);
    }
}
