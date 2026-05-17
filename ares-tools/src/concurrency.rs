//! Global concurrency caps for memory-heavy tools.
//!
//! `netexec spider_plus` (used by `smbclient_spider` and `sysvol_script_search`)
//! enumerates SMB share trees recursively and holds the file metadata in RAM
//! across the walk. Each invocation costs ~100–150 MB resident; without a cap,
//! 60+ concurrent dispatches blow the EC2 cgroup to 6–9 GB and OOM-kill the
//! orchestrator.
//!
//! This module provides a process-wide async semaphore for those tools.
//! Both the worker `tool_executor` path and the orchestrator's
//! `LocalToolDispatcher` route through `ares_tools::dispatch`, so a single
//! cap here covers both.

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
}
