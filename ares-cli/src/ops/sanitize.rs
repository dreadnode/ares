//! `ares ops sanitize` — manually wipe cross-op attacker-side residue (hashcat
//! potfile, netexec `~/.nxc` DBs + spider downloads, `/tmp/ares-tickets`
//! ccaches) so the next operation starts fresh. This is the same pass the
//! orchestrator runs automatically at op start; exposed standalone for a manual
//! clean slate between ops or before a benchmark run.

use anyhow::Result;

pub(crate) async fn ops_sanitize() -> Result<()> {
    let r = ares_tools::sanitize::sanitize_workspace();
    println!(
        "Workspace sanitized: potfile_reset={}, nxc_paths_removed={}, ccaches_removed={}",
        r.potfile_reset, r.nxc_paths_removed, r.ccaches_removed
    );
    Ok(())
}
