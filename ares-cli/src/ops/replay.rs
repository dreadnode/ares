//! `ares ops replay` — rebuild a point-in-time state snapshot from the
//! JetStream `ARES_OPSTATE` event log. Phase 5 forensics tooling.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use ares_core::nats::NatsBroker;

use crate::orchestrator::state::replay::{replay_op_to_snapshot, ReplayCutoff, ReplaySnapshot};

pub(crate) async fn ops_replay(
    operation_id: String,
    until: Option<String>,
    until_count: Option<usize>,
    json: bool,
) -> Result<()> {
    let until_dt: Option<DateTime<Utc>> = match until.as_deref() {
        None => None,
        Some(raw) => Some(
            DateTime::parse_from_rfc3339(raw)
                .with_context(|| format!("--until value '{raw}' is not RFC 3339"))?
                .with_timezone(&Utc),
        ),
    };
    let cutoff = ReplayCutoff {
        until: until_dt,
        until_count,
    };

    let nats = NatsBroker::connect_from_env()
        .await
        .context("Failed to connect to NATS (set ARES_NATS_URL)")?;

    let snapshot = replay_op_to_snapshot(&nats, &operation_id, cutoff)
        .await
        .context("Replay failed")?;

    if json {
        let s = serde_json::to_string_pretty(&snapshot).context("serialize snapshot")?;
        println!("{s}");
    } else {
        print_human_summary(&snapshot);
    }
    Ok(())
}

fn print_human_summary(s: &ReplaySnapshot) {
    println!("Replay snapshot for operation: {}", s.operation_id);
    println!("Events applied:                {}", s.events_applied);
    println!("Credentials:                   {}", s.credentials.len());
    println!("Hashes:                        {}", s.hashes.len());
    println!("Hosts:                         {}", s.hosts.len());
    println!(
        "  owned:                       {}",
        s.hosts.iter().filter(|h| h.owned).count()
    );
    println!(
        "  domain controllers:          {}",
        s.hosts.iter().filter(|h| h.is_dc).count()
    );
    println!("Users:                         {}", s.users.len());
    println!(
        "Discovered vulnerabilities:    {}",
        s.discovered_vulnerabilities.len()
    );
    println!(
        "Exploited vulnerabilities:     {}",
        s.exploited_vulnerabilities.len()
    );
}
