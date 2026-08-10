use anyhow::Result;
use std::collections::BTreeMap;

use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};

/// Per-`vuln_type` discovered/exploited tallies for the `inspect-vulns`
/// conversion diagnostic. `exploited` is the number of discovered vulns of
/// this type whose `vuln_id` is in the operation's exploited set, so it is
/// always `<= discovered`.
#[derive(Default, serde::Serialize)]
struct VulnBucket {
    discovered: usize,
    exploited: usize,
}

/// Bucket an operation's discovered vulnerabilities by `vuln_type` and count how
/// many of each have been exploited.
///
/// The vuln→exploit conversion gap is the first-look diagnostic for a stalled
/// op: types with a high discovered count and a low exploited count are where
/// the dispatch pipeline is leaking, not where the individual primitive is
/// broken. Rows are ordered by that gap (discovered − exploited) so the biggest
/// offenders surface at the top.
pub(crate) async fn ops_inspect_vulns(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    json: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());
    if !reader.exists(&mut conn).await? {
        println!("Operation {op_id} not found");
        return Ok(());
    }

    let vulns = reader.get_vulnerabilities(&mut conn).await?;
    let exploited = reader.get_exploited_vulnerabilities(&mut conn).await?;

    let mut buckets: BTreeMap<String, VulnBucket> = BTreeMap::new();
    for v in vulns.values() {
        let bucket = buckets.entry(v.vuln_type.clone()).or_default();
        bucket.discovered += 1;
        if exploited.contains(&v.vuln_id) {
            bucket.exploited += 1;
        }
    }

    let total_discovered = vulns.len();
    let total_exploited = vulns
        .values()
        .filter(|v| exploited.contains(&v.vuln_id))
        .count();

    if json {
        let out = serde_json::json!({
            "operation_id": op_id,
            "total_discovered": total_discovered,
            "total_exploited": total_exploited,
            "by_type": buckets,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    // Order by the unexploited gap (discovered − exploited) descending; break
    // ties by discovered count so the loudest fix candidates lead.
    let mut rows: Vec<(&String, &VulnBucket)> = buckets.iter().collect();
    rows.sort_by(|a, b| {
        let gap_a = a.1.discovered - a.1.exploited;
        let gap_b = b.1.discovered - b.1.exploited;
        gap_b
            .cmp(&gap_a)
            .then_with(|| b.1.discovered.cmp(&a.1.discovered))
    });

    let type_w = rows
        .iter()
        .map(|(t, _)| t.len())
        .max()
        .unwrap_or(0)
        .max("vuln_type".len());

    println!("Operation: {op_id}");
    println!(
        "{:<type_w$}  {:>10}  {:>9}  {:>6}",
        "vuln_type", "discovered", "exploited", "rate"
    );
    let rule = "-".repeat(type_w + 2 + 10 + 2 + 9 + 2 + 6);
    println!("{rule}");
    for (vtype, bucket) in rows {
        println!(
            "{:<type_w$}  {:>10}  {:>9}  {:>5.1}%",
            vtype,
            bucket.discovered,
            bucket.exploited,
            conversion_rate(bucket.discovered, bucket.exploited)
        );
    }
    println!("{rule}");
    println!(
        "{:<type_w$}  {:>10}  {:>9}  {:>5.1}%",
        "TOTAL",
        total_discovered,
        total_exploited,
        conversion_rate(total_discovered, total_exploited)
    );

    Ok(())
}

/// Exploited-over-discovered as a percentage, guarding the empty-op divide.
fn conversion_rate(discovered: usize, exploited: usize) -> f64 {
    if discovered == 0 {
        0.0
    } else {
        100.0 * exploited as f64 / discovered as f64
    }
}

#[cfg(test)]
mod tests {
    use super::conversion_rate;

    #[test]
    fn conversion_rate_handles_empty() {
        assert_eq!(conversion_rate(0, 0), 0.0);
    }

    #[test]
    fn conversion_rate_computes_percentage() {
        assert_eq!(conversion_rate(4, 1), 25.0);
        assert_eq!(conversion_rate(10, 10), 100.0);
    }
}
