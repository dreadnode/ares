//! MITRE ATT&CK technique coverage analysis.

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::rows::{MitreCoverage, MitreTechniqueRow};
use super::HistoricalQueryService;

impl HistoricalQueryService {
    /// Get MITRE ATT&CK technique coverage across operations.
    pub async fn get_mitre_coverage(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<MitreCoverage>> {
        let rows = if let Some(s) = since {
            sqlx::query_as::<_, MitreTechniqueRow>(
                "SELECT te.mitre_techniques, o.operation_id
                 FROM timeline_events te JOIN operations o ON te.operation_id = o.id
                 WHERE te.mitre_techniques IS NOT NULL
                   AND array_length(te.mitre_techniques, 1) > 0
                   AND o.started_at >= $1",
            )
            .bind(s)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, MitreTechniqueRow>(
                "SELECT te.mitre_techniques, o.operation_id
                 FROM timeline_events te JOIN operations o ON te.operation_id = o.id
                 WHERE te.mitre_techniques IS NOT NULL
                   AND array_length(te.mitre_techniques, 1) > 0",
            )
            .fetch_all(&self.pool)
            .await?
        };

        // Aggregate by technique
        let mut technique_ops: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            if let Some(techniques) = row.mitre_techniques {
                for t in techniques {
                    technique_ops
                        .entry(t)
                        .or_default()
                        .push(row.operation_id.clone());
                }
            }
        }

        // Deduplicate operations per technique
        let mut result: Vec<MitreCoverage> = technique_ops
            .into_iter()
            .map(|(technique_id, mut ops)| {
                ops.sort();
                ops.dedup();
                let occurrence_count = ops.len();
                MitreCoverage {
                    technique_id,
                    occurrence_count,
                    operations: ops,
                }
            })
            .collect();

        // Sort by occurrence count descending
        result.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));

        Ok(result)
    }
}
