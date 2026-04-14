//! Post-recovery analysis helper.

use std::collections::HashMap;
use std::fmt::Write as _;

use ares_core::models::{Hash, SharedRedTeamState, TaskInfo, VulnerabilityInfo};

use super::types::{InterruptedTask, RetryingTask};

/// Post-recovery analysis helper.
///
/// Provides convenience methods to inspect the recovered state and produce
/// a human-readable summary for the orchestrator.
#[allow(dead_code)]
pub struct OperationResumeHelper<'a> {
    pub state: &'a SharedRedTeamState,
    pub requeued_task_ids: &'a [String],
    pub failed_task_ids: &'a [String],
    /// Pending tasks loaded during recovery (task_id -> TaskInfo).
    pub pending_tasks: &'a HashMap<String, TaskInfo>,
}

#[allow(dead_code)]
impl<'a> OperationResumeHelper<'a> {
    /// Get tasks that permanently failed (exceeded max retries during recovery).
    pub fn get_interrupted_tasks(&self) -> Vec<InterruptedTask> {
        let mut out = Vec::new();
        for task_id in self.failed_task_ids {
            if let Some(task) = self.pending_tasks.get(task_id) {
                out.push(InterruptedTask {
                    task_id: task_id.clone(),
                    task_type: task.task_type.clone(),
                    assigned_agent: task.assigned_agent.clone(),
                    retry_count: task.retry_count,
                    error: task.error.clone().unwrap_or_default(),
                });
            }
        }
        out
    }

    /// Get tasks that were auto-requeued and are currently retrying.
    pub fn get_retrying_tasks(&self) -> Vec<RetryingTask> {
        let mut out = Vec::new();
        for task_id in self.requeued_task_ids {
            if let Some(task) = self.pending_tasks.get(task_id) {
                out.push(RetryingTask {
                    task_id: task_id.clone(),
                    task_type: task.task_type.clone(),
                    assigned_agent: task.assigned_agent.clone(),
                    retry_count: task.retry_count,
                    max_retries: task.max_retries,
                });
            }
        }
        out
    }

    /// Get vulnerabilities that have been discovered but not yet exploited.
    pub fn get_unexploited_vulnerabilities(&self) -> Vec<&VulnerabilityInfo> {
        let mut vulns: Vec<&VulnerabilityInfo> = self
            .state
            .discovered_vulnerabilities
            .values()
            .filter(|v| !self.state.exploited_vulnerabilities.contains(&v.vuln_id))
            .collect();
        vulns.sort_by_key(|v| v.priority);
        vulns
    }

    /// Get hashes that have not been cracked yet.
    pub fn get_uncracked_hashes(&self) -> Vec<&Hash> {
        self.state
            .all_hashes
            .iter()
            .filter(|h| h.cracked_password.is_none())
            .collect()
    }

    /// Generate a human-readable summary of the recovery state.
    pub fn get_resume_summary(&self) -> String {
        let mut s = String::new();

        let _ = writeln!(s, "OPERATION RESUMED AFTER RECOVERY");
        let _ = writeln!(s, "{}", "=".repeat(50));
        let _ = writeln!(s);
        let _ = writeln!(s, "Operation ID: {}", self.state.operation_id);
        let _ = writeln!(s, "Credentials found: {}", self.state.all_credentials.len());
        let _ = writeln!(s, "Hosts discovered: {}", self.state.all_hosts.len());
        let _ = writeln!(
            s,
            "Domain admin: {}",
            if self.state.has_domain_admin {
                "YES"
            } else {
                "NO"
            }
        );
        let _ = writeln!(s);

        // Retrying tasks
        let retrying = self.get_retrying_tasks();
        if !retrying.is_empty() {
            let _ = writeln!(s, "[RETRYING] {} tasks auto-requeued:", retrying.len());
            for task in retrying.iter().take(5) {
                let _ = writeln!(
                    s,
                    "  - {} -> {} (retry {}/{})",
                    task.task_type, task.assigned_agent, task.retry_count, task.max_retries
                );
            }
            let _ = writeln!(s);
        }

        // Permanently failed tasks
        let interrupted = self.get_interrupted_tasks();
        if !interrupted.is_empty() {
            let _ = writeln!(
                s,
                "[FAILED] {} tasks exceeded max retries:",
                interrupted.len()
            );
            for task in interrupted.iter().take(5) {
                let _ = writeln!(
                    s,
                    "  - {} -> {} (retried {}x)",
                    task.task_type, task.assigned_agent, task.retry_count
                );
            }
            let _ = writeln!(s);
        }

        // Unexploited vulnerabilities
        let unexploited = self.get_unexploited_vulnerabilities();
        if !unexploited.is_empty() {
            let _ = writeln!(
                s,
                "[PENDING] {} unexploited vulnerabilities:",
                unexploited.len()
            );
            for v in unexploited.iter().take(5) {
                let _ = writeln!(
                    s,
                    "  - {}: {} (priority {})",
                    v.vuln_type, v.target, v.priority
                );
            }
            let _ = writeln!(s);
        }

        // Uncracked hashes
        let uncracked = self.get_uncracked_hashes();
        if !uncracked.is_empty() {
            let _ = writeln!(s, "[PENDING] {} uncracked hashes", uncracked.len());
            let _ = writeln!(s);
        }

        if retrying.is_empty() && interrupted.is_empty() {
            let _ = writeln!(s, "[OK] No interrupted tasks - clean recovery");
            let _ = writeln!(s);
        }

        s
    }
}
