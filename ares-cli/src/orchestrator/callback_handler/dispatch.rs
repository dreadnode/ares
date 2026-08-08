use anyhow::Result;
use tracing::{debug, info, warn};

use ares_llm::provider::ToolCall;
use ares_llm::CallbackResult;

use super::OrchestratorCallbackHandler;

fn find_usable_credential(
    credentials: &[ares_core::models::Credential],
    username: &str,
    domain: &str,
) -> Option<ares_core::models::Credential> {
    credentials
        .iter()
        .find(|c| {
            c.username.eq_ignore_ascii_case(username)
                && (domain.is_empty() || c.domain.eq_ignore_ascii_case(domain))
                && !c.password.is_empty()
        })
        .cloned()
}

fn realm_from_hosts(hosts: &[ares_core::models::Host], target_ip: &str) -> Option<String> {
    hosts
        .iter()
        .find(|h| h.ip == target_ip)
        .and_then(|h| h.hostname.split_once('.').map(|(_, d)| d.to_lowercase()))
}

pub(super) fn is_cross_realm(cred_domain: &str, target_realm: &str) -> bool {
    let cd = cred_domain.to_lowercase();
    let td = target_realm.to_lowercase();
    !cd.is_empty()
        && !td.is_empty()
        && cd != td
        && !td.ends_with(&format!(".{cd}"))
        && !cd.ends_with(&format!(".{td}"))
}

impl OrchestratorCallbackHandler {
    pub(super) async fn dispatch_recon(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let techniques: Vec<&str> = call.arguments["techniques"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let task_id = dispatcher
            .request_recon(target_ip, domain, &techniques, None)
            .await?;

        info!(target_ip = target_ip, "Dispatched recon task");
        Ok(CallbackResult::Continue(format!(
            "Recon task dispatched: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_credential_access(
        &self,
        call: &ToolCall,
    ) -> Result<CallbackResult> {
        let technique = call.arguments["technique"]
            .as_str()
            .unwrap_or("secretsdump");
        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let priority = call.arguments["priority"].as_i64().unwrap_or(5) as i32;

        let (target_realm, cred) = {
            let state = self.state.read().await;
            (
                realm_from_hosts(&state.hosts, target_ip),
                find_usable_credential(&state.credentials, username, domain),
            )
        };

        if let Some(td) = target_realm {
            if is_cross_realm(domain, &td) {
                warn!(
                    target_ip = target_ip,
                    target_realm = %td,
                    cred_domain = domain,
                    cred_user = username,
                    technique = technique,
                    "Rejecting cross-realm credential access from LLM — returning dead-end message"
                );
                return Ok(CallbackResult::Continue(format!(
                    "REJECTED: cross-realm credential access ({domain} cred → {td} target at \
                     {target_ip}) will not work, and any secrets it returned would be stamped \
                     with the wrong realm. DCSync/{technique} requires replication rights held \
                     in {td}. Instead: dispatch forest_trust_escalation, exploit ESC8/MSSQL/ACL \
                     paths to acquire a {td}-realm credential, then re-dispatch with domain={td}."
                )));
            }
        }

        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let Some(cred) = cred else {
            warn!(
                username = username,
                domain = domain,
                technique = technique,
                "dispatch_credential_access names a principal with no usable secret"
            );
            return Ok(CallbackResult::Continue(format!(
                "REJECTED: no usable credential is held for {username}@{domain}, so this \
                 dispatch would authenticate with nothing. Call get_all_credentials() and \
                 dispatch as a principal listed there with has_password true."
            )));
        };

        let task_id = dispatcher
            .request_credential_access(technique, target_ip, domain, &cred, priority)
            .await?;

        info!(
            technique = technique,
            target_ip = target_ip,
            "Dispatched credential access task"
        );
        Ok(CallbackResult::Continue(format!(
            "Credential access task ({technique}) dispatched: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_lateral(&self, call: &ToolCall) -> Result<CallbackResult> {
        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let technique = call.arguments["technique"].as_str().unwrap_or("psexec");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");

        let (target_realm, cred) = {
            let state = self.state.read().await;
            (
                realm_from_hosts(&state.hosts, target_ip),
                find_usable_credential(&state.credentials, username, domain),
            )
        };
        if let Some(td) = target_realm {
            if is_cross_realm(domain, &td) {
                let cd = domain.to_lowercase();
                warn!(
                    target_ip = target_ip,
                    target_realm = %td,
                    cred_domain = %cd,
                    cred_user = username,
                    technique = technique,
                    "Rejecting cross-realm lateral from LLM — returning dead-end message"
                );
                return Ok(CallbackResult::Continue(format!(
                    "REJECTED: cross-realm lateral movement ({cd} cred → {td} target at {target_ip}) \
                     will not work. Windows strips ExtraSid RID<1000 across forests, and same-realm \
                     auth is required for SMB/WMI/PSExec. DO NOT retry this combination with any \
                     {technique}/pth_*/smbexec/wmiexec/psexec variant. Instead: dispatch \
                     forest_trust_escalation, exploit ESC8/MSSQL/ACL paths to acquire a \
                     {td}-realm credential, or pivot via FSP membership."
                )));
            }
        }

        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let Some(cred) = cred else {
            warn!(
                username = username,
                domain = domain,
                technique = technique,
                "dispatch_lateral_movement names a principal with no usable secret"
            );
            return Ok(CallbackResult::Continue(format!(
                "REJECTED: no usable credential is held for {username}@{domain}. Call \
                 get_all_credentials() and move as a principal listed there with \
                 has_password true."
            )));
        };

        let task_id = dispatcher
            .request_lateral(target_ip, &cred, technique)
            .await?;

        info!(
            technique = technique,
            target_ip = target_ip,
            "Dispatched lateral movement task"
        );
        Ok(CallbackResult::Continue(format!(
            "Lateral movement ({technique}) dispatched to {target_ip}: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_exploit(&self, call: &ToolCall) -> Result<CallbackResult> {
        let vuln_id = call.arguments["vuln_id"].as_str().unwrap_or("");
        let priority = call.arguments["priority"].as_i64().unwrap_or(3) as i32;

        let vuln = {
            let state = self.state.read().await;
            state.discovered_vulnerabilities.get(vuln_id).cloned()
        };

        let Some(vuln) = vuln else {
            return Ok(CallbackResult::Continue(format!(
                "Vulnerability {vuln_id} not found in discovered vulnerabilities. Call \
                 get_operation_summary() and pass a vuln_id that appears there — do not \
                 invent one."
            )));
        };

        // The deterministic exploitation workflow abandons a vuln at
        // MAX_EXPLOIT_FAILURES; this tool bypassed that cap entirely, so the
        // planner could re-propose the same dead vuln every turn. One vuln was
        // dispatched 16 times in op-20260806-030246.
        if self.state.is_exploit_abandoned(vuln_id).await {
            debug!(
                vuln_id = vuln_id,
                "Refusing orchestrator exploit dispatch — vuln abandoned at max failures"
            );
            return Ok(CallbackResult::Continue(format!(
                "Refused: {vuln_id} has already failed {} times and is abandoned for this \
                 operation. Re-dispatching it will fail the same way. Pick a different \
                 vuln_id, or unlock this path first (crack a hash, capture a credential \
                 for the target domain, or resolve the missing enumeration data).",
                crate::orchestrator::state::MAX_EXPLOIT_FAILURES
            )));
        }

        if crate::orchestrator::exploitation::is_trust_automation_owned_vuln(&vuln.vuln_type) {
            debug!(
                vuln_id = vuln_id,
                vuln_type = %vuln.vuln_type,
                "Refusing orchestrator exploit dispatch — forest-pivot vuln is owned by auto_trust_follow"
            );
            return Ok(CallbackResult::Continue(format!(
                "Refused: {vuln_id} is a {} vuln, which the trust automation owns end to end \
                 (trust-key extraction → inter-realm ticket forge → secretsdump). Dispatching it \
                 here produces an exploit task with no trust key and it always fails. The \
                 automation retries on its own whenever new trust material lands, so do not \
                 dispatch it. To unblock that forest, get a credential or certificate valid in \
                 the TARGET realm instead — ADCS enrolment, a relay, or cracking a hash from it.",
                vuln.vuln_type
            )));
        }

        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let task_id = dispatcher.request_exploit(&vuln, priority).await?;
        info!(vuln_id = vuln_id, "Dispatched exploit task");
        Ok(CallbackResult::Continue(format!(
            "Exploit task for {} dispatched: {}",
            vuln_id,
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_coercion(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let listener_ip = call.arguments["listener_ip"].as_str().unwrap_or("");
        let techniques: Vec<&str> = call.arguments["techniques"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_else(|| vec!["petitpotam", "printerbug"]);

        let task_id = dispatcher
            .request_coercion(target_ip, listener_ip, &techniques)
            .await?;

        info!(target_ip = target_ip, "Dispatched coercion task");
        Ok(CallbackResult::Continue(format!(
            "Coercion task dispatched to {target_ip}: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_crack(&self, call: &ToolCall) -> Result<CallbackResult> {
        let username = call.arguments["username"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let hash_type = call.arguments["hash_type"].as_str();

        let (hash, dominated) = {
            let state = self.state.read().await;
            let dominated: std::collections::HashSet<String> = state
                .dominated_domains
                .iter()
                .map(|d| d.trim().to_lowercase())
                .collect();
            let hash = state
                .hashes
                .iter()
                .find(|h| {
                    h.username.eq_ignore_ascii_case(username)
                        && (domain.is_empty() || h.domain.eq_ignore_ascii_case(domain))
                        && h.cracked_password.is_none()
                        && hash_type
                            .map(|t| h.hash_type.eq_ignore_ascii_case(t))
                            .unwrap_or(true)
                })
                .cloned();
            (hash, dominated)
        };

        let Some(hash) = hash else {
            return Ok(CallbackResult::Continue(format!(
                "No uncracked hash is held for {username}@{domain}. Call get_all_hashes() \
                 and pick a principal whose cracked field is false."
            )));
        };

        if crate::orchestrator::automation::is_owned_domain_ntlm(&hash, &dominated) {
            return Ok(CallbackResult::Continue(format!(
                "Refused: {username}@{} is NTLM for a domain already fully compromised, and \
                 its hash is already usable for pass-the-hash. Cracking it buys no new access \
                 and would delay roastable (AS-REP/kerberoast) hashes that unlock domains we \
                 do not own. Pick an uncracked AS-REP or kerberoast hash instead.",
                hash.domain
            )));
        }

        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let hash_type_label = hash.hash_type.clone();
        let task_id = dispatcher.request_crack(&hash).await?;

        info!(hash_type = %hash_type_label, "Dispatched crack task");
        Ok(CallbackResult::Continue(format!(
            "Crack task dispatched for {username}@{domain} ({hash_type_label}): {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn complete_operation(&self, call: &ToolCall) -> Result<CallbackResult> {
        let summary = call.arguments["summary"]
            .as_str()
            .unwrap_or("Operation completed")
            .to_string();

        {
            let mut state = self.state.write().await;
            state.completed = true;
        }

        warn!(summary = %summary, "Orchestrator marked the operation complete");
        Ok(CallbackResult::Continue(format!(
            "Operation marked complete: {summary}. The completion monitor will drain \
             outstanding red tasks and finalize the report. Call task_complete now."
        )))
    }
}

impl OrchestratorCallbackHandler {
    pub(super) async fn get_proposed_work(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let limit = call.arguments["limit"].as_u64().unwrap_or(30) as usize;
        let proposals = dispatcher.proposals.list(limit).await;

        if proposals.is_empty() {
            return Ok(CallbackResult::Continue(
                "No work is currently proposed. The automations have nothing pending your \
                 review. If you believe something is being missed, dispatch it yourself."
                    .to_string(),
            ));
        }

        let result = serde_json::json!({
            "proposed_work": proposals,
            "total": dispatcher.proposals.len().await,
            "auto_release_window_secs": dispatcher.proposals.window().as_secs(),
        });
        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    pub(super) async fn approve_work(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let ids: Vec<String> = call.arguments["proposal_ids"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        if ids.is_empty() {
            return Ok(CallbackResult::Continue(
                "No proposal_ids supplied. Call get_proposed_work() and pass the ids you \
                 want to run."
                    .to_string(),
            ));
        }

        let (approved, unknown) = dispatcher.proposals.approve(&ids).await;
        let mut submitted = 0_usize;
        for task in approved {
            match dispatcher
                .submit_approved(
                    &task.task_type,
                    &task.target_role,
                    task.payload.clone(),
                    task.priority,
                )
                .await
            {
                Ok(_) => submitted += 1,
                Err(e) => {
                    warn!(err = %e, task_type = %task.task_type, "Approved work failed to submit")
                }
            }
        }

        info!(
            submitted,
            unknown = unknown.len(),
            "Orchestrator approved work"
        );
        let mut msg = format!("Approved and dispatched {submitted} task(s).");
        if !unknown.is_empty() {
            msg.push_str(&format!(
                " Unknown ids ignored: {}. They were already approved, rejected, or \
                 auto-released — call get_proposed_work() for the current list.",
                unknown.join(", ")
            ));
        }
        Ok(CallbackResult::Continue(msg))
    }

    pub(super) async fn reject_work(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let id = call.arguments["proposal_id"].as_str().unwrap_or("");
        let reason = call.arguments["reason"].as_str().unwrap_or("");

        match dispatcher.proposals.reject(id).await {
            Some(task) => {
                info!(
                    proposal = id,
                    task_type = %task.task_type,
                    reason = reason,
                    "Orchestrator rejected proposed work"
                );
                Ok(CallbackResult::Continue(format!(
                    "Rejected {id} ({}). It will not be re-proposed during the cooldown.",
                    task.task_type
                )))
            }
            None => Ok(CallbackResult::Continue(format!(
                "No pending proposal {id}. It was already approved, rejected, or \
                 auto-released — call get_proposed_work() for the current list."
            ))),
        }
    }
}
