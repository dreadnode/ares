//! Task prompt generation for LLM agent steps.
//!
//! Ports the prompt building logic from `src/ares/core/worker/prompts.py`.
//! Each task type gets a specific prompt rendered from a Tera template.
//! Variable extraction from JSON payloads happens in Rust; prompt wording
//! and structure lives in `.tera` template files.

#[cfg(feature = "blue")]
pub mod blue;
pub mod templates;

mod acl;
mod coercion;
mod command;
mod crack;
mod credential_access;
mod exploit;
mod helpers;
mod lateral;
mod privesc;
mod recon;
mod state_context;

use std::collections::HashMap;

use ares_core::models::{Credential, Hash, Host, Share, VulnerabilityInfo};
use serde_json::Value;

pub use state_context::format_state_context;

// ---------------------------------------------------------------------------
// StateSnapshot — cheap, clonable view of operation state
// ---------------------------------------------------------------------------

/// A snapshot of operation state used for prompt generation.
/// Cloned from `SharedState` to avoid holding the RwLock during LLM calls.
#[derive(Debug, Clone, Default)]
pub struct StateSnapshot {
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub shares: Vec<Share>,
    pub domains: Vec<String>,
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: std::collections::HashSet<String>,
    pub domain_controllers: HashMap<String, String>,
    pub netbios_to_fqdn: HashMap<String, String>,
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    /// Forest root domains that still need krbtgt hashes (computed at snapshot time).
    pub undominated_forests: Vec<String>,
    /// Usernames (lowercased) that are delegating accounts for constrained
    /// delegation or RBCD vulnerabilities.  Agents must NOT use these
    /// credentials for generic auth — they are reserved for S4U.
    pub delegation_accounts: std::collections::HashSet<String>,
}

// ---------------------------------------------------------------------------
// Task prompt generation
// ---------------------------------------------------------------------------

/// Generate a task prompt from a task type and JSON payload.
///
/// Returns `None` if the task type is not recognized.
/// Each task type extracts variables from the payload and renders
/// the corresponding `.tera` template.
pub fn generate_task_prompt(
    task_type: &str,
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> Option<String> {
    let result = match task_type {
        "recon" => recon::generate_recon_prompt(task_id, payload, state),
        "crack" => crack::generate_crack_prompt(task_id, payload),
        "credential_access" => {
            credential_access::generate_credential_access_prompt(task_id, payload, state)
        }
        "lateral_movement" | "lateral" => lateral::generate_lateral_prompt(task_id, payload, state),
        "exploit" => exploit::generate_exploit_prompt(task_id, payload, state),
        "coercion" => coercion::generate_coercion_prompt(task_id, payload, state),
        "privesc_enumeration" => {
            privesc::generate_privesc_enumeration_prompt(task_id, payload, state)
        }
        "acl_analysis" => acl::generate_acl_analysis_prompt(task_id, payload, state),
        "command" => command::generate_command_prompt(task_id, payload),
        _ => return None,
    };
    Some(result.unwrap_or_else(|e| format!("Error generating prompt: {e}")))
}

#[cfg(test)]
mod tests;
