//! Credential access task prompt generation.
//!
//! Split into submodules by branch:
//! - `kerberos` -- Kerberos ticket-based secretsdump prompt
//! - `low_hanging` -- Low-hanging fruit with/without credentials
//! - `spray` -- Username-as-password spray prompt
//! - `no_cred` -- Technique enforcement without credentials
//! - `generic` -- Generic fallback prompt

mod generic;
mod kerberos;
mod low_hanging;
mod no_cred;
mod spray;

use serde_json::Value;

use super::helpers::{is_pass_the_hash_compatible, payload_techniques};
use super::StateSnapshot;

/// Shared extracted parameters from the task payload.
pub(crate) struct Params<'a> {
    pub hash_value: Option<&'a str>,
    pub hash_is_pth: bool,
    pub techniques: Vec<String>,
    pub targets: Vec<&'a str>,
    pub dc_ip: &'a str,
    pub domain: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub reason: &'a str,
    pub ticket_path: Option<&'a str>,
    pub no_pass: bool,
    pub has_password: bool,
    pub has_hash: bool,
    pub has_creds: bool,
}

pub(crate) fn generate_credential_access_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let hash_value = payload
        .get("hash_value")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let hash_is_pth = is_pass_the_hash_compatible(hash_value);

    let mut techniques = payload_techniques(payload);
    // Also read singular "technique" from dispatchers that use it
    if techniques.is_empty() {
        if let Some(t) = payload.get("technique").and_then(|v| v.as_str()) {
            if !t.is_empty() {
                techniques.push(t.to_string());
            }
        }
    }
    if hash_value.is_some() && !hash_is_pth {
        techniques.retain(|t| {
            let lower = t.to_lowercase();
            lower != "secretsdump" && lower != "lsassy"
        });
    }

    let targets: Vec<&str> = payload
        .get("target_ips")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let dc_ip = payload
        .get("dc_ip")
        .or_else(|| payload.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    // Read from nested "credential" object first (dispatchers nest it), flat fallback
    let cred_obj = payload.get("credential");
    let username = cred_obj
        .and_then(|c| c.get("username"))
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("username").and_then(|v| v.as_str()))
        .unwrap_or("");
    let password = cred_obj
        .and_then(|c| c.get("password"))
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("password").and_then(|v| v.as_str()))
        .unwrap_or("");
    let reason = payload.get("reason").and_then(|v| v.as_str()).unwrap_or("");

    let ticket_path = payload.get("ticket_path").and_then(|v| v.as_str());
    let no_pass = payload
        .get("no_pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_password = !password.is_empty();
    let has_hash = hash_value.is_some();
    let has_creds = has_password || (hash_is_pth && has_hash);

    let params = Params {
        hash_value,
        hash_is_pth,
        techniques,
        targets,
        dc_ip,
        domain,
        username,
        password,
        reason,
        ticket_path,
        no_pass,
        has_password,
        has_hash,
        has_creds,
    };

    // Branch 1: Kerberos ticket-based secretsdump
    if let Some(result) = kerberos::try_generate(task_id, &params, state) {
        return result;
    }

    // Determine low-hanging-fruit flags
    let has_sysvol = params
        .techniques
        .iter()
        .any(|t| t == "sysvol_script_search" || t == "gpp_password_finder");
    let has_spray_tech = params
        .techniques
        .iter()
        .any(|t| t == "username_as_password" || t == "password_spray");
    let has_low_hanging =
        params.reason.to_lowercase().contains("low_hanging_fruit") || has_sysvol || has_spray_tech;

    // Branch 2: Low-hanging fruit WITH credentials
    if has_low_hanging && params.has_password {
        return low_hanging::generate_with_creds(task_id, &params, state);
    }

    // Branch 3: Username-as-password spray
    if let Some(result) = spray::try_generate(task_id, &params, state) {
        return result;
    }

    // Branch 4: Share spider
    if let Some(result) = low_hanging::try_share_spider(task_id, &params, state) {
        return result;
    }

    // Branch 5: Technique enforcement WITHOUT credentials
    if let Some(result) = no_cred::try_generate(task_id, &params, state) {
        return result;
    }

    // Branch 6: Low-hanging fruit WITHOUT credentials
    if has_low_hanging && !params.has_password && !params.has_hash {
        return low_hanging::generate_without_creds(task_id, &params, state);
    }

    // Branch 7: Technique enforcement WITH credentials
    if let Some(result) = generic::try_generate_with_creds(task_id, payload, &params, state) {
        return result;
    }

    // Generic fallback
    generic::generate_fallback(task_id, payload, &params, state)
}
