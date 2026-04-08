//! Shared helpers for prompt generation.

use serde_json::Value;
use tera::Context;

use super::state_context::format_state_context;
use super::StateSnapshot;

/// Extract credential fields from payload into a Tera context.
pub(crate) fn insert_credential_context(ctx: &mut Context, payload: &Value) {
    if let Some(cred) = payload.get("credential") {
        let user = cred["username"].as_str().unwrap_or("");
        let cred_domain = cred["domain"].as_str().unwrap_or("");
        if !user.is_empty() {
            ctx.insert("credential_username", user);
            ctx.insert("credential_domain", cred_domain);

            let has_password = cred
                .get("password")
                .and_then(|v| v.as_str())
                .is_some_and(|p| !p.is_empty());
            ctx.insert(
                "auth_type",
                if has_password {
                    "password"
                } else {
                    "hash/ticket"
                },
            );
        }
    }
}

/// Insert formatted state context into a Tera context.
pub(crate) fn insert_state_context(
    ctx: &mut Context,
    state: Option<&StateSnapshot>,
    task_type: &str,
    target: Option<&str>,
) {
    if let Some(s) = state {
        let state_ctx = format_state_context(s, task_type, target);
        if !state_ctx.is_empty() {
            ctx.insert("state_context", &state_ctx);
        }
    }
}

/// Check if a hash value is compatible with pass-the-hash (NTLM LM:NT format).
pub(crate) fn is_pass_the_hash_compatible(hash_value: Option<&str>) -> bool {
    let Some(raw) = hash_value else {
        return false;
    };
    let normalized = raw.trim();
    if normalized.is_empty() || normalized.contains('$') {
        return false;
    }
    let hex32 = |s: &str| -> bool { s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) };
    if let Some((lm, nt)) = normalized.split_once(':') {
        if normalized.matches(':').count() != 1 {
            return false;
        }
        if !lm.is_empty() && !hex32(lm) {
            return false;
        }
        hex32(nt)
    } else {
        hex32(normalized)
    }
}

/// Extract techniques array from a payload.
pub(crate) fn payload_techniques(payload: &Value) -> Vec<String> {
    payload
        .get("techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Build the credential parameter string for technique call sites.
pub(crate) fn cred_param_str(payload: &Value, hash_value: Option<&str>) -> String {
    if let Some(pw) = payload.get("password").and_then(|v| v.as_str()) {
        if !pw.is_empty() {
            return format!("password='{pw}'");
        }
    }
    if let Some(h) = hash_value {
        return format!("hashes='{h}'");
    }
    "password='N/A'".to_string()
}

/// Build the credential display string.
pub(crate) fn cred_display_str(payload: &Value, hash_value: Option<&str>) -> String {
    if let Some(pw) = payload.get("password").and_then(|v| v.as_str()) {
        if !pw.is_empty() {
            return pw.to_string();
        }
    }
    if let Some(h) = hash_value {
        return format!("[HASH] {h}");
    }
    "N/A".to_string()
}
