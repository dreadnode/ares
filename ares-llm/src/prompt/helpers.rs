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

            let password = cred.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let has_password = !password.is_empty();
            if has_password {
                ctx.insert("credential_password", password);
            }
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

/// Extract password from payload — checks nested `credential.password` first,
/// then flat top-level `password` (matches both dispatcher shapes).
fn extract_password(payload: &Value) -> Option<&str> {
    payload
        .get("credential")
        .and_then(|c| c.get("password"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            payload
                .get("password")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
}

/// Build the credential parameter string for technique call sites.
pub(crate) fn cred_param_str(payload: &Value, hash_value: Option<&str>) -> String {
    if let Some(pw) = extract_password(payload) {
        return format!("password='{pw}'");
    }
    if let Some(h) = hash_value {
        return format!("hashes='{h}'");
    }
    "password='N/A'".to_string()
}

/// Build the credential display string.
pub(crate) fn cred_display_str(payload: &Value, hash_value: Option<&str>) -> String {
    if let Some(pw) = extract_password(payload) {
        return pw.to_string();
    }
    if let Some(h) = hash_value {
        return format!("[HASH] {h}");
    }
    "N/A".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- is_pass_the_hash_compatible ---

    #[test]
    fn test_pth_compat_lm_nt() {
        assert!(is_pass_the_hash_compatible(Some(
            "aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c"
        )));
    }

    #[test]
    fn test_pth_compat_nt_only() {
        assert!(is_pass_the_hash_compatible(Some(
            "313b6f423a71d74c0a1b8a2f43b22d4c"
        )));
    }

    #[test]
    fn test_pth_compat_none() {
        assert!(!is_pass_the_hash_compatible(None));
    }

    #[test]
    fn test_pth_compat_empty() {
        assert!(!is_pass_the_hash_compatible(Some("")));
    }

    #[test]
    fn test_pth_compat_kerberos_hash() {
        assert!(!is_pass_the_hash_compatible(Some(
            "$krb5tgs$23$*svc_sql$contoso.local"
        )));
    }

    #[test]
    fn test_pth_compat_multiple_colons() {
        assert!(!is_pass_the_hash_compatible(Some("aad3:b435:b514")));
    }

    #[test]
    fn test_pth_compat_lm_empty_nt_valid() {
        // Empty LM part with valid NT
        assert!(is_pass_the_hash_compatible(Some(
            ":313b6f423a71d74c0a1b8a2f43b22d4c"
        )));
    }

    // --- payload_techniques ---

    #[test]
    fn test_payload_techniques_present() {
        let payload = json!({"techniques": ["network_scan", "user_enumeration"]});
        let techs = payload_techniques(&payload);
        assert_eq!(techs, vec!["network_scan", "user_enumeration"]);
    }

    #[test]
    fn test_payload_techniques_missing() {
        let payload = json!({"target": "192.168.58.10"});
        let techs = payload_techniques(&payload);
        assert!(techs.is_empty());
    }

    #[test]
    fn test_payload_techniques_empty_array() {
        let payload = json!({"techniques": []});
        let techs = payload_techniques(&payload);
        assert!(techs.is_empty());
    }

    // --- cred_param_str ---

    #[test]
    fn test_cred_param_str_password() {
        let payload = json!({"password": "P@ss1"});
        assert_eq!(cred_param_str(&payload, None), "password='P@ss1'");
    }

    #[test]
    fn test_cred_param_str_nested_password() {
        let payload = json!({"credential": {"username": "admin", "domain": "contoso.local", "password": "Summer2025"}});
        assert_eq!(cred_param_str(&payload, None), "password='Summer2025'");
    }

    #[test]
    fn test_cred_param_str_nested_takes_precedence() {
        let payload = json!({"password": "flat", "credential": {"password": "nested"}});
        assert_eq!(cred_param_str(&payload, None), "password='nested'");
    }

    #[test]
    fn test_cred_param_str_hash() {
        let payload = json!({});
        assert_eq!(
            cred_param_str(&payload, Some("aabbccdd")),
            "hashes='aabbccdd'"
        );
    }

    #[test]
    fn test_cred_param_str_fallback() {
        let payload = json!({});
        assert_eq!(cred_param_str(&payload, None), "password='N/A'");
    }

    #[test]
    fn test_cred_param_str_empty_password_uses_hash() {
        let payload = json!({"password": ""});
        assert_eq!(cred_param_str(&payload, Some("aabb")), "hashes='aabb'");
    }

    #[test]
    fn test_cred_param_str_nested_empty_uses_hash() {
        let payload = json!({"credential": {"password": ""}});
        assert_eq!(cred_param_str(&payload, Some("aabb")), "hashes='aabb'");
    }

    // --- cred_display_str ---

    #[test]
    fn test_cred_display_str_password() {
        let payload = json!({"password": "Secret123"});
        assert_eq!(cred_display_str(&payload, None), "Secret123");
    }

    #[test]
    fn test_cred_display_str_nested_password() {
        let payload = json!({"credential": {"password": "Summer2025"}});
        assert_eq!(cred_display_str(&payload, None), "Summer2025");
    }

    #[test]
    fn test_cred_display_str_hash() {
        let payload = json!({});
        assert_eq!(
            cred_display_str(&payload, Some("aabbccdd")),
            "[HASH] aabbccdd"
        );
    }

    #[test]
    fn test_cred_display_str_fallback() {
        let payload = json!({});
        assert_eq!(cred_display_str(&payload, None), "N/A");
    }

    // --- insert_credential_context ---

    #[test]
    fn test_insert_credential_context_with_password() {
        let payload = json!({
            "credential": {
                "username": "admin",
                "domain": "contoso.local",
                "password": "P@ss1"
            }
        });
        let mut ctx = Context::new();
        insert_credential_context(&mut ctx, &payload);
        let json = ctx.into_json();
        assert_eq!(json["credential_username"], "admin");
        assert_eq!(json["credential_domain"], "contoso.local");
        assert_eq!(json["credential_password"], "P@ss1");
        assert_eq!(json["auth_type"], "password");
    }

    #[test]
    fn test_insert_credential_context_with_hash() {
        let payload = json!({
            "credential": {
                "username": "admin",
                "domain": "contoso.local"
            }
        });
        let mut ctx = Context::new();
        insert_credential_context(&mut ctx, &payload);
        let json = ctx.into_json();
        assert_eq!(json["auth_type"], "hash/ticket");
    }

    #[test]
    fn test_insert_credential_context_no_cred() {
        let payload = json!({"target": "192.168.58.10"});
        let mut ctx = Context::new();
        insert_credential_context(&mut ctx, &payload);
        let json = ctx.into_json();
        assert!(json.get("credential_username").is_none());
    }
}
