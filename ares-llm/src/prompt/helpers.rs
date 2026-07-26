//! Shared helpers for prompt generation.
//!
//! These helpers MUST NOT emit credential values (passwords, hashes, AES keys,
//! ticket bytes) into prompts. The worker resolves credentials from operation
//! state at dispatch time; the LLM only ever sees principals (username/domain)
//! and capability labels ("password", "nthash", "aes256", "ticket"). See
//! `ares-cli/src/worker/credential_resolver.rs` for the resolution path.

use serde_json::Value;
use tera::Context;

use super::state_context::format_state_context;
use super::StateSnapshot;

/// Insert principal-only credential context into a Tera context.
/// Surfaces `credential_username`, `credential_domain`, `credential_auth_type`
/// — never the raw password/hash. Templates that need to brand "we have creds"
/// vs "we don't" can branch on `credential_username` presence; templates that
/// need to brand the auth type can branch on `credential_auth_type`.
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
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            ctx.insert(
                "credential_auth_type",
                if has_password {
                    "password"
                } else {
                    "hash/ticket"
                },
            );
        }
    }
    // Surface bind_domain so templates can instruct the LLM to use it
    if let Some(bd) = payload.get("bind_domain").and_then(|v| v.as_str()) {
        if !bd.is_empty() {
            ctx.insert("bind_domain", bd);
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

/// Capability label for a payload's credential.
///
/// Returns one of: `"password"`, `"nthash"`, `"none"`. The label is **non-secret**
/// — it tells the LLM what auth class will be auto-resolved, not the value.
pub(crate) fn cred_capability_label(payload: &Value, hash_value: Option<&str>) -> &'static str {
    let has_password = payload
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
        .is_some();
    if has_password {
        "password"
    } else if hash_value.is_some() {
        "nthash"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pth_compat_lm_nt() {
        assert!(is_pass_the_hash_compatible(Some(
            "aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c"
        )));
    }

    #[test]
    fn pth_compat_nt_only() {
        assert!(is_pass_the_hash_compatible(Some(
            "313b6f423a71d74c0a1b8a2f43b22d4c"
        )));
    }

    #[test]
    fn pth_compat_none() {
        assert!(!is_pass_the_hash_compatible(None));
    }

    #[test]
    fn pth_compat_empty() {
        assert!(!is_pass_the_hash_compatible(Some("")));
    }

    #[test]
    fn pth_compat_kerberos_hash() {
        assert!(!is_pass_the_hash_compatible(Some(
            "$krb5tgs$23$*svc_sql$contoso.local"
        )));
    }

    #[test]
    fn pth_compat_multiple_colons() {
        assert!(!is_pass_the_hash_compatible(Some("aad3:b435:b514")));
    }

    #[test]
    fn pth_compat_lm_empty_nt_valid() {
        assert!(is_pass_the_hash_compatible(Some(
            ":313b6f423a71d74c0a1b8a2f43b22d4c"
        )));
    }

    #[test]
    fn payload_techniques_present() {
        let payload = json!({"techniques": ["network_scan", "user_enumeration"]});
        let techs = payload_techniques(&payload);
        assert_eq!(techs, vec!["network_scan", "user_enumeration"]);
    }

    #[test]
    fn payload_techniques_missing() {
        let payload = json!({"target": "192.168.58.10"});
        let techs = payload_techniques(&payload);
        assert!(techs.is_empty());
    }

    #[test]
    fn payload_techniques_empty_array() {
        let payload = json!({"techniques": []});
        let techs = payload_techniques(&payload);
        assert!(techs.is_empty());
    }

    #[test]
    fn cred_capability_password() {
        let payload = json!({"password": "secret"});
        assert_eq!(cred_capability_label(&payload, None), "password");
    }

    #[test]
    fn cred_capability_nested_password() {
        let payload = json!({"credential": {"password": "secret"}});
        assert_eq!(cred_capability_label(&payload, None), "password");
    }

    #[test]
    fn cred_capability_hash_only() {
        let payload = json!({});
        assert_eq!(cred_capability_label(&payload, Some("aabb")), "nthash");
    }

    #[test]
    fn cred_capability_none() {
        let payload = json!({});
        assert_eq!(cred_capability_label(&payload, None), "none");
    }

    #[test]
    fn cred_capability_password_takes_precedence() {
        let payload = json!({"password": "secret"});
        assert_eq!(cred_capability_label(&payload, Some("aabb")), "password");
    }

    #[test]
    fn cred_capability_empty_password_falls_back_to_hash() {
        let payload = json!({"password": ""});
        assert_eq!(cred_capability_label(&payload, Some("aabb")), "nthash");
    }

    #[test]
    fn insert_credential_context_with_password_does_not_leak_value() {
        let payload = json!({
            "credential": {
                "username": "admin",
                "domain": "contoso.local",
                "password": "P@ss1"
            }
        });
        let mut ctx = Context::new();
        insert_credential_context(&mut ctx, &payload);
        assert_eq!(
            ctx.get("credential_username").and_then(|v| v.as_str()),
            Some("admin")
        );
        assert_eq!(
            ctx.get("credential_domain").and_then(|v| v.as_str()),
            Some("contoso.local")
        );
        assert_eq!(
            ctx.get("credential_auth_type").and_then(|v| v.as_str()),
            Some("password")
        );
        assert!(
            ctx.get("credential_password").is_none(),
            "credential_password must never be exposed to templates"
        );
    }

    #[test]
    fn insert_credential_context_with_hash() {
        let payload = json!({
            "credential": {
                "username": "admin",
                "domain": "contoso.local"
            }
        });
        let mut ctx = Context::new();
        insert_credential_context(&mut ctx, &payload);
        assert_eq!(
            ctx.get("credential_auth_type").and_then(|v| v.as_str()),
            Some("hash/ticket")
        );
        assert!(ctx.get("credential_password").is_none());
    }

    #[test]
    fn insert_credential_context_no_cred() {
        let payload = json!({"target": "192.168.58.10"});
        let mut ctx = Context::new();
        insert_credential_context(&mut ctx, &payload);
        assert!(ctx.get("credential_username").is_none());
        assert!(ctx.get("credential_password").is_none());
    }
}
