//! Generic fallback and technique-with-credentials prompt branches.

use std::collections::HashMap;

use serde_json::Value;
use tera::Context;

use crate::prompt::helpers::{cred_display_str, cred_param_str, insert_state_context};
use crate::prompt::templates::{
    render_template_with_context, TASK_CREDACCESS_FALLBACK, TASK_CREDACCESS_WITH_CREDS,
};
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate a technique enforcement prompt WITH credentials (Branch 7).
/// Returns `Some` if conditions match, `None` otherwise.
pub(super) fn try_generate_with_creds(
    task_id: &str,
    payload: &Value,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    if p.techniques.is_empty() || !p.has_creds {
        return None;
    }

    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let username = p.username;
    let cred_param = cred_param_str(payload, p.hash_value);
    let cred_display = cred_display_str(payload, p.hash_value);

    let technique_map: HashMap<&str, String> = [
        (
            "sysvol_script_search",
            format!(
                "sysvol_script_search(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - ~2 seconds, finds hardcoded passwords in login scripts"
            ),
        ),
        (
            "gpp_password_finder",
            format!(
                "gpp_password_finder(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - ~2 seconds, finds GPP/cpassword credentials"
            ),
        ),
        (
            "ldap_search_descriptions",
            format!(
                "ldap_search_descriptions(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - finds passwords in LDAP description fields"
            ),
        ),
        (
            "kerberoast",
            format!(
                "kerberoast(domain='{domain}', username='{username}', \
                 {cred_param}, dc_ip='{dc_ip}') \
                 - service account hashes (uses correct DC for the domain)"
            ),
        ),
        (
            "secretsdump",
            format!(
                "secretsdump(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - dump hashes (requires admin)"
            ),
        ),
        (
            "lsassy",
            format!(
                "lsassy(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - LSASS memory dump"
            ),
        ),
        (
            "laps_dump",
            format!(
                "laps_dump(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - LAPS local admin passwords"
            ),
        ),
    ]
    .into_iter()
    .collect();

    let mut instructions = Vec::new();
    for (i, technique) in p.techniques.iter().enumerate() {
        let idx = i + 1;
        if let Some(desc) = technique_map.get(technique.as_str()) {
            instructions.push(format!("{idx}. {desc}"));
        } else {
            instructions.push(format!("{idx}. {technique}(...)"));
        }
    }

    if instructions.is_empty() {
        return None;
    }

    let targets_display = if p.targets.is_empty() {
        "N/A".to_string()
    } else {
        p.targets.join(", ")
    };

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", domain);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    ctx.insert("targets_display", &targets_display);
    ctx.insert(
        "user_display",
        if username.is_empty() { "N/A" } else { username },
    );
    ctx.insert("cred_display", &cred_display);
    ctx.insert("instructions_text", &instructions.join("\n"));
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    Some(render_template_with_context(
        TASK_CREDACCESS_WITH_CREDS,
        &ctx,
    ))
}

/// Generate the generic fallback prompt.
pub(super) fn generate_fallback(
    task_id: &str,
    payload: &Value,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let dc_ip = p.dc_ip;

    let cred_type = if p.has_password {
        "password"
    } else if p.has_hash {
        if p.hash_is_pth {
            "hash"
        } else {
            "hash (non-NTLM)"
        }
    } else {
        "none"
    };
    let hash_note = if p.has_hash && !p.hash_is_pth {
        "NOTE: Provided hash is not NTLM pass-the-hash compatible; \
         do not attempt secretsdump/lsassy with it."
    } else {
        ""
    };
    let cred_value = if p.has_password {
        p.password
    } else {
        p.hash_value.unwrap_or("N/A")
    };
    let source = payload
        .get("credential_source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let hash_type = payload
        .get("hash_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let techniques_display = if p.techniques.is_empty() {
        "auto-select".to_string()
    } else {
        p.techniques.join(", ")
    };
    let targets_display = if p.targets.is_empty() {
        "N/A".to_string()
    } else {
        p.targets.join(", ")
    };

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", p.domain);
    ctx.insert("targets_display", &targets_display);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    ctx.insert(
        "user_display",
        if p.username.is_empty() {
            "N/A"
        } else {
            p.username
        },
    );
    ctx.insert("cred_type", cred_type);
    ctx.insert("cred_value", cred_value);
    ctx.insert("techniques_display", &techniques_display);
    if !hash_type.is_empty() {
        ctx.insert("hash_type", hash_type);
    }
    if !source.is_empty() {
        ctx.insert("source", source);
    }
    if !p.reason.is_empty() {
        ctx.insert("reason", p.reason);
    }
    if !hash_note.is_empty() {
        ctx.insert("hash_note", hash_note);
    }
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    render_template_with_context(TASK_CREDACCESS_FALLBACK, &ctx)
}
