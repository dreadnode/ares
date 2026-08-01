//! Certificate-to-NT-hash (PKINIT) prompt branch.
//!
//! `auto_certipy_auth` dispatches a `credential_access` task whose payload
//! carries the `pfx_path` of a certificate already on disk — from an ADCS
//! relay, an ESC chain, or a shadow-credential write. Every other branch in
//! this module keys on techniques and credentials and drops that path, so the
//! agent was handed "run certipy_auth" with nothing to run it on and abandoned
//! the task with "requires a PFX certificate file path, but none is provided
//! in the task context/state" — with the certificate sitting in the payload.

use serde_json::Value;
use tera::Context;

use crate::prompt::helpers::insert_state_context;
use crate::prompt::templates::{render_template_with_context, TASK_CREDACCESS_CERT_AUTH};
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate the certificate-authentication prompt.
///
/// Fires whenever the payload names a PFX, whatever the technique list says:
/// a certificate on disk is convertible on its own, and the conversion is the
/// only move this task exists to make.
pub(super) fn try_generate(
    task_id: &str,
    payload: &Value,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    let pfx_path = payload
        .get("pfx_path")
        .or_else(|| payload.get("certificate_path"))
        .or_else(|| payload.get("cert_file"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;

    let target_user = payload
        .get("target_user")
        .or_else(|| payload.get("upn"))
        .or_else(|| payload.get("account_name"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("the certificate's subject");

    let dc_ip = p.dc_ip;

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("pfx_path", pfx_path);
    ctx.insert("target_user", target_user);
    ctx.insert("domain", p.domain);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "(unset)" } else { dc_ip },
    );
    if !dc_ip.is_empty() {
        ctx.insert("dc_ip", dc_ip);
    }
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    Some(render_template_with_context(
        TASK_CREDACCESS_CERT_AUTH,
        &ctx,
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::prompt::generate_task_prompt;

    fn prompt(payload: serde_json::Value) -> String {
        generate_task_prompt("credential_access", "task-1", &payload, None)
            .expect("credential_access prompt renders")
    }

    #[test]
    fn a_dispatched_pfx_reaches_the_agent() {
        let rendered = prompt(json!({
            "technique": "certipy_auth",
            "vuln_id": "certificate_obtained_svc_sql_contoso_local",
            "pfx_path": "/tmp/ares_shadowcred_svc_sql_1754000000000.pfx",
            "domain": "contoso.local",
            "target_user": "svc_sql",
            "dc_ip": "192.168.58.10",
            "target_ip": "192.168.58.10",
        }));
        assert!(
            rendered.contains("/tmp/ares_shadowcred_svc_sql_1754000000000.pfx"),
            "the PFX path must reach the agent: {rendered}"
        );
        assert!(rendered.contains("certipy_auth("));
        assert!(rendered.contains("svc_sql"));
        assert!(rendered.contains("192.168.58.10"));
    }

    #[test]
    fn an_adcs_certificate_gets_the_same_conversion_prompt() {
        let rendered = prompt(json!({
            "technique": "certipy_auth",
            "pfx_path": "/tmp/cert_ESC1_1754000000000.pfx",
            "domain": "fabrikam.local",
            "target_user": "administrator",
            "dc_ip": "192.168.58.20",
        }));
        assert!(rendered.contains("/tmp/cert_ESC1_1754000000000.pfx"));
        assert!(rendered.contains("certipy_auth("));
    }

    #[test]
    fn a_payload_without_a_certificate_is_left_to_the_other_branches() {
        let rendered = prompt(json!({
            "technique": "secretsdump",
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "username": "alice",
        }));
        assert!(!rendered.contains("CERTIFICATE -> NT HASH"));
    }

    #[test]
    fn an_empty_pfx_path_is_not_a_certificate() {
        let rendered = prompt(json!({
            "technique": "certipy_auth",
            "pfx_path": "",
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
        }));
        assert!(!rendered.contains("CERTIFICATE -> NT HASH"));
    }
}
