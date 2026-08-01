//! ACL analysis task prompt generation.

use serde_json::Value;
use tera::Context;

use super::helpers::insert_state_context;
use super::templates::{render_template_with_context, TASK_ACL_ANALYSIS, TASK_ACL_CHAIN_STEP};
use super::StateSnapshot;

pub(crate) fn generate_acl_analysis_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);

    if let Some(chain) = payload.get("chain") {
        ctx.insert(
            "chain_json",
            &serde_json::to_string_pretty(chain).unwrap_or_default(),
        );
    }

    insert_state_context(&mut ctx, state, "acl_analysis", None);

    render_template_with_context(TASK_ACL_ANALYSIS, &ctx)
}

/// Render an `acl_chain_step` prompt.
///
/// Two payload shapes are supported:
///   1. Flat fields from `auto_dacl_abuse` (acl_type / source_user / target_user /
///      target_dn / target_type / target_ip / domain / vuln_id / credential).
///   2. Nested `step` object from `auto_acl_chain_follow` (raw BloodHound
///      step). Best-effort extraction of source/target/domain/dc_ip from the
///      step keys, falling back to the credential domain.
pub(crate) fn generate_acl_chain_step_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);

    let credential = payload.get("credential");
    let cred_username = credential
        .and_then(|c| c.get("username"))
        .and_then(|v| v.as_str());
    let cred_domain = credential
        .and_then(|c| c.get("domain"))
        .and_then(|v| v.as_str());

    let step = payload.get("step");

    let pick_str = |keys: &[&str]| -> Option<String> {
        for k in keys {
            if let Some(v) = payload.get(*k).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
            if let Some(s) = step {
                if let Some(v) = s.get(*k).and_then(|v| v.as_str()) {
                    return Some(v.to_string());
                }
            }
        }
        None
    };

    if let Some(v) = pick_str(&["acl_type", "edge_type", "edge", "right"]) {
        ctx.insert("acl_type", &v);
    }
    let source_user =
        pick_str(&["source_user", "source", "from"]).or_else(|| cred_username.map(String::from));
    if let Some(ref v) = source_user {
        ctx.insert("source_user", v);
    }
    let source_domain =
        pick_str(&["source_domain", "domain"]).or_else(|| cred_domain.map(String::from));
    if let Some(ref v) = source_domain {
        ctx.insert("source_domain", v);
    }
    if let Some(v) = pick_str(&["target_user", "target", "to"]) {
        ctx.insert("target_user", &v);
    }
    if let Some(v) = pick_str(&["target_dn", "target_distinguished_name"]) {
        ctx.insert("target_dn", &v);
    }
    if let Some(v) = pick_str(&["target_type", "target_class"]) {
        ctx.insert("target_type", &v);
    }
    if let Some(v) = pick_str(&["domain"]).or_else(|| cred_domain.map(String::from)) {
        ctx.insert("domain", &v);
    }
    if let Some(v) = pick_str(&["target_ip", "dc_ip", "target"]) {
        ctx.insert("dc_ip", &v);
    }
    if let Some(v) = pick_str(&["vuln_id"]) {
        ctx.insert("vuln_id", &v);
    }

    if let Some(s) = step {
        ctx.insert(
            "step_json",
            &serde_json::to_string_pretty(s).unwrap_or_default(),
        );
    }

    insert_state_context(&mut ctx, state, "acl_chain_step", None);

    render_template_with_context(TASK_ACL_CHAIN_STEP, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn writeowner_step_routes_through_owner_edit_before_dacl_edit() {
        let payload = json!({
            "technique": "dacl_abuse",
            "acl_type": "writeowner",
            "vuln_id": "acl_writeowner_alice_svc_sql",
            "source_user": "alice",
            "target_user": "svc_sql",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
        });
        let prompt = generate_acl_chain_step_prompt("acl_chain_step_1", &payload, None)
            .expect("writeowner step must render");

        let row = prompt
            .lines()
            .find(|l| l.starts_with("| `writeowner`"))
            .expect("the tool-choice table must still carry a writeowner row");
        let owner_at = row
            .find("owner_edit")
            .expect("writeowner has no primitive other than owner_edit");
        let dacl_at = row.find("dacl_edit").expect("dacl_edit is step two");
        assert!(
            owner_at < dacl_at,
            "owner_edit must be named before dacl_edit — dacl_edit first on a \
             writeowner edge can only fail; row was: {row}"
        );
    }

    #[test]
    fn gpo_step_surfaces_the_distinguished_name_and_names_the_dn_argument() {
        let dn =
            "CN={34034095-875D-4230-9232-2611A167C9E1},CN=Policies,CN=System,DC=contoso,DC=local";
        let payload = json!({
            "technique": "dacl_abuse",
            "acl_type": "gpo_writeowner",
            "vuln_id": "gpo_writeowner_alice__34034095_875d_4230_9232_2611a167c9e1_",
            "source_user": "alice",
            "target_user": "{34034095-875D-4230-9232-2611A167C9E1}",
            "target_type": "GPO",
            "target_dn": dn,
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
        });
        let prompt = generate_acl_chain_step_prompt("acl_chain_step_gpo", &payload, None)
            .expect("GPO step must render");

        assert!(
            prompt.contains(dn),
            "the DN is the only handle owneredit.py / dacledit.py accept for a GPO; \
             without it in the prompt the model can only pass the bare GUID: {prompt}"
        );
        assert!(
            prompt.contains("target_dn"),
            "the prompt has to name the argument dacl_edit's schema requires"
        );
        assert!(
            prompt.contains("Group Policy Object targets have no SAM account name"),
            "the GPO steer must survive template edits"
        );
    }

    #[test]
    fn chain_step_omits_the_dn_block_when_the_edge_has_no_dn() {
        let payload = json!({
            "acl_type": "writeowner",
            "source_user": "alice",
            "target_user": "svc_sql",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
        });
        let prompt = generate_acl_chain_step_prompt("acl_chain_step_3", &payload, None)
            .expect("step without a DN must still render");
        assert!(!prompt.contains("**Target distinguished name (`target_dn` argument"));
        assert!(!prompt.contains("**Target object class:**"));
    }

    #[test]
    fn chain_step_renders_without_a_target() {
        let payload = json!({
            "acl_type": "writeowner",
            "source_user": "alice",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
        });
        assert!(
            generate_acl_chain_step_prompt("acl_chain_step_2", &payload, None).is_ok(),
            "target_user is inserted conditionally, so an unguarded {{ target_user }} \
             in the template kills the whole task rather than one instruction"
        );
    }
}
