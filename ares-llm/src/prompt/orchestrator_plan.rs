use serde_json::Value;
use tera::Context;

use super::templates::{render_template_with_context, TASK_ORCHESTRATOR_PLAN};

fn count(payload: &Value, key: &str) -> u64 {
    payload[key].as_u64().unwrap_or(0)
}

fn string_list(payload: &Value, key: &str) -> Vec<String> {
    payload[key]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn generate_orchestrator_plan_prompt(
    task_id: &str,
    payload: &Value,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);

    for key in [
        "credentials",
        "admin_credentials",
        "hashes",
        "uncracked_hashes",
        "hosts",
        "pending_tasks",
    ] {
        ctx.insert(key, &count(payload, key));
    }

    ctx.insert(
        "has_domain_admin",
        &payload["has_domain_admin"].as_bool().unwrap_or(false),
    );
    ctx.insert("domains", &string_list(payload, "domains"));
    ctx.insert(
        "undominated_forests",
        &string_list(payload, "undominated_forests"),
    );
    ctx.insert(
        "unexploited_vulnerability_ids",
        &string_list(payload, "unexploited_vulnerability_ids"),
    );

    render_template_with_context(TASK_ORCHESTRATOR_PLAN, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_counts_and_vuln_ids() {
        let payload = json!({
            "domains": ["contoso.local", "fabrikam.local"],
            "credentials": 4,
            "admin_credentials": 1,
            "hashes": 9,
            "uncracked_hashes": 3,
            "hosts": 6,
            "has_domain_admin": false,
            "undominated_forests": ["fabrikam.local"],
            "unexploited_vulnerability_ids": ["esc1_ca01", "acl_alice_bob"],
            "pending_tasks": 2,
        });

        let out = generate_orchestrator_plan_prompt("plan-1", &payload).unwrap();
        assert!(out.contains("plan-1"));
        assert!(out.contains("contoso.local, fabrikam.local"));
        assert!(out.contains("esc1_ca01"));
        assert!(out.contains("acl_alice_bob"));
        assert!(out.contains("fabrikam.local"));
        assert!(out.contains("3 uncracked"));
    }

    #[test]
    fn renders_with_empty_state() {
        let out = generate_orchestrator_plan_prompt("plan-2", &json!({})).unwrap();
        assert!(out.contains("plan-2"));
        assert!(out.contains("none discovered yet"));
        assert!(!out.contains("Forests not yet dominated"));
    }
}
