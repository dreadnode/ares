//! Detection template catalog — listing and lookup.

use anyhow::Result;
use serde_json::Value;

use super::config::detection_config;
use crate::ToolOutput;

/// List all available detection templates with MITRE mappings.
pub async fn list_detection_templates(_args: &Value) -> Result<ToolOutput> {
    let config = detection_config();

    let mut entries: Vec<String> = Vec::new();

    for (name, tmpl) in &config.templates {
        let tool_str = tmpl.red_team_tool.as_deref().unwrap_or("-");
        entries.push(format!(
            "- **{name}** [{mitre}] ({tactic}) severity={severity} tool={tool_str}",
            mitre = tmpl.mitre_id,
            tactic = tmpl.tactic,
            severity = tmpl.severity,
        ));
        for alias in &tmpl.aliases {
            entries.push(format!(
                "- **{alias}** [{mitre}] ({tactic}) severity={severity} tool={tool_str}",
                mitre = tmpl.mitre_id,
                tactic = tmpl.tactic,
                severity = tmpl.severity,
            ));
        }
    }

    // Investigation tools (not detection templates)
    entries.push("- **get_host_activity** [-] (investigation) severity=- tool=-".to_string());
    entries.push("- **get_user_activity** [-] (investigation) severity=- tool=-".to_string());

    Ok(ToolOutput {
        stdout: format!(
            "Available detection templates ({}):\n\n{}",
            entries.len(),
            entries.join("\n")
        ),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}
