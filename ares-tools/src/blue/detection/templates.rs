//! Detection template metadata and builder.

use super::config::{build_template_logql, find_template};

// ─── Template metadata ─────────────────────────────────────────────────────

pub(super) struct DetectionTemplate {
    pub(super) logql: String,
    pub(super) description: &'static str,
    pub(super) mitre_id: &'static str,
    pub(super) tactic: &'static str,
    pub(super) severity: &'static str,
    pub(super) red_team_tool: Option<&'static str>,
    pub(super) auto_pivot: bool,
}

impl DetectionTemplate {
    pub(super) fn format_header(&self) -> String {
        let mut header = format!(
            "## {} ({})\n**Severity:** {} | **Tactic:** {}",
            self.description, self.mitre_id, self.severity, self.tactic,
        );
        if let Some(tool) = self.red_team_tool {
            header.push_str(&format!(" | **Red Team Tool:** {tool}"));
        }
        if self.auto_pivot {
            header.push_str(" | **Auto-Pivot:** yes");
        }
        header.push_str(&format!("\n**Query:** `{}`\n", self.logql));
        header
    }
}

// ─── Template builder ───────────────────────────────────────────────────────

pub(super) fn build_detection_template(
    name: &str,
    host: Option<&str>,
) -> Option<DetectionTemplate> {
    let (_, entry) = find_template(name)?;
    let logql = build_template_logql(entry, host);

    Some(DetectionTemplate {
        logql,
        description: entry.description.as_str(),
        mitre_id: entry.mitre_id.as_str(),
        tactic: entry.tactic.as_str(),
        severity: entry.severity.as_str(),
        red_team_tool: entry.red_team_tool.as_deref(),
        auto_pivot: entry.auto_pivot,
    })
}
