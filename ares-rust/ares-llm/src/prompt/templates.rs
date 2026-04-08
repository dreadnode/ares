//! Tera template embedding and rendering for agent instructions.
//!
//! Templates are embedded at compile time via `include_str!` and rendered
//! with a `tera::Context` containing role-specific variables like capabilities
//! and multi-forest mode flags.

use anyhow::{Context as _, Result};
use once_cell::sync::Lazy;
use tera::{Context, Tera};

// ---------------------------------------------------------------------------
// Embedded templates
// ---------------------------------------------------------------------------

const RECON_TEMPLATE: &str = include_str!("../../templates/redteam/agents/recon.md.tera");

// Template name constants
pub const TEMPLATE_RECON: &str = "redteam/agents/recon";

/// Global Tera instance with all agent templates registered.
static TEMPLATES: Lazy<Tera> = Lazy::new(|| {
    let mut tera = Tera::default();
    tera.add_raw_template(TEMPLATE_RECON, RECON_TEMPLATE)
        .expect("Failed to register recon template");
    // Future templates will be added here as they are ported:
    // tera.add_raw_template(TEMPLATE_CREDENTIAL_ACCESS, CRED_ACCESS_TEMPLATE)...
    tera
});

/// Render an agent instruction template with the given context variables.
///
/// # Arguments
/// * `template_name` - Template identifier (e.g. `TEMPLATE_RECON`)
/// * `capabilities` - List of tool names available to this agent role
/// * `multi_forest_mode` - Whether multi-forest operation is active
/// * `undominated_forests` - Forest names not yet dominated (for orchestrator)
pub fn render_agent_instructions(
    template_name: &str,
    capabilities: &[String],
    multi_forest_mode: bool,
    undominated_forests: &[String],
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("capabilities", capabilities);
    ctx.insert("multi_forest_mode", &multi_forest_mode);
    ctx.insert("undominated_forests", undominated_forests);

    TEMPLATES
        .render(template_name, &ctx)
        .with_context(|| format!("Failed to render template '{template_name}'"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_recon_template() {
        let capabilities = vec![
            "nmap_scan".to_string(),
            "enumerate_users".to_string(),
            "run_bloodhound".to_string(),
        ];
        let result = render_agent_instructions(TEMPLATE_RECON, &capabilities, false, &[]).unwrap();

        assert!(result.contains("RECON Worker Agent"));
        assert!(result.contains("- nmap_scan"));
        assert!(result.contains("- enumerate_users"));
        assert!(result.contains("- run_bloodhound"));
    }

    #[test]
    fn test_render_recon_empty_capabilities() {
        let result = render_agent_instructions(TEMPLATE_RECON, &[], false, &[]).unwrap();
        assert!(result.contains("RECON Worker Agent"));
        assert!(result.contains("## Available Tools"));
    }

    #[test]
    fn test_invalid_template_name() {
        let result = render_agent_instructions("nonexistent", &[], false, &[]);
        assert!(result.is_err());
    }
}
