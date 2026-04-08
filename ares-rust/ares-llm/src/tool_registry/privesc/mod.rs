//! Privilege escalation role tool definitions.
//!
//! Split into submodules by category:
//! - `adcs` — Certipy / ADCS tools
//! - `delegation` — Kerberos delegation tools (find_delegation, S4U, RBCD)
//! - `tickets` — Golden ticket, trust keys, Windows privesc binaries, CVE exploits

mod adcs;
mod delegation;
mod tickets;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = adcs::definitions();
    tools.extend(delegation::definitions());
    tools.extend(tickets::definitions());
    tools
}
