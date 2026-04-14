//! Privilege escalation role tool definitions.
//!
//! Split into submodules by category:
//! - `adcs` — Certipy / ADCS tools
//! - `delegation` — Kerberos delegation tools (find_delegation, S4U, RBCD)
//! - `tickets` — Golden ticket, trust keys, SID lookup, DNS tool
//! - `escalation` — Windows privesc binaries, gMSA, unconstrained delegation
//! - `cve_exploits` — noPac, PrintNightmare, PetitPotam

mod adcs;
mod cve_exploits;
mod delegation;
mod escalation;
mod tickets;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = adcs::definitions();
    tools.extend(delegation::definitions());
    tools.extend(tickets::definitions());
    tools.extend(escalation::definitions());
    tools.extend(cve_exploits::definitions());
    tools
}
