//! Credential access role tool definitions.
//!
//! Split into submodules by category:
//! - `kerberos` — Kerberoast, AS-REP roast, user enum
//! - `secretsdump` — Secretsdump tool definition
//! - `misc` — Remaining credential access tools (lsassy, spray, GPP, LAPS, etc.)

mod kerberos;
mod misc;
mod secretsdump;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = kerberos::definitions();
    tools.extend(secretsdump::definitions());
    tools.extend(misc::definitions());
    tools
}
