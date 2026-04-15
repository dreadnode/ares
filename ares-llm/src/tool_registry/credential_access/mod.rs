//! Credential access role tool definitions.
//!
//! Split into submodules by category:
//! - `kerberos` — Kerberoast, AS-REP roast, user enum
//! - `secretsdump` — Secretsdump tool definition
//! - `misc` — Remaining credential access tools (lsassy, NTDS)
//! - `netexec_tools` — Tools requiring netexec/ldapsearch (run on recon workers via cross-role routing)

mod kerberos;
mod misc;
pub(crate) mod netexec_tools;
mod secretsdump;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = kerberos::definitions();
    tools.extend(secretsdump::definitions());
    tools.extend(misc::definitions());
    tools.extend(netexec_tools::definitions());
    tools
}
