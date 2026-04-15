//! Lateral movement role tool definitions.
//!
//! Split into submodules by category:
//! - `execution` -- Remote execution tools (psexec, wmiexec, smbexec, evil-winrm, etc.)
//! - `pth` -- Pass-the-hash tools (pth-winexe, pth-smbclient, pth-rpcclient, pth-wmic)
//! - `kerberos` -- Kerberos TGT tools
//! - `mssql` -- MSSQL tools (command, impersonation, linked servers)
//! - `callbacks` -- Lateral movement result reporting

mod callbacks;
mod execution;
mod kerberos;
pub(super) mod mssql;
mod pth;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    let mut tools = execution::definitions();
    tools.extend(pth::definitions());
    tools.extend(kerberos::definitions());
    tools.extend(mssql::definitions());
    tools
}

pub(super) fn callback_definitions() -> Vec<ToolDefinition> {
    callbacks::definitions()
}
