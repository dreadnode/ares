//! Windows privilege escalation and enumeration tool definitions.
//!
//! NOTE: The following tools are excluded because their binaries are not in the
//! privesc container image:
//! - gmsa_dump_passwords (netexec)
//! - unconstrained_coerce_and_capture (printerbug.py)
//! - printspoofer, godpotato, sweetpotato, seatbelt, sharpup, powerup,
//!   winpeas, linpeas, runas_cs, scm_uac_bypass, powerupsql (no executor
//!   implemented; Windows binaries run on-target, not locally)

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![ToolDefinition {
        name: "unconstrained_tgt_dump".into(),
        description: "Dump cached TGTs from a host with unconstrained delegation. \
                Retrieves Kerberos tickets stored in memory that can be used for \
                impersonation."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g. contoso.local)"
                },
                "username": {
                    "type": "string",
                    "description": "Username for authentication"
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication"
                },
                "dc_ip": {
                    "type": "string",
                    "description": "Domain controller IP address"
                },
                "target_host": {
                    "type": "string",
                    "description": "Host with unconstrained delegation to dump TGTs from"
                }
            },
            "required": ["domain", "username", "password", "dc_ip", "target_host"]
        }),
    }]
}
