//! Windows privilege escalation and enumeration tool definitions.
//!
//! NOTE: The following tools are excluded because they have no executor
//! implemented (Windows binaries run on-target, not locally):
//! - printspoofer, godpotato, sweetpotato, seatbelt, sharpup, powerup,
//!   winpeas, linpeas, runas_cs, scm_uac_bypass, powerupsql

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "unconstrained_coerce_and_capture".into(),
            description: "Coerce authentication from a remote host to an unconstrained \
                    delegation host using SpoolService (PrinterBug). The target's TGT \
                    is cached in LSASS on the listener. Follow up with \
                    unconstrained_tgt_dump to extract the TGT."
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
                    "coerce_from": {
                        "type": "string",
                        "description": "Host to coerce authentication FROM (typically a DC IP)"
                    },
                    "listener_ip": {
                        "type": "string",
                        "description": "IP of the unconstrained delegation host (where the TGT will be cached)"
                    }
                },
                "required": ["domain", "username", "password", "coerce_from", "listener_ip"]
            }),
        },
        ToolDefinition {
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
        },
        ToolDefinition {
            name: "pygpoabuse_immediate_task".into(),
            description: "Create an immediate scheduled task on domain computers via GPO abuse. \
                    Exploits write access to a Group Policy Object to push an immediate \
                    scheduled task that executes a command on all computers where the GPO \
                    is linked. Requires GpoEditDeleteModifySecurity, WriteProperty, WriteDacl, \
                    or GenericWrite on the GPO."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to the GPO)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "gpo_id": {
                        "type": "string",
                        "description": "GPO name or GUID to abuse (e.g. 'Default Domain Policy' or '{6AC1786C-...}')"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on targeted computers (e.g. 'net localgroup Administrators attacker /add')"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "task_name": {
                        "type": "string",
                        "description": "Name for the scheduled task (default: WindowsUpdate — use an inconspicuous name)",
                        "default": "WindowsUpdate"
                    },
                    "force": {
                        "type": "boolean",
                        "description": "Force overwrite if task already exists (default: true)",
                        "default": true
                    }
                },
                "required": ["domain", "username", "password", "gpo_id", "command", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "sharpgpoabuse".into(),
            description: "Abuse Group Policy Objects via SharpGPOAbuse to add local admin, \
                    create scheduled tasks, or grant user rights on domain computers where \
                    the GPO is linked. Run via mono on Linux. Requires write access to the \
                    target GPO."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "gpo_name": {
                        "type": "string",
                        "description": "Name of the GPO to abuse"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
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
                    "user_to_add": {
                        "type": "string",
                        "description": "User account to grant privileges (defaults to the authenticating user)"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["AddLocalAdmin", "AddComputerTask", "AddUserRights"],
                        "description": "GPO abuse action (default: AddLocalAdmin)",
                        "default": "AddLocalAdmin"
                    },
                    "computer_target": {
                        "type": "string",
                        "description": "Specific computer to target (optional — applies to all linked computers if omitted)"
                    }
                },
                "required": ["gpo_name", "domain", "username", "password", "dc_ip"]
            }),
        },
    ]
}
