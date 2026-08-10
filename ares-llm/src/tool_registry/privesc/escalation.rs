//! Windows privilege escalation and enumeration tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "windows_stage_and_run".into(),
            description: "Escalate to SYSTEM on a Windows host by staging a privilege \
                escalation binary on an SMB share and running it through MSSQL \
                xp_cmdshell. xp_cmdshell executes as the SQL Server service account, \
                which is NOT a local administrator but does hold SeImpersonatePrivilege \
                — the context the potato family exploits. Use this after \
                mssql_enum_impersonation shows a login that can reach sysadmin. \
                Nothing is written to the target's disk. Fails deliberately when the \
                execution channel is already SYSTEM, because that is not an escalation."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname to escalate on"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for MSSQL authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NT hash for pass-the-hash authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for Windows authentication"
                    },
                    "windows_auth": {
                        "type": "boolean",
                        "description": "Use Windows authentication instead of SQL auth",
                        "default": true
                    },
                    "impersonate_user": {
                        "type": "string",
                        "description": "SQL login to impersonate via EXECUTE AS LOGIN (e.g. 'sa') when the connecting login is not sysadmin"
                    },
                    "attacker_ip": {
                        "type": "string",
                        "description": "Listener IP on this worker that the target reaches over SMB. Must be a local interface address — pass it exactly as supplied, do not guess."
                    },
                    "payload": {
                        "type": "string",
                        "enum": ["printspoofer"],
                        "description": "Registered payload to stage. 'printspoofer' abuses SeImpersonatePrivilege via the print spooler named pipe."
                    },
                    "child_command": {
                        "type": "string",
                        "description": "Command to run as SYSTEM. Defaults to 'whoami /all', which is what proves the escalation. Restricted to alphanumerics, space, and / \\ . : - _ = , — no quotes, pipes or redirects.",
                        "default": "whoami /all"
                    }
                },
                "required": ["target", "username", "attacker_ip", "payload"]
            }),
        },
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
