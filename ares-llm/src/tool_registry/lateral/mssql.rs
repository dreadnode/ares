//! MSSQL tool definitions (command, impersonation, linked servers, NTLM coercion).

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "mssql_command".into(),
            description: "Execute a SQL command on a MSSQL server. Supports Windows and SQL \
                authentication."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "SQL command to execute"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for Windows authentication"
                    },
                    "windows_auth": {
                        "type": "boolean",
                        "description": "Use Windows authentication instead of SQL auth",
                        "default": true
                    }
                },
                "required": ["target", "username", "password", "command"]
            }),
        },
        ToolDefinition {
            name: "mssql_enable_xp_cmdshell".into(),
            description: "Enable xp_cmdshell on a MSSQL server. Required before executing \
                OS commands through MSSQL. Pass impersonate_user='sa' when the connecting \
                account lacks sysadmin but can impersonate sa."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
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
                        "description": "SQL login to impersonate via EXECUTE AS LOGIN before enabling xp_cmdshell (e.g. 'sa'). Required when the connecting user is not sysadmin but has IMPERSONATE privilege."
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "mssql_enum_impersonation".into(),
            description: "Enumerate MSSQL impersonation privileges. Identifies users that \
                can be impersonated for privilege escalation within SQL Server."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for Windows authentication"
                    },
                    "windows_auth": {
                        "type": "boolean",
                        "description": "Use Windows authentication instead of SQL auth",
                        "default": true
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "mssql_impersonate".into(),
            description: "Execute SQL queries as an impersonated MSSQL user. Requires \
                impersonation privileges on the target user."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "impersonate_user": {
                        "type": "string",
                        "description": "SQL user to impersonate (e.g. sa)"
                    },
                    "query": {
                        "type": "string",
                        "description": "SQL query to execute as the impersonated user"
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
                    "database": {
                        "type": "string",
                        "description": "Database context for the query"
                    }
                },
                "required": ["target", "username", "password", "impersonate_user", "query"]
            }),
        },
        ToolDefinition {
            name: "mssql_enum_linked_servers".into(),
            description: "Enumerate MSSQL linked servers. Discovers linked server connections \
                that can be used for lateral movement between SQL servers."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for Windows authentication"
                    },
                    "windows_auth": {
                        "type": "boolean",
                        "description": "Use Windows authentication instead of SQL auth",
                        "default": true
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "mssql_exec_linked".into(),
            description: "Execute SQL queries on a linked MSSQL server via `EXEC ('...') AT \
                [link]` (RPC OUT). The hop runs as the connecting user's mapped credential, \
                which fails on cross-forest links without Kerberos delegation. For cross-forest \
                pivots: pass `impersonate_user='sa'` to wrap the hop in EXECUTE AS LOGIN \
                (uses the local SeImpersonate path), or use `mssql_openquery` to ride the \
                linked server's stored login mapping."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname (entry point)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "linked_server": {
                        "type": "string",
                        "description": "Name of the linked server to query"
                    },
                    "query": {
                        "type": "string",
                        "description": "SQL query to execute on the linked server"
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
                        "description": "Optional source-side login to impersonate before the hop (EXECUTE AS LOGIN). Use 'sa' to break out of double-hop limits when the local connection has IMPERSONATE on sa."
                    }
                },
                "required": ["target", "username", "password", "linked_server", "query"]
            }),
        },
        ToolDefinition {
            name: "mssql_openquery".into(),
            description: "Query a linked MSSQL server via OPENQUERY using the linked server's \
                configured remote login (sp_addlinkedsrvlogin). Bypasses Kerberos double-hop \
                — use this when `mssql_exec_linked` fails on cross-forest links because the \
                connecting principal can't delegate, but the linked server has a stored \
                credential mapping (RPC OUT + sp_addlinkedsrvlogin)."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname (entry point)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "linked_server": {
                        "type": "string",
                        "description": "Name of the linked server to query"
                    },
                    "query": {
                        "type": "string",
                        "description": "SQL query string passed inside OPENQUERY (single quotes auto-escaped)"
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
                        "description": "Optional source-side login to impersonate before OPENQUERY (e.g. 'sa') for IMPERSONATE-based escalation."
                    }
                },
                "required": ["target", "username", "password", "linked_server", "query"]
            }),
        },
        ToolDefinition {
            name: "mssql_linked_enable_xpcmdshell".into(),
            description: "Enable xp_cmdshell on a linked MSSQL server. Required before \
                executing OS commands on the linked server. Pass `impersonate_user='sa'` \
                for cross-forest hops where the connecting principal lacks delegation."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname (entry point)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "linked_server": {
                        "type": "string",
                        "description": "Name of the linked server to enable xp_cmdshell on"
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
                        "description": "Optional source-side login to impersonate (EXECUTE AS LOGIN) before the hop."
                    }
                },
                "required": ["target", "username", "password", "linked_server"]
            }),
        },
        ToolDefinition {
            name: "mssql_linked_xpcmdshell".into(),
            description: "Execute an OS command via xp_cmdshell on a linked MSSQL server. \
                Requires xp_cmdshell to be enabled on the linked server first. Pass \
                `impersonate_user='sa'` for cross-forest hops where the connecting \
                principal can't double-hop."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname (entry point)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "linked_server": {
                        "type": "string",
                        "description": "Name of the linked server to execute on"
                    },
                    "command": {
                        "type": "string",
                        "description": "OS command to execute via xp_cmdshell"
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
                        "description": "Optional source-side login to impersonate (EXECUTE AS LOGIN) before the hop."
                    }
                },
                "required": ["target", "username", "password", "linked_server", "command"]
            }),
        },
        ToolDefinition {
            name: "mssql_far_host_secretsdump".into(),
            description: "Harvest SAM/SYSTEM/SECURITY registry hives from a linked \
                (typically cross-forest) MSSQL host via xp_cmdshell over the link hop, \
                then parse them locally with `impacket-secretsdump LOCAL`. Use this \
                after a `mssql_linked_server` sysadmin pivot when you need to convert \
                the SQL-sysadmin foothold on the linked host into OS credentials \
                (local admin hashes, LSA secrets, cached domain-service-account \
                cleartext) — the standard SMB-based secretsdump path can't reach a \
                cross-forest host without a far-forest admin credential. Pass \
                `impersonate_user='sa'` when the connecting principal isn't sysadmin \
                on the source but has IMPERSONATE. Output is the standard \
                impacket-secretsdump text, parsed automatically."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Source MSSQL server IP or hostname (entry point)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for source-side authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for source-side authentication (omit if `hash` is set)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NT hash for pass-the-hash source-side authentication (omit if `password` is set)"
                    },
                    "linked_server": {
                        "type": "string",
                        "description": "Name of the linked SQL server (the far host to dump)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for source-side Windows authentication"
                    },
                    "windows_auth": {
                        "type": "boolean",
                        "description": "Use Windows authentication instead of SQL auth",
                        "default": true
                    },
                    "impersonate_user": {
                        "type": "string",
                        "description": "Optional source-side login to impersonate (EXECUTE AS LOGIN) before the hop. Use 'sa' when the connecting user isn't sysadmin but has IMPERSONATE."
                    }
                },
                "required": ["target", "username", "linked_server"]
            }),
        },
        ToolDefinition {
            name: "mssql_ntlm_coerce".into(),
            description: "Coerce NTLM authentication from a MSSQL server. Forces the SQL \
                server to authenticate to a listener for hash capture via xp_dirtree."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "MSSQL server IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "listener_ip": {
                        "type": "string",
                        "description": "IP address of the listener to capture the NTLM hash"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for Windows authentication"
                    },
                    "windows_auth": {
                        "type": "boolean",
                        "description": "Use Windows authentication instead of SQL auth",
                        "default": true
                    }
                },
                "required": ["target", "username", "password", "listener_ip"]
            }),
        },
    ]
}
