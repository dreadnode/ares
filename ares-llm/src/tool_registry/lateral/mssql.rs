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
            description: "Execute SQL queries on a linked MSSQL server via OPENQUERY. \
                Enables lateral movement through SQL Server linked server chains."
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
                    }
                },
                "required": ["target", "username", "password", "linked_server", "query"]
            }),
        },
        ToolDefinition {
            name: "mssql_linked_enable_xpcmdshell".into(),
            description: "Enable xp_cmdshell on a linked MSSQL server. Required before \
                executing OS commands on the linked server."
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
                    }
                },
                "required": ["target", "username", "password", "linked_server"]
            }),
        },
        ToolDefinition {
            name: "mssql_linked_xpcmdshell".into(),
            description: "Execute an OS command via xp_cmdshell on a linked MSSQL server. \
                Requires xp_cmdshell to be enabled on the linked server first."
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
                    }
                },
                "required": ["target", "username", "password", "linked_server", "command"]
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
