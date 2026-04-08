//! Lateral movement role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // -----------------------------------------------------------------
        // Remote execution tools
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "psexec".into(),
            description: "Execute commands via PsExec (SMB/RPC). Requires valid credentials \
                or NTLM hash for pass-the-hash authentication."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "cmd.exe"
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "psexec_kerberos".into(),
            description: "Execute commands via PsExec using Kerberos ticket authentication. \
                Requires a valid TGT or service ticket."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname (must match SPN in ticket)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username associated with the Kerberos ticket"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. contoso.local)"
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to the Kerberos ticket (.ccache file)"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "cmd.exe /c whoami && hostname"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP for Kerberos communication"
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address (if different from hostname resolution)"
                    }
                },
                "required": ["target", "username", "domain"]
            }),
        },
        ToolDefinition {
            name: "wmiexec".into(),
            description: "Execute commands via WMI (Windows Management Instrumentation). \
                Uses DCOM for semi-interactive shell."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "wmiexec_kerberos".into(),
            description: "Execute commands via WMI using Kerberos ticket authentication. \
                Uses DCOM with Kerberos for semi-interactive shell."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname (must match SPN in ticket)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username associated with the Kerberos ticket"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. contoso.local)"
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to the Kerberos ticket (.ccache file)"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "whoami"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP for Kerberos communication"
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address (if different from hostname resolution)"
                    }
                },
                "required": ["target", "username", "domain"]
            }),
        },
        ToolDefinition {
            name: "smbexec".into(),
            description: "Execute commands via SMBExec. Creates a Windows service to run \
                commands through SMB."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "smbexec_kerberos".into(),
            description: "Execute commands via SMBExec using Kerberos ticket authentication. \
                Creates a Windows service to run commands through SMB with Kerberos auth."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname (must match SPN in ticket)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username associated with the Kerberos ticket"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. contoso.local)"
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to the Kerberos ticket (.ccache file)"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "whoami"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP for Kerberos communication"
                    }
                },
                "required": ["target", "username", "domain"]
            }),
        },
        ToolDefinition {
            name: "evil_winrm".into(),
            description: "Remote shell via Evil-WinRM (WinRM/PSRemoting). Provides PowerShell \
                access to Windows hosts with WinRM enabled (port 5985/5986)."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "PowerShell command to execute"
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "xfreerdp".into(),
            description: "Remote desktop connection via xfreerdp. Connects to Windows hosts \
                with RDP enabled (port 3389)."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for restricted admin pass-the-hash"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute via RemoteApp"
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "ssh_with_password".into(),
            description: "SSH to a target host with password authentication. Useful for \
                Linux/Unix hosts or Windows hosts with OpenSSH installed."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "SSH username"
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "id && hostname"
                    },
                    "port": {
                        "type": "integer",
                        "description": "SSH port number",
                        "default": 22
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "secretsdump_kerberos".into(),
            description: "Dump secrets (NTLM hashes, Kerberos keys) from a remote host using \
                Kerberos ticket authentication. Uses impacket-secretsdump with -k flag."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname (must match SPN in ticket)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username associated with the Kerberos ticket"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. contoso.local)"
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to the Kerberos ticket (.ccache file)"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP for Kerberos communication"
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address (if different from hostname resolution)"
                    },
                    "timeout_minutes": {
                        "type": "integer",
                        "description": "Maximum time in minutes before aborting the dump",
                        "default": 5
                    }
                },
                "required": ["target", "username", "domain"]
            }),
        },
        // -----------------------------------------------------------------
        // Pass-the-Hash tools
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "pth_winexe".into(),
            description: "Execute commands via pass-the-hash using pth-winexe. Provides \
                command execution on Windows hosts using only an NTLM hash."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote host",
                        "default": "cmd.exe /c whoami && hostname"
                    }
                },
                "required": ["target", "username", "hash"]
            }),
        },
        ToolDefinition {
            name: "pth_smbclient".into(),
            description: "SMB client with pass-the-hash authentication. Access file shares \
                and enumerate directories using only an NTLM hash."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "share": {
                        "type": "string",
                        "description": "SMB share to connect to",
                        "default": "C$"
                    },
                    "command": {
                        "type": "string",
                        "description": "SMB client command to execute",
                        "default": "dir"
                    }
                },
                "required": ["target", "username", "hash"]
            }),
        },
        ToolDefinition {
            name: "pth_rpcclient".into(),
            description: "RPC client with pass-the-hash authentication. Execute RPC commands \
                against Windows hosts using only an NTLM hash."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "RPC command to execute",
                        "default": "enumdomusers"
                    }
                },
                "required": ["target", "username", "hash"]
            }),
        },
        ToolDefinition {
            name: "pth_wmic".into(),
            description: "WMI queries with pass-the-hash authentication. Execute WQL queries \
                against Windows hosts using only an NTLM hash."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "query": {
                        "type": "string",
                        "description": "WQL query to execute",
                        "default": "SELECT * FROM Win32_OperatingSystem"
                    }
                },
                "required": ["target", "username", "hash"]
            }),
        },
        // -----------------------------------------------------------------
        // Kerberos
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "get_tgt".into(),
            description: "Request a TGT (Ticket Granting Ticket) from the KDC. Used to \
                obtain initial Kerberos authentication for subsequent ticket-based operations."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to request the TGT for"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g. contoso.local)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash TGT request"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP for KDC communication"
                    }
                },
                "required": ["username", "domain"]
            }),
        },
        // -----------------------------------------------------------------
        // MSSQL tools
        // -----------------------------------------------------------------
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
                OS commands through MSSQL."
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

pub(super) fn callback_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "report_lateral_success".into(),
            description: "Report successful lateral movement to a new host. Records the \
                method used and any new credentials or hashes obtained during the move."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID associated with this lateral movement attempt"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "The host that was successfully accessed (IP or hostname)"
                    },
                    "method": {
                        "type": "string",
                        "description": "The lateral movement method used (e.g. psexec, wmiexec, evil_winrm)"
                    },
                    "new_credentials": {
                        "type": "string",
                        "description": "JSON array of new credentials discovered (e.g. [{\"username\": \"admin\", \"password\": \"pass\", \"domain\": \"contoso.local\"}])"
                    },
                    "new_hashes": {
                        "type": "string",
                        "description": "JSON array of new NTLM hashes discovered (e.g. [{\"username\": \"admin\", \"hash\": \"aad3b435...:31d6cfe0...\", \"domain\": \"contoso.local\"}])"
                    }
                },
                "required": ["task_id", "target_host", "method"]
            }),
        },
        ToolDefinition {
            name: "report_lateral_failed".into(),
            description: "Report a failed lateral movement attempt. Records the target, \
                reason for failure, and allows the orchestrator to retry with different \
                methods or credentials."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID associated with this lateral movement attempt"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "The host that could not be accessed (IP or hostname)"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason the lateral movement failed (e.g. access denied, port closed, authentication error)"
                    }
                },
                "required": ["task_id", "target_host", "reason"]
            }),
        },
    ]
}
