//! Remote execution tool definitions (psexec, wmiexec, smbexec, evil-winrm, xfreerdp, ssh, secretsdump_kerberos).

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
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
            name: "secretsdump".into(),
            description: "Dump secrets from a target machine including SAM hashes, NTDS.dit \
                credentials, LSA secrets, and cached domain credentials via DRSUAPI or \
                registry extraction. Use after gaining admin access to a host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
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
                        "description": "NTLM hash for pass-the-hash authentication (LM:NT format)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP (used for DRSUAPI replication)"
                    },
                    "timeout_minutes": {
                        "type": "integer",
                        "description": "Overall operation timeout in minutes (default: 3)",
                        "default": 3
                    }
                },
                "required": ["target", "username"]
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
    ]
}
