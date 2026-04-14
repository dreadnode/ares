//! Pass-the-hash tool definitions (pth-winexe, pth-smbclient, pth-rpcclient, pth-wmic).

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
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
    ]
}
