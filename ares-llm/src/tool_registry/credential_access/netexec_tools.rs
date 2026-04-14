//! Netexec-based credential access tool definitions.
//!
//! These tools require `netexec` or `ldapsearch` which are NOT available in the
//! credential_access container image. They are defined here so the LLM agent
//! can call them; the tool dispatcher routes execution to the recon worker
//! queue where the binaries exist.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "ldap_search_descriptions".into(),
            description: "Search LDAP user description fields for passwords. Many AD environments have passwords stored in user description fields. Requires valid domain credentials.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name (e.g. contoso.local)"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "password_spray".into(),
            description: "Spray a single password across all domain users. Tests one password against many accounts. Use password_policy first to check lockout thresholds. Uses a built-in username wordlist if no users_file is provided.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "users_file": {
                        "type": "string",
                        "description": "Optional path to file containing usernames (one per line). If omitted, a built-in common username list is used."
                    },
                    "password": {
                        "type": "string",
                        "description": "Password to spray"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "delay_seconds": {
                        "type": "integer",
                        "description": "Optional delay between attempts to avoid lockout"
                    }
                },
                "required": ["target", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "username_as_password".into(),
            description: "Test if any domain users have their username as their password. High success rate in many environments, zero lockout risk (one attempt per user). Uses a built-in username wordlist if no users_file is provided.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "users_file": {
                        "type": "string",
                        "description": "Optional: path to file containing usernames (one per line). If omitted, a built-in wordlist is used."
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["target", "domain"]
            }),
        },
        ToolDefinition {
            name: "gpp_password_finder".into(),
            description: "Search Group Policy Preferences for credentials (cpassword). Finds GPP XML files in SYSVOL containing encrypted passwords that can be trivially decrypted.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "sysvol_script_search".into(),
            description: "Spider SYSVOL for login scripts and config files that may contain hardcoded credentials. Searches .bat, .ps1, .vbs, .cmd, and config files.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "password_policy".into(),
            description: "Retrieve domain password policy including lockout threshold and duration. Run this before password spraying to avoid account lockouts.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "laps_dump".into(),
            description: "Dump LAPS (Local Administrator Password Solution) passwords from Active Directory. Retrieves managed local admin passwords if the user has read access.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "domain_admin_checker".into(),
            description: "Check for admin access on target hosts via netexec SMB. Tests if current credentials have local administrator privileges. Returns Pwn3d! for admin targets.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range to check admin access on"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
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
                        "description": "Target domain name"
                    }
                },
                "required": ["targets"]
            }),
        },
        ToolDefinition {
            name: "check_credman_entries".into(),
            description: "Enumerate Windows Credential Manager entries on a target host. Retrieves stored credentials using cmdkey /list.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "check_autologon_registry".into(),
            description: "Query Windows autologon registry values (AutoAdminLogon, DefaultUserName, DefaultPassword) from HKLM\\...\\Winlogon. May reveal stored plaintext credentials.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "gmsa_dump_passwords".into(),
            description: "Dump Group Managed Service Account (gMSA) passwords from Active Directory. Retrieves plaintext gMSA passwords via the msDS-ManagedPassword attribute if the authenticated user has read access.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    }
                },
                "required": ["dc_ip"]
            }),
        },
        ToolDefinition {
            name: "smbclient_spider".into(),
            description: "Spider SMB shares for interesting files containing credentials (config files, scripts, text files with passwords).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "share": {
                        "type": "string",
                        "description": "Specific share name to spider (default: all readable shares)"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "File pattern to search for"
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Maximum directory depth to spider"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
    ]
}
