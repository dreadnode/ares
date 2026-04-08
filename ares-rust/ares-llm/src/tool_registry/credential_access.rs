//! Credential access role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "kerberoast".into(),
            description: "Extract Kerberos TGS tickets for SPNs in the domain for offline password cracking. Targets service accounts with registered Service Principal Names.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target Active Directory domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "asrep_roast".into(),
            description: "Find accounts that do not require Kerberos pre-authentication and extract AS-REP hashes for offline cracking. Targets accounts with DONT_REQUIRE_PREAUTH set.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target Active Directory domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "kerberos_user_enum_noauth".into(),
            description: "Enumerate valid Kerberos usernames without requiring domain credentials. Sends AS-REQ messages to identify valid accounts by response codes.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target Active Directory domain (e.g. contoso.local)"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "users_file": {
                        "type": "string",
                        "description": "Path to file containing usernames to test (one per line)"
                    }
                },
                "required": ["domain", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "secretsdump".into(),
            description: "Dump secrets from a target machine including SAM hashes, NTDS.dit credentials, LSA secrets, and cached domain credentials via DRSUAPI or registry extraction.".into(),
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
                    "no_pass": {
                        "type": "boolean",
                        "description": "Attempt authentication with no password"
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to Kerberos ccache ticket file for authentication"
                    },
                    "timeout_minutes": {
                        "type": "integer",
                        "description": "Overall operation timeout in minutes (default: 3)",
                        "default": 3
                    },
                    "connection_timeout": {
                        "type": "integer",
                        "description": "Connection timeout in seconds (default: 30)",
                        "default": 30
                    },
                    "skip_connectivity_check": {
                        "type": "boolean",
                        "description": "Skip the initial connectivity check before dumping"
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "lsassy".into(),
            description: "Remotely extract credentials from LSASS process memory on a target host. Retrieves plaintext passwords, NTLM hashes, and Kerberos tickets from memory.".into(),
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
                    "method": {
                        "type": "string",
                        "description": "LSASS dump method (default: comsvcs_stealth)",
                        "default": "comsvcs_stealth"
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "domain_admin_checker".into(),
            description: "Check if the provided credentials have domain administrator access on one or more target hosts. Tests administrative SMB access and privilege levels.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Target IP(s) or hostname(s) to check, comma-separated or CIDR"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to test for admin access"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash authentication (LM:NT format)"
                    }
                },
                "required": ["targets", "username"]
            }),
        },
        ToolDefinition {
            name: "gpp_password_finder".into(),
            description: "Search Group Policy Preferences (GPP) XML files for stored passwords. GPP passwords use a known AES key and can be trivially decrypted (MS14-025).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
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
            description: "Search SYSVOL share for logon scripts, batch files, and PowerShell scripts that may contain hardcoded credentials, connection strings, or sensitive configuration.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
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
            description: "Dump Local Administrator Password Solution (LAPS) passwords from Active Directory. Retrieves auto-rotated local admin passwords stored in AD attributes.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    }
                },
                "required": ["target", "domain", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "ldap_search_descriptions".into(),
            description: "Search LDAP user description fields for passwords and secrets. Administrators often store temporary passwords or notes in the description attribute of user objects.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    }
                },
                "required": ["target", "domain", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "smbclient_spider".into(),
            description: "Spider SMB shares recursively searching for sensitive files such as configuration files, scripts, password databases, and documents that may contain credentials.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "share": {
                        "type": "string",
                        "description": "SMB share name to spider (e.g. 'SYSVOL', 'NETLOGON', 'C$')"
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
                        "description": "Domain name for authentication"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Comma-separated file patterns to search for (default: '*.txt,*.xml,*.ini,*.cfg,*.ps1,*.bat,*.cmd,*.kdbx,*.config')",
                        "default": "*.txt,*.xml,*.ini,*.cfg,*.ps1,*.bat,*.cmd,*.kdbx,*.config"
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Maximum directory recursion depth (default: 5)",
                        "default": 5
                    }
                },
                "required": ["target", "share", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "ntds_dit_extract".into(),
            description: "Extract the NTDS.dit database from a domain controller for offline hash extraction. Uses Volume Shadow Copy or other techniques to access the locked database file.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP address or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (requires admin privileges)"
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
                    }
                },
                "required": ["target", "username"]
            }),
        },
        ToolDefinition {
            name: "password_policy".into(),
            description: "Query the domain password policy including minimum length, complexity requirements, lockout threshold, lockout duration, and password history. Essential before attempting password spraying.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    }
                },
                "required": ["target", "domain", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "password_spray".into(),
            description: "Spray a single password across multiple domain user accounts. Tests one password against many users to avoid account lockout. Always check password policy first.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password to spray across all users"
                    },
                    "users_file": {
                        "type": "string",
                        "description": "Path to file containing usernames to spray (one per line)"
                    },
                    "delay_seconds": {
                        "type": "integer",
                        "description": "Delay in seconds between authentication attempts to avoid lockout (default: 0)",
                        "default": 0
                    }
                },
                "required": ["target", "domain", "password"]
            }),
        },
        ToolDefinition {
            name: "username_as_password".into(),
            description: "Test each domain username as its own password (e.g. user 'jsmith' with password 'jsmith'). A common weak credential pattern in enterprise environments.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "users_file": {
                        "type": "string",
                        "description": "Path to file containing usernames to test (one per line)"
                    }
                },
                "required": ["target", "domain"]
            }),
        },
        ToolDefinition {
            name: "check_credman_entries".into(),
            description: "Check Windows Credential Manager on a remote host for stored credentials. Retrieves saved passwords for network resources, RDP sessions, and other cached logon data.".into(),
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
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "check_autologon_registry".into(),
            description: "Check the Windows registry on a remote host for auto-logon credentials stored in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon (DefaultUserName, DefaultPassword, etc.).".into(),
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
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
    ]
}
