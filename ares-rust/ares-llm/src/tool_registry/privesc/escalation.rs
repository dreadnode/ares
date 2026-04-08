//! Windows privilege escalation binary and enumeration tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        // -----------------------------------------------------------------
        // gMSA / Unconstrained delegation
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "gmsa_dump_passwords".into(),
            description: "Dump Group Managed Service Account (gMSA) passwords from Active \
                Directory. Retrieves the msDS-ManagedPassword attribute for accounts the \
                authenticated user can read."
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
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
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
            name: "unconstrained_coerce_and_capture".into(),
            description: "Coerce authentication from a target to an unconstrained delegation \
                host and capture the resulting TGT. Combines coercion (e.g. PrinterBug, \
                PetitPotam) with ticket capture."
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
                    "target_host": {
                        "type": "string",
                        "description": "Host to coerce authentication from (e.g. a domain controller)"
                    },
                    "coerce_from": {
                        "type": "string",
                        "description": "Host with unconstrained delegation that will receive the coerced auth"
                    },
                    "listener_ip": {
                        "type": "string",
                        "description": "IP address of the listener capturing the TGT"
                    }
                },
                "required": ["domain", "username", "password", "target_host", "coerce_from", "listener_ip"]
            }),
        },
        // -----------------------------------------------------------------
        // Windows privilege escalation binaries
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "printspoofer".into(),
            description: "Execute PrintSpoofer privilege escalation to elevate from service \
                account (SeImpersonatePrivilege) to SYSTEM on a target host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as SYSTEM. Defaults to whoami.",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "godpotato".into(),
            description: "Execute GodPotato privilege escalation to elevate from service \
                account to SYSTEM on a target host. Works on Windows Server 2012-2022."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as SYSTEM. Defaults to whoami.",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "sweetpotato".into(),
            description: "Execute SweetPotato privilege escalation to elevate from service \
                account to SYSTEM using various potato techniques."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as SYSTEM. Defaults to whoami.",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "seatbelt".into(),
            description: "Run Seatbelt security audit on a target host. Performs comprehensive \
                security checks including credential storage, UAC settings, service \
                misconfigurations, and more."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "group": {
                        "type": "string",
                        "description": "Seatbelt check group to run (e.g. 'system', 'user', 'all'). Defaults to system.",
                        "default": "system"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "sharpup".into(),
            description: "Run SharpUp privilege escalation checks on a target host. Identifies \
                service misconfigurations, modifiable binaries, and other local privesc paths."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "powerup".into(),
            description: "Run PowerUp privilege escalation checks via PowerShell on a target \
                host. Identifies service misconfigurations, unquoted paths, DLL hijacking, \
                and registry-based privesc opportunities."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "winpeas".into(),
            description: "Run WinPEAS enumeration on a Windows target. Performs comprehensive \
                local enumeration including services, scheduled tasks, credentials, and \
                privilege escalation vectors."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "linpeas".into(),
            description: "Run LinPEAS enumeration on a Linux target. Performs comprehensive \
                local enumeration including SUID binaries, cron jobs, writable paths, \
                and privilege escalation vectors."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for SSH authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for SSH authentication"
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "runas_cs".into(),
            description: "Execute a command as a different user using RunasCs. Useful for \
                lateral movement and testing credentials on a target host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "run_as_user": {
                        "type": "string",
                        "description": "Username to run the command as"
                    },
                    "run_as_password": {
                        "type": "string",
                        "description": "Password for the run-as user"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as the run-as user"
                    },
                    "run_as_domain": {
                        "type": "string",
                        "description": "Domain for the run-as user (defaults to target domain)"
                    }
                },
                "required": ["target", "username", "password", "domain", "run_as_user", "run_as_password", "command"]
            }),
        },
        ToolDefinition {
            name: "scm_uac_bypass".into(),
            description: "Bypass User Account Control (UAC) via the Service Control Manager \
                to execute commands with elevated privileges."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must be local admin)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute with elevated privileges"
                    }
                },
                "required": ["target", "username", "password", "domain", "command"]
            }),
        },
        ToolDefinition {
            name: "powerupsql".into(),
            description: "Run PowerUpSQL for SQL Server privilege escalation. Enumerates SQL \
                instances, checks for misconfigurations, and identifies paths to sysadmin."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "sql_server": {
                        "type": "string",
                        "description": "SQL Server instance to target (e.g. 'db01.contoso.local' or 'db01.contoso.local,1433')"
                    }
                },
                "required": ["target", "username", "password", "domain", "sql_server"]
            }),
        },
    ]
}
