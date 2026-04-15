//! Miscellaneous credential access tool definitions (lsassy, NTDS).
//!
//! NOTE: Tools that require `netexec` (domain_admin_checker, gpp_password_finder,
//! sysvol_script_search, laps_dump, smbclient_spider, password_policy,
//! password_spray, username_as_password, check_credman_entries,
//! check_autologon_registry) and `ldapsearch` (ldap_search_descriptions) are
//! NOT included here because the credential_access container image does not
//! ship those binaries. Those tools remain in the executor crate so they can
//! be called from roles that *do* have the binaries (e.g. recon has netexec).

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
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
    ]
}
