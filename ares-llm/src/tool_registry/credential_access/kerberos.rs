//! Kerberos credential access tool definitions (Kerberoast, AS-REP roast, user enum).

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
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
            description: "Find accounts that do not require Kerberos pre-authentication and extract AS-REP hashes for offline cracking. Works WITHOUT credentials: uses a built-in wordlist to test usernames. Can also work WITH credentials for LDAP-based enumeration.".into(),
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
                    "username": {
                        "type": "string",
                        "description": "Optional: domain username for authenticated LDAP enumeration"
                    },
                    "password": {
                        "type": "string",
                        "description": "Optional: password for authenticated mode"
                    },
                    "users_file": {
                        "type": "string",
                        "description": "Optional: path to username wordlist for unauthenticated mode. If omitted, a built-in wordlist is used."
                    }
                },
                "required": ["domain", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "kerberos_user_enum_noauth".into(),
            description: "Enumerate valid Kerberos usernames without credentials. Sends AS-REQ messages to identify valid accounts by response codes. Uses a built-in wordlist of common AD usernames if no users_file is provided.".into(),
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
                        "description": "Optional: path to username wordlist. If omitted, a built-in wordlist of common AD and service account names is used."
                    }
                },
                "required": ["domain", "dc_ip"]
            }),
        },
    ]
}
