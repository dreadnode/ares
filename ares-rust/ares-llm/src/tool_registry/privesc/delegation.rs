//! Kerberos delegation tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "find_delegation".into(),
            description: "Find Kerberos delegation vulnerabilities in the domain including \
                unconstrained delegation, constrained delegation, and resource-based \
                constrained delegation (RBCD) misconfigurations."
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
            name: "s4u_attack".into(),
            description: "Perform S4U2Self/S4U2Proxy constrained delegation attack to obtain \
                a service ticket impersonating a privileged user. Requires an account with \
                constrained delegation configured."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_spn": {
                        "type": "string",
                        "description": "Target SPN to request access to (e.g. 'cifs/dc01.contoso.local')"
                    },
                    "impersonate": {
                        "type": "string",
                        "description": "User to impersonate (e.g. 'Administrator')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Account with delegation rights"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for the delegated account"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for authentication (alternative to password)"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_spn", "impersonate", "domain", "username"]
            }),
        },
        ToolDefinition {
            name: "add_computer".into(),
            description: "Add a computer account to the domain. Useful for RBCD attacks where \
                a controlled computer account is needed as the attacker principal."
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
                    "computer_name": {
                        "type": "string",
                        "description": "Name for the new computer account"
                    },
                    "computer_password": {
                        "type": "string",
                        "description": "Password for the new computer account"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "addspn".into(),
            description: "Add or remove a Service Principal Name (SPN) on a domain account. \
                Useful for targeted Kerberoasting or setting up delegation attacks."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_account": {
                        "type": "string",
                        "description": "Target account to modify the SPN on"
                    },
                    "spn": {
                        "type": "string",
                        "description": "SPN value to add or remove (e.g. 'http/web01.contoso.local')"
                    },
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
                    "action": {
                        "type": "string",
                        "description": "Action to perform: 'add' or 'remove'. Defaults to add.",
                        "default": "add"
                    }
                },
                "required": ["target_account", "spn", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "rbcd_write".into(),
            description: "Write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on a \
                target computer to enable Resource-Based Constrained Delegation (RBCD). \
                Allows the attacker-controlled SID to impersonate users to the target."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_computer": {
                        "type": "string",
                        "description": "Target computer account to write RBCD attribute on"
                    },
                    "attacker_sid": {
                        "type": "string",
                        "description": "SID of the attacker-controlled computer account"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to target)"
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
                "required": ["target_computer", "attacker_sid", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "krbrelayup".into(),
            description: "Execute KrbRelayUp attack for local privilege escalation on a \
                domain-joined machine by relaying Kerberos authentication to LDAP and \
                abusing RBCD or Shadow Credentials."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "method": {
                        "type": "string",
                        "description": "Attack method: 'rbcd' or 'shadowcred'. Defaults to rbcd.",
                        "default": "rbcd"
                    },
                    "create_user": {
                        "type": "string",
                        "description": "Username for the new computer account to create"
                    },
                    "create_password": {
                        "type": "string",
                        "description": "Password for the new computer account"
                    }
                },
                "required": ["domain", "dc_ip"]
            }),
        },
    ]
}
