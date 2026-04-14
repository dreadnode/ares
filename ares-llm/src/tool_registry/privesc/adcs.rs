//! ADCS / Certipy tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "certipy_find".into(),
            description: "Find vulnerable certificate templates in Active Directory Certificate \
                Services (AD CS). Enumerates CAs, templates, and identifies exploitable \
                misconfigurations (ESC1-ESC8)."
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
                    "vulnerable": {
                        "type": "boolean",
                        "description": "Only show vulnerable templates. Defaults to true.",
                        "default": true
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "certipy_request".into(),
            description: "Request a certificate from AD CS using a specific CA and template. \
                Used to exploit vulnerable templates (e.g. ESC1) to obtain certificates for \
                privileged accounts."
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
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-DC01-CA')"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to request"
                    },
                    "upn": {
                        "type": "string",
                        "description": "User Principal Name to request the certificate for. Defaults to Administrator.",
                        "default": "Administrator"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca", "template"]
            }),
        },
        ToolDefinition {
            name: "certipy_auth".into(),
            description: "Authenticate to Active Directory using a PFX certificate file. \
                Performs PKINIT Kerberos authentication and retrieves the NT hash of the \
                certificate's subject."
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
                    "pfx_path": {
                        "type": "string",
                        "description": "Path to the PFX certificate file"
                    }
                },
                "required": ["domain", "dc_ip", "pfx_path"]
            }),
        },
        ToolDefinition {
            name: "certipy_shadow".into(),
            description: "Exploit Shadow Credentials by adding a Key Credential to a target \
                account's msDS-KeyCredentialLink attribute via Certipy, then authenticating \
                with the resulting certificate."
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
                        "description": "Username for authentication (must have write access to target)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target account to add shadow credentials to"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "target"]
            }),
        },
        ToolDefinition {
            name: "certipy_template_esc4".into(),
            description: "Modify a vulnerable certificate template for ESC4 exploitation. \
                Overwrites template attributes to allow enrollment and subject alternative \
                name specification."
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
                        "description": "Username for authentication (must have write access to template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to modify"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "template"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc4_full_chain".into(),
            description: "Execute the full ESC4 exploit chain: modify a vulnerable certificate \
                template, request a certificate for a privileged user, and authenticate with \
                the resulting certificate to obtain NT hashes."
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
                        "description": "Username for authentication (must have write access to template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to exploit"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-DC01-CA')"
                    },
                    "target_upn": {
                        "type": "string",
                        "description": "UPN of the target user to impersonate. Defaults to Administrator.",
                        "default": "Administrator"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "template", "ca"]
            }),
        },
    ]
}
