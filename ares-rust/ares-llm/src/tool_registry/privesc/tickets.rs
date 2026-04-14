//! Trust, golden ticket, and SID tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        // -----------------------------------------------------------------
        // Golden ticket / SID tools
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "generate_golden_ticket".into(),
            description: "Create a Kerberos golden ticket using a compromised krbtgt hash. \
                Grants unrestricted access to the domain. Optionally include an extra SID \
                for ExtraSid attack to escalate from child to parent domain."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "krbtgt_hash": {
                        "type": "string",
                        "description": "NTLM hash of the krbtgt account"
                    },
                    "domain_sid": {
                        "type": "string",
                        "description": "Domain SID (e.g. 'S-1-5-21-...')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain FQDN (e.g. contoso.local)"
                    },
                    "extra_sid": {
                        "type": "string",
                        "description": "Extra SID to include for ExtraSid attack on parent domain (e.g. parent SID + '-519' for Enterprise Admins)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Account name for RID 500 to embed in the ticket. Defaults to 'Administrator'. Use the actual RID-500 name if it has been renamed.",
                        "default": "Administrator"
                    }
                },
                "required": ["krbtgt_hash", "domain_sid", "domain"]
            }),
        },
        ToolDefinition {
            name: "raise_child".into(),
            description: "Elevate privileges from a child domain to the parent domain using \
                the ExtraSid or trust key technique. Automatically performs golden ticket \
                creation with Enterprise Admin SID."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "child_domain": {
                        "type": "string",
                        "description": "Child domain FQDN (e.g. north.contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username with admin rights in the child domain"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "target_domain": {
                        "type": "string",
                        "description": "Parent domain FQDN (auto-detected from child if omitted)"
                    }
                },
                "required": ["child_domain", "username", "password"]
            }),
        },
        // -----------------------------------------------------------------
        // Trust / Cross-forest tools
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "extract_trust_key".into(),
            description: "Extract the inter-domain trust key from a domain controller using \
                secretsdump. The trust key is used to forge inter-realm TGTs for cross-forest \
                movement."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Source domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username with admin rights (typically Domain Admin)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "trusted_domain": {
                        "type": "string",
                        "description": "The trusted domain to extract the trust key for (e.g. fabrikam.local)"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "trusted_domain"]
            }),
        },
        ToolDefinition {
            name: "create_inter_realm_ticket".into(),
            description: "Create an inter-realm TGT for cross-forest movement using a \
                compromised trust key. The forged ticket allows authentication to the \
                target forest."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source_domain": {
                        "type": "string",
                        "description": "Source domain FQDN (e.g. contoso.local)"
                    },
                    "source_sid": {
                        "type": "string",
                        "description": "SID of the source domain"
                    },
                    "trust_key": {
                        "type": "string",
                        "description": "NTLM hash of the inter-domain trust key"
                    },
                    "target_domain": {
                        "type": "string",
                        "description": "Target domain FQDN (e.g. fabrikam.local)"
                    },
                    "target_sid": {
                        "type": "string",
                        "description": "SID of the target domain"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to embed in the ticket. Defaults to Administrator.",
                        "default": "Administrator"
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Ticket duration in days. Defaults to 3650.",
                        "default": 3650
                    }
                },
                "required": ["source_domain", "source_sid", "trust_key", "target_domain", "target_sid"]
            }),
        },
        ToolDefinition {
            name: "get_sid".into(),
            description: "Get the domain SID using impacket-lookupsid. Required for golden \
                ticket creation and cross-domain attacks."
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
                        "description": "Password for authentication (use this OR hash)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash authentication (e.g. aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0). Use this OR password."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "dc_ip"]
            }),
        },
        // NOTE: dnstool removed — dnstool.py not in privesc container.
    ]
}
