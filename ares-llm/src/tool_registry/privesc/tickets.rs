//! Trust, golden ticket, and SID tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
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
            name: "generate_silver_ticket".into(),
            description: "Forge a Kerberos silver ticket: a service ticket (TGS) for ONE SPN, \
                signed with that service account's own key instead of krbtgt. Use when you \
                hold a service or machine account's key but NOT krbtgt — e.g. after \
                secretsdump on a member server (its $MACHINE.ACC LSA secret), a gMSA \
                password read, or an NTDS dump. Grants access to that one service as any \
                principal you name, with no traffic to the DC. `username` is the account \
                that OWNS the SPN and signs the ticket; `impersonate` is the principal \
                embedded in it. Prefer generate_golden_ticket when a krbtgt hash is \
                available — that is domain-wide."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Account that owns the SPN and whose key signs the ticket (e.g. 'SQL01$' for a machine account, or a service user like 'svc_sql'). NOT the principal you want to become — that is `impersonate`. Its key is resolved from operation state, so this account must already have a captured NTLM hash or AES key."
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain FQDN of the service account (e.g. contoso.local)"
                    },
                    "spn": {
                        "type": "string",
                        "description": "Service principal name the ticket is scoped to, as service class + host (e.g. 'cifs/sql01.contoso.local' for SMB, 'MSSQLSvc/sql01.contoso.local:1433' for SQL, 'host/ws01.contoso.local' for scheduled tasks). Must include the '/' — the ticket is only accepted by this one service."
                    },
                    "domain_sid": {
                        "type": "string",
                        "description": "Domain SID (e.g. 'S-1-5-21-...'). Obtain via get_sid if unknown."
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash of the service account (LM:NT or NT-only)"
                    },
                    "aes_key": {
                        "type": "string",
                        "description": "AES256 key of the service account (hex, 64 chars). Preferred over the NTLM hash — a host configured for AES-only Kerberos rejects an RC4 service ticket."
                    },
                    "impersonate": {
                        "type": "string",
                        "description": "Principal to embed in the ticket. Defaults to 'Administrator'. The service performs no PAC validation against the DC, so any name works.",
                        "default": "Administrator"
                    }
                },
                "required": ["username", "domain", "spn", "domain_sid"]
            }),
        },
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
                        "description": "Password for authentication (use this OR hash, must be non-empty)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash authentication (LM:NT or NT-only). Use this OR password."
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
                "required": ["domain", "username", "dc_ip", "trusted_domain"]
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
                    "extra_sid": {
                        "type": "string",
                        "description": "Extra SID to embed (e.g. '<target_sid>-519' for Enterprise Admins). Use for child-to-parent escalation within the same forest. OMIT for cross-forest trusts — SID filtering blocks RIDs < 1000."
                    },
                    "aes_key": {
                        "type": "string",
                        "description": "AES256 trust key (hex, 64 chars). REQUIRED for Windows Server 2016+ target DCs — RC4-only inter-realm tickets are rejected with KDC_ERR_TGT_REVOKED. Extract alongside the NT hash via extract_trust_key (look for ':aes256-cts-hmac-sha1-96:' line)."
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
