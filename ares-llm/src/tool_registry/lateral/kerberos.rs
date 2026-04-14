//! Kerberos TGT tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![ToolDefinition {
        name: "get_tgt".into(),
        description: "Request a TGT (Ticket Granting Ticket) from the KDC. Used to \
            obtain initial Kerberos authentication for subsequent ticket-based operations."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Username to request the TGT for"
                },
                "domain": {
                    "type": "string",
                    "description": "Domain name (e.g. contoso.local)"
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication"
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash TGT request"
                },
                "dc_ip": {
                    "type": "string",
                    "description": "Domain controller IP for KDC communication"
                }
            },
            "required": ["username", "domain"]
        }),
    }]
}
