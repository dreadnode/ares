//! Orchestrator role tool definitions.
//!
//! These tools are available exclusively to the orchestrator agent, providing
//! oversight capabilities: querying collected credentials and hashes, monitoring
//! agent and task status, and marking the operation as complete.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "get_hash_summary".into(),
            description: "Get a summary of all collected password hashes across the operation. \
                Returns counts grouped by hash type (NTLM, Kerberos TGS-REP, AS-REP, etc.) \
                and shows how many have been cracked vs remain uncracked."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_credential_summary".into(),
            description: "Get a summary of all collected credentials across the operation. \
                Returns counts grouped by domain, distinguishing admin-level credentials \
                from standard user credentials."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_all_hashes".into(),
            description: "List all collected password hashes with pagination support. \
                Returns hash values, associated usernames, domains, hash types, \
                and cracked status for each entry."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of hashes to return per page. Defaults to 30.",
                        "default": 30
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Number of hashes to skip for pagination. Defaults to 0.",
                        "default": 0
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_all_credentials".into(),
            description: "List all collected credentials (username/password pairs and hashes) \
                with pagination support. Returns username, domain, credential type, \
                and admin status for each entry."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of credentials to return per page. Defaults to 30.",
                        "default": 30
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Number of credentials to skip for pagination. Defaults to 0.",
                        "default": 0
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_hash_value".into(),
            description: "Retrieve the hash value for a specific user account. \
                Useful when you need the raw hash for pass-the-hash, golden ticket, \
                or other credential-based attacks."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "The account username to look up (e.g. 'Administrator', 'krbtgt')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "The domain the account belongs to (e.g. 'contoso.local')"
                    },
                    "hash_type": {
                        "type": "string",
                        "description": "Specific hash type to retrieve (e.g. 'ntlm', 'aes256', 'kerberos'). If omitted, returns all available hash types for the user."
                    }
                },
                "required": ["username", "domain"]
            }),
        },
        ToolDefinition {
            name: "get_pending_tasks".into(),
            description: "List all pending and in-progress tasks across all agent queues. \
                Returns task IDs, descriptions, assigned roles, current status \
                (pending/running/blocked), and how long each has been in its current state."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_agent_status".into(),
            description: "Get the current status of all active agents in the operation. \
                Returns each agent's role, whether it is busy or idle, the task it is \
                currently executing (if any), and the last time it reported activity."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "complete_operation".into(),
            description: "Mark the entire red team operation as complete. This finalizes all \
                outstanding tasks, generates the operation report, and signals all agents \
                to wind down. Should only be called when the operation objectives have been \
                achieved or no further progress is possible."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Final operation summary describing what was accomplished, key findings, compromised assets, and any remaining attack paths not explored."
                    }
                },
                "required": ["summary"]
            }),
        },
    ]
}
