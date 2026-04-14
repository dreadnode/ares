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
        // ----- Dispatch tools (orchestrator submits sub-tasks) -----
        ToolDefinition {
            name: "dispatch_recon".into(),
            description: "Dispatch a reconnaissance task to scan a target. The task will be \
                assigned to a recon agent and executed asynchronously."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address to scan"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. 'contoso.local')"
                    },
                    "techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific recon techniques to use (e.g. ['nmap', 'smb_sweep']). Leave empty for general recon."
                    }
                },
                "required": ["target_ip"]
            }),
        },
        ToolDefinition {
            name: "dispatch_credential_access".into(),
            description:
                "Dispatch a credential access task (secretsdump, kerberoast, ASREP roast, \
                password spray, etc.) to attack a specific target with given credentials."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "technique": {
                        "type": "string",
                        "description": "Attack technique (e.g. 'secretsdump', 'kerberoast', 'asrep_roast', 'password_spray', 'lsassy')"
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Task priority (1=highest, 10=lowest). Default: 5"
                    }
                },
                "required": ["technique", "target_ip", "domain", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "dispatch_lateral_movement".into(),
            description:
                "Dispatch a lateral movement task to move to a new host using compromised \
                credentials. Techniques include psexec, wmiexec, smbexec, etc."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "Target host IP to move to"
                    },
                    "technique": {
                        "type": "string",
                        "description": "Lateral movement technique (e.g. 'psexec', 'wmiexec', 'smbexec', 'atexec')"
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
                        "description": "Domain for the credential"
                    }
                },
                "required": ["target_ip", "technique", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "dispatch_privesc_exploit".into(),
            description: "Dispatch an exploitation task for a discovered vulnerability. Provide \
                the vulnerability ID from the discovered vulnerabilities list."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "vuln_id": {
                        "type": "string",
                        "description": "Vulnerability ID to exploit (from discovered vulnerabilities)"
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Task priority (1=highest, 10=lowest). Default: 3"
                    }
                },
                "required": ["vuln_id"]
            }),
        },
        ToolDefinition {
            name: "dispatch_coercion".into(),
            description: "Dispatch a coercion/relay attack against a target. Uses techniques like \
                PetitPotam, PrinterBug to coerce authentication to a relay listener."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "Target to coerce"
                    },
                    "listener_ip": {
                        "type": "string",
                        "description": "Relay listener IP"
                    },
                    "techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Coercion techniques (default: ['petitpotam', 'printerbug'])"
                    }
                },
                "required": ["target_ip", "listener_ip"]
            }),
        },
        ToolDefinition {
            name: "dispatch_crack".into(),
            description: "Dispatch a hash cracking task. The cracker agent will attempt to crack \
                the hash using hashcat (default) or john."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "The hash value to crack"
                    },
                    "hash_type": {
                        "type": "string",
                        "description": "Hash type (e.g. 'ntlm', 'kerberos_tgs', 'kerberos_as', 'mscache2')"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username associated with the hash"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain associated with the hash"
                    },
                    "use_john": {
                        "type": "boolean",
                        "description": "Use john instead of hashcat. Default: false"
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Task priority (1=highest, 10=lowest). Default: 5"
                    }
                },
                "required": ["hash_value", "hash_type"]
            }),
        },
        // ----- Operation lifecycle -----
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
