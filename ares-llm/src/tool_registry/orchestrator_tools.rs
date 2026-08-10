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
                Returns associated usernames, domains, hash types and cracked status. \
                Raw hash material is never returned — dispatch by principal instead."
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
            description: "List all collected credentials with pagination support. Returns \
                username, domain, whether usable secret material is held, and admin status \
                for each entry. Secret values are never returned."
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
            name: "get_pending_tasks".into(),
            description: "List all pending and in-progress tasks across all agent queues. \
                Returns task IDs, descriptions, assigned roles, current status \
                (pending/running/blocked), and how long each has been in its current state. \
                Use this before dispatching to avoid queueing duplicate work."
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
                password spray, etc.) against a target, authenticating as the named principal. \
                Name the principal only — the secret is resolved from operation state at \
                dispatch time. The principal must already appear in get_all_credentials."
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
                        "description": "Domain of the authenticating principal"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username of the authenticating principal"
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Task priority (1=highest, 10=lowest). Default: 5"
                    }
                },
                "required": ["technique", "target_ip", "domain", "username"]
            }),
        },
        ToolDefinition {
            name: "dispatch_lateral_movement".into(),
            description:
                "Dispatch a lateral movement task to move to a new host as the named principal. \
                Techniques include psexec, wmiexec, smbexec, atexec. Name the principal only — \
                the secret is resolved from operation state at dispatch time. Cross-realm \
                combinations are rejected with an explanation."
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
                        "description": "Username of the authenticating principal"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain of the authenticating principal"
                    }
                },
                "required": ["target_ip", "technique", "username", "domain"]
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
            description: "Dispatch a hash cracking task for a principal whose hash is already \
                held in operation state. Name the principal — the hash material is resolved at \
                dispatch time. Check get_all_hashes first; cracking an already-cracked or \
                absent principal is rejected."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username associated with the hash"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain associated with the hash"
                    },
                    "hash_type": {
                        "type": "string",
                        "description": "Which held hash type to crack (e.g. 'ntlm', 'kerberos_tgs', 'kerberos_as', 'mscache2'). If omitted, the first uncracked hash for the principal is used."
                    }
                },
                "required": ["username", "domain"]
            }),
        },
        ToolDefinition {
            name: "get_proposed_work".into(),
            description: "List work the deterministic automations have proposed and are waiting \
                on you to rule on. Each entry is already validated and executable — the rule that \
                proposed it built the payload. Review these FIRST every turn: approving good work \
                is faster and safer than composing a dispatch yourself. Anything you do not rule \
                on is released automatically when its window expires."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum proposals to return, lowest priority number first. Defaults to 30.",
                        "default": 30
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "approve_work".into(),
            description: "Approve proposed work by id, releasing it for dispatch immediately. \
                Pass every id you want to run — approving in bulk is normal and cheap. Ids come \
                from get_proposed_work; an unknown id is reported back rather than ignored."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "proposal_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Proposal ids to approve (e.g. ['p0001', 'p0002'])"
                    }
                },
                "required": ["proposal_ids"]
            }),
        },
        ToolDefinition {
            name: "reject_work".into(),
            description: "Reject proposed work by id so it is not dispatched and is not \
                re-proposed for a cooldown period. Use this to suppress work that is redundant, \
                aimed at a dead end, or lower value than what you are prioritising. Rejecting is \
                a real decision — the rule that proposed it will stay suppressed, so give a \
                reason you would stand behind."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "proposal_id": {
                        "type": "string",
                        "description": "The proposal id to reject"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why this work should not run"
                    }
                },
                "required": ["proposal_id", "reason"]
            }),
        },
        ToolDefinition {
            name: "complete_operation".into(),
            description: "Mark the entire red team operation as complete. This finalizes all \
                outstanding tasks, generates the operation report, and signals all agents \
                to wind down. Should only be called when the operation objectives have been \
                achieved or no further progress is possible. Only the orchestrator may call \
                this; worker roles cannot end the operation."
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
