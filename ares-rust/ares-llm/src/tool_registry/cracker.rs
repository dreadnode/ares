//! Cracker role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "crack_with_hashcat".into(),
            description: "Crack password hashes using hashcat with GPU acceleration. Supports \
                Kerberos TGS-REP, AS-REP, NTLM, and other hash types. Automatically selects \
                rules and wordlists when use_dynamic_wordlist is enabled."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "The hash to crack (raw hash string or path to a file containing hashes)"
                    },
                    "hashcat_mode": {
                        "type": "integer",
                        "description": "Hashcat hash mode. Common modes: 13100=Kerberos TGS-REP (Kerberoasting), 18200=Kerberos AS-REP (ASREPRoasting), 1000=NTLM, 5600=NetNTLMv2, 3000=LM. Defaults to 13100.",
                        "default": 13100
                    },
                    "wordlist_path": {
                        "type": "string",
                        "description": "Path to a custom wordlist file. If omitted, the default wordlist (e.g. rockyou.txt) is used."
                    },
                    "max_time_minutes": {
                        "type": "integer",
                        "description": "Maximum time in minutes before aborting the crack attempt. Defaults to 10.",
                        "default": 10
                    },
                    "use_dynamic_wordlist": {
                        "type": "boolean",
                        "description": "When true, augments the wordlist with previously cracked passwords and domain-specific mutations. Defaults to true.",
                        "default": true
                    }
                },
                "required": ["hash_value"]
            }),
        },
        ToolDefinition {
            name: "crack_with_john".into(),
            description: "Crack password hashes using John the Ripper. Supports Kerberos, NTLM, \
                and other formats. Useful as a fallback when hashcat GPU cracking is unavailable \
                or for formats better handled by JtR."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "The hash to crack (raw hash string or path to a file containing hashes)"
                    },
                    "hash_format": {
                        "type": "string",
                        "description": "John the Ripper hash format name. Common formats: krb5tgs (Kerberoasting), krb5asrep (ASREPRoasting), nt (NTLM), netntlmv2 (NetNTLMv2). Defaults to krb5tgs.",
                        "default": "krb5tgs"
                    },
                    "wordlist_path": {
                        "type": "string",
                        "description": "Path to a custom wordlist file. If omitted, the default wordlist is used."
                    },
                    "max_time_minutes": {
                        "type": "integer",
                        "description": "Maximum time in minutes before aborting the crack attempt. Defaults to 10.",
                        "default": 10
                    },
                    "use_dynamic_wordlist": {
                        "type": "boolean",
                        "description": "When true, augments the wordlist with previously cracked passwords and domain-specific mutations. Defaults to true.",
                        "default": true
                    }
                },
                "required": ["hash_value"]
            }),
        },
    ]
}

pub(super) fn callback_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "report_cracked_credential".into(),
            description: "Report a successfully cracked password back to the orchestrator. \
                The credential will be stored and made available to other agents for \
                lateral movement and privilege escalation."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID associated with this cracking job"
                    },
                    "username": {
                        "type": "string",
                        "description": "The account username the cracked hash belongs to"
                    },
                    "password": {
                        "type": "string",
                        "description": "The recovered plaintext password"
                    },
                    "original_hash": {
                        "type": "string",
                        "description": "The original hash value that was cracked"
                    },
                    "domain": {
                        "type": "string",
                        "description": "The domain the account belongs to (e.g. contoso.local)"
                    },
                    "method": {
                        "type": "string",
                        "description": "The cracking method used. Defaults to hashcat.",
                        "default": "hashcat"
                    }
                },
                "required": ["task_id", "username", "password", "original_hash"]
            }),
        },
        ToolDefinition {
            name: "report_crack_failed".into(),
            description: "Report that a cracking attempt failed and no password was recovered. \
                This allows the orchestrator to update task status and potentially retry with \
                different parameters or a larger wordlist."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID associated with this cracking job"
                    },
                    "hash_value": {
                        "type": "string",
                        "description": "The hash value that could not be cracked"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason the cracking failed (e.g. exhausted wordlist, timeout, unsupported format). Defaults to 'exhausted wordlist'.",
                        "default": "exhausted wordlist"
                    }
                },
                "required": ["task_id", "hash_value"]
            }),
        },
    ]
}
