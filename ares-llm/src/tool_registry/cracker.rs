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
                    "rules_file": {
                        "type": "string",
                        "description": "Path to a hashcat rules file (e.g. /usr/share/hashcat/rules/best64.rule). If omitted, default rules (best64 + d3ad0ne) are applied automatically after the straight wordlist phase."
                    },
                    "max_time_minutes": {
                        "type": "integer",
                        "description": "Maximum time in minutes before aborting the crack attempt. Defaults to 10.",
                        "default": 10
                    },
                    "use_dynamic_wordlist": {
                        "type": "boolean",
                        "description": "When true, augments the wordlist with username-derived password candidates (e.g. john.smith -> John, Smith, john1, Smith123). Defaults to true.",
                        "default": true
                    },
                    "known_usernames": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of known usernames from the target domain, used to generate dynamic password candidates. Pass all discovered usernames for best coverage."
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
                        "description": "When true, augments the wordlist with username-derived password candidates. Defaults to true.",
                        "default": true
                    },
                    "known_usernames": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of known usernames from the target domain, used to generate dynamic password candidates."
                    }
                },
                "required": ["hash_value"]
            }),
        },
    ]
}

pub(super) fn callback_definitions() -> Vec<ToolDefinition> {
    vec![
        // NOTE: report_cracked_credential removed — cracked passwords are extracted
        // from hashcat/john stdout via output_extraction.rs parsers. LLMs must never
        // construct credential data directly.
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
