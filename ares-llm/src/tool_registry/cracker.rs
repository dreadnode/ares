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
                        "description": "OPTIONAL override for the hashcat hash mode. Leave this UNSET for Kerberos (krb5tgs/krb5asrep) and NTLM hashes: the tool reads the Kerberos etype from the hash and auto-selects the correct mode, including the AES tickets impacket returns by default (etype 18 -> 19700, etype 17 -> 19600, etype 23 -> 13100; AS-REP -> 18200; NTLM -> 1000). Any value supplied here is IGNORED for Kerberos hashes. Only set it for non-Kerberos hashes the detector can't identify (e.g. 5600=NetNTLMv2, 3000=LM). Never force 13100 for Kerberoast — AES tickets require 19600/19700 and 13100 makes hashcat reject them with 'Separator unmatched'."
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
                        "description": "Maximum time in minutes before aborting the crack attempt. Defaults to 20. Do NOT set below 20 — CPU-only cracking needs time to traverse large wordlists.",
                        "default": 20
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
                    },
                    "known_passwords": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Plaintext passwords already recovered this op (cracked or harvested cleartext). Tried FIRST, before any wordlist, so a re-issued or different-etype ticket for an already-cracked account — or any account reusing a known password — cracks instantly. Pass every recovered plaintext."
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
                        "description": "OPTIONAL John the Ripper format override (e.g. krb5tgs, krb5asrep, nt, netntlmv2). Leave UNSET to let John auto-detect from the hash — its krb5tgs format already handles both the AES Kerberoast etypes (17/18) and RC4 (23), so do not pin a format for Kerberos hashes. Only set this if auto-detection fails to load the hash."
                    },
                    "wordlist_path": {
                        "type": "string",
                        "description": "Path to a custom wordlist file. If omitted, the default wordlist is used."
                    },
                    "max_time_minutes": {
                        "type": "integer",
                        "description": "Maximum time in minutes before aborting the crack attempt. Defaults to 20. Do NOT set below 20 — CPU-only cracking needs time to traverse large wordlists.",
                        "default": 20
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
                    },
                    "known_passwords": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Plaintext passwords already recovered this op (cracked or harvested cleartext). Tried FIRST, before any wordlist, so a re-issued or different-etype ticket for an already-cracked account — or any account reusing a known password — cracks instantly. Pass every recovered plaintext."
                    }
                },
                "required": ["hash_value"]
            }),
        },
    ]
}

pub(super) fn callback_definitions() -> Vec<ToolDefinition> {
    vec![ToolDefinition {
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
    }]
}
