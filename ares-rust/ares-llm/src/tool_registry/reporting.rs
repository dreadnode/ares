//! Universal reporting tool definitions.
//!
//! These tools are available to ALL agent roles, providing a shared interface
//! for recording credentials, vulnerabilities, compromised hosts, and timeline
//! events during an operation.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "record_credential".into(),
            description: "Record a discovered credential (password, hash, or both) found during \
                the operation. The credential is stored centrally and made available to all \
                agents for lateral movement and privilege escalation."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "The account username (e.g. 'jsmith', 'Administrator')"
                    },
                    "password": {
                        "type": "string",
                        "description": "The plaintext password, if known"
                    },
                    "hash": {
                        "type": "string",
                        "description": "The password hash value (NTLM, AES key, etc.)"
                    },
                    "domain": {
                        "type": "string",
                        "description": "The domain the account belongs to (e.g. 'contoso.local')"
                    },
                    "source": {
                        "type": "string",
                        "description": "Where the credential was found (e.g. 'Kerberoasting', 'secretsdump on DC01', 'LSASS dump')"
                    },
                    "is_admin": {
                        "type": "boolean",
                        "description": "Whether this credential has admin-level privileges (Domain Admin, local admin, etc.). Defaults to false.",
                        "default": false
                    }
                },
                "required": ["username"]
            }),
        },
        ToolDefinition {
            name: "record_weakness".into(),
            description: "Record a discovered security weakness or vulnerability. \
                This builds the operation's findings report and helps the orchestrator \
                prioritize attack paths."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short descriptive title for the weakness (e.g. 'SMB Signing Disabled on File Server')"
                    },
                    "vulnerability": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability, including what was found and why it is exploitable"
                    },
                    "affected_resource": {
                        "type": "string",
                        "description": "The affected host, service, or account (e.g. '192.168.58.10', 'MSSQL on db01.contoso.local', 'svc_backup account')"
                    },
                    "impact": {
                        "type": "string",
                        "description": "Potential impact if exploited (e.g. 'Remote code execution', 'Credential theft', 'Lateral movement to domain controller')"
                    },
                    "discovery_method": {
                        "type": "string",
                        "description": "How the weakness was discovered (e.g. 'nmap scan', 'BloodHound analysis', 'manual LDAP enumeration')"
                    }
                },
                "required": ["title", "vulnerability"]
            }),
        },
        ToolDefinition {
            name: "record_compromised_host".into(),
            description:
                "Record a host that has been compromised or accessed during the operation. \
                Tracks the scope of compromise and available pivot points for lateral movement."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address of the compromised host"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Hostname or FQDN of the compromised host (e.g. 'dc01.contoso.local')"
                    },
                    "os": {
                        "type": "string",
                        "description": "Operating system of the host (e.g. 'Windows Server 2019', 'Windows 10 Enterprise')"
                    },
                    "access_level": {
                        "type": "string",
                        "description": "Level of access obtained (e.g. 'SYSTEM', 'local admin', 'domain user', 'service account')"
                    },
                    "notes": {
                        "type": "string",
                        "description": "Additional notes about the compromise (e.g. method used, services running, useful files found)"
                    }
                },
                "required": ["ip"]
            }),
        },
        ToolDefinition {
            name: "record_timeline_event".into(),
            description: "Record a significant event in the operation timeline. \
                Builds a chronological narrative of the operation for the final report \
                and helps track overall progress."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Description of the event (e.g. 'Gained Domain Admin via Kerberoasting of svc_sql account')"
                    },
                    "mitre_techniques": {
                        "type": "string",
                        "description": "Comma-separated MITRE ATT&CK technique IDs relevant to this event (e.g. 'T1558.003,T1078')"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence level for this event from 0.0 to 1.0. Defaults to 1.0.",
                        "default": 1.0
                    }
                },
                "required": ["description"]
            }),
        },
        ToolDefinition {
            name: "list_credentials".into(),
            description: "List all credentials that have been recorded during the operation. \
                Returns usernames, domains, credential types, admin status, and sources \
                for every collected credential."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "list_weaknesses".into(),
            description: "List all security weaknesses and vulnerabilities recorded during \
                the operation. Returns titles, descriptions, affected resources, and \
                impact assessments."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "get_operation_summary".into(),
            description: "Get a high-level summary of the current operation status. \
                Includes counts of compromised hosts, collected credentials, discovered \
                weaknesses, active agents, and pending tasks."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
    ]
}
