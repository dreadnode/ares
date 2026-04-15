//! Recon role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run an nmap scan against target IP(s) or subnet. Returns discovered hosts, open ports, and services.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range (e.g. 192.168.58.0/24)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g. '1-1000', '80,443,445'). Use targeted ranges, not all ports."
                    },
                    "arguments": {
                        "type": "string",
                        "description": "Additional nmap arguments (e.g. '-sV -sC -O')"
                    }
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "smb_sweep".into(),
            description: "Sweep a subnet for hosts with SMB (port 445) open. Returns reachable hosts.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Target IP range or CIDR (e.g. 192.168.58.0/24)"
                    }
                },
                "required": ["targets"]
            }),
        },
        ToolDefinition {
            name: "enumerate_users".into(),
            description: "Enumerate domain users via netexec SMB (--users with --rid-brute fallback). Returns usernames and domain membership.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain controller IP or hostname"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain name"
                    },
                    "username": {"type": "string", "description": "Username for authentication"},
                    "password": {"type": "string", "description": "Password for authentication"},
                    "null_session": {
                        "type": "boolean",
                        "description": "Use null session (empty creds) for unauthenticated enumeration"
                    }
                },
                "required": ["target", "domain"]
            }),
        },
        ToolDefinition {
            name: "enumerate_shares".into(),
            description: "Enumerate SMB shares on a target host. Returns share names, types, and permissions.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "domain": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "smb_signing_check".into(),
            description: "Check SMB signing status on target hosts. Identifies relay targets (hosts without signing required).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range"
                    }
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "run_bloodhound".into(),
            description: "Run BloodHound data collection. Requires valid domain credentials.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "dc_ip": {"type": "string", "description": "Domain controller IP"},
                    "collection_method": {
                        "type": "string",
                        "description": "Collection method (default: All)"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "ldap_search".into(),
            description: "Execute an LDAP search query against a domain controller.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "DC IP or hostname"},
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "filter": {"type": "string", "description": "LDAP filter (e.g. '(objectClass=user)')"},
                    "attributes": {
                        "type": "string",
                        "description": "Comma-separated attributes to retrieve"
                    }
                },
                "required": ["target", "domain", "filter"]
            }),
        },
        ToolDefinition {
            name: "rpcclient_command".into(),
            description: "Execute an rpcclient command against a target.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "command": {"type": "string", "description": "rpcclient command (e.g. 'enumdomusers')"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "domain": {"type": "string"}
                },
                "required": ["target", "command"]
            }),
        },
        ToolDefinition {
            name: "dig_query".into(),
            description: "Execute a DNS query using dig.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "DNS query (e.g. 'contoso.local')"},
                    "record_type": {
                        "type": "string",
                        "description": "Record type (A, SRV, MX, NS, etc.)"
                    },
                    "server": {"type": "string", "description": "DNS server to query"}
                },
                "required": ["query"]
            }),
        },
        ToolDefinition {
            name: "enumerate_domain_trusts".into(),
            description: "Enumerate domain trust relationships via LDAP. Queries trustedDomain objects.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "DC IP"},
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"}
                },
                "required": ["target", "domain"]
            }),
        },
        ToolDefinition {
            name: "check_rdp_reachability".into(),
            description: "Check if RDP (port 3389) is reachable on a target host.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "check_winrm_reachability".into(),
            description: "Check if WinRM (port 5985/5986) is reachable on a target host.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "zerologon_check".into(),
            description: "Check if a domain controller is vulnerable to Zerologon (CVE-2020-1472).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["dc_ip"]
            }),
        },
        ToolDefinition {
            name: "adidnsdump".into(),
            description: "Dump AD Integrated DNS records for a domain.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "dc_ip": {"type": "string", "description": "Domain controller IP"},
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"}
                },
                "required": ["dc_ip", "domain", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "save_users_to_file".into(),
            description: "Save enumerated domain users to a file for use with other tools.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "DC IP or hostname"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "domain": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "smbclient_kerberos_shares".into(),
            description: "Enumerate SMB shares using Kerberos ticket authentication. Requires a valid TGT in the ccache (no password needed). Use after obtaining a Kerberos ticket via S4U, golden ticket, or ADCS.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target hostname (must match SPN in ticket)"},
                    "target_ip": {"type": "string", "description": "Target IP address (if hostname does not resolve via DNS)"}
                },
                "required": ["target"]
            }),
        },
    ]
}
