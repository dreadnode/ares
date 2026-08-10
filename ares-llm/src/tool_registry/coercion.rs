//! Coercion/relay agent role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "start_responder".into(),
            description: "Start Responder for LLMNR/NBT-NS/mDNS poisoning to capture Net-NTLM hashes from broadcast name resolution requests on the local network segment.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Network interface to listen on (e.g. 'eth0')"
                    },
                    "analyze_mode": {
                        "type": "boolean",
                        "description": "Run in analyze-only mode without poisoning responses (default: false). Passive: captures nothing — do NOT combine with force_ntlmv1.",
                        "default": false
                    },
                    "force_ntlmv1": {
                        "type": "boolean",
                        "description": "Force a NetNTLMv1 downgrade by adding Responder's --lm --disable-ess flags. Clients with LmCompatibilityLevel <= 2 then negotiate NetNTLMv1 instead of v2. Paired with the static server challenge the coercion_tools role pins in Responder.conf (1122334455667788), captured v1 hashes are crack.sh rainbow-table candidates (hashcat mode 5500). Targets enforcing NTLMv2 ignore the downgrade and still yield v2. Default: false.",
                        "default": false
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "start_mitm6".into(),
            description: "Start mitm6 to perform IPv6 DNS poisoning by advertising as a DHCPv6 server and replying to DNS queries. Exploits Windows default IPv6 preference to redirect authentication to an attacker-controlled host.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target Active Directory domain to poison DNS for (e.g. contoso.local)"
                    },
                    "interface": {
                        "type": "string",
                        "description": "Network interface to listen on (e.g. 'eth0')"
                    }
                },
                "required": ["domain"]
            }),
        },
        ToolDefinition {
            name: "coercer".into(),
            description: "Coerce NTLM authentication from a target using multiple RPC protocols (MS-RPRN, MS-EFSR, MS-FSRVP, MS-DFSNM, etc.). Triggers the target machine to authenticate back to a listener for relay or hash capture.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname to coerce authentication from"
                    },
                    "listener": {
                        "type": "string",
                        "description": "Attacker IP address that the target will authenticate to"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authenticated coercion"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    }
                },
                "required": ["target", "listener"]
            }),
        },
        ToolDefinition {
            name: "petitpotam".into(),
            description: "Coerce NTLM authentication from a target via the MS-EFSR (Encrypting File System Remote) protocol. Triggers EfsRpcOpenFileRaw to force the target machine account to authenticate to the listener.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname to coerce authentication from"
                    },
                    "listener": {
                        "type": "string",
                        "description": "Attacker IP address that the target will authenticate to"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authenticated coercion (optional for unauthenticated variant)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    }
                },
                "required": ["target", "listener"]
            }),
        },
        ToolDefinition {
            name: "dfscoerce".into(),
            description: "Coerce NTLM authentication from a target via the MS-DFSNM (Distributed File System Namespace Management) protocol. Exploits the NetrDfsRemoveStdRoot or NetrDfsAddStdRoot RPC calls to trigger machine account authentication.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname to coerce authentication from"
                    },
                    "listener": {
                        "type": "string",
                        "description": "Attacker IP address that the target will authenticate to"
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authenticated coercion"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name for authentication"
                    }
                },
                "required": ["target", "listener"]
            }),
        },
        ToolDefinition {
            name: "ntlmrelayx_to_ldaps".into(),
            description: "Relay captured NTLM authentication to LDAPS on a domain controller. Performs Resource-Based Constrained Delegation (RBCD) or shadow credentials attack to gain control over the relayed account's target systems.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address to relay NTLM authentication to via LDAPS"
                    },
                    "delegate_access": {
                        "type": "boolean",
                        "description": "Configure Resource-Based Constrained Delegation on the relayed computer account (default: true)",
                        "default": true
                    }
                },
                "required": ["dc_ip"]
            }),
        },
        ToolDefinition {
            name: "ntlmrelayx_to_adcs".into(),
            description: "Relay captured NTLM authentication to Active Directory Certificate Services (AD CS) web enrollment endpoint. Requests a certificate on behalf of the relayed account for subsequent authentication via PKINIT.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ca_host": {
                        "type": "string",
                        "description": "AD CS server hostname or IP running the Certificate Authority web enrollment service"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template to request (default: DomainController)",
                        "default": "DomainController"
                    }
                },
                "required": ["ca_host"]
            }),
        },
        ToolDefinition {
            name: "ntlmrelayx_to_smb".into(),
            description: "Relay captured NTLM authentication to SMB on a target host. Can execute commands via service creation if the relayed account has local admin rights, or establish a SOCKS proxy for interactive SMB access.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address to relay NTLM authentication to via SMB"
                    },
                    "socks": {
                        "type": "boolean",
                        "description": "Keep connections open as SOCKS proxies for later interactive use (default: true)",
                        "default": true
                    },
                    "interactive": {
                        "type": "boolean",
                        "description": "Launch an interactive SMB shell on successful relay (default: false)",
                        "default": false
                    }
                },
                "required": ["target_ip"]
            }),
        },
        ToolDefinition {
            name: "relay_and_coerce".into(),
            description: "Run the full ADCS ESC8 relay+coerce attack as ONE deterministic call. Starts ntlmrelayx targeting the AD CS web enrollment endpoint, then coerces a remote machine to authenticate back: phase 1 attempts unauthenticated PetitPotam (works on unpatched DCs without any creds — preferred); phase 2 falls back to authenticated DFSCoerce (MS-DFSNM); phase 3 falls back to coercer over MS-EFSR → MS-RPRN if creds are supplied. CRITICAL: source ≠ target. coerce_target MUST be a different machine than ca_host — Windows NTLM same-machine loopback protection blocks relay when the coerced host is the relay target. Coerce a DC or other machine and relay it to the CA. The captured certificate is decoded from the relay log and a `certificate_obtained` vulnerability is emitted automatically — `auto_certipy_auth` will then PKINIT and extract the NT hash. Use this instead of orchestrating ntlmrelayx_to_adcs + petitpotam/coercer manually.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ca_host": {
                        "type": "string",
                        "description": "AD CS server IP/hostname running the Certificate Authority web enrollment service (HTTP /certsrv)"
                    },
                    "coerce_target": {
                        "type": "string",
                        "description": "Machine to coerce (NOT ca_host — must be a different host). Its machine account is what the relay will impersonate. Typically a DC's IP/hostname; in cross-forest scenarios any reachable machine in the target's RPC scope works."
                    },
                    "attacker_ip": {
                        "type": "string",
                        "description": "Local listener IP that the coerced machine will authenticate to"
                    },
                    "coerce_user": {
                        "type": "string",
                        "description": "Optional username for authenticated coercer fallback (only needed if unauth PetitPotam is patched; cross-forest: child user with RPC access)"
                    },
                    "coerce_password": {
                        "type": "string",
                        "description": "Password for coerce_user (provide either coerce_password OR coerce_hash; only required if coerce_user is set)"
                    },
                    "coerce_hash": {
                        "type": "string",
                        "description": "NT hash for coerce_user (provide either coerce_password OR coerce_hash; only required if coerce_user is set)"
                    },
                    "coerce_domain": {
                        "type": "string",
                        "description": "Domain for coerce_user (the user's home realm, may differ from coerce_target's realm; only required if coerce_user is set)"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template to request (default: DomainController)",
                        "default": "DomainController"
                    }
                },
                "required": ["ca_host", "coerce_target", "attacker_ip"]
            }),
        },
        ToolDefinition {
            name: "ntlmrelayx_multirelay".into(),
            description: "Relay captured NTLM authentication to multiple SMB targets simultaneously. Attempts to dump SAM database hashes from each target where the relayed account has local administrator privileges.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "targets_file": {
                        "type": "string",
                        "description": "Path to file containing target IPs/hostnames (one per line)"
                    },
                    "target_ips": {
                        "type": "string",
                        "description": "Comma-separated list of target IP addresses to relay to"
                    },
                    "dump_sam": {
                        "type": "boolean",
                        "description": "Dump SAM database hashes from targets where relay succeeds with admin access (default: true)",
                        "default": true
                    }
                },
                "required": []
            }),
        },
    ]
}
