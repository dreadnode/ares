//! Kerberos delegation tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "find_delegation".into(),
            description: "Find Kerberos delegation vulnerabilities in the domain including \
                unconstrained delegation, constrained delegation, and resource-based \
                constrained delegation (RBCD) misconfigurations."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for authentication (alternative to password)"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "s4u_attack".into(),
            description: "Perform S4U2Self/S4U2Proxy constrained delegation attack to obtain \
                a service ticket impersonating a privileged user. Requires an account with \
                constrained delegation configured."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_spn": {
                        "type": "string",
                        "description": "Target SPN to request access to (e.g. 'cifs/dc01.contoso.local')"
                    },
                    "impersonate": {
                        "type": "string",
                        "description": "User to impersonate (e.g. 'Administrator')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Account with delegation rights"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for the delegated account"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for authentication (alternative to password)"
                    },
                    "aes_key": {
                        "type": "string",
                        "description": "AES256 key (hex, 64 chars) of the delegating account. Pass it so getST requests AES-etype tickets — REQUIRED when the account or DC has RC4 disabled, otherwise the S4U TGS is rejected with KDC_ERR_ETYPE_NOSUPP. Resolved from operation state alongside the NT hash; look for the ':aes256-cts-hmac-sha1-96:' line in secretsdump output."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_spn", "impersonate", "domain", "username"]
            }),
        },
        ToolDefinition {
            name: "add_computer".into(),
            description: "Add a computer account to the domain. Useful for RBCD attacks where \
                a controlled computer account is needed as the attacker principal. \
                Auth precedence: `ticket_path` (Kerberos ccache) > `hash` (NTLM \
                pass-the-hash) > `password` (plaintext); the worker injects whichever \
                material the operation actually holds, so a hash-only foothold works \
                here. Supply `dc_host` — it is mandatory for the Kerberos path."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to impacket-addcomputer as `-hashes LMHASH:NTHASH -no-pass`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; invokes impacket-addcomputer with `-k -no-pass` and sets KRB5CCNAME. Requires `dc_host`."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "dc_host": {
                        "type": "string",
                        "description": "Domain controller DNS name (e.g. 'dc01.contoso.local'). Required when authenticating with a Kerberos ccache — impacket-addcomputer rejects `-k` without `-dc-host`."
                    },
                    "computer_name": {
                        "type": "string",
                        "description": "Name for the new computer account"
                    },
                    "computer_password": {
                        "type": "string",
                        "description": "Password for the new computer account"
                    }
                },
                "required": ["domain", "username", "dc_ip"]
            }),
        },
        // NOTE: addspn removed — bloodyAD not in privesc container (ACL role only).
        ToolDefinition {
            name: "rbcd_write".into(),
            description: "Write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on a \
                target computer to enable Resource-Based Constrained Delegation (RBCD). \
                Lets the attacker-controlled account impersonate users to the target. \
                Auth precedence: `ticket_path` (Kerberos ccache) > `hash` (NTLM \
                pass-the-hash) > `password` (plaintext); the worker injects whichever \
                material the operation actually holds, so a hash-only foothold works here. \
                Typically chained after `add_computer`: pass that machine account's NAME as \
                `attacker_account`."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_computer": {
                        "type": "string",
                        "description": "Target computer account to write RBCD attribute on"
                    },
                    "attacker_account": {
                        "type": "string",
                        "description": "sAMAccountName of the attacker-controlled account, e.g. 'EVILPC$' (include the trailing $ for a computer account). Passed to impacket-rbcd as `-delegate-from`, which resolves it with an (sAMAccountName=...) LDAP search — a SID here matches nothing and the write is silently skipped."
                    },
                    "attacker_sid": {
                        "type": "string",
                        "description": "SID of the attacker-controlled account (e.g. 'S-1-5-21-...-1105'). Optional and NOT sent to impacket; teardown uses it to verify the delegation entry was removed, since the attribute reads back as SDDL containing raw SIDs. Supply it when known."
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to target)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to impacket-rbcd as `-hashes LMHASH:NTHASH -no-pass`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; invokes impacket-rbcd with `-k -no-pass` and sets KRB5CCNAME."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "dc_host": {
                        "type": "string",
                        "description": "Domain controller DNS name (e.g. 'dc01.contoso.local'). Optional, but supplying it skips impacket-rbcd's anonymous SMB lookup of the DC's machine name, which a hardened DC refuses."
                    }
                },
                "required": ["target_computer", "attacker_account", "domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "krbrelayup".into(),
            description: "Perform local privilege escalation via Kerberos relay (KrbRelayUp). \
                Abuses Kerberos authentication to relay credentials and escalate privileges \
                on the local machine. Supports RBCD and Shadow Credentials methods."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["rbcd", "shadowcred"],
                        "description": "Relay method: 'rbcd' (default) creates a computer account and configures RBCD, 'shadowcred' uses shadow credentials",
                        "default": "rbcd"
                    },
                    "create_user": {
                        "type": "string",
                        "description": "Computer account name to create (for RBCD method)"
                    },
                    "create_password": {
                        "type": "string",
                        "description": "Password for the created computer account"
                    }
                },
                "required": ["domain", "dc_ip"]
            }),
        },
    ]
}
