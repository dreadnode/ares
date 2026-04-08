//! Privilege escalation role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // -----------------------------------------------------------------
        // ADCS / Certipy tools
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "certipy_find".into(),
            description: "Find vulnerable certificate templates in Active Directory Certificate \
                Services (AD CS). Enumerates CAs, templates, and identifies exploitable \
                misconfigurations (ESC1-ESC8)."
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "vulnerable": {
                        "type": "boolean",
                        "description": "Only show vulnerable templates. Defaults to true.",
                        "default": true
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "certipy_request".into(),
            description: "Request a certificate from AD CS using a specific CA and template. \
                Used to exploit vulnerable templates (e.g. ESC1) to obtain certificates for \
                privileged accounts."
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-DC01-CA')"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to request"
                    },
                    "upn": {
                        "type": "string",
                        "description": "User Principal Name to request the certificate for. Defaults to Administrator.",
                        "default": "Administrator"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca", "template"]
            }),
        },
        ToolDefinition {
            name: "certipy_auth".into(),
            description: "Authenticate to Active Directory using a PFX certificate file. \
                Performs PKINIT Kerberos authentication and retrieves the NT hash of the \
                certificate's subject."
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
                    "pfx_path": {
                        "type": "string",
                        "description": "Path to the PFX certificate file"
                    }
                },
                "required": ["domain", "dc_ip", "pfx_path"]
            }),
        },
        ToolDefinition {
            name: "certipy_shadow".into(),
            description: "Exploit Shadow Credentials by adding a Key Credential to a target \
                account's msDS-KeyCredentialLink attribute via Certipy, then authenticating \
                with the resulting certificate."
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
                        "description": "Username for authentication (must have write access to target)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target account to add shadow credentials to"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "target"]
            }),
        },
        ToolDefinition {
            name: "certipy_template_esc4".into(),
            description: "Modify a vulnerable certificate template for ESC4 exploitation. \
                Overwrites template attributes to allow enrollment and subject alternative \
                name specification."
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
                        "description": "Username for authentication (must have write access to template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to modify"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "template"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc4_full_chain".into(),
            description: "Execute the full ESC4 exploit chain: modify a vulnerable certificate \
                template, request a certificate for a privileged user, and authenticate with \
                the resulting certificate to obtain NT hashes."
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
                        "description": "Username for authentication (must have write access to template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to exploit"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-DC01-CA')"
                    },
                    "target_upn": {
                        "type": "string",
                        "description": "UPN of the target user to impersonate. Defaults to Administrator.",
                        "default": "Administrator"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "template", "ca"]
            }),
        },
        // -----------------------------------------------------------------
        // Kerberos / Delegation tools
        // -----------------------------------------------------------------
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_spn", "impersonate", "domain", "username"]
            }),
        },
        ToolDefinition {
            name: "generate_golden_ticket".into(),
            description: "Create a Kerberos golden ticket using a compromised krbtgt hash. \
                Grants unrestricted access to the domain. Optionally include an extra SID \
                for ExtraSid attack to escalate from child to parent domain."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "krbtgt_hash": {
                        "type": "string",
                        "description": "NTLM hash of the krbtgt account"
                    },
                    "domain_sid": {
                        "type": "string",
                        "description": "Domain SID (e.g. 'S-1-5-21-...')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain FQDN (e.g. contoso.local)"
                    },
                    "extra_sid": {
                        "type": "string",
                        "description": "Extra SID to include for ExtraSid attack on parent domain (e.g. parent SID + '-519' for Enterprise Admins)"
                    }
                },
                "required": ["krbtgt_hash", "domain_sid", "domain"]
            }),
        },
        ToolDefinition {
            name: "add_computer".into(),
            description: "Add a computer account to the domain. Useful for RBCD attacks where \
                a controlled computer account is needed as the attacker principal."
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
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
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "addspn".into(),
            description: "Add or remove a Service Principal Name (SPN) on a domain account. \
                Useful for targeted Kerberoasting or setting up delegation attacks."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_account": {
                        "type": "string",
                        "description": "Target account to modify the SPN on"
                    },
                    "spn": {
                        "type": "string",
                        "description": "SPN value to add or remove (e.g. 'http/web01.contoso.local')"
                    },
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "action": {
                        "type": "string",
                        "description": "Action to perform: 'add' or 'remove'. Defaults to add.",
                        "default": "add"
                    }
                },
                "required": ["target_account", "spn", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "rbcd_write".into(),
            description: "Write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on a \
                target computer to enable Resource-Based Constrained Delegation (RBCD). \
                Allows the attacker-controlled SID to impersonate users to the target."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_computer": {
                        "type": "string",
                        "description": "Target computer account to write RBCD attribute on"
                    },
                    "attacker_sid": {
                        "type": "string",
                        "description": "SID of the attacker-controlled computer account"
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
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_computer", "attacker_sid", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "krbrelayup".into(),
            description: "Execute KrbRelayUp attack for local privilege escalation on a \
                domain-joined machine by relaying Kerberos authentication to LDAP and \
                abusing RBCD or Shadow Credentials."
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
                        "description": "Attack method: 'rbcd' or 'shadowcred'. Defaults to rbcd.",
                        "default": "rbcd"
                    },
                    "create_user": {
                        "type": "string",
                        "description": "Username for the new computer account to create"
                    },
                    "create_password": {
                        "type": "string",
                        "description": "Password for the new computer account"
                    }
                },
                "required": ["domain", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "raise_child".into(),
            description: "Elevate privileges from a child domain to the parent domain using \
                the ExtraSid or trust key technique. Automatically performs golden ticket \
                creation with Enterprise Admin SID."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "child_domain": {
                        "type": "string",
                        "description": "Child domain FQDN (e.g. north.contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username with admin rights in the child domain"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "target_domain": {
                        "type": "string",
                        "description": "Parent domain FQDN (auto-detected from child if omitted)"
                    }
                },
                "required": ["child_domain", "username", "password"]
            }),
        },
        // -----------------------------------------------------------------
        // Trust / Cross-forest tools
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "extract_trust_key".into(),
            description: "Extract the inter-domain trust key from a domain controller using \
                secretsdump. The trust key is used to forge inter-realm TGTs for cross-forest \
                movement."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Source domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username with admin rights (typically Domain Admin)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "trusted_domain": {
                        "type": "string",
                        "description": "The trusted domain to extract the trust key for (e.g. fabrikam.local)"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "trusted_domain"]
            }),
        },
        ToolDefinition {
            name: "create_inter_realm_ticket".into(),
            description: "Create an inter-realm TGT for cross-forest movement using a \
                compromised trust key. The forged ticket allows authentication to the \
                target forest."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source_domain": {
                        "type": "string",
                        "description": "Source domain FQDN (e.g. contoso.local)"
                    },
                    "source_sid": {
                        "type": "string",
                        "description": "SID of the source domain"
                    },
                    "trust_key": {
                        "type": "string",
                        "description": "NTLM hash of the inter-domain trust key"
                    },
                    "target_domain": {
                        "type": "string",
                        "description": "Target domain FQDN (e.g. fabrikam.local)"
                    },
                    "target_sid": {
                        "type": "string",
                        "description": "SID of the target domain"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to embed in the ticket. Defaults to Administrator.",
                        "default": "Administrator"
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Ticket duration in days. Defaults to 3650.",
                        "default": 3650
                    }
                },
                "required": ["source_domain", "source_sid", "trust_key", "target_domain", "target_sid"]
            }),
        },
        ToolDefinition {
            name: "get_sid".into(),
            description: "Get the domain SID using impacket-lookupsid. Required for golden \
                ticket creation and cross-domain attacks."
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "dnstool".into(),
            description: "Add, modify, or delete DNS records in Active Directory Integrated \
                DNS. Useful for injecting records to redirect traffic or support relay attacks."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
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
                    "record_name": {
                        "type": "string",
                        "description": "DNS record name to create/modify/delete"
                    },
                    "record_data": {
                        "type": "string",
                        "description": "DNS record data (e.g. IP address for A record)"
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type. Defaults to A.",
                        "default": "A"
                    },
                    "action": {
                        "type": "string",
                        "description": "Action to perform: 'add', 'modify', or 'delete'. Defaults to add.",
                        "default": "add"
                    }
                },
                "required": ["dc_ip", "domain", "username", "password", "record_name", "record_data"]
            }),
        },
        // -----------------------------------------------------------------
        // gMSA / Unconstrained delegation
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "gmsa_dump_passwords".into(),
            description: "Dump Group Managed Service Account (gMSA) passwords from Active \
                Directory. Retrieves the msDS-ManagedPassword attribute for accounts the \
                authenticated user can read."
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "unconstrained_tgt_dump".into(),
            description: "Dump cached TGTs from a host with unconstrained delegation. \
                Retrieves Kerberos tickets stored in memory that can be used for \
                impersonation."
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
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "Host with unconstrained delegation to dump TGTs from"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "target_host"]
            }),
        },
        ToolDefinition {
            name: "unconstrained_coerce_and_capture".into(),
            description: "Coerce authentication from a target to an unconstrained delegation \
                host and capture the resulting TGT. Combines coercion (e.g. PrinterBug, \
                PetitPotam) with ticket capture."
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
                    "target_host": {
                        "type": "string",
                        "description": "Host to coerce authentication from (e.g. a domain controller)"
                    },
                    "coerce_from": {
                        "type": "string",
                        "description": "Host with unconstrained delegation that will receive the coerced auth"
                    },
                    "listener_ip": {
                        "type": "string",
                        "description": "IP address of the listener capturing the TGT"
                    }
                },
                "required": ["domain", "username", "password", "target_host", "coerce_from", "listener_ip"]
            }),
        },
        // -----------------------------------------------------------------
        // Windows privilege escalation binaries
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "printspoofer".into(),
            description: "Execute PrintSpoofer privilege escalation to elevate from service \
                account (SeImpersonatePrivilege) to SYSTEM on a target host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as SYSTEM. Defaults to whoami.",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "godpotato".into(),
            description: "Execute GodPotato privilege escalation to elevate from service \
                account to SYSTEM on a target host. Works on Windows Server 2012-2022."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as SYSTEM. Defaults to whoami.",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "sweetpotato".into(),
            description: "Execute SweetPotato privilege escalation to elevate from service \
                account to SYSTEM using various potato techniques."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as SYSTEM. Defaults to whoami.",
                        "default": "whoami"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "seatbelt".into(),
            description: "Run Seatbelt security audit on a target host. Performs comprehensive \
                security checks including credential storage, UAC settings, service \
                misconfigurations, and more."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "group": {
                        "type": "string",
                        "description": "Seatbelt check group to run (e.g. 'system', 'user', 'all'). Defaults to system.",
                        "default": "system"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "sharpup".into(),
            description: "Run SharpUp privilege escalation checks on a target host. Identifies \
                service misconfigurations, modifiable binaries, and other local privesc paths."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "powerup".into(),
            description: "Run PowerUp privilege escalation checks via PowerShell on a target \
                host. Identifies service misconfigurations, unquoted paths, DLL hijacking, \
                and registry-based privesc opportunities."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "winpeas".into(),
            description: "Run WinPEAS enumeration on a Windows target. Performs comprehensive \
                local enumeration including services, scheduled tasks, credentials, and \
                privilege escalation vectors."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    }
                },
                "required": ["target", "username", "password", "domain"]
            }),
        },
        ToolDefinition {
            name: "linpeas".into(),
            description: "Run LinPEAS enumeration on a Linux target. Performs comprehensive \
                local enumeration including SUID binaries, cron jobs, writable paths, \
                and privilege escalation vectors."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for SSH authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for SSH authentication"
                    }
                },
                "required": ["target", "username", "password"]
            }),
        },
        ToolDefinition {
            name: "runas_cs".into(),
            description: "Execute a command as a different user using RunasCs. Useful for \
                lateral movement and testing credentials on a target host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "run_as_user": {
                        "type": "string",
                        "description": "Username to run the command as"
                    },
                    "run_as_password": {
                        "type": "string",
                        "description": "Password for the run-as user"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute as the run-as user"
                    },
                    "run_as_domain": {
                        "type": "string",
                        "description": "Domain for the run-as user (defaults to target domain)"
                    }
                },
                "required": ["target", "username", "password", "domain", "run_as_user", "run_as_password", "command"]
            }),
        },
        ToolDefinition {
            name: "scm_uac_bypass".into(),
            description: "Bypass User Account Control (UAC) via the Service Control Manager \
                to execute commands with elevated privileges."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must be local admin)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute with elevated privileges"
                    }
                },
                "required": ["target", "username", "password", "domain", "command"]
            }),
        },
        ToolDefinition {
            name: "powerupsql".into(),
            description: "Run PowerUpSQL for SQL Server privilege escalation. Enumerates SQL \
                instances, checks for misconfigurations, and identifies paths to sysadmin."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication to the target"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain for authentication"
                    },
                    "sql_server": {
                        "type": "string",
                        "description": "SQL Server instance to target (e.g. 'db01.contoso.local' or 'db01.contoso.local,1433')"
                    }
                },
                "required": ["target", "username", "password", "domain", "sql_server"]
            }),
        },
        // -----------------------------------------------------------------
        // CVE exploits
        // -----------------------------------------------------------------
        ToolDefinition {
            name: "nopac".into(),
            description: "Exploit CVE-2021-42278/CVE-2021-42287 (noPac/sAMAccountName spoofing) \
                to impersonate a domain controller and obtain a privileged TGT. Can escalate \
                any domain user to Domain Admin."
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
                        "description": "Any valid domain username"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "dc_host": {
                        "type": "string",
                        "description": "Domain controller hostname (e.g. DC01)"
                    },
                    "target_user": {
                        "type": "string",
                        "description": "User to impersonate. Defaults to Administrator.",
                        "default": "Administrator"
                    },
                    "shell": {
                        "type": "boolean",
                        "description": "Whether to attempt to get a shell. Defaults to false.",
                        "default": false
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "dc_host"]
            }),
        },
        ToolDefinition {
            name: "printnightmare".into(),
            description: "Exploit PrintNightmare (CVE-2021-34527) to achieve remote code \
                execution via the Windows Print Spooler service by loading a malicious DLL."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname"
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
                        "description": "Domain for authentication"
                    },
                    "dll_path": {
                        "type": "string",
                        "description": "UNC path to the malicious DLL (e.g. '\\\\attacker\\share\\payload.dll')"
                    }
                },
                "required": ["target", "username", "password", "domain", "dll_path"]
            }),
        },
        ToolDefinition {
            name: "petitpotam_unauth".into(),
            description: "Trigger unauthenticated PetitPotam (CVE-2021-36942) NTLM coercion. \
                Forces the target to authenticate to the listener via MS-EFSRPC, enabling \
                relay attacks."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "listener": {
                        "type": "string",
                        "description": "Listener IP address to capture the coerced authentication"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target host IP or hostname to coerce authentication from"
                    }
                },
                "required": ["listener", "target"]
            }),
        },
    ]
}
