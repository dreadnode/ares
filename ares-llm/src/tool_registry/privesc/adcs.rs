//! ADCS / Certipy tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "certipy_find".into(),
            description: "Find vulnerable certificate templates in Active Directory Certificate \
                Services (AD CS). Enumerates CAs, templates, and identifies exploitable \
                misconfigurations (ESC1-ESC15)."
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
                    "hashes": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (format: 'lmhash:nthash' or just ':nthash'). Use instead of password."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a forged inter-realm Kerberos ccache for cross-forest enumeration. Injected automatically by the credential resolver when the target forest has no reusable credential; when present, certipy authenticates via `-k -no-pass` (KRB5CCNAME) and password/hash are ignored. Auth precedence: ticket_path > hashes > password."
                    },
                    "vulnerable": {
                        "type": "boolean",
                        "description": "Only show vulnerable templates. Defaults to true.",
                        "default": true
                    }
                },
                "required": ["domain", "username", "dc_ip"]
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
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname to connect to for certificate enrollment. REQUIRED when the CA is on a different host than the DC (e.g. CA on a member server, DC on the domain controller). Without this, certipy tries RPC on the DC which fails with ept_s_not_registered."
                    },
                    "sid": {
                        "type": "string",
                        "description": "Object SID to embed in the certificate (e.g. 'S-1-5-21-...-500' for Administrator). Required by certipy v5+ to prevent SID mismatch errors during certipy_auth. For Administrator, use the domain SID + '-500'."
                    },
                    "out": {
                        "type": "string",
                        "description": "Output filename for the PFX certificate (without .pfx extension). A unique name is auto-generated if not specified. The resulting file will be <out>.pfx — use this path for certipy_auth's pfx_path parameter."
                    },
                    "application_policies": {
                        "type": "string",
                        "description": "Application policy OID to include in the certificate request. Used for ESC15 (CVE-2024-49019) exploitation where the template uses application policy OIDs for authorization."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a forged inter-realm Kerberos ccache for cross-forest enrollment. Injected automatically by the credential resolver when the target forest has no reusable credential; when present, certipy authenticates via `-k -no-pass` (KRB5CCNAME) and password is ignored. Auth precedence: ticket_path > password."
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca", "template"]
            }),
        },
        ToolDefinition {
            name: "certipy_auth".into(),
            description: "Authenticate to Active Directory using a PFX certificate file. \
                Performs PKINIT Kerberos authentication and retrieves the NT hash of the \
                certificate's subject. Works on both an unprotected PFX from certipy_req \
                and the passphrase-protected PFX pywhisker writes — the passphrase for the \
                latter is applied for you, so pass only the path."
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
                with the resulting certificate. You MUST provide exactly one of `password` \
                OR `hashes` — never pass an empty string for the unused field; omit it \
                entirely. If the orchestrator handed you a plaintext password, pass \
                `password` and DO NOT include `hashes` at all."
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
                        "description": "Plaintext password for the source account. Use this when the orchestrator provides a `password` field — do NOT also pass `hashes`."
                    },
                    "hashes": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (format: 'lmhash:nthash' or ':nthash'). Use ONLY when the orchestrator provides a `hash` / `nt_hash` field and NO password. Omit this field entirely — do not pass an empty string — when using `password`."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target account to add shadow credentials to"
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a forged inter-realm Kerberos ccache for a cross-forest shadow-credentials write. Injected automatically by the credential resolver when the target forest has no reusable credential; when present, certipy authenticates via `-k -no-pass` (KRB5CCNAME) and password/hash are ignored. Auth precedence: ticket_path > hashes > password."
                    }
                },
                "required": ["domain", "username", "dc_ip", "target"]
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
            name: "certipy_account_update".into(),
            description: "Modify a target account's userPrincipalName via certipy (account \
                update). The primitive for ESC9 (set a GenericAll-controlled user's UPN to \
                administrator@<domain>, request a cert with the spoofed UPN, then restore the \
                original UPN) and ESC10 (UPN manipulation for weak implicit cert mapping). \
                Runs on the privesc worker alongside certipy_request/certipy_auth so the whole \
                chain completes on one host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain of the authenticating account (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Authenticating user — must have GenericAll/Write over the target account"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for the authenticating user"
                    },
                    "user": {
                        "type": "string",
                        "description": "Target account whose userPrincipalName is being changed"
                    },
                    "upn": {
                        "type": "string",
                        "description": "New userPrincipalName (e.g. administrator@<domain>); pass the original value to restore it afterward"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["domain", "username", "password", "user", "upn", "dc_ip"]
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
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for certificate enrollment. REQUIRED when the CA is on a different host than the DC."
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "template", "ca"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc1_full_chain".into(),
            description:
                "Execute the full ESC1 (enrollee supplies subject) exploit chain: request \
                a certificate with an attacker-chosen UPN and SID, PKINIT-authenticate with it to \
                recover the impersonated principal's NT hash, and — when `dc_host` is supplied and \
                the KDC refuses the u2u hash recovery (KDC_ERR_ETYPE_NOSUPP on RC4-disabled KDCs) \
                — DCSync krbtgt with the resulting ccache. Use this when the template allows the \
                enrollee to supply the subject. Both `upn` and `sid` are REQUIRED: KB5014754 \
                strict certificate mapping rejects a certificate whose Security-Extension SID does \
                not match the impersonated account. Do NOT use this for an issuance-policy \
                template — use certipy_esc13_full_chain, which enrolls plainly."
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
                        "description": "Username for authentication (needs Enroll rights on the template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-CA01-CA')"
                    },
                    "template": {
                        "type": "string",
                        "description": "ESC1-vulnerable certificate template name"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "upn": {
                        "type": "string",
                        "description": "UPN to impersonate (e.g. 'administrator@contoso.local'). REQUIRED — this is the enrollee-supplied subject."
                    },
                    "sid": {
                        "type": "string",
                        "description": "Object SID of the impersonated principal (domain SID + '-500' for Administrator). REQUIRED — KB5014754 strict mapping denies the PKINIT if it is absent or does not match the UPN."
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for certificate enrollment. REQUIRED when the CA is on a different host than the DC — otherwise certipy hits the DC's RPC endpoint and fails with ept_s_not_registered. `ca_host` and `target_ip` are accepted as aliases."
                    },
                    "dc_host": {
                        "type": "string",
                        "description": "DC FQDN (e.g. 'dc01.contoso.local') enabling the DCSync tail when certipy auth obtains a TGT but cannot recover the NT hash. Must be the FQDN — an IP yields KDC_ERR_S_PRINCIPAL_UNKNOWN."
                    }
                },
                "required": ["domain", "username", "password", "ca", "template", "dc_ip", "upn", "sid"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc3_full_chain".into(),
            description: "Execute the full ESC3 (enrollment agent) exploit chain: enroll an \
                enrollment-agent certificate from `agent_template` (the template carrying the \
                Certificate Request Agent application policy), use that agent certificate to \
                request a second certificate on behalf of `on_behalf_of` from a SEPARATE \
                `on_behalf_template`, then authenticate with the resulting PFX to obtain NT \
                hashes. ESC3 needs BOTH templates — a single certipy_request cannot do it, \
                because the on-behalf-of request must be signed by the agent PFX produced by the \
                first enrollment."
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
                        "description": "Username for authentication (needs Enroll rights on the agent template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-CA01-CA')"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "agent_template": {
                        "type": "string",
                        "description": "Enrollment-agent template — the one with the 'Certificate Request Agent' application policy. This is the ESC3-vulnerable template reported by certipy_find."
                    },
                    "on_behalf_template": {
                        "type": "string",
                        "description": "Template used for the on-behalf-of request. Defaults to 'User' (the universal client-auth template). Override when the on-behalf-of target is a custom template that requires agent-signed enrollment.",
                        "default": "User"
                    },
                    "on_behalf_of": {
                        "type": "string",
                        "description": "sAMAccountName of the principal to impersonate. Defaults to 'administrator'.",
                        "default": "administrator"
                    },
                    "nt_domain": {
                        "type": "string",
                        "description": "NetBIOS/flat domain name for certipy's -on-behalf-of (NETBIOS\\principal). Derived from the first label of `domain`, uppercased, when omitted — certipy rejects an FQDN here and the CA then denies the request. `flat_name` is accepted as an alias."
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for certificate enrollment. REQUIRED when the CA is on a different host than the DC. `ca_host` and `target_ip` are accepted as aliases."
                    }
                },
                "required": ["domain", "username", "password", "ca", "dc_ip", "agent_template"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc13_full_chain".into(),
            description: "Execute the full ESC13 (issuance policy linked to a group) exploit \
                chain: enroll the template AS THE LOW-PRIVILEGE USER with a PLAIN request, \
                PKINIT-authenticate, then DCSync krbtgt with the now-elevated ccache. The \
                template's issuance-policy OID is linked via msDS-OIDToGroupLink to a privileged \
                group, so the DC stamps that group's SID into the enrolling user's own PKINIT TGT \
                — there is no impersonation. This tool therefore takes NO `upn`/`sid` override: \
                passing ESC1-style subject parameters makes the CA policy module deny the request \
                (0x80070547) and trips KB5014754 strict mapping, because the certificate's \
                Security-Extension SID is the requester's. Use certipy_esc1_full_chain instead \
                when the template lets the enrollee supply the subject."
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
                        "description": "Low-privilege user to enroll as — the OID-linked group lands in THIS account's ticket"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-CA01-CA')"
                    },
                    "template": {
                        "type": "string",
                        "description": "Template whose issuance policy OID is linked to a privileged group"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for certificate enrollment. REQUIRED when the CA is on a different host than the DC. `ca_host` and `target_ip` are accepted as aliases."
                    },
                    "dc_host": {
                        "type": "string",
                        "description": "DC FQDN (e.g. 'dc01.contoso.local') for the DCSync tail — without it the chain stops after PKINIT and only reports the enrolling user's hash. Must be the FQDN — an IP yields KDC_ERR_S_PRINCIPAL_UNKNOWN."
                    }
                },
                "required": ["domain", "username", "password", "ca", "template", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "certipy_ca".into(),
            description:
                "Manage a Certificate Authority using Certipy. Can add yourself as a \
                CA officer (ManageCA right required), issue a pending certificate request, or \
                back up the CA's private key + certificate (requires SYSTEM/local admin on the \
                CA host — produces a PFX usable for offline certificate forgery via certipy_forge)."
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
                        "description": "Username for authentication (must have ManageCA rights)"
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
                        "description": "Certificate Authority name (e.g. 'CONTOSO-CA')"
                    },
                    "add_officer": {
                        "type": "boolean",
                        "description": "Add yourself as a CA officer. Requires ManageCA rights."
                    },
                    "issue_request": {
                        "type": "integer",
                        "description": "Issue (approve) a pending certificate request by its request ID."
                    },
                    "backup": {
                        "type": "boolean",
                        "description": "Back up the CA private key + certificate to a PFX. Requires SYSTEM or local admin on the CA host (use the credential of an account with that access). Output PFX is the input to certipy_forge for offline Golden Certificate forgery."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a forged inter-realm Kerberos ccache for a cross-forest CA operation. Injected automatically by the credential resolver when the target forest has no reusable credential; when present, certipy authenticates via `-k -no-pass` (KRB5CCNAME) and password is ignored. Auth precedence: ticket_path > password."
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca"]
            }),
        },
        ToolDefinition {
            name: "certipy_forge".into(),
            description: "Forge a certificate offline using a CA's backed-up private key (Golden \
                Certificate). Use after certipy_ca with backup=true to produce a PFX for any UPN \
                in the CA's domain — bypasses normal enrollment, no DC interaction. The forged \
                PFX feeds certipy_auth to obtain the target user's NT hash via PKINIT."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ca_pfx": {
                        "type": "string",
                        "description": "Path to the CA's backed-up PFX file (produced by certipy_ca with backup=true)."
                    },
                    "upn": {
                        "type": "string",
                        "description": "User Principal Name to forge the certificate for (e.g. 'administrator@contoso.local'). Used as the certificate subject for PKINIT authentication."
                    },
                    "subject": {
                        "type": "string",
                        "description": "Optional certificate subject (Distinguished Name). Defaults to a sensible value derived from the UPN."
                    },
                    "template": {
                        "type": "string",
                        "description": "Optional certificate template name to mimic. Defaults to a generic client-auth template."
                    },
                    "out": {
                        "type": "string",
                        "description": "Output filename for the forged PFX. Auto-generated if omitted (forged_<upn>_<timestamp>.pfx)."
                    }
                },
                "required": ["ca_pfx", "upn"]
            }),
        },
        ToolDefinition {
            name: "certipy_retrieve".into(),
            description: "Retrieve a previously issued certificate from the CA by its request ID. \
                Used after certipy_ca -issue-request approves a pending request."
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
                        "description": "Certificate Authority name"
                    },
                    "request_id": {
                        "type": "integer",
                        "description": "The certificate request ID to retrieve"
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for RPC enrollment"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca", "request_id"]
            }),
        },
        ToolDefinition {
            name: "certipy_relay".into(),
            description: "Start a Certipy relay listener for ADCS certificate enrollment via \
                relay attacks. Supports HTTP relay (ESC8) and RPC relay (ESC11). \
                For ESC8: target=http://ca-host. For ESC11: target=rpc://ca-host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Relay target URL. Use 'http://<ca-host>' for ESC8 (HTTP web enrollment relay) or 'rpc://<ca-host>' for ESC11 (RPC certificate enrollment relay)."
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'CONTOSO-CA')"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template to request during relay. Optional — defaults to Machine for HTTP or uses the CA's default."
                    }
                },
                "required": ["target", "ca"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc7_full_chain".into(),
            description: "Execute the full ESC7 exploit chain: add yourself as CA officer \
                (ManageCA abuse), request a SubCA certificate (gets denied), issue the pending \
                request, retrieve the certificate, and authenticate to obtain NT hashes. \
                Requires the user to have ManageCA rights on the target CA."
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
                        "description": "Username for authentication (must have ManageCA rights)"
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
                        "description": "Certificate Authority name (e.g. 'CONTOSO-CA')"
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for certificate enrollment. REQUIRED when the CA is on a different host than the DC."
                    },
                    "upn": {
                        "type": "string",
                        "description": "UPN of the user to impersonate. Defaults to 'administrator@<domain>'.",
                        "default": "administrator"
                    },
                    "sid": {
                        "type": "string",
                        "description": "SID to embed in the certificate (e.g. domain SID + '-500' for Administrator)"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca"]
            }),
        },
    ]
}
