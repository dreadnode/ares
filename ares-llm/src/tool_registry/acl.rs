//! ACL exploitation role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "bloodyad_add_group_member".into(),
            description: "Add a user to a domain group via BloodyAD. Exploits write permissions (GenericAll, GenericWrite, WriteDacl) on the group object to add an attacker-controlled principal as a member. Auth precedence: `ticket_path` (Kerberos ccache) > `hash` (NTLM pass-the-hash) > `password` (plaintext NTLM bind); the worker injects whichever material the operation actually holds.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_user": {
                        "type": "string",
                        "description": "SAMAccountName of the user to add to the group"
                    },
                    "group": {
                        "type": "string",
                        "description": "Name of the target group (e.g. 'Domain Admins')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (principal with write access)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for NTLM authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to bloodyAD as `-p LMHASH:NTHASH`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Takes precedence over `hash` and `password`; required for cross-forest writes an NTLM bind would reject with 0x52e."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_user", "group", "domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "bloodyad_set_password".into(),
            description: "Force-set a user's password via BloodyAD. Exploits ForceChangePassword, GenericAll, or AllExtendedRights permissions on the target user object to reset their password without knowing the current one. Auth precedence: `ticket_path` (Kerberos ccache) > `hash` (NTLM pass-the-hash) > `password` (plaintext NTLM bind); the worker injects whichever material the operation actually holds.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_user": {
                        "type": "string",
                        "description": "SAMAccountName of the user whose password will be reset"
                    },
                    "new_password": {
                        "type": "string",
                        "description": "New password to set on the target account"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (principal with password reset rights)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for NTLM authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to bloodyAD as `-p LMHASH:NTHASH`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Takes precedence over `hash` and `password`; required for cross-forest writes an NTLM bind would reject with 0x52e."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_user", "new_password", "domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "bloodyad_add_genericall".into(),
            description: "Add a GenericAll ACE to a target object via BloodyAD. Grants full control over the target by writing a new ACE into its DACL. Requires WriteDacl permission on the target. Auth precedence: `ticket_path` (Kerberos ccache) > `hash` (NTLM pass-the-hash) > `password` (plaintext NTLM bind); the worker injects whichever material the operation actually holds.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_dn": {
                        "type": "string",
                        "description": "Distinguished name of the target object (e.g. 'CN=victim,CN=Users,DC=contoso,DC=local')"
                    },
                    "principal": {
                        "type": "string",
                        "description": "SAMAccountName or DN of the principal to grant GenericAll access"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have WriteDacl on target)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for NTLM authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to bloodyAD as `-p LMHASH:NTHASH`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Takes precedence over `hash` and `password`; required for cross-forest writes an NTLM bind would reject with 0x52e."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_dn", "principal", "domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "bloodyad_set_object_attr".into(),
            description: "Set a single LDAP attribute on an AD object via \
                `bloodyAD set object`. Primary use cases: ESC9 (set \
                `userPrincipalName` to `administrator@<domain>` on a user we \
                have GenericAll on, then request cert with the spoofed UPN, \
                then restore the original UPN); ESC10 Case 2 (clear \
                `userPrincipalName` so the implicit cert-mapping rule binds \
                to administrator); RBCD (write \
                `msDS-AllowedToActOnBehalfOfOtherIdentity` on a victim \
                computer); any other primitive where the LLM needs to write \
                ONE attribute without granting itself a DACL right first. Auth precedence: `ticket_path` > `hash` > `password`; the worker injects whichever material the operation actually holds."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "SAMAccountName or DN of the AD object whose attribute we're modifying."
                    },
                    "attribute": {
                        "type": "string",
                        "description": "LDAP attribute name (e.g. `userPrincipalName`, `userAccountControl`, `servicePrincipalName`, `msDS-AllowedToActOnBehalfOfOtherIdentity`)."
                    },
                    "value": {
                        "type": "string",
                        "description": "New value to write. For text attributes, the literal string. For binary attributes (e.g. security descriptors), the hex-encoded bytes bloodyAD expects via its `-v` flag."
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have WriteProperty on the target attribute)."
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to bloodyAD as `-p LMHASH:NTHASH`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; invokes bloodyAD with `-k ccache=<path>` and sets KRB5CCNAME."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target", "attribute", "value", "domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "adminsd_holder_add_ace".into(),
            description: "Add an ACE via AdminSDHolder to gain persistent privileged access. The SDProp process propagates AdminSDHolder's DACL to all protected groups (Domain Admins, Enterprise Admins, etc.) every 60 minutes, providing a stealthy persistence mechanism. Auth precedence: `ticket_path` > `hash` > `password`; the worker injects whichever material the operation actually holds.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have WriteDacl on AdminSDHolder)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to bloodyAD as `-p LMHASH:NTHASH`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; invokes bloodyAD with `-k ccache=<path>` and sets KRB5CCNAME."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "principal": {
                        "type": "string",
                        "description": "SAMAccountName of the principal to grant access via AdminSDHolder"
                    },
                    "right": {
                        "type": "string",
                        "description": "Right to grant (default: GenericAll). Examples: GenericAll, GenericWrite, WriteDacl, WriteOwner",
                        "default": "GenericAll"
                    }
                },
                "required": ["domain", "username", "dc_ip", "principal"]
            }),
        },
        ToolDefinition {
            name: "gmsa_read_password_bloodyad".into(),
            description: "Read a Group Managed Service Account (gMSA) password via BloodyAD. Extracts the NTLM hash from the msDS-ManagedPassword attribute. Requires read access to the gMSA's msDS-ManagedPassword attribute, typically granted via msDS-GroupMSAMembership. Auth precedence: `ticket_path` > `hash` > `password`; the worker injects whichever material the operation actually holds.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must be allowed to read gMSA password)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to bloodyAD as `-p LMHASH:NTHASH`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; invokes bloodyAD with `-k ccache=<path>` and sets KRB5CCNAME."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "gmsa_account": {
                        "type": "string",
                        "description": "SAMAccountName of the gMSA account (e.g. 'svc_sql$')"
                    }
                },
                "required": ["domain", "username", "dc_ip", "gmsa_account"]
            }),
        },
        ToolDefinition {
            name: "pywhisker".into(),
            description: "Manage msDS-KeyCredentialLink attribute for Shadow Credentials attack. Adds, removes, or lists Key Credential entries on a target object. When adding, generates a PFX certificate that can be used with PKINIT to obtain a TGT for the target principal. Auth precedence: ticket_path > hash > password.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_samaccountname": {
                        "type": "string",
                        "description": "SAMAccountName of the target object to modify"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to msDS-KeyCredentialLink)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no ticket_path or hash is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT). Takes precedence over password."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; sets KRB5CCNAME and invokes pywhisker with -k --no-pass."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["add", "remove", "list"],
                        "description": "Action to perform on the KeyCredentialLink attribute (default: add)",
                        "default": "add"
                    }
                },
                "required": ["target_samaccountname", "domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "targeted_kerberoast".into(),
            description: "Set a Service Principal Name (SPN) on a target account and then Kerberoast it. Exploits GenericAll or GenericWrite permissions to add an SPN to an account that lacks one, then requests a TGS ticket whose hash can be cracked offline to recover the account's password. Auth precedence: ticket_path > hash > password.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_user": {
                        "type": "string",
                        "description": "SAMAccountName of the target user to set an SPN on and Kerberoast"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to servicePrincipalName)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no ticket_path or hash is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT). Takes precedence over password."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; sets KRB5CCNAME and invokes the tool with -k -no-pass."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_user", "domain", "username", "dc_ip"]
            }),
        },
        // NOTE: sharpgpoabuse removed — SharpGPOAbuse.exe not in ACL container.
        // NOTE: pygpoabuse_immediate_task removed — pygpoabuse not in ACL container.
        ToolDefinition {
            name: "dacl_edit".into(),
            description: "Edit the Discretionary Access Control List (DACL) on an Active Directory object to grant specific rights. Directly modifies the security descriptor to add, remove, or modify ACEs, enabling fine-grained control over object permissions such as DCSync, WriteDacl, or WriteOwner. Auth precedence: `ticket_path` > `hash` > `password`; the worker injects whichever material the operation actually holds.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_dn": {
                        "type": "string",
                        "description": "Distinguished name of the target AD object (e.g. 'DC=contoso,DC=local' for domain root)"
                    },
                    "principal": {
                        "type": "string",
                        "description": "SAMAccountName or DN of the principal to grant rights to"
                    },
                    "rights": {
                        "type": "string",
                        "description": "Rights to grant (e.g. 'DCSync', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'AllExtendedRights')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target domain FQDN"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have WriteDacl on the target)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication (used only when no `ticket_path` or `hash` is supplied)"
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT or bare NT), passed to dacledit.py as `-hashes LMHASH:NTHASH`. Takes precedence over `password`."
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to a Kerberos ccache file. Highest auth precedence; invokes dacledit.py with `-k -no-pass` and sets KRB5CCNAME."
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "action": {
                        "type": "string",
                        "description": "DACL action to perform (default: write). Options: write, remove, backup, restore",
                        "default": "write"
                    }
                },
                "required": ["target_dn", "principal", "rights", "domain", "username", "dc_ip"]
            }),
        },
    ]
}
