//! ACL exploitation role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "bloodyad_add_group_member".into(),
            description: "Add a user to a domain group via BloodyAD. Exploits write permissions (GenericAll, GenericWrite, WriteDacl) on the group object to add an attacker-controlled principal as a member.".into(),
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
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_user", "group", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "bloodyad_set_password".into(),
            description: "Force-set a user's password via BloodyAD. Exploits ForceChangePassword, GenericAll, or AllExtendedRights permissions on the target user object to reset their password without knowing the current one.".into(),
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
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_user", "new_password", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "bloodyad_add_genericall".into(),
            description: "Add a GenericAll ACE to a target object via BloodyAD. Grants full control over the target by writing a new ACE into its DACL. Requires WriteDacl permission on the target.".into(),
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
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_dn", "principal", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "adminsd_holder_add_ace".into(),
            description: "Add an ACE via AdminSDHolder to gain persistent privileged access. The SDProp process propagates AdminSDHolder's DACL to all protected groups (Domain Admins, Enterprise Admins, etc.) every 60 minutes, providing a stealthy persistence mechanism.".into(),
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
                        "description": "Password for authentication"
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
                "required": ["domain", "username", "password", "dc_ip", "principal"]
            }),
        },
        ToolDefinition {
            name: "gmsa_read_password_bloodyad".into(),
            description: "Read a Group Managed Service Account (gMSA) password via BloodyAD. Extracts the NTLM hash from the msDS-ManagedPassword attribute. Requires read access to the gMSA's msDS-ManagedPassword attribute, typically granted via msDS-GroupMSAMembership.".into(),
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
                        "description": "Password for authentication"
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
                "required": ["domain", "username", "password", "dc_ip", "gmsa_account"]
            }),
        },
        ToolDefinition {
            name: "pywhisker".into(),
            description: "Manage msDS-KeyCredentialLink attribute for Shadow Credentials attack. Adds, removes, or lists Key Credential entries on a target object. When adding, generates a PFX certificate that can be used with PKINIT to obtain a TGT for the target principal.".into(),
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
                        "description": "Password for authentication"
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
                "required": ["target_samaccountname", "domain", "username", "password", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "targeted_kerberoast".into(),
            description: "Set a Service Principal Name (SPN) on a target account and then Kerberoast it. Exploits GenericAll or GenericWrite permissions to add an SPN to an account that lacks one, then requests a TGS ticket whose hash can be cracked offline to recover the account's password.".into(),
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
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    }
                },
                "required": ["target_user", "domain", "username", "password", "dc_ip"]
            }),
        },
        // NOTE: sharpgpoabuse removed — SharpGPOAbuse.exe not in ACL container.
        // NOTE: pygpoabuse_immediate_task removed — pygpoabuse not in ACL container.
        ToolDefinition {
            name: "dacl_edit".into(),
            description: "Edit the Discretionary Access Control List (DACL) on an Active Directory object to grant specific rights. Directly modifies the security descriptor to add, remove, or modify ACEs, enabling fine-grained control over object permissions such as DCSync, WriteDacl, or WriteOwner.".into(),
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
                        "description": "Password for authentication"
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
                "required": ["target_dn", "principal", "rights", "domain", "username", "password", "dc_ip"]
            }),
        },
    ]
}
