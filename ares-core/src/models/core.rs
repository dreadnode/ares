//! Core data models: Target, Host, User, Credential, Hash, Share.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::util::{default_hash_type, new_uuid};

/// Primary target information.
///
/// Matches Python: `class Target(Model)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Target {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
}

/// Discovered host information.
///
/// Matches Python: `class Host(Model)`
/// Redis serialization: `{"ip","hostname","os","roles","services","is_dc"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(default)]
    pub is_dc: bool,
    #[serde(default)]
    pub owned: bool,
}

impl Host {
    /// Detect if this host is a domain controller based on services/hostname/roles.
    pub fn detect_dc(&self) -> bool {
        let hostname_lower = self.hostname.to_lowercase();
        let roles_lower = self.roles.join(" ").to_lowercase();

        if hostname_lower.contains("dc") || roles_lower.contains("domain controller") {
            return true;
        }

        let dc_port_prefixes = ["88/tcp", "389/tcp"];
        let dc_service_names = ["kerberos", "ldap"];

        for svc in &self.services {
            let svc_lower = svc.to_lowercase();
            if dc_port_prefixes.iter().any(|p| svc_lower.starts_with(p)) {
                return true;
            }
            if dc_service_names.iter().any(|name| svc_lower.contains(name)) {
                return true;
            }
        }
        false
    }
}

/// Discovered user account.
///
/// Matches Python: `class User(Model)`
/// Redis serialization: `{"username","domain","source"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

/// Discovered credential.
///
/// Matches Python: `class Credential(Model)`
/// Redis serialization: `{"id","username","password","domain","source","parent_id","attack_step"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Credential {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub attack_step: i32,
}

/// Discovered password hash.
///
/// Matches Python: `class Hash(Model)`
/// Redis serialization: `{"id","username","hash_type","hash_value","domain","source","cracked_password","discovered_at","parent_id","attack_step"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hash {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub username: String,
    pub hash_value: String,
    #[serde(default = "default_hash_type")]
    pub hash_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cracked_password: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub attack_step: i32,
    /// AES256 key for Kerberos golden tickets (Windows 2016+ rejects RC4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aes_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(hostname: &str, services: Vec<&str>, roles: Vec<&str>) -> Host {
        Host {
            ip: "192.168.58.10".to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: roles.into_iter().map(String::from).collect(),
            services: services.into_iter().map(String::from).collect(),
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn detect_dc_by_kerberos_service() {
        let host = make_host("srv01", vec!["88/tcp (kerberos-sec)"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_ldap_service() {
        let host = make_host("srv01", vec!["389/tcp (ldap)"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_hostname_prefix() {
        let host = make_host("dc01.contoso.local", vec![], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_role() {
        let host = make_host("srv01", vec![], vec!["domain controller"]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_not_dc() {
        let host = make_host(
            "srv01.contoso.local",
            vec!["445/tcp (microsoft-ds)"],
            vec![],
        );
        assert!(!host.detect_dc());
    }

    #[test]
    fn detect_dc_empty() {
        let host = make_host("", vec![], vec![]);
        assert!(!host.detect_dc());
    }

    #[test]
    fn detect_dc_case_insensitive() {
        let host = make_host("DC01.CONTOSO.LOCAL", vec![], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_kerberos_service_name() {
        let host = make_host("server", vec!["kerberos"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_ldap_service_name() {
        let host = make_host("server", vec!["ldap"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn trust_info_is_parent_child() {
        let t = TrustInfo {
            domain: "child.corp.local".to_string(),
            flat_name: "CHILD".to_string(),
            direction: "bidirectional".to_string(),
            trust_type: "parent_child".to_string(),
            sid_filtering: false,
        };
        assert!(t.is_parent_child());
        assert!(!t.is_cross_forest());
    }

    #[test]
    fn trust_info_is_cross_forest() {
        let t = TrustInfo {
            domain: "fabrikam.local".to_string(),
            flat_name: "FABRIKAM".to_string(),
            direction: "outbound".to_string(),
            trust_type: "forest".to_string(),
            sid_filtering: true,
        };
        assert!(t.is_cross_forest());
        assert!(!t.is_parent_child());
    }

    #[test]
    fn trust_info_external_is_cross_forest() {
        let t = TrustInfo {
            domain: "other.local".to_string(),
            flat_name: "OTHER".to_string(),
            direction: "inbound".to_string(),
            trust_type: "external".to_string(),
            sid_filtering: false,
        };
        assert!(t.is_cross_forest());
    }

    #[test]
    fn trust_info_unknown_type_not_cross_forest() {
        let t = TrustInfo {
            domain: "x.local".to_string(),
            flat_name: String::new(),
            direction: String::new(),
            trust_type: "unknown".to_string(),
            sid_filtering: false,
        };
        assert!(!t.is_cross_forest());
        assert!(!t.is_parent_child());
    }

    #[test]
    fn host_serde_roundtrip() {
        let host = Host {
            ip: "10.0.0.1".to_string(),
            hostname: "web01".to_string(),
            os: "Windows Server 2019".to_string(),
            roles: vec!["web".to_string()],
            services: vec!["80/tcp".to_string(), "443/tcp".to_string()],
            is_dc: false,
            owned: true,
        };
        let json = serde_json::to_string(&host).unwrap();
        let deser: Host = serde_json::from_str(&json).unwrap();
        assert_eq!(host, deser);
    }

    #[test]
    fn host_serde_defaults() {
        let json = r#"{"ip":"10.0.0.1"}"#;
        let host: Host = serde_json::from_str(json).unwrap();
        assert_eq!(host.ip, "10.0.0.1");
        assert!(host.hostname.is_empty());
        assert!(host.os.is_empty());
        assert!(host.roles.is_empty());
        assert!(host.services.is_empty());
        assert!(!host.is_dc);
        assert!(!host.owned);
    }

    #[test]
    fn credential_serde_roundtrip() {
        let cred = Credential {
            id: "test-id".to_string(),
            username: "admin".to_string(),
            password: "P@ssw0rd".to_string(),
            domain: "CORP".to_string(),
            source: "secretsdump".to_string(),
            discovered_at: None,
            is_admin: true,
            parent_id: Some("parent-1".to_string()),
            attack_step: 2,
        };
        let json = serde_json::to_string(&cred).unwrap();
        let deser: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, deser);
    }

    #[test]
    fn hash_serde_defaults() {
        let json = r#"{"username":"admin","hash_value":"aad3b435"}"#;
        let hash: Hash = serde_json::from_str(json).unwrap();
        assert_eq!(hash.username, "admin");
        assert_eq!(hash.hash_value, "aad3b435");
        assert_eq!(hash.hash_type, "NTLM");
        assert!(hash.domain.is_empty());
        assert!(hash.cracked_password.is_none());
        assert!(hash.aes_key.is_none());
        assert_eq!(hash.attack_step, 0);
    }

    #[test]
    fn hash_serde_with_aes_key() {
        let hash = Hash {
            id: "h1".to_string(),
            username: "krbtgt".to_string(),
            hash_value: "abc123".to_string(),
            hash_type: "NTLM".to_string(),
            domain: "CORP".to_string(),
            cracked_password: None,
            source: "dcsync".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 1,
            aes_key: Some("aes256key".to_string()),
        };
        let json = serde_json::to_string(&hash).unwrap();
        assert!(json.contains("aes256key"));
        let deser: Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, deser);
    }

    #[test]
    fn share_serde_roundtrip() {
        let share = Share {
            host: "10.0.0.5".to_string(),
            name: "ADMIN$".to_string(),
            permissions: "READ".to_string(),
            comment: "Remote Admin".to_string(),
        };
        let json = serde_json::to_string(&share).unwrap();
        let deser: Share = serde_json::from_str(&json).unwrap();
        assert_eq!(share, deser);
    }

    #[test]
    fn share_serde_defaults() {
        let json = r#"{"host":"10.0.0.5","name":"C$"}"#;
        let share: Share = serde_json::from_str(json).unwrap();
        assert_eq!(share.host, "10.0.0.5");
        assert_eq!(share.name, "C$");
        assert!(share.permissions.is_empty());
        assert!(share.comment.is_empty());
    }

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            username: "jdoe".to_string(),
            domain: "CORP".to_string(),
            description: "John Doe".to_string(),
            is_admin: true,
            source: "ldap".to_string(),
        };
        let json = serde_json::to_string(&user).unwrap();
        let deser: User = serde_json::from_str(&json).unwrap();
        assert_eq!(user, deser);
    }

    #[test]
    fn user_serde_defaults() {
        let json = r#"{"username":"guest"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "guest");
        assert!(user.domain.is_empty());
        assert!(user.description.is_empty());
        assert!(!user.is_admin);
        assert!(user.source.is_empty());
    }

    #[test]
    fn target_serde_roundtrip() {
        let target = Target {
            ip: "192.168.1.1".to_string(),
            hostname: "dc01".to_string(),
            domain: "corp.local".to_string(),
            environment: "prod".to_string(),
        };
        let json = serde_json::to_string(&target).unwrap();
        let deser: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deser);
    }

    #[test]
    fn target_serde_skip_empty() {
        let target = Target {
            ip: "10.0.0.1".to_string(),
            hostname: String::new(),
            domain: String::new(),
            environment: String::new(),
        };
        let json = serde_json::to_string(&target).unwrap();
        assert!(!json.contains("hostname"));
        assert!(!json.contains("domain"));
        assert!(!json.contains("environment"));
    }

    #[test]
    fn trust_info_serde_roundtrip() {
        let trust = TrustInfo {
            domain: "child.corp.local".to_string(),
            flat_name: "CHILD".to_string(),
            direction: "bidirectional".to_string(),
            trust_type: "parent_child".to_string(),
            sid_filtering: true,
        };
        let json = serde_json::to_string(&trust).unwrap();
        let deser: TrustInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(trust, deser);
    }

    #[test]
    fn detect_dc_by_multiple_services() {
        let host = make_host(
            "srv01",
            vec!["88/tcp (kerberos)", "389/tcp (ldap)", "445/tcp"],
            vec![],
        );
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_non_dc_services_only() {
        let host = make_host(
            "fileserver",
            vec!["445/tcp (microsoft-ds)", "139/tcp (netbios-ssn)"],
            vec!["file server"],
        );
        assert!(!host.detect_dc());
    }

    #[test]
    fn host_skip_empty_fields_in_json() {
        let host = Host {
            ip: "10.0.0.1".to_string(),
            hostname: String::new(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(!json.contains("hostname"));
        assert!(!json.contains("os"));
        assert!(!json.contains("roles"));
        assert!(!json.contains("services"));
    }
}

/// Trust relationship metadata for an AD domain trust.
///
/// Stores structured trust information discovered via `enumerate_domain_trusts`
/// (LDAP `objectClass=trustedDomain`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustInfo {
    /// FQDN of the trusted domain (e.g. `fabrikam.local`).
    pub domain: String,
    /// NetBIOS / flat name (e.g. `FABRIKAM`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flat_name: String,
    /// Trust direction: `"inbound"`, `"outbound"`, or `"bidirectional"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub direction: String,
    /// Trust type: `"parent_child"`, `"forest"`, `"external"`, or `"unknown"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trust_type: String,
    /// Whether SID filtering is active (blocks RID < 1000 across forest trusts).
    #[serde(default)]
    pub sid_filtering: bool,
}

impl TrustInfo {
    /// Is this a parent-child (intra-forest) trust?
    pub fn is_parent_child(&self) -> bool {
        self.trust_type == "parent_child"
    }

    /// Is this a cross-forest trust?
    pub fn is_cross_forest(&self) -> bool {
        self.trust_type == "forest" || self.trust_type == "external"
    }
}

/// Discovered SMB share.
///
/// Matches Python: `class Share(Model)`
/// Redis serialization: `{"host","name","permissions","comment"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Share {
    pub host: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub permissions: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}
