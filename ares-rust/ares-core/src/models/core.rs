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
    fn test_detect_dc_by_kerberos_service() {
        let host = make_host("srv01", vec!["88/tcp (kerberos-sec)"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn test_detect_dc_by_ldap_service() {
        let host = make_host("srv01", vec!["389/tcp (ldap)"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn test_detect_dc_by_hostname_prefix() {
        let host = make_host("dc01.contoso.local", vec![], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn test_detect_dc_by_role() {
        let host = make_host("srv01", vec![], vec!["domain controller"]);
        assert!(host.detect_dc());
    }

    #[test]
    fn test_detect_dc_not_dc() {
        let host = make_host(
            "srv01.contoso.local",
            vec!["445/tcp (microsoft-ds)"],
            vec![],
        );
        assert!(!host.detect_dc());
    }

    #[test]
    fn test_detect_dc_empty() {
        let host = make_host("", vec![], vec![]);
        assert!(!host.detect_dc());
    }

    #[test]
    fn test_detect_dc_case_insensitive() {
        let host = make_host("DC01.CONTOSO.LOCAL", vec![], vec![]);
        assert!(host.detect_dc());
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
