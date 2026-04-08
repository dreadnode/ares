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
