//! Template context helpers (serializable structs for Tera).

use std::collections::HashSet;

use serde::Serialize;

use crate::models::{Credential, Hash, Host, Share, User, VulnerabilityInfo};

use super::vuln_details::format_vuln_details;

#[derive(Serialize)]
pub(crate) struct HostCtx {
    pub label: String,
    pub ip: String,
    pub os: String,
    pub roles: String,
    pub services: Vec<String>,
    pub is_dc: bool,
}

impl From<&Host> for HostCtx {
    fn from(h: &Host) -> Self {
        let is_dc = h.is_dc || h.detect_dc();
        Self {
            label: if h.hostname.is_empty() {
                h.ip.clone()
            } else {
                h.hostname.clone()
            },
            ip: h.ip.clone(),
            os: if h.os.is_empty() {
                String::new()
            } else {
                h.os.clone()
            },
            roles: if h.roles.is_empty() {
                String::new()
            } else {
                h.roles.join(", ")
            },
            services: h.services.clone(),
            is_dc,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct UserCtx {
    pub username: String,
    pub domain: String,
    pub description: String,
    pub is_admin: bool,
    pub admin_display: String,
}

impl From<&User> for UserCtx {
    fn from(u: &User) -> Self {
        Self {
            username: u.username.clone(),
            domain: u.domain.clone(),
            description: if u.description.is_empty() {
                String::new()
            } else {
                u.description.clone()
            },
            is_admin: u.is_admin,
            admin_display: if u.is_admin {
                "Yes".to_string()
            } else {
                "No".to_string()
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct CredCtx {
    pub username: String,
    pub domain: String,
    pub password: String,
    pub source: String,
    pub is_admin: bool,
    pub admin_display: String,
}

impl From<&Credential> for CredCtx {
    fn from(c: &Credential) -> Self {
        Self {
            username: c.username.clone(),
            domain: if c.domain.is_empty() {
                "Unknown".to_string()
            } else {
                c.domain.clone()
            },
            password: c.password.clone(),
            source: c.source.clone(),
            is_admin: c.is_admin,
            admin_display: if c.is_admin {
                "Yes".to_string()
            } else {
                "No".to_string()
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct HashCtx {
    pub domain: String,
    pub username: String,
    pub hash_type: String,
    pub hash_value: String,
    pub source: String,
}

impl From<&Hash> for HashCtx {
    fn from(h: &Hash) -> Self {
        Self {
            domain: h.domain.clone(),
            username: h.username.clone(),
            hash_type: h.hash_type.clone(),
            hash_value: h.hash_value.clone(),
            source: h.source.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct ShareCtx {
    pub name: String,
    pub host: String,
    pub permissions: String,
    pub comment: String,
}

impl From<&Share> for ShareCtx {
    fn from(s: &Share) -> Self {
        Self {
            name: s.name.clone(),
            host: s.host.clone(),
            permissions: if s.permissions.is_empty() {
                String::new()
            } else {
                s.permissions.clone()
            },
            comment: if s.comment.is_empty() {
                String::new()
            } else {
                s.comment.clone()
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct TimelineEventCtx {
    pub timestamp: String,
    pub description: String,
    pub description_short: String,
    pub mitre_display: String,
    pub mitre_techniques: Vec<String>,
    pub confidence_display: String,
}

#[derive(Serialize)]
pub(crate) struct VulnCtx {
    pub vuln_id: String,
    pub vuln_type: String,
    pub target: String,
    pub target_ip: String,
    pub target_host: String,
    pub priority: i32,
    pub exploited: bool,
    pub exploited_display: String,
    pub status_display: String,
    pub details: String,
}

pub(crate) fn build_vuln_ctx(
    vuln_id: &str,
    vuln: &VulnerabilityInfo,
    exploited_set: &HashSet<String>,
) -> VulnCtx {
    let exploited = exploited_set.contains(vuln_id);
    VulnCtx {
        vuln_id: vuln_id.to_string(),
        vuln_type: vuln.vuln_type.clone(),
        target: vuln.target.clone(),
        target_ip: vuln.target.clone(),
        target_host: vuln.target.clone(),
        priority: vuln.priority,
        exploited,
        exploited_display: if exploited {
            "\u{2713}".to_string() // checkmark
        } else {
            "\u{2717}".to_string() // cross
        },
        status_display: if exploited {
            "EXPLOITED".to_string()
        } else {
            "Not Exploited".to_string()
        },
        details: format_vuln_details(&vuln.details),
    }
}
