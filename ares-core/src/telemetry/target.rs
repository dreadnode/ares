//! Target extraction and classification for span attributes.
//!
//! Mirrors Python's `tracing.py` logic for extracting target info from tool
//! call arguments and inferring target type from hostnames.

/// Extracted target information from tool call arguments.
#[derive(Debug, Default)]
pub struct ToolTargetInfo {
    pub target_ip: Option<String>,
    pub target_fqdn: Option<String>,
    pub target_user: Option<String>,
}

/// Extract target IP, FQDN, and username from tool call arguments JSON.
///
/// Matches Python's extraction logic in `red_agents.py`:
/// - IP: `target_ip`, `target`, `host`, `ip` (if it looks like an IP)
/// - FQDN: `target_fqdn`, `target`, `host`, `hostname` (if it looks like an FQDN)
/// - User: `username`, `user`, `target_user`
pub fn extract_target_info(arguments: &serde_json::Value) -> ToolTargetInfo {
    let mut info = ToolTargetInfo::default();

    let obj = match arguments.as_object() {
        Some(o) => o,
        None => return info,
    };

    // Extract IP
    for key in &["target_ip", "target", "host", "ip"] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            if is_ip_address(val) {
                info.target_ip = Some(val.to_string());
                break;
            }
        }
    }

    // Extract FQDN
    for key in &["target_fqdn", "target", "host", "hostname"] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            if is_likely_fqdn(val) {
                info.target_fqdn = Some(val.to_string());
                break;
            }
        }
    }

    // Extract username
    for key in &["username", "user", "target_user"] {
        if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
            if !val.is_empty() {
                info.target_user = Some(val.to_string());
                break;
            }
        }
    }

    info
}

/// Infer target type from a hostname or FQDN.
///
/// Matches Python's `infer_target_type()`:
/// - `dc*` prefix -> `"domain_controller"`
/// - `sql*`, `db*`, `mssql*`, `database*` prefix -> `"sql_server"`
/// - `web*`, `www*`, `iis*`, `apache*`, `nginx*` prefix -> `"web_server"`
/// - `ws*`, `pc*`, `desktop*`, `laptop*`, `client*` prefix -> `"workstation"`
/// - anything else -> `"server"`
pub fn infer_target_type(host: &str) -> &'static str {
    // Extract the first label (hostname part) from FQDN
    let hostname = host.split('.').next().unwrap_or(host).to_lowercase();

    if hostname.starts_with("dc") {
        "domain_controller"
    } else if hostname.starts_with("sql")
        || hostname.starts_with("db")
        || hostname.starts_with("mssql")
        || hostname.starts_with("database")
    {
        "sql_server"
    } else if hostname.starts_with("web")
        || hostname.starts_with("www")
        || hostname.starts_with("iis")
        || hostname.starts_with("apache")
        || hostname.starts_with("nginx")
    {
        "web_server"
    } else if hostname.starts_with("ws")
        || hostname.starts_with("pc")
        || hostname.starts_with("desktop")
        || hostname.starts_with("laptop")
        || hostname.starts_with("client")
    {
        "workstation"
    } else {
        "server"
    }
}

/// Infer target type, falling back to `"user"` when only a username is present.
pub fn infer_target_type_from_info(info: &ToolTargetInfo) -> Option<&'static str> {
    // Prefer hostname-based inference
    if let Some(ref fqdn) = info.target_fqdn {
        return Some(infer_target_type(fqdn));
    }
    // If we only have a user, it's a user-targeted attack
    if info.target_user.is_some() {
        return Some("user");
    }
    None
}

fn is_ip_address(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn is_likely_fqdn(s: &str) -> bool {
    // Must contain at least one dot and not be an IP
    s.contains('.')
        && !is_ip_address(s)
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_target_type_dc() {
        assert_eq!(infer_target_type("dc01.contoso.local"), "domain_controller");
        assert_eq!(infer_target_type("DC02"), "domain_controller");
    }

    #[test]
    fn test_infer_target_type_sql() {
        assert_eq!(infer_target_type("sql01.contoso.local"), "sql_server");
        assert_eq!(infer_target_type("mssql.contoso.local"), "sql_server");
        assert_eq!(infer_target_type("db01"), "sql_server");
    }

    #[test]
    fn test_infer_target_type_web() {
        assert_eq!(infer_target_type("web01.contoso.local"), "web_server");
        assert_eq!(infer_target_type("iis01"), "web_server");
    }

    #[test]
    fn test_infer_target_type_workstation() {
        assert_eq!(infer_target_type("ws01.contoso.local"), "workstation");
        assert_eq!(infer_target_type("pc01"), "workstation");
        assert_eq!(infer_target_type("desktop-user1"), "workstation");
    }

    #[test]
    fn test_infer_target_type_server_fallback() {
        assert_eq!(infer_target_type("fileserver01.contoso.local"), "server");
        assert_eq!(infer_target_type("app01"), "server");
    }

    #[test]
    fn test_extract_target_info_ip() {
        let args = serde_json::json!({"target_ip": "192.168.58.10", "username": "admin"});
        let info = extract_target_info(&args);
        assert_eq!(info.target_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(info.target_user.as_deref(), Some("admin"));
    }

    #[test]
    fn test_extract_target_info_fqdn() {
        let args = serde_json::json!({"target": "dc01.contoso.local"});
        let info = extract_target_info(&args);
        assert_eq!(info.target_fqdn.as_deref(), Some("dc01.contoso.local"));
        assert!(info.target_ip.is_none());
    }

    #[test]
    fn test_extract_target_info_ip_in_target() {
        let args = serde_json::json!({"target": "192.168.58.10"});
        let info = extract_target_info(&args);
        assert_eq!(info.target_ip.as_deref(), Some("192.168.58.10"));
        assert!(info.target_fqdn.is_none());
    }

    #[test]
    fn test_infer_from_info_fqdn() {
        let info = ToolTargetInfo {
            target_fqdn: Some("dc01.contoso.local".to_string()),
            target_user: Some("admin".to_string()),
            ..Default::default()
        };
        assert_eq!(
            infer_target_type_from_info(&info),
            Some("domain_controller")
        );
    }

    #[test]
    fn test_infer_from_info_user_only() {
        let info = ToolTargetInfo {
            target_user: Some("svc_backup".to_string()),
            ..Default::default()
        };
        assert_eq!(infer_target_type_from_info(&info), Some("user"));
    }

    #[test]
    fn test_infer_from_info_nothing() {
        let info = ToolTargetInfo::default();
        assert_eq!(infer_target_type_from_info(&info), None);
    }
}
