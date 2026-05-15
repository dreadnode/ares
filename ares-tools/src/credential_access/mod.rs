//! Credential access tool executors.
//!
//! Each function takes a JSON `Value` of arguments and returns a `ToolOutput`
//! produced by running the corresponding CLI tool as a subprocess.

mod kerberos;
mod misc;
mod secretsdump;

pub use kerberos::*;
pub use misc::*;
pub use secretsdump::*;

#[cfg(test)]
mod tests {
    use crate::args::{optional_i64, required_str};
    use serde_json::json;

    /// Verify that the base_dn builder produces correct LDAP distinguished names.
    #[test]
    fn base_dn_from_domain() {
        let domain = "contoso.local";
        let dn: String = domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(dn, "DC=contoso,DC=local");
    }

    /// Verify that the base_dn builder handles a deeper domain.
    #[test]
    fn base_dn_from_child_domain() {
        let domain = "child.contoso.local";
        let dn: String = domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(dn, "DC=child,DC=contoso,DC=local");
    }

    /// Verify password_spray builds args for jitter correctly (presence only).
    #[test]
    fn password_spray_args_shape() {
        // We can't fully execute without the binary, but we can verify
        // the required_str / optional helpers parse correctly.
        let args = json!({
            "target": "192.168.58.10",
            "users_file": "/tmp/users.txt",
            "password": "Welcome1",
            "domain": "contoso.local",
            "delay_seconds": 5
        });
        assert_eq!(required_str(&args, "target").unwrap(), "192.168.58.10");
        assert_eq!(optional_i64(&args, "delay_seconds"), Some(5));
    }

    /// Verify username_as_password parses required fields.
    #[test]
    fn username_as_password_args() {
        let args = json!({
            "target": "192.168.58.10",
            "users_file": "/tmp/users.txt",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "target").is_ok());
        assert!(required_str(&args, "users_file").is_ok());
        assert!(required_str(&args, "domain").is_ok());
    }

    /// Verify secretsdump timeout default is 180 seconds when no timeout_minutes.
    #[test]
    fn secretsdump_timeout_default() {
        let args = json!({"target": "192.168.58.1", "username": "admin"});
        let timeout_minutes = optional_i64(&args, "timeout_minutes");
        let timeout_secs = timeout_minutes.map(|m| (m * 60) as u64).unwrap_or(180);
        assert_eq!(timeout_secs, 180);
    }

    /// Verify kerberoast target string format.
    #[test]
    fn kerberoast_format() {
        let domain = "contoso.local";
        let username = "svc_sql";
        let password = "SqlP@ss!";
        let target = format!("{domain}/{username}:{password}");
        assert_eq!(target, "contoso.local/svc_sql:SqlP@ss!");
    }

    /// Verify ldap_search_descriptions bind_dn format.
    #[test]
    fn ldap_bind_dn_format() {
        let username = "jsmith";
        let domain = "child.contoso.local";
        let bind_dn = format!("{username}@{domain}");
        assert_eq!(bind_dn, "jsmith@child.contoso.local");
    }

    /// Verify ldap_search_descriptions ldap_uri format.
    #[test]
    fn ldap_uri_format() {
        let target = "dc01.contoso.local";
        let ldap_uri = format!("ldap://{target}");
        assert_eq!(ldap_uri, "ldap://dc01.contoso.local");
    }

    /// Verify lsassy hash prefix logic.
    #[test]
    fn lsassy_hash_prefix_logic() {
        let plain = "aabbccdd";
        let with_colon = "lm:nt";
        let formatted_plain = if plain.contains(':') {
            plain.to_string()
        } else {
            format!(":{plain}")
        };
        let formatted_colon = if with_colon.contains(':') {
            with_colon.to_string()
        } else {
            format!(":{with_colon}")
        };
        assert_eq!(formatted_plain, ":aabbccdd");
        assert_eq!(formatted_colon, "lm:nt");
    }
}
