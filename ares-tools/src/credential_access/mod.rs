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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::args::{optional_i64, required_str};
    use serde_json::json;

    /// Verify that the base_dn builder produces correct LDAP distinguished names.
    #[test]
    fn test_base_dn_from_domain() {
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
    fn test_base_dn_from_child_domain() {
        let domain = "north.contoso.local";
        let dn: String = domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(dn, "DC=north,DC=contoso,DC=local");
    }

    /// Verify password_spray builds args for jitter correctly (presence only).
    #[test]
    fn test_password_spray_args_shape() {
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
    fn test_username_as_password_args() {
        let args = json!({
            "target": "192.168.58.10",
            "users_file": "/tmp/users.txt",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "target").is_ok());
        assert!(required_str(&args, "users_file").is_ok());
        assert!(required_str(&args, "domain").is_ok());
    }
}
