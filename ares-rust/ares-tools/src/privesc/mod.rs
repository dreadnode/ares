//! Privilege escalation tool executors.
//!
//! Each function accepts a JSON `Value` containing the tool arguments and
//! returns a `ToolOutput` produced by running a CLI subprocess via
//! `CommandBuilder`.

mod adcs;
mod cve_exploits;
mod delegation;
mod gmsa;
mod trust;

pub use adcs::*;
pub use cve_exploits::*;
pub use delegation::*;
pub use gmsa::*;
pub use trust::*;

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_certipy_find_requires_username() {
        let args = json!({});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(certipy_find(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("username"));
    }

    #[test]
    fn test_generate_golden_ticket_requires_hash() {
        let args = json!({});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(generate_golden_ticket(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("krbtgt_hash"));
    }

    #[test]
    fn test_petitpotam_requires_listener() {
        let args = json!({});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(petitpotam_unauth(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("listener"));
    }
}
