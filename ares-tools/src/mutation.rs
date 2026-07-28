//! Classification of how far a tool mutates the target environment.
//!
//! The orchestrator reaches the same destructive primitive from several
//! independent dispatch paths (`auto_dacl_abuse`, `auto_acl_chain_follow`, the
//! exploit queue, and a direct LLM tool call). Guarding those paths one at a
//! time has already failed once: a ForceChangePassword edge that
//! `auto_dacl_abuse` correctly refused was picked up seconds later by
//! `auto_acl_chain_follow`, which carried no such check, and a Domain
//! Administrator account was overwritten with an LLM-invented string.
//!
//! So the classification lives here, beside [`crate::dispatch`], and is
//! enforced there — the one function every path funnels through, in the same
//! pre-execution position as [`crate::credentials::validate_arguments`] and
//! [`crate::scope::validate_in_scope`]. A dispatch path written next month
//! inherits the gate without knowing it exists.

use anyhow::Result;

/// How far a tool mutates state that outlives the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationClass {
    /// Reads, authenticates, or writes only to attacker-local files.
    ReadOnly,
    /// Mutates the target directory or host, but the change can be undone
    /// from the arguments alone (delete the computer we added, clear the
    /// delegation attribute we wrote, disable the feature we enabled).
    Reversible,
    /// Mutates the target in a way no teardown can restore, because the
    /// pre-change value is not recoverable from anything we hold. Overwriting
    /// a password destroys the only copy of it.
    Irreversible,
}

/// Env var that opts an operation into irreversible mutation.
pub const ALLOW_IRREVERSIBLE_ENV: &str = "ARES_ALLOW_IRREVERSIBLE_MUTATION";

/// Tools whose effect cannot be undone from their arguments.
const IRREVERSIBLE_TOOLS: &[&str] = &["bloodyad_set_password"];

/// Tools that write to the target but whose change is recoverable.
///
/// Membership here is what makes a mutation eligible for teardown: the
/// operation's mutation journal records the call, and the reversal is derived
/// from the same arguments.
const REVERSIBLE_TOOLS: &[&str] = &[
    "add_computer",
    "addspn",
    "adminsd_holder_add_ace",
    "bloodyad_add_genericall",
    "bloodyad_add_group_member",
    "bloodyad_set_object_attr",
    "certipy_account_update",
    "certipy_ca",
    "certipy_esc4_full_chain",
    "certipy_esc7_full_chain",
    "certipy_shadow",
    "certipy_template_esc4",
    "dacl_edit",
    "dnstool",
    "krbrelayup",
    "mssql_enable_xp_cmdshell",
    "mssql_linked_enable_xpcmdshell",
    "nopac",
    "ntlmrelayx_to_adcs",
    "ntlmrelayx_to_ldaps",
    "printnightmare",
    "pygpoabuse_immediate_task",
    "pywhisker",
    "rbcd_write",
    "sharpgpoabuse",
    "targeted_kerberoast",
];

/// Classify a tool by its registered dispatch name.
///
/// Unknown names classify as [`MutationClass::ReadOnly`]: the gate must never
/// be the reason a newly added recon tool stops working. New *mutating* tools
/// are added to the lists above, and the `every_classified_tool_is_dispatchable`
/// test fails the build if a name here stops matching a real dispatch arm.
pub fn classify(tool_name: &str) -> MutationClass {
    if IRREVERSIBLE_TOOLS.contains(&tool_name) {
        MutationClass::Irreversible
    } else if REVERSIBLE_TOOLS.contains(&tool_name) {
        MutationClass::Reversible
    } else {
        MutationClass::ReadOnly
    }
}

/// True when this process is allowed to run irreversible mutations.
///
/// Off unless [`ALLOW_IRREVERSIBLE_ENV`] is set to a truthy value, so a fresh
/// or misconfigured deployment cannot destroy target accounts by default.
pub fn irreversible_allowed() -> bool {
    matches!(
        std::env::var(ALLOW_IRREVERSIBLE_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Refuse an irreversible tool unless the operation opted in.
///
/// Called by [`crate::dispatch`] before any subprocess runs.
pub fn validate_mutation_allowed(tool_name: &str) -> Result<()> {
    validate_mutation_allowed_with(tool_name, irreversible_allowed())
}

/// Policy half of [`validate_mutation_allowed`], with the opt-in passed in.
///
/// Split out so the decision is testable without mutating process-global env,
/// which races when the test harness runs cases in parallel.
pub fn validate_mutation_allowed_with(tool_name: &str, irreversible_allowed: bool) -> Result<()> {
    if classify(tool_name) == MutationClass::Irreversible && !irreversible_allowed {
        anyhow::bail!(
            "refusing to run '{tool_name}': it mutates the target irreversibly and \
             {ALLOW_IRREVERSIBLE_ENV} is not set. The pre-change value cannot be \
             restored afterwards. Authenticate with the hash or ticket already in \
             operation state instead, or set {ALLOW_IRREVERSIBLE_ENV}=1 to allow it."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the cases that must touch process-global env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard(Option<String>);

    impl EnvGuard {
        fn set(value: Option<&str>) -> Self {
            let prev = std::env::var(ALLOW_IRREVERSIBLE_ENV).ok();
            match value {
                Some(v) => unsafe { std::env::set_var(ALLOW_IRREVERSIBLE_ENV, v) },
                None => unsafe { std::env::remove_var(ALLOW_IRREVERSIBLE_ENV) },
            }
            Self(prev)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => unsafe { std::env::set_var(ALLOW_IRREVERSIBLE_ENV, v) },
                None => unsafe { std::env::remove_var(ALLOW_IRREVERSIBLE_ENV) },
            }
        }
    }

    #[test]
    fn password_reset_is_irreversible() {
        assert_eq!(
            classify("bloodyad_set_password"),
            MutationClass::Irreversible
        );
    }

    #[test]
    fn directory_writes_are_reversible() {
        for tool in ["add_computer", "rbcd_write", "pywhisker", "dacl_edit"] {
            assert_eq!(classify(tool), MutationClass::Reversible, "{tool}");
        }
    }

    #[test]
    fn recon_and_credential_access_are_read_only() {
        for tool in ["nmap_scan", "secretsdump", "run_bloodhound", "kerberoast"] {
            assert_eq!(classify(tool), MutationClass::ReadOnly, "{tool}");
        }
    }

    #[test]
    fn unknown_tools_default_to_read_only() {
        assert_eq!(
            classify("some_tool_added_next_month"),
            MutationClass::ReadOnly
        );
    }

    #[test]
    fn irreversible_is_refused_without_opt_in() {
        let err = validate_mutation_allowed_with("bloodyad_set_password", false)
            .expect_err("must refuse without opt-in");
        assert!(err.to_string().contains(ALLOW_IRREVERSIBLE_ENV), "{err}");
    }

    #[test]
    fn irreversible_is_allowed_with_opt_in() {
        assert!(validate_mutation_allowed_with("bloodyad_set_password", true).is_ok());
    }

    #[test]
    fn opt_in_accepts_common_truthy_spellings() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for v in ["1", "true", "TRUE", "yes", "on"] {
            let _g = EnvGuard::set(Some(v));
            assert!(irreversible_allowed(), "{v} should enable");
        }
        for v in ["0", "false", "no", "off", ""] {
            let _g = EnvGuard::set(Some(v));
            assert!(!irreversible_allowed(), "{v} should not enable");
        }
    }

    #[test]
    fn opt_in_is_off_when_env_is_absent() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set(None);
        assert!(!irreversible_allowed());
    }

    #[test]
    fn reversible_and_read_only_never_need_opt_in() {
        for tool in ["add_computer", "rbcd_write", "nmap_scan", "secretsdump"] {
            assert!(
                validate_mutation_allowed_with(tool, false).is_ok(),
                "{tool}"
            );
        }
    }

    #[test]
    fn classified_tools_are_disjoint() {
        for tool in IRREVERSIBLE_TOOLS {
            assert!(
                !REVERSIBLE_TOOLS.contains(tool),
                "{tool} classified twice — the stricter class would be masked"
            );
        }
    }

    #[test]
    fn every_classified_tool_is_dispatchable() {
        let dispatch_src = include_str!("lib.rs");
        for tool in IRREVERSIBLE_TOOLS.iter().chain(REVERSIBLE_TOOLS.iter()) {
            assert!(
                dispatch_src.contains(&format!("\"{tool}\" =>")),
                "{tool} is classified but has no dispatch arm — the gate would be a no-op"
            );
        }
    }
}
