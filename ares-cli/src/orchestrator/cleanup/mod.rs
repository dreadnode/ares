//! Operation teardown — journal every persistent mutation an operation makes
//! against a target, then reverse it and validate the reversal.
//!
//! Pieces:
//! - [`journal`]  — the durable per-op record of mutations (Redis LIST).
//! - [`dispatcher::JournalingToolDispatcher`] — the decorator that captures
//!   mutations at the single `ToolDispatcher` choke point (LLM + deterministic).
//! - [`registry`] — maps each mutation to its inverse and a reversibility class.
//! - [`engine`]   — reads the journal (LIFO), reverses it, and reports.
//!
//! Entry points: the in-process post-op pass that orchestrator shutdown runs
//! (see [`auto_teardown_enabled`]), and the standalone
//! `ares ops teardown <op-id>` subcommand, which survives a SIGKILLed op.
//!
//! The post-op pass is what makes the journal useful in practice. Teardown
//! reads its plan from `ares:op:{id}:mutation_journal`, and `ec2:launch`
//! flushes Redis — so every mutation an operation leaves behind becomes
//! unrecoverable the moment the *next* operation starts. Reverting at
//! shutdown is the only point where the record still exists.

pub mod capture;
pub mod dispatcher;
pub mod engine;
pub mod journal;
pub mod registry;

pub use dispatcher::JournalingToolDispatcher;
pub use engine::{run_teardown, TeardownOptions};

/// Env var that disables the post-operation teardown pass.
pub const AUTO_TEARDOWN_ENV: &str = "ARES_AUTO_TEARDOWN";

/// Whether orchestrator shutdown should revert the operation's mutations.
///
/// On unless [`AUTO_TEARDOWN_ENV`] is explicitly falsy. Defaulting off would
/// preserve today's behaviour, in which the pass never runs at all and the
/// range accumulates every machine account, RBCD write, and enabled
/// `xp_cmdshell` an operation created.
pub fn auto_teardown_enabled() -> bool {
    !matches!(
        std::env::var(AUTO_TEARDOWN_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard(Option<String>);

    impl EnvGuard {
        fn set(value: Option<&str>) -> Self {
            let prev = std::env::var(AUTO_TEARDOWN_ENV).ok();
            match value {
                Some(v) => unsafe { std::env::set_var(AUTO_TEARDOWN_ENV, v) },
                None => unsafe { std::env::remove_var(AUTO_TEARDOWN_ENV) },
            }
            Self(prev)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => unsafe { std::env::set_var(AUTO_TEARDOWN_ENV, v) },
                None => unsafe { std::env::remove_var(AUTO_TEARDOWN_ENV) },
            }
        }
    }

    #[test]
    fn teardown_is_on_when_unset() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set(None);
        assert!(auto_teardown_enabled());
    }

    #[test]
    fn teardown_is_off_only_for_explicit_falsy_values() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for v in ["0", "false", "FALSE", "no", "off"] {
            let _g = EnvGuard::set(Some(v));
            assert!(!auto_teardown_enabled(), "{v} should disable teardown");
        }
        for v in ["1", "true", "yes", "on", ""] {
            let _g = EnvGuard::set(Some(v));
            assert!(auto_teardown_enabled(), "{v} should leave teardown on");
        }
    }
}
