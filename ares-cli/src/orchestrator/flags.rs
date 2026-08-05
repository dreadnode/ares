//! Resolution of orchestrator behaviour flags across env, config and code.
//!
//! `ARES_ORCHESTRATOR_PLANNER` and `ARES_ORCHESTRATOR_MEDIATION` used to be
//! readable only from the environment, so `config/ares.yaml` could show
//! `agents.orchestrator.model` while the orchestrator never ran a turn. The
//! config file now supplies the default and the env var still wins at runtime.
//!
//! Config defaults are installed once at startup via [`init_config_defaults`].
//! Call sites that never initialize them (tests, one-shot CLI paths) fall back
//! to [`OrchestratorConfig::default`].

use std::sync::OnceLock;

use ares_core::config::OrchestratorConfig;

static CONFIG_DEFAULTS: OnceLock<OrchestratorConfig> = OnceLock::new();

/// Where a resolved flag value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagSource {
    Env,
    Config,
    Default,
}

impl FlagSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Config => "config",
            Self::Default => "default",
        }
    }
}

/// Install the config-supplied defaults. The first call wins.
pub(crate) fn init_config_defaults(config: OrchestratorConfig) {
    let _ = CONFIG_DEFAULTS.set(config);
}

fn config_default<T>(pick: impl Fn(&OrchestratorConfig) -> T) -> (T, FlagSource) {
    match CONFIG_DEFAULTS.get() {
        Some(config) => (pick(config), FlagSource::Config),
        None => (pick(&OrchestratorConfig::default()), FlagSource::Default),
    }
}

fn is_falsey(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "on" | "yes"
    )
}

/// Resolve the planner flag and report which layer decided it.
///
/// An unrecognized env value leaves the planner on, matching the historical
/// `!falsey` reading — only an explicit falsey value disables it.
pub(crate) fn resolve_planner_enabled() -> (bool, FlagSource) {
    match std::env::var("ARES_ORCHESTRATOR_PLANNER") {
        Ok(v) => (!is_falsey(&v), FlagSource::Env),
        Err(_) => config_default(|c| c.planner_enabled),
    }
}

/// Resolve the mediation flag and report which layer decided it.
///
/// Only an explicit truthy env value enables mediation, matching the
/// historical reading — anything else defers to config.
pub(crate) fn resolve_mediation_enabled() -> (bool, FlagSource) {
    match std::env::var("ARES_ORCHESTRATOR_MEDIATION") {
        Ok(v) => (is_truthy(&v), FlagSource::Env),
        Err(_) => config_default(|c| c.mediation_enabled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_wins_over_config_for_planner() {
        std::env::set_var("ARES_ORCHESTRATOR_PLANNER", "off");
        let (enabled, source) = resolve_planner_enabled();
        assert!(!enabled, "an explicit falsey env value must disable");
        assert_eq!(source, FlagSource::Env);
        std::env::remove_var("ARES_ORCHESTRATOR_PLANNER");
    }

    #[test]
    fn env_wins_over_config_for_mediation() {
        std::env::set_var("ARES_ORCHESTRATOR_MEDIATION", "yes");
        let (enabled, source) = resolve_mediation_enabled();
        assert!(enabled, "an explicit truthy env value must enable");
        assert_eq!(source, FlagSource::Env);
        std::env::remove_var("ARES_ORCHESTRATOR_MEDIATION");
    }

    #[test]
    fn uninitialized_defaults_match_the_compiled_fallbacks() {
        let (planner, _) = config_default(|c| c.planner_enabled);
        let (mediation, _) = config_default(|c| c.mediation_enabled);
        assert!(planner, "planner ships on so the orchestrator runs turns");
        assert!(!mediation, "mediation stays opt-in");
    }

    #[test]
    fn shipped_config_surfaces_both_flags() {
        const SHIPPED: &str = include_str!("../../../config/ares.yaml");
        let doc: serde_yaml::Value = serde_yaml::from_str(SHIPPED).unwrap();
        let section = doc
            .get("orchestrator")
            .expect("an operator reading ares.yaml must see whether the planner runs at all");
        assert!(
            section.get("planner_enabled").is_some(),
            "planner_enabled must stay in the shipped config or the orchestrator ships dark again"
        );
        assert!(
            section.get("mediation_enabled").is_some(),
            "mediation_enabled must stay in the shipped config"
        );

        let cfg: ares_core::config::AresConfig = serde_yaml::from_str(SHIPPED).unwrap();
        assert!(cfg.orchestrator.planner_enabled);
        assert!(!cfg.orchestrator.mediation_enabled);
    }

    #[test]
    fn a_config_without_the_section_still_loads() {
        const MINIMAL: &str = include_str!("../../../config/ares.yaml");
        let mut doc: serde_yaml::Value = serde_yaml::from_str(MINIMAL).unwrap();
        doc.as_mapping_mut().unwrap().remove("orchestrator");
        let cfg: ares_core::config::AresConfig = serde_yaml::from_value(doc).unwrap();
        assert!(
            cfg.orchestrator.planner_enabled,
            "a deployment on an older config file must keep the compiled-in defaults"
        );
        assert!(!cfg.orchestrator.mediation_enabled);
    }

    #[test]
    fn unrecognized_env_values_keep_the_historical_reading() {
        std::env::set_var("ARES_ORCHESTRATOR_PLANNER", "banana");
        assert!(resolve_planner_enabled().0, "only falsey disables");
        std::env::remove_var("ARES_ORCHESTRATOR_PLANNER");

        std::env::set_var("ARES_ORCHESTRATOR_MEDIATION", "banana");
        assert!(!resolve_mediation_enabled().0, "only truthy enables");
        std::env::remove_var("ARES_ORCHESTRATOR_MEDIATION");
    }
}
