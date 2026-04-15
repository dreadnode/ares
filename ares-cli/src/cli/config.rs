use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Pretty-print the resolved configuration
    Show {
        /// Only show model assignments per role
        #[arg(long)]
        models: bool,

        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },

    /// Validate the configuration file
    Validate {
        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },

    /// Set the model for one or all agent roles (edits the YAML in-place)
    SetModel {
        /// Agent role (e.g. orchestrator, recon). Omit when using --all.
        role: Option<String>,

        /// Model identifier (e.g. gpt-5.2, gpt-4.1)
        model: String,

        /// Set all roles to the given model
        #[arg(long)]
        all: bool,

        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },
}
