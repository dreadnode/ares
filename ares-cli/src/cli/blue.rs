use clap::Subcommand;

#[cfg(feature = "blue")]
#[derive(Subcommand)]
pub(crate) enum BlueCommands {
    /// List all investigations
    List {
        /// Only print the latest investigation ID
        #[arg(long)]
        latest: bool,
        /// Filter by red team operation ID
        #[arg(long)]
        operation_id: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Get the status of an investigation
    Status {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
    },

    /// Show evidence collected during an investigation
    Evidence {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show MITRE ATT&CK techniques identified during an investigation
    Techniques {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
    },

    /// Show runtime information for an investigation
    Runtime {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
    },

    /// Show triage decision and audit trail for an investigation
    TriageStatus {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show aggregate status of all investigations from a red team operation
    OperationStatus {
        /// Red team operation ID
        operation_id: Option<String>,
        /// Use the latest red team operation
        #[arg(long)]
        latest: bool,
        /// Watch mode: refresh every N seconds (0=off)
        #[arg(long, default_value = "0")]
        watch: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Delete an investigation
    Delete {
        /// Investigation ID
        investigation_id: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Delete an operation and all its investigations
    DeleteOperation {
        /// Operation ID
        operation_id: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Clean up old investigations
    Cleanup {
        /// Max age in hours
        #[arg(long, default_value = "24")]
        max_age_hours: u64,
        /// Delete ALL investigations (ignores max-age-hours)
        #[arg(long)]
        all: bool,
        /// Show what would be deleted
        #[arg(long)]
        dry_run: bool,
        /// Skip confirmation for --all
        #[arg(long)]
        force: bool,
    },

    /// Generate a markdown report for a blue team operation or investigation
    Report {
        /// Operation ID (generates multi-investigation report)
        #[arg(long)]
        operation_id: Option<String>,
        /// Investigation ID (generates single investigation report)
        #[arg(long)]
        investigation_id: Option<String>,
        /// Use the latest operation or investigation
        #[arg(long)]
        latest: bool,
        /// Force regeneration (skip cached report)
        #[arg(long)]
        regenerate: bool,
        /// Output directory
        #[arg(long, default_value = "reports")]
        output_dir: String,
    },

    /// Submit a new blue team investigation
    Submit {
        /// Alert JSON string or path to JSON file
        alert_json: String,
        /// Investigation ID (auto-generated if not provided)
        #[arg(long)]
        investigation_id: Option<String>,
        /// LLM model to use (defaults to ARES_ORCHESTRATOR_MODEL or ARES_MODEL env)
        #[arg(long)]
        model: Option<String>,
        /// Maximum agent steps
        #[arg(long, default_value = "25")]
        max_steps: u32,
        /// Force multi-agent mode
        #[arg(long)]
        multi_agent: bool,
        /// Disable auto-routing HIGH/CRITICAL to multi-agent
        #[arg(long)]
        no_auto_route: bool,
        /// Grafana URL
        #[arg(long, env = "GRAFANA_URL")]
        grafana_url: Option<String>,
        /// Grafana API key
        #[arg(long, env = "GRAFANA_SERVICE_ACCOUNT_TOKEN")]
        grafana_api_key: Option<String>,
    },

    /// Continuously poll and submit investigations from the latest red team operation
    Watch {
        /// Seconds between polls
        #[arg(long, default_value = "30")]
        poll_interval: u64,
        /// LLM model to use
        #[arg(long)]
        model: Option<String>,
        /// Maximum agent steps per investigation
        #[arg(long, default_value = "25")]
        max_steps: u32,
        /// Grafana URL
        #[arg(long, env = "GRAFANA_URL")]
        grafana_url: Option<String>,
        /// Grafana API key
        #[arg(long, env = "GRAFANA_SERVICE_ACCOUNT_TOKEN")]
        grafana_api_key: Option<String>,
    },

    /// Submit investigations for alerts from a red team operation
    #[command(name = "from-operation")]
    FromOperation {
        /// Red team operation ID
        operation_id: Option<String>,
        /// Use the latest red team operation
        #[arg(long)]
        latest: bool,
        /// LLM model to use
        #[arg(long)]
        model: Option<String>,
        /// Maximum agent steps
        #[arg(long, default_value = "25")]
        max_steps: u32,
        /// Grafana URL
        #[arg(long, env = "GRAFANA_URL")]
        grafana_url: Option<String>,
        /// Grafana API key
        #[arg(long, env = "GRAFANA_SERVICE_ACCOUNT_TOKEN")]
        grafana_api_key: Option<String>,
    },
}
