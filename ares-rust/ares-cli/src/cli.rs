use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ares-cli",
    about = "Ares red team orchestration CLI",
    version,
    propagate_version = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Redis URL (default: from ARES_REDIS_URL or redis://localhost:6379)
    #[arg(long, global = true, env = "ARES_REDIS_URL")]
    pub redis_url: Option<String>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Red team operations
    #[command(subcommand)]
    Ops(OpsCommands),

    /// Blue team investigations
    #[command(subcommand)]
    Blue(BlueCommands),

    /// Historical operation queries (requires Postgres)
    #[command(subcommand)]
    History(HistoryCommands),

    /// Configuration management (single source of truth)
    #[command(subcommand)]
    Config(ConfigCommands),
}

// ============================================================================
// Red Team Operations (ops)
// ============================================================================

#[derive(Subcommand)]
pub(crate) enum OpsCommands {
    /// List all operations
    List {
        /// Only print the latest operation ID (prefer running)
        #[arg(long)]
        latest: bool,
    },

    /// Get the status of an operation
    Status {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation (prefer running)
        #[arg(long)]
        latest: bool,
    },

    /// Show runtime for an operation
    Runtime {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation (prefer running)
        #[arg(long)]
        latest: bool,
    },

    /// Dump loot (users, credentials, hosts, hashes) from operation state
    Loot {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation (prefer running)
        #[arg(long)]
        latest: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Watch mode: refresh every N seconds (0=off)
        #[arg(long, default_value = "0")]
        watch: u64,
        /// Diff mode: only print new items each refresh (implies --watch)
        #[arg(long)]
        diff: bool,
    },

    /// List tasks for an operation
    Tasks {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
        /// Filter by status (running/completed/failed/pending/all)
        #[arg(long, default_value = "running")]
        status: String,
        /// Filter by role
        #[arg(long)]
        role: Option<String>,
    },

    /// List operations and queue state from Redis
    Queue,

    /// Claim the next queued operation request from Redis
    ClaimNext {
        /// BRPOP timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
    },

    /// Generate a report for an operation
    Report {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
        /// Regenerate report from state (ignore cached)
        #[arg(long)]
        regenerate: bool,
        /// Output directory for report
        #[arg(long, default_value = "./reports")]
        output_dir: String,
    },

    /// Inject a credential into an operation's shared state
    InjectCredential {
        /// Operation ID
        operation_id: String,
        /// Username to inject
        username: String,
        /// Password for the credential
        password: String,
        /// Domain for the credential
        #[arg(long, default_value = "")]
        domain: String,
        /// Source of the credential
        #[arg(long, default_value = "manual-inject")]
        source: String,
        /// Mark credential as admin
        #[arg(long)]
        is_admin: bool,
    },

    /// Inject a vulnerability into an operation's shared state
    InjectVulnerability {
        /// Operation ID
        operation_id: String,
        /// Vulnerability type (e.g., constrained_delegation, esc1, esc4)
        vuln_type: String,
        /// Target IP address
        target_ip: String,
        /// Target hostname
        #[arg(long, default_value = "")]
        target_hostname: String,
        /// Target SPN for delegation attacks
        #[arg(long, default_value = "")]
        target_spn: String,
        /// Account name (for delegation)
        #[arg(long, default_value = "")]
        account_name: String,
        /// Domain
        #[arg(long, default_value = "")]
        domain: String,
        /// Additional details (JSON string)
        #[arg(long, default_value = "{}")]
        details: String,
    },

    /// Inject a host into an operation's shared state
    InjectHost {
        /// Operation ID
        operation_id: String,
        /// IP address
        ip: String,
        /// Hostname
        hostname: String,
    },

    /// Inject a hash into an operation's shared state
    InjectHash {
        /// Operation ID
        operation_id: String,
        /// Username (account the hash belongs to)
        username: String,
        /// Hash value (e.g., NTLM hash)
        hash_value: String,
        /// Domain
        #[arg(long, default_value = "")]
        domain: String,
        /// Hash type (NTLM, AS-REP, Kerberoast, etc.)
        #[arg(long, default_value = "NTLM")]
        hash_type: String,
        /// Source of the hash
        #[arg(long, default_value = "manual-inject")]
        source: String,
        /// AES256 key for golden tickets (Windows 2016+ rejects RC4)
        #[arg(long)]
        aes_key: Option<String>,
    },

    /// Inject a domain SID into an operation's shared state
    InjectDomainSid {
        /// Operation ID
        operation_id: String,
        /// Domain FQDN (e.g., contoso.local)
        domain: String,
        /// Domain SID (e.g., S-1-5-21-...)
        sid: String,
    },

    /// Delete an operation and all its associated data
    Delete {
        /// Operation ID
        operation_id: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Backfill domain list from discovered data
    BackfillDomains {
        /// Operation ID
        operation_id: String,
    },

    /// Export detection playbook from operation state
    ExportDetection {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
        /// Output directory for playbook files
        #[arg(long, default_value = "./reports")]
        output_dir: String,
        /// Output JSON to stdout instead of files
        #[arg(long)]
        json: bool,
        /// Skip markdown playbook generation
        #[arg(long)]
        no_markdown: bool,
    },

    /// Clean up old operation checkpoints
    Cleanup {
        /// Max age in hours
        #[arg(long, default_value = "24")]
        max_age_hours: u64,
    },

    /// Persist token usage from Redis to PostgreSQL for an operation
    OffloadCost {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
    },

    /// Run red-blue correlation analysis on report files
    Correlate {
        /// Directory containing red team and investigation report files
        #[arg(long, default_value = "./reports")]
        reports_dir: String,
        /// Time window in minutes for matching activities to detections
        #[arg(long, default_value = "30")]
        time_window: i64,
        /// Output as JSON instead of markdown
        #[arg(long)]
        json: bool,
    },

    /// Evaluate blue team detection against red team operation state
    Evaluate {
        /// Directory containing red team state JSON files
        #[arg(long)]
        states_dir: Option<String>,
        /// Single red team state JSON file
        #[arg(long)]
        state_file: Option<String>,
        /// Output directory for evaluation results
        #[arg(long, default_value = "./eval_results")]
        output_dir: String,
        /// Output as JSON instead of summary
        #[arg(long)]
        json: bool,
        /// Save results and gap analysis to output directory
        #[arg(long)]
        save: bool,
    },

    /// Submit a new red team operation to the orchestrator service
    Submit {
        /// Target name or identifier
        target: String,
        /// Target domain (e.g., contoso.local)
        domain: String,
        /// Target IP addresses (comma-separated or repeated)
        #[arg(long, value_delimiter = ',', required = true)]
        ips: Vec<String>,
        /// Operation ID (auto-generated if not provided)
        #[arg(long)]
        operation_id: Option<String>,
        /// Initial credential username
        #[arg(long)]
        username: Option<String>,
        /// Initial credential password
        #[arg(long)]
        password: Option<String>,
        /// Initial credential NTLM hash
        #[arg(long)]
        ntlm_hash: Option<String>,
        /// Resume from checkpoint
        #[arg(long)]
        resume: bool,
        /// LLM model to use (defaults to ARES_ORCHESTRATOR_MODEL or ARES_MODEL env)
        #[arg(long)]
        model: Option<String>,
        /// Maximum agent steps
        #[arg(long, default_value = "200")]
        max_steps: u32,
        /// Target environment for tracing (e.g., dev, staging, prod)
        #[arg(long)]
        env: Option<String>,
    },
}

// ============================================================================
// Blue Team Investigations (blue)
// ============================================================================

#[derive(Subcommand)]
pub(crate) enum BlueCommands {
    /// List all investigations
    List {
        /// Only print the latest investigation ID
        #[arg(long)]
        latest: bool,
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

// ============================================================================
// History Commands (history)
// ============================================================================

#[derive(Subcommand)]
pub(crate) enum HistoryCommands {
    /// List historical operations (requires Postgres)
    List {
        /// Filter by target domain
        #[arg(long)]
        domain: Option<String>,
        /// Filter by domain admin achieved
        #[arg(long)]
        has_da: Option<bool>,
        /// Operations from last N days
        #[arg(long)]
        since_days: Option<i64>,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Get detailed information about a specific operation
    Get {
        /// Operation ID
        operation_id: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Search credentials across all historical operations
    SearchCreds {
        /// Filter by domain
        #[arg(long)]
        domain: Option<String>,
        /// Filter by username (partial)
        #[arg(long)]
        username: Option<String>,
        /// Only admin accounts
        #[arg(long)]
        admin: bool,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Search hashes across all historical operations
    SearchHashes {
        /// Filter by domain
        #[arg(long)]
        domain: Option<String>,
        /// Filter by username
        #[arg(long)]
        username: Option<String>,
        /// Filter by type (ntlm, asrep, kerberoast)
        #[arg(long)]
        hash_type: Option<String>,
        /// Only cracked hashes
        #[arg(long)]
        cracked: bool,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show MITRE ATT&CK technique coverage across operations
    MitreCoverage {
        /// Operations from last N days
        #[arg(long)]
        since_days: Option<i64>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show token usage and cost across historical operations
    Cost {
        /// Filter by target domain
        #[arg(long)]
        domain: Option<String>,
        /// Operations from last N days
        #[arg(long)]
        since_days: Option<i64>,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

// ============================================================================
// Config Commands (config)
// ============================================================================

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
