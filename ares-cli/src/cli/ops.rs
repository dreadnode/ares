use clap::Subcommand;

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

    /// Stop a running operation (signals graceful shutdown)
    Stop {
        /// Operation ID (omit to stop the latest running operation)
        operation_id: Option<String>,
        /// Use the latest running operation
        #[arg(long)]
        latest: bool,
    },

    /// Delete an operation and all its associated data
    Delete {
        /// Operation ID
        operation_id: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Kill running operations (stop + delete). By default keeps the latest running operation.
    Kill {
        /// Kill a specific operation (instead of all running)
        operation_id: Option<String>,
        /// Kill ALL running operations (by default the latest is kept)
        #[arg(long)]
        all: bool,
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
    #[cfg(feature = "blue")]
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
    #[cfg(feature = "blue")]
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
        /// Target name or EC2 Name tag pattern (resolved to IPs with --resolve-targets)
        target: String,
        /// Target domain (e.g., contoso.local)
        domain: String,
        /// Target IP addresses (comma-separated or repeated). Optional if --resolve-targets is used.
        #[arg(long, value_delimiter = ',')]
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

        /// Resolve target name to IPs via AWS EC2 Name tag lookup
        #[arg(long)]
        resolve_targets: bool,
        /// AWS profile for target resolution (default: lab)
        #[arg(long, default_value = "lab")]
        aws_profile: String,
        /// AWS region for target resolution (default: us-west-1)
        #[arg(long, default_value = "us-west-1")]
        aws_region: String,

        /// Set this operation as the active operation in Redis (workers will prefer it)
        #[arg(long)]
        pin_active: bool,

        /// Follow operation progress after submit (poll Redis for status updates)
        #[arg(long)]
        follow: bool,
        /// Poll interval in seconds for --follow mode
        #[arg(long, default_value = "5")]
        follow_interval: u64,
        /// Auto-fetch report when operation completes (requires --follow)
        #[arg(long)]
        auto_report: bool,
        /// Output directory for auto-report
        #[arg(long, default_value = "./reports")]
        report_dir: String,
    },
}
