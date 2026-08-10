use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum SessionsCommands {
    /// List operation IDs (and optionally task IDs) that have session logs
    List {
        /// Operation ID; when set, lists task IDs under that operation
        operation_id: Option<String>,
    },

    /// Print a session log file (raw JSONL or pretty-printed)
    Show {
        /// Operation ID
        operation_id: String,
        /// Task ID
        task_id: String,
        /// Pretty-print each event instead of raw JSONL
        #[arg(long)]
        pretty: bool,
    },

    /// Replay the conversation messages from a session log
    Replay {
        /// Operation ID
        operation_id: String,
        /// Task ID
        task_id: String,
        /// Output as JSON array instead of human-readable transcript
        #[arg(long)]
        json: bool,
    },
}

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

    /// Bucket discovered vs exploited vulnerabilities by type (conversion diagnostic)
    InspectVulns {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation (prefer running)
        #[arg(long)]
        latest: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
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
        /// Mark this host as a domain controller
        #[arg(long)]
        dc: bool,
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

    /// Inject a trust relationship into an operation's shared state
    InjectTrust {
        /// Operation ID
        operation_id: String,
        /// Trusted domain FQDN (e.g., fabrikam.local)
        domain: String,
        /// Trust type: parent_child, forest, external
        #[arg(long, default_value = "forest")]
        trust_type: String,
        /// Trust direction: inbound, outbound, bidirectional
        #[arg(long, default_value = "bidirectional")]
        direction: String,
        /// NetBIOS / flat name of the trusted domain
        #[arg(long, default_value = "")]
        flat_name: String,
        /// Whether SID filtering is active
        #[arg(long)]
        sid_filtering: bool,
    },

    /// Force an inter-realm ticket forge, bypassing the SID-filter check and
    /// trust_follow dedup (operator escape hatch for a stalled cross-forest pivot)
    ForceInterRealmForge {
        /// Operation ID
        operation_id: String,
        /// Source forest whose <TARGET>$ trust key forges the ticket (e.g. contoso.local)
        #[arg(long)]
        source: String,
        /// Foreign forest to forge into (e.g. fabrikam.local)
        #[arg(long)]
        target: String,
        /// NT hash of the inter-realm trust account (source\\TARGET$)
        #[arg(long)]
        trust_key: String,
        /// AES256 key of the trust account (required when the DC has RC4 disabled)
        #[arg(long)]
        aes_key: Option<String>,
        /// Source-forest domain SID embedded in the forged TGT
        #[arg(long)]
        source_sid: Option<String>,
        /// Target-forest domain SID (informational / state priming)
        #[arg(long)]
        target_sid: Option<String>,
        /// Target DC IP (primed into state so the forge can chain service tickets)
        #[arg(long)]
        target_dc_ip: Option<String>,
        /// Target DC FQDN (e.g. dc01.fabrikam.local)
        #[arg(long)]
        target_dc_fqdn: Option<String>,
    },

    /// Stop a running operation (signals graceful shutdown)
    Stop {
        /// Operation ID (omit to stop the latest running operation)
        operation_id: Option<String>,
        /// Use the latest running operation
        #[arg(long)]
        latest: bool,
    },

    /// Reverse the persistent target mutations an operation made (using its
    /// mutation journal). Distinct from `cleanup` (Redis-key GC).
    Teardown {
        /// Operation ID (omit to use the latest operation)
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
        /// Print the revert plan without touching any target
        #[arg(long)]
        dry_run: bool,
        /// Only revert mutations from this tool (e.g. `rbcd_write`)
        #[arg(long)]
        only: Option<String>,
    },

    /// Wipe cross-op attacker-side residue (potfile, ~/.nxc, ccaches) so the
    /// next op starts fresh. Same pass the orchestrator runs at op start.
    Sanitize {},

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

    /// Inspect or replay JSONL session logs from the agent loop
    Sessions {
        #[command(subcommand)]
        cmd: SessionsCommands,
    },

    /// Replay the operation state event log into a point-in-time snapshot
    Replay {
        /// Operation ID to replay
        operation_id: String,
        /// Stop applying events whose `recorded_at` exceeds this ISO-8601 timestamp
        #[arg(long)]
        until: Option<String>,
        /// Stop after this many events have been applied
        #[arg(long)]
        until_count: Option<usize>,
        /// Emit the snapshot as JSON instead of a human-readable summary
        #[arg(long)]
        json: bool,
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
        /// Auto-fetch report when operation completes; implied by --follow
        #[arg(long)]
        auto_report: bool,
        /// Output directory for auto-report
        #[arg(long, default_value = "./reports")]
        report_dir: String,
    },
}
