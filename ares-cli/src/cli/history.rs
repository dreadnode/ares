use clap::Subcommand;

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
