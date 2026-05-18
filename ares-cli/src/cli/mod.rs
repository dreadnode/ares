use clap::{Parser, Subcommand};

pub(crate) mod config;
pub(crate) mod history;
pub(crate) mod ops;

#[cfg(feature = "blue")]
pub(crate) mod blue;

pub(crate) use config::ConfigCommands;
pub(crate) use history::HistoryCommands;
pub(crate) use ops::{OpsCommands, SessionsCommands};

#[cfg(feature = "blue")]
pub(crate) use blue::BlueCommands;

#[derive(Parser)]
#[command(
    name = "ares",
    about = "Ares red team orchestration system",
    version,
    propagate_version = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Redis URL (default: from ARES_REDIS_URL / REDIS_URL or redis://localhost:6379)
    #[arg(long, global = true, env = "ARES_REDIS_URL")]
    pub redis_url: Option<String>,

    /// Load environment variables from a file (default: auto-loads .env if present)
    #[arg(long, global = true)]
    pub env_file: Option<String>,

    /// Load secrets from an external provider (supported: 1password)
    #[arg(long, global = true)]
    pub secrets_from: Option<String>,

    /// Run command on a K8s pod via kubectl exec (value: namespace, e.g. ares-red)
    #[arg(long, global = true)]
    pub k8s: Option<String>,

    /// K8s deployment name for --k8s (default: auto-detected from subcommand)
    #[arg(long, global = true)]
    pub k8s_deploy: Option<String>,

    /// Run command on an EC2 instance via AWS SSM (value: Name tag pattern, e.g. kali-ares)
    #[arg(long, global = true)]
    pub ec2: Option<String>,

    /// AWS profile for --ec2 (default: lab)
    #[arg(long, global = true, default_value = "lab")]
    pub ec2_profile: String,

    /// AWS region for --ec2 (default: us-west-1)
    #[arg(long, global = true, default_value = "us-west-1")]
    pub ec2_region: String,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Red team operations
    #[command(subcommand)]
    Ops(OpsCommands),

    /// Blue team investigations
    #[cfg(feature = "blue")]
    #[command(subcommand)]
    Blue(BlueCommands),

    /// Historical operation queries (requires Postgres)
    #[command(subcommand)]
    History(HistoryCommands),

    /// Configuration management (single source of truth)
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Run the orchestrator (long-running service)
    Orchestrator,

    /// Run a worker (task executor)
    Worker {
        /// Legacy positional role argument (ignored; use ARES_WORKER_ROLE env var)
        #[arg(hide = true)]
        _role: Option<String>,

        /// Accept and ignore legacy `--worker-args.*` flags
        #[arg(long = "worker-args.redis-url", hide = true)]
        _legacy_redis_url: Option<String>,
    },
}
