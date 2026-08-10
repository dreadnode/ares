use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum BenchmarkCommands {
    /// Capture a complete benchmark snapshot from a finished operation.
    ///
    /// Exports the full Loki log state (all streams, noise included), fired
    /// Grafana alerts, red team state, and ground truth into a self-contained
    /// snapshot directory. Automatically uploads to the benchmark S3 bucket.
    Capture {
        /// Operation ID to capture (or use --latest)
        operation_id: Option<String>,

        /// Use the most recently completed operation
        #[arg(long)]
        latest: bool,

        /// Output directory for the snapshot
        #[arg(long, default_value = "benchmarks")]
        output_dir: String,

        /// Hours before attack start to include in the capture window
        #[arg(long, default_value_t = 6)]
        pre_window_hours: u32,

        /// Minutes after attack end to include in the capture window
        #[arg(long, default_value_t = 360)]
        post_window_minutes: u32,

        /// Skip automatic S3 upload after capture
        #[arg(long)]
        no_upload: bool,

        /// Attacker/operator source IP(s), comma-separated, scored as required
        /// IOCs. The attack's most blue-observable indicator, which the
        /// target-centric red state does not record — supply it here.
        #[arg(long, value_delimiter = ',')]
        attacker_ips: Vec<String>,

        /// Skip waiting for Loki to flush the attack-window logs to S3 before
        /// capturing. Waiting is the DEFAULT — Loki's ingester flushes with
        /// ~30-60 min latency, so an immediate capture silently misses the attack
        /// tail. Pass this only to capture immediately, accepting a thin snapshot.
        #[arg(long)]
        no_wait_for_flush: bool,

        /// Max minutes to wait for the Loki flush before proceeding with a warning.
        #[arg(long, default_value_t = 60)]
        flush_timeout_mins: u32,
    },

    /// Import a snapshot's Loki data into a target Loki instance.
    ///
    /// Reads the JSONL files from a snapshot directory and pushes them into
    /// the specified Loki instance. The target must be configured with
    /// `reject_old_samples: false` to accept historical timestamps.
    Load {
        /// Path to the snapshot directory
        snapshot_dir: String,

        /// Target Loki URL (e.g. http://localhost:3100)
        #[arg(long)]
        loki_url: String,

        /// Auth token for the target Loki instance
        #[arg(long)]
        loki_token: Option<String>,
    },

    /// Run a blue investigation against a pre-provisioned replay stack.
    ///
    /// The stack is stood up by `task benchmark:replay:provision OP_ID=<op>`
    /// (or the equivalent AWS-CLI orchestration); its private IP is passed
    /// as `--stack-ip`. This command submits the investigation to NATS,
    /// polls Redis for completion, and computes the score. It does NOT
    /// provision or tear down the stack — see `.taskfiles/benchmark/` for
    /// the end-to-end flow (`task benchmark:replay`).
    ///
    /// Two replay modes are supported:
    /// - `timeline` (default): a quiet period precedes the first alert,
    ///   trigger uses alert-replay (no attack_window_end), simulating an
    ///   unfolding attack. The realistic mode.
    /// - `static`: all data pre-loaded, agent knows the full attack window.
    Run {
        /// Snapshot ID (operation ID, e.g. op-20260630-222023).
        /// Downloaded from the benchmark S3 bucket.
        snapshot: String,

        /// Local snapshot directory (overrides S3 download for local testing)
        #[arg(long)]
        snapshot_dir: Option<String>,

        /// Replay mode: "timeline" (default) adds a quiet period and uses the
        /// alert-replay trigger (no end window), simulating an unfolding attack —
        /// the realistic mode. "static" loads all data upfront with the full
        /// attack window handed to the agent (convenient but less realistic).
        #[arg(long, default_value = "timeline")]
        replay_mode: String,

        /// Trigger mode: "alert-replay" uses the first captured alert,
        /// "operation" uses the full operation context (like `blue from-operation`).
        /// In timeline mode, this is always overridden to "alert-replay".
        #[arg(long, default_value = "alert-replay")]
        trigger_mode: String,

        /// Output directory for benchmark results
        #[arg(long, default_value = "benchmark-results")]
        output_dir: String,

        /// LLM model for the blue team investigation
        #[arg(long)]
        model: Option<String>,

        /// Maximum agent steps per investigation
        #[arg(long, default_value_t = 25)]
        max_steps: u32,

        /// Seconds of quiet time before first alert delivery (timeline mode).
        /// Simulates the agent being deployed to a "normal" environment.
        /// Set to 0 to skip. Default: random 60-300s.
        #[arg(long)]
        quiet_period: Option<f64>,

        /// Timeline clock advance: "step" (deterministic — the attack unfolds
        /// across the agent's step budget; default) or "wallclock" (real-time).
        /// Ignored in static mode.
        #[arg(long, default_value = "step")]
        clock: String,

        /// Private IP of an already-provisioned replay stack. Stand the stack
        /// up with `task benchmark:replay:provision OP_ID=<op>` (or invoke
        /// `task benchmark:replay` for the full provision → investigate →
        /// teardown flow).
        #[arg(long, required = true)]
        stack_ip: String,

        /// LLM sampling seed for best-effort deterministic runs. Passed to
        /// providers that honour it (OpenAI); providers that don't (Anthropic,
        /// Ollama) log a warning and continue with default sampling. When set
        /// without `--temperature`, temperature is forced to 0.0.
        #[arg(long)]
        seed: Option<u64>,
        /// LLM sampling temperature override for the blue investigation.
        /// Lower values reduce run-to-run variance; 0.0 is greedy decoding.
        /// Unset ⇒ provider default (typical: 1.0).
        #[arg(long)]
        temperature: Option<f32>,
        /// Number of independent replicates to run against the same stack.
        /// K > 1 reports mean/stddev/min/max across replicates so callers can
        /// distinguish a real score change from LLM sampling noise. The stack
        /// is NOT reprovisioned between replicates; each replicate gets its
        /// own investigation `run_id`.
        #[arg(long, default_value_t = 1)]
        replicates: u32,
    },

    /// List available benchmark snapshots from S3.
    ///
    /// Shows snapshot metadata: operation ID, target domain, date, techniques,
    /// whether domain admin was achieved, and credential count.
    List,
}
