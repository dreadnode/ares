use std::io::Write;

use anyhow::Result;
use serde_json::Value;

#[allow(unused_imports)]
use crate::args::optional_bool;
use crate::args::{optional_i64, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

const DEFAULT_WORDLIST: &str = "/usr/share/wordlists/rockyou.txt";
const DEFAULT_MAX_TIME_MINUTES: i64 = 10;

/// Auto-detect hashcat mode from hash prefix.
///
/// Returns the appropriate `-m` mode number:
/// - `$krb5tgs$` prefix -> 13100 (Kerberoasting TGS-REP)
/// - `$krb5asrep$` prefix -> 18200 (AS-REP roasting)
/// - Otherwise -> 1000 (NTLM)
fn detect_hashcat_mode(hash_value: &str) -> i64 {
    if hash_value.starts_with("$krb5tgs$") {
        13100
    } else if hash_value.starts_with("$krb5asrep$") {
        18200
    } else {
        1000
    }
}

/// Crack a hash using hashcat with a wordlist attack.
///
/// Writes the hash to a temporary file and runs:
/// `hashcat -m [mode] -a 0 [hash_file] [wordlist] --maxtime [seconds] --force`
pub async fn crack_with_hashcat(args: &Value) -> Result<ToolOutput> {
    let hash_value = required_str(args, "hash_value")?;
    let wordlist = optional_str(args, "wordlist_path").unwrap_or(DEFAULT_WORDLIST);
    let max_time_minutes =
        optional_i64(args, "max_time_minutes").unwrap_or(DEFAULT_MAX_TIME_MINUTES);
    let max_time_secs = max_time_minutes * 60;

    let mode =
        optional_i64(args, "hashcat_mode").unwrap_or_else(|| detect_hashcat_mode(hash_value));

    // Write hash to a temp file that persists until command completes.
    let mut hash_file = tempfile::NamedTempFile::new()?;
    hash_file.write_all(hash_value.as_bytes())?;
    hash_file.flush()?;

    let hash_path = hash_file.path().to_string_lossy().to_string();
    let timeout_secs = (max_time_secs + 60) as u64;

    CommandBuilder::new("hashcat")
        .flag("-m", mode.to_string())
        .arg("-a")
        .arg("0")
        .arg(&hash_path)
        .arg(wordlist)
        .flag("--maxtime", max_time_secs.to_string())
        .arg("--force")
        .timeout_secs(timeout_secs)
        .execute()
        .await
}

/// Crack a hash using John the Ripper with a wordlist attack.
///
/// Writes the hash to a temporary file and runs:
/// `john [hash_file] --wordlist=[wordlist] [--format=format] --max-run-time=[seconds]`
///
/// After john finishes, runs `john --show [hash_file]` to retrieve cracked results.
pub async fn crack_with_john(args: &Value) -> Result<ToolOutput> {
    let hash_value = required_str(args, "hash_value")?;
    let hash_format = optional_str(args, "hash_format");
    let wordlist = optional_str(args, "wordlist_path").unwrap_or(DEFAULT_WORDLIST);
    let max_time_minutes =
        optional_i64(args, "max_time_minutes").unwrap_or(DEFAULT_MAX_TIME_MINUTES);
    let max_time_secs = max_time_minutes * 60;

    // Write hash to a temp file that persists until both commands complete.
    let mut hash_file = tempfile::NamedTempFile::new()?;
    hash_file.write_all(hash_value.as_bytes())?;
    hash_file.flush()?;

    let hash_path = hash_file.path().to_string_lossy().to_string();
    let timeout_secs = (max_time_secs + 60) as u64;

    let format_arg = hash_format.map(|f| format!("--format={f}"));

    // Run the cracking pass.
    let _crack_result = CommandBuilder::new("john")
        .arg(&hash_path)
        .arg(format!("--wordlist={wordlist}"))
        .arg_if(
            format_arg.is_some(),
            format_arg.as_deref().unwrap_or_default(),
        )
        .arg(format!("--max-run-time={max_time_secs}"))
        .timeout_secs(timeout_secs)
        .execute()
        .await?;

    // Run `john --show` to get the cracked results.
    CommandBuilder::new("john")
        .arg("--show")
        .arg_if(
            format_arg.is_some(),
            format_arg.as_deref().unwrap_or_default(),
        )
        .arg(&hash_path)
        .timeout_secs(30)
        .execute()
        .await
}
