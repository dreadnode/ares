/// Build an impacket-style authentication target string.
///
/// Format: `domain/username:password@target` or `username@target` (for hash auth).
pub fn impacket_target(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    target: &str,
) -> String {
    let user_part = match domain {
        Some(d) if !d.is_empty() => format!("{d}/{username}"),
        _ => username.to_string(),
    };
    match password {
        Some(p) => format!("{user_part}:{p}@{target}"),
        None => format!("{user_part}@{target}"),
    }
}

/// Build `-hashes` args for impacket tools using pass-the-hash.
///
/// Returns `["-hashes", ":NTHASH"]`.
pub fn hash_args(hash: &str) -> Vec<String> {
    let h = if hash.contains(':') {
        hash.to_string()
    } else {
        format!(":{hash}")
    };
    vec!["-hashes".to_string(), h]
}

/// Build netexec-style credential args: `-u user -p pass -d domain` or `-u user -H hash`.
pub fn netexec_creds(
    username: Option<&str>,
    password: Option<&str>,
    hash: Option<&str>,
    domain: Option<&str>,
) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(u) = username {
        args.extend(["-u".to_string(), u.to_string()]);
    }
    if let Some(h) = hash {
        let h = if h.contains(':') {
            h.to_string()
        } else {
            format!(":{h}")
        };
        args.extend(["-H".to_string(), h]);
    } else if let Some(p) = password {
        args.extend(["-p".to_string(), p.to_string()]);
    }
    if let Some(d) = domain {
        args.extend(["-d".to_string(), d.to_string()]);
    }
    args
}

/// Build bloodyAD-style credential prefix args: `-d domain -u user -p pass --host dc_ip`.
pub fn bloodyad_creds(domain: &str, username: &str, password: &str, dc_ip: &str) -> Vec<String> {
    vec![
        "-d".to_string(),
        domain.to_string(),
        "-u".to_string(),
        username.to_string(),
        "-p".to_string(),
        password.to_string(),
        "--host".to_string(),
        dc_ip.to_string(),
    ]
}

/// Determine auth strategy from available credentials and return
/// (target_string, extra_args) for impacket tools.
pub fn impacket_auth(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    hash: Option<&str>,
    target: &str,
) -> (String, Vec<String>) {
    if let Some(h) = hash {
        let target_str = impacket_target(domain, username, None, target);
        let extra = hash_args(h);
        (target_str, extra)
    } else {
        let target_str = impacket_target(domain, username, password, target);
        (target_str, vec![])
    }
}

/// Build KRB5CCNAME env var for Kerberos ticket-based auth.
pub fn kerberos_env(ticket_path: &str) -> (String, String) {
    ("KRB5CCNAME".to_string(), ticket_path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impacket_target_with_domain_and_password() {
        let result = impacket_target(Some("CONTOSO"), "admin", Some("P@ss"), "10.0.0.1");
        assert_eq!(result, "CONTOSO/admin:P@ss@10.0.0.1");
    }

    #[test]
    fn impacket_target_no_domain() {
        let result = impacket_target(None, "admin", Some("pass"), "dc01");
        assert_eq!(result, "admin:pass@dc01");
    }

    #[test]
    fn impacket_target_empty_domain() {
        let result = impacket_target(Some(""), "admin", Some("pass"), "dc01");
        assert_eq!(result, "admin:pass@dc01");
    }

    #[test]
    fn impacket_target_no_password() {
        let result = impacket_target(Some("CONTOSO"), "admin", None, "dc01");
        assert_eq!(result, "CONTOSO/admin@dc01");
    }

    #[test]
    fn impacket_target_no_domain_no_password() {
        let result = impacket_target(None, "user", None, "target");
        assert_eq!(result, "user@target");
    }

    #[test]
    fn hash_args_plain_nthash() {
        let args = hash_args("aabbccdd");
        assert_eq!(args, vec!["-hashes", ":aabbccdd"]);
    }

    #[test]
    fn hash_args_lm_nt_pair() {
        let args = hash_args("aad3b435:aabbccdd");
        assert_eq!(args, vec!["-hashes", "aad3b435:aabbccdd"]);
    }

    #[test]
    fn netexec_creds_password_auth() {
        let args = netexec_creds(Some("admin"), Some("P@ss"), None, Some("CONTOSO"));
        assert_eq!(args, vec!["-u", "admin", "-p", "P@ss", "-d", "CONTOSO"]);
    }

    #[test]
    fn netexec_creds_hash_auth() {
        let args = netexec_creds(
            Some("admin"),
            Some("ignored"),
            Some("aabbccdd"),
            Some("CONTOSO"),
        );
        // Hash takes priority over password
        assert_eq!(
            args,
            vec!["-u", "admin", "-H", ":aabbccdd", "-d", "CONTOSO"]
        );
    }

    #[test]
    fn netexec_creds_hash_with_colon() {
        let args = netexec_creds(Some("admin"), None, Some("lm:nt"), None);
        assert_eq!(args, vec!["-u", "admin", "-H", "lm:nt"]);
    }

    #[test]
    fn netexec_creds_no_username() {
        let args = netexec_creds(None, Some("pass"), None, None);
        assert_eq!(args, vec!["-p", "pass"]);
    }

    #[test]
    fn netexec_creds_empty() {
        let args = netexec_creds(None, None, None, None);
        assert!(args.is_empty());
    }

    #[test]
    fn bloodyad_creds_builds_correct_args() {
        let args = bloodyad_creds("contoso.local", "admin", "P@ssw0rd", "10.0.0.1");
        assert_eq!(
            args,
            vec![
                "-d",
                "contoso.local",
                "-u",
                "admin",
                "-p",
                "P@ssw0rd",
                "--host",
                "10.0.0.1",
            ]
        );
    }

    #[test]
    fn impacket_auth_with_hash() {
        let (target, extra) = impacket_auth(
            Some("CONTOSO"),
            "admin",
            Some("ignored"),
            Some("aabbccdd"),
            "dc01",
        );
        assert_eq!(target, "CONTOSO/admin@dc01");
        assert_eq!(extra, vec!["-hashes", ":aabbccdd"]);
    }

    #[test]
    fn impacket_auth_with_password() {
        let (target, extra) = impacket_auth(Some("CONTOSO"), "admin", Some("P@ss"), None, "dc01");
        assert_eq!(target, "CONTOSO/admin:P@ss@dc01");
        assert!(extra.is_empty());
    }

    #[test]
    fn impacket_auth_no_creds() {
        let (target, extra) = impacket_auth(None, "user", None, None, "host");
        assert_eq!(target, "user@host");
        assert!(extra.is_empty());
    }

    #[test]
    fn kerberos_env_builds_tuple() {
        let (key, val) = kerberos_env("/tmp/krb5cc_admin");
        assert_eq!(key, "KRB5CCNAME");
        assert_eq!(val, "/tmp/krb5cc_admin");
    }
}
