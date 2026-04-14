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
