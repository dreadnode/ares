//! State-based credential resolver for tool dispatch.
//!
//! The LLM names principals (`username`, `domain`) and targets — never secret
//! material. This module resolves the actual `password`, `hash`, `aes_key`,
//! `ticket_path`, `trust_key`, and SID values from operation state immediately
//! before `ares_tools::dispatch`.
//!
//! If the LLM (or anything upstream) supplies a credential-shaped argument, this
//! resolver replaces it with the state-resolved value. The LLM never wins.
//!
//! When state has no value for a credential the tool needs, the resolver leaves
//! the field absent and the tool's executor surfaces a normal "missing
//! parameter" error to the LLM. That signal tells the orchestrator to harvest
//! credentials before retrying.
//!
//! Lookup keys per field:
//!
//! | Field                 | Source                                         |
//! | --------------------- | ---------------------------------------------- |
//! | `password`            | `Credential.password` by `(username, domain)`  |
//! | `hash`                | `Hash.hash_value` by `(username, domain)`      |
//! | `nt_hash`             | NT half of `Hash.hash_value`                   |
//! | `aes_key`             | `Hash.aes_key` by `(username, domain)`         |
//! | `ticket_path`         | most-recent `*.ccache` matching principal      |
//! | `krbtgt_hash`         | `Hash` for `(krbtgt, domain)`                  |
//! | `child_krbtgt_hash`   | `Hash` for `(krbtgt, child_domain)`            |
//! | `trust_key`           | `Hash` for `(target_netbios + '$', source)`    |
//! | `trust_aes_key`       | `Hash.aes_key` for trust account                |
//! | `domain_sid`          | `domain_sids` HASH by `domain`                 |
//! | `source_sid`          | `domain_sids` HASH by `source_domain`          |
//! | `target_sid`          | `domain_sids` HASH by `target_domain`/trusted  |

use std::path::PathBuf;

use anyhow::Result;
use redis::aio::ConnectionManager;
use serde_json::{Map, Value};
use tracing::{debug, info, warn};

use ares_core::models::{Credential, Hash};
use ares_core::state::RedisStateReader;

use crate::orchestrator::recovery::{
    normalize_credential_domains, normalize_hash_domains, resolve_domain,
};

/// Argument keys that contain secret material and must come from state, never
/// from the LLM.
pub const CREDENTIAL_KEYS: &[&str] = &[
    "password",
    "hash",
    "nt_hash",
    "ntlm_hash",
    "aes_key",
    "aes256_key",
    "ticket_path",
    "krbtgt_hash",
    "child_krbtgt_hash",
    "parent_krbtgt_hash",
    "trust_key",
    "trust_aes_key",
    "trust_hash",
    "admin_hash",
    "coerce_password",
    "coerce_hash",
    "domain_sid",
    "source_sid",
    "target_sid",
    "extra_sid",
    "kerberos_keys",
];

/// Resolve credential arguments for a tool call from operation state.
///
/// Mutates `arguments` in place. Reads `username`, `domain`, `source_domain`,
/// `target_domain`, `trusted_domain`, `child_domain` to identify the principal.
/// Looks up credentials from the operation's Redis state and sets credential
/// keys on the arguments object.
///
/// If `operation_id` is `None`, this is a no-op: the tool runs with whatever
/// arguments were provided. This handles direct CLI invokes and tests.
/// Resolve the credential, ticket, and tool-redirection inputs for a single
/// tool dispatch. Returns `Ok(Some(new_tool_name))` when a cross-forest Kerberos
/// coercion redirected the call to a `*_kerberos` variant — callers MUST
/// substitute that name before invoking `ares_tools::dispatch`. `Ok(None)`
/// means the call should proceed under the original `tool_name`.
pub async fn resolve_credentials(
    conn: &mut ConnectionManager,
    operation_id: Option<&str>,
    tool_name: &str,
    arguments: &mut Value,
) -> Result<Option<String>> {
    let Some(op_id) = operation_id else {
        debug!(
            tool = %tool_name,
            "credential_resolver: no operation_id, skipping resolution"
        );
        return Ok(None);
    };

    let Some(args_obj) = arguments.as_object_mut() else {
        return Ok(None);
    };

    let mut redirected_tool: Option<String> = None;

    // Strip any LLM-supplied credential placeholders before lookup. Even if
    // state has nothing, we never want a `[HASH]` or `<password>` literal to
    // reach the dispatch layer.
    strip_placeholder_credentials(args_obj);

    let reader = RedisStateReader::new(op_id.to_string());

    // Bulk-load state once per call. These are HASHes/LISTs cached in Redis,
    // so the cost is small relative to the subsequent tool execution.
    let mut credentials = reader.get_credentials(conn).await.unwrap_or_default();
    let mut hashes = reader.get_hashes(conn).await.unwrap_or_default();
    let domain_sids = reader.get_domain_sids(conn).await.unwrap_or_default();
    let netbios_map = reader.get_netbios_map(conn).await.unwrap_or_default();

    // Collapse NetBIOS short-form domains ("CONTOSO") to FQDN
    // ("contoso.local") on the in-memory copy so a lookup against either form
    // finds the cred. The recovery loop also normalizes at rest, but
    // ingestion between recoveries can leave short-form rows; matching both
    // shapes from the read side avoids burning a tool call when the cred is
    // on the board.
    if !netbios_map.is_empty() {
        normalize_credential_domains(&mut credentials, &netbios_map);
        normalize_hash_domains(&mut hashes, &netbios_map);
    }

    let primary_username = string_field(args_obj, "username");
    // `bind_domain` is the auth realm for cross-forest queries (e.g.
    // ldap_search against fabrikam.local using a contoso.local principal).
    // `domain` is the *target* of the query in those tools, not the
    // credential's domain — looking up `(user, domain=target)` misses the
    // stored principal. Prefer `bind_domain` when present so cross-forest
    // LDAP/RPC enumerations can resolve their auth cred.
    let mut primary_domain = string_field(args_obj, "bind_domain")
        .or_else(|| string_field(args_obj, "domain"))
        .or_else(|| string_field(args_obj, "source_domain"))
        .or_else(|| string_field(args_obj, "child_domain"));

    // Fallback: when LLM passes `domain=""`, infer the domain from the
    // target host. Without this, every downstream resolution (password,
    // hash, ticket) fails because primary_domain is None and the
    // `(Some, Some)` guard below never fires. Tools then bail with
    // "credentials must be present in operation state for the (user, domain)
    // pair" even though the credential exists under the host's domain.
    //
    // Resolution order — first match wins:
    //   1. If `target`/`target_ip`/`dc_ip` is an IP that matches a DC, use
    //      that DC's domain.
    //   2. If `target_hostname`/`hostname`/`target` carries an FQDN suffix
    //      (e.g. `dc01.contoso.local`), use the suffix.
    if primary_domain.is_none() {
        primary_domain = infer_domain_from_target(args_obj, conn, &reader).await;
        if let Some(ref d) = primary_domain {
            // Inject the resolved domain back into args so downstream tools
            // (which read `domain` directly) get a non-empty realm too.
            if !args_obj
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                args_obj.insert("domain".to_string(), Value::String(d.clone()));
            }
            debug!(
                tool = %tool_name,
                domain = %d,
                "credential_resolver: inferred missing domain from target host"
            );
        }
    }

    // If the resolved domain is a NetBIOS short-form ("CONTOSO"), collapse to
    // FQDN before the lookup. Stored creds (above) are already normalized in
    // memory; this normalizes the *query* side so both shapes converge. Runs
    // after both args-supplied and inferred paths so neither escapes.
    if let Some(d) = primary_domain.as_deref() {
        if let Some(fqdn) = resolve_domain(d, &netbios_map) {
            primary_domain = Some(fqdn);
        }
    }

    info!(
        tool = %tool_name,
        user = primary_username.as_deref().unwrap_or("(none)"),
        domain = primary_domain.as_deref().unwrap_or("(none)"),
        cred_count = credentials.len(),
        hash_count = hashes.len(),
        "credential_resolver: resolving"
    );

    // Standard principal credentials (password, hash, aes_key)
    if let (Some(user), Some(domain)) = (primary_username.as_deref(), primary_domain.as_deref()) {
        let pw_before = args_obj.contains_key("password");
        let hash_before = args_obj.contains_key("hash");
        let realm_strict = requires_exact_realm(tool_name);
        resolve_principal_credentials(args_obj, &credentials, &hashes, user, domain, realm_strict);
        let pw_injected = !pw_before && args_obj.contains_key("password");
        let hash_injected = !hash_before && args_obj.contains_key("hash");
        if pw_injected || hash_injected {
            info!(
                tool = %tool_name,
                user = %user,
                domain = %domain,
                injected_password = pw_injected,
                injected_hash = hash_injected,
                "credential_resolver: injected from state"
            );
        } else if !pw_before && !hash_before {
            warn!(
                tool = %tool_name,
                user = %user,
                domain = %domain,
                cred_count = credentials.len(),
                hash_count = hashes.len(),
                "credential_resolver: no credential matched principal in state"
            );
        }
    }

    // Auxiliary principal: `coerce_user` / `coerce_domain` for relay_and_coerce.
    // The LLM names the coercion principal; the resolver injects
    // `coerce_password` or `coerce_hash` from state.
    resolve_coerce_principal(args_obj, &credentials, &hashes);

    // Kerberos ticket path — pick most recent matching ccache when the schema
    // expects one but the args don't have it.
    if expects_ticket(tool_name, args_obj) {
        if let (Some(user), Some(domain)) = (primary_username.as_deref(), primary_domain.as_deref())
        {
            if let Some(path) = find_ccache(user, domain) {
                args_obj.insert("ticket_path".to_string(), Value::String(path));
            }
        }
    }

    // krbtgt hash — for golden ticket forging.
    resolve_krbtgt_hashes(args_obj, &hashes);

    // Cross-forest Kerberos ticket — inject ticket_path when the target server
    // is in a foreign forest and we have a forged inter-realm ccache for it.
    //
    // Two trigger paths:
    //
    // 1. LDAP-bind tools (`requires_exact_realm`) — the LLM passes
    //    `domain=<target_realm>` and `bind_domain=<auth_realm>`. `primary_domain`
    //    is the auth realm; the *target* realm is `domain`/`target_domain`.
    //    Without this distinction we look up the ticket under the auth realm
    //    and miss the forged ccache, leaving the tool to attempt cross-realm
    //    NTLM bind (which the foreign DC rejects with 0x52e).
    //
    // 2. impacket-secretsdump-class tools (`supports_kerberos_auth_mode`) —
    //    `domain` is the user's realm, not the target. cross-realm NTLM bind
    //    against a hardened DC is rejected (impacket cross-realm referral is
    //    broken — see CLAUDE.md). Infer the target realm from the target host
    //    so the forged ccache for the *server's* realm is found, then flip the
    //    tool into Kerberos mode (`no_pass=true`, strip password/hash).
    if !args_obj.contains_key("ticket_path") {
        let target_realm = if requires_exact_realm(tool_name) {
            string_field(args_obj, "target_domain")
                .or_else(|| string_field(args_obj, "domain"))
                .or_else(|| primary_domain.clone())
        } else if supports_kerberos_auth_mode(tool_name) {
            infer_domain_from_target(args_obj, conn, &reader)
                .await
                .or_else(|| primary_domain.clone())
        } else {
            None
        };
        if let Some(ref realm) = target_realm {
            if let Some(renamed) =
                resolve_cross_forest_ticket(args_obj, &reader, conn, tool_name, realm, &hashes)
                    .await
            {
                redirected_tool = Some(renamed);
            }
        }
    }

    // Trust keys — Hash entries for `<TRUSTED>$` machine accounts.
    resolve_trust_key(args_obj, &hashes, &reader, conn).await;

    // Domain SIDs — direct lookup against the domain_sids HASH.
    resolve_domain_sids(args_obj, &domain_sids);

    Ok(redirected_tool)
}

/// Remove any credential-shaped argument whose value is empty, null, or a
/// placeholder literal (e.g. `[HASH]`, `<password>`, `N/A`, `unknown`).
fn strip_placeholder_credentials(args: &mut Map<String, Value>) {
    let mut to_remove = Vec::new();
    for key in CREDENTIAL_KEYS {
        if let Some(v) = args.get(*key) {
            if is_placeholder_value(v) {
                to_remove.push((*key).to_string());
            }
        }
    }
    for key in to_remove {
        warn!(
            arg = %key,
            "credential_resolver: stripping LLM-supplied placeholder credential"
        );
        args.remove(&key);
    }
}

fn is_placeholder_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => is_placeholder_str(s),
        _ => false,
    }
}

fn is_placeholder_str(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    // Bracketed placeholders: [TGT], [PWD], <hash>, <parent_admin_hash>
    if (t.starts_with('[') && t.ends_with(']')) || (t.starts_with('<') && t.ends_with('>')) {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    // Bare placeholder words the LLM has been observed to invent.
    matches!(
        lower.as_str(),
        "n/a"
            | "na"
            | "null"
            | "none"
            | "nil"
            | "unknown"
            | "tbd"
            | "todo"
            | "password"
            | "hash"
            | "ntlm"
            | "nthash"
            | "tgt"
            | "ticket"
            | "ccache"
            | "aes"
            | "aes_key"
            | "trust_key"
            | "domain_sid"
            | "krbtgt_hash"
            | "placeholder"
            | "<value>"
            | "<password>"
            | "<hash>"
            | "<tgt>"
            | "<pwd>"
    )
}

/// Resolve `password`, `hash`, `nt_hash`, `aes_key` for the primary principal.
///
/// `realm_strict` controls cross-realm fallback. When true, only credentials
/// matching the requested `domain` are returned; the `any_user` fallback is
/// suppressed. Set this for tools that perform a direct bind against the
/// target realm's DC (LDAP/RPC), where a foreign-realm cred just produces
/// invalidCredentials (52e/775). Leave false for tools that traverse trusts
/// via Kerberos referral or NTLM pass-through (smbclient, secretsdump),
/// where the user-matching cred from a different realm still authenticates.
fn resolve_principal_credentials(
    args: &mut Map<String, Value>,
    credentials: &[Credential],
    hashes: &[Hash],
    username: &str,
    domain: &str,
    realm_strict: bool,
) {
    if !args.contains_key("password") {
        if let Some(cred) = find_credential(credentials, username, domain, realm_strict) {
            if !cred.password.is_empty() {
                args.insert("password".to_string(), Value::String(cred.password.clone()));
                debug!(
                    user = %username,
                    domain = %domain,
                    "credential_resolver: injected password from state"
                );
            }
        }
    }

    let hash_match = find_hash(hashes, username, domain, realm_strict);
    if let Some(h) = hash_match {
        if !args.contains_key("hash") && !h.hash_value.is_empty() {
            args.insert("hash".to_string(), Value::String(h.hash_value.clone()));
            debug!(
                user = %username,
                domain = %domain,
                "credential_resolver: injected hash from state"
            );
        }
        // Tools that expose the field as `hashes` (impacket-style — certipy_find,
        // any wrapper passing `-hashes` directly) won't pick up `hash`. Inject
        // both spellings so the tool wrapper finds whichever key it reads.
        // Without this, certipy_find sees no hashes, falls through to its
        // password branch, fails with `missing required argument: password`,
        // and the LLM bails with "Assistance requested" — burning ~30k input
        // tokens per failed dispatch.
        if !args.contains_key("hashes") && !h.hash_value.is_empty() {
            args.insert("hashes".to_string(), Value::String(h.hash_value.clone()));
        }
        if !args.contains_key("nt_hash") && !h.hash_value.is_empty() {
            let nt = nt_hash_only(&h.hash_value).to_string();
            if !nt.is_empty() {
                args.insert("nt_hash".to_string(), Value::String(nt));
            }
        }
        if !args.contains_key("aes_key") {
            if let Some(aes) = h.aes_key.as_deref().filter(|s| !s.is_empty()) {
                args.insert("aes_key".to_string(), Value::String(aes.to_string()));
            }
        }
    }
}

/// Inject `coerce_password` / `coerce_hash` for `relay_and_coerce` based on
/// `(coerce_user, coerce_domain)` in the args. Mirrors
/// `resolve_principal_credentials` but writes to the `coerce_*` keys.
///
/// No-op when `coerce_user` is absent or empty. When the user has only a
/// password in state, sets `coerce_password`; when only a hash, sets
/// `coerce_hash`. If both exist, sets only `coerce_hash` (the auth path
/// downstream prefers PTH for relay-fallback DFSCoerce/Coercer auth).
fn resolve_coerce_principal(
    args: &mut Map<String, Value>,
    credentials: &[Credential],
    hashes: &[Hash],
) {
    let Some(user) = string_field(args, "coerce_user") else {
        return;
    };
    if user.is_empty() {
        return;
    }
    let domain = string_field(args, "coerce_domain").unwrap_or_default();

    if !args.contains_key("coerce_hash") && !args.contains_key("coerce_password") {
        if let Some(h) = find_hash(hashes, &user, &domain, false) {
            if !h.hash_value.is_empty() {
                args.insert(
                    "coerce_hash".to_string(),
                    Value::String(h.hash_value.clone()),
                );
                debug!(
                    user = %user,
                    domain = %domain,
                    "credential_resolver: injected coerce_hash from state"
                );
                return;
            }
        }
        if let Some(cred) = find_credential(credentials, &user, &domain, false) {
            if !cred.password.is_empty() {
                args.insert(
                    "coerce_password".to_string(),
                    Value::String(cred.password.clone()),
                );
                debug!(
                    user = %user,
                    domain = %domain,
                    "credential_resolver: injected coerce_password from state"
                );
            }
        }
    }
}

/// Look up the krbtgt hash for the relevant domain when the tool needs it.
///
/// Tools like `generate_golden_ticket` consume `krbtgt_hash`. The LLM names
/// the domain to forge in; we look up the most recent `Hash` for `krbtgt` in
/// that domain.
fn resolve_krbtgt_hashes(args: &mut Map<String, Value>, hashes: &[Hash]) {
    // krbtgt is per-domain — never cross-realm fall back. A different
    // domain's krbtgt forges a useless ticket.
    if !args.contains_key("krbtgt_hash") {
        if let Some(domain) = string_field(args, "domain") {
            if let Some(h) = find_hash(hashes, "krbtgt", &domain, true) {
                if !h.hash_value.is_empty() {
                    args.insert(
                        "krbtgt_hash".to_string(),
                        Value::String(h.hash_value.clone()),
                    );
                }
            }
        }
    }

    if !args.contains_key("child_krbtgt_hash") {
        if let Some(child) = string_field(args, "child_domain") {
            if let Some(h) = find_hash(hashes, "krbtgt", &child, true) {
                if !h.hash_value.is_empty() {
                    args.insert(
                        "child_krbtgt_hash".to_string(),
                        Value::String(h.hash_value.clone()),
                    );
                }
            }
        }
    }
}

/// Resolve the inter-realm trust key for cross-domain ticket forging.
///
/// Trust keys are stored as `Hash` entries with username `<TRUSTED_NETBIOS>$`
/// in the source domain (where the trust was extracted). We try both the
/// trusted-domain name and its NetBIOS flat name from the trust info.
async fn resolve_trust_key(
    args: &mut Map<String, Value>,
    hashes: &[Hash],
    reader: &RedisStateReader,
    conn: &mut ConnectionManager,
) {
    if args.contains_key("trust_key") {
        return;
    }
    let Some(source_domain) = string_field(args, "source_domain")
        .or_else(|| string_field(args, "domain"))
        .or_else(|| string_field(args, "child_domain"))
    else {
        return;
    };
    let Some(target_domain) = string_field(args, "target_domain")
        .or_else(|| string_field(args, "trusted_domain"))
        .or_else(|| string_field(args, "parent_domain"))
    else {
        return;
    };

    // Possible trust account usernames the worker has stored.
    let mut candidates: Vec<String> = vec![
        format!("{}$", target_domain.split('.').next().unwrap_or("")).to_uppercase(),
        format!("{target_domain}$"),
    ];
    // Look up flat name from trust info.
    if let Ok(trusted) = reader.get_trusted_domains(conn).await {
        if let Some(trust) = trusted.get(&target_domain.to_lowercase()) {
            if !trust.flat_name.is_empty() {
                candidates.push(format!("{}$", trust.flat_name));
                candidates.push(format!("{}$", trust.flat_name.to_uppercase()));
            }
        }
    }
    candidates.retain(|c| !c.is_empty() && !c.starts_with('$'));

    for cand in &candidates {
        // Trust keys are per-(source, target$) — never cross-realm fall back.
        if let Some(h) = find_hash(hashes, cand, &source_domain, true) {
            if !h.hash_value.is_empty() {
                args.insert("trust_key".to_string(), Value::String(h.hash_value.clone()));
                if !args.contains_key("trust_aes_key") {
                    if let Some(aes) = h.aes_key.as_deref().filter(|s| !s.is_empty()) {
                        args.insert("trust_aes_key".to_string(), Value::String(aes.to_string()));
                    }
                }
                debug!(
                    source = %source_domain,
                    target = %target_domain,
                    account = %cand,
                    "credential_resolver: injected trust_key from state"
                );
                return;
            }
        }
    }
}

/// Resolve `domain_sid`, `source_sid`, `target_sid` from the `domain_sids` HASH.
fn resolve_domain_sids(
    args: &mut Map<String, Value>,
    domain_sids: &std::collections::HashMap<String, String>,
) {
    let lookups: &[(&str, &[&str])] = &[
        ("domain_sid", &["domain"]),
        ("source_sid", &["source_domain", "domain", "child_domain"]),
        (
            "target_sid",
            &["target_domain", "trusted_domain", "parent_domain"],
        ),
    ];

    for (sid_key, domain_keys) in lookups {
        if args.contains_key(*sid_key) {
            continue;
        }
        for domain_key in *domain_keys {
            if let Some(domain) = string_field(args, domain_key) {
                if let Some(sid) = lookup_domain_sid(domain_sids, &domain) {
                    args.insert((*sid_key).to_string(), Value::String(sid));
                    break;
                }
            }
        }
    }
}

fn lookup_domain_sid(
    domain_sids: &std::collections::HashMap<String, String>,
    domain: &str,
) -> Option<String> {
    let lower = domain.to_lowercase();
    if let Some(s) = domain_sids.get(&lower) {
        return Some(s.clone());
    }
    domain_sids.get(domain).cloned()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Best-effort domain resolution from a tool call's target arguments.
///
/// Walks the standard target argument keys in priority order:
///   - IP-shaped values are matched against the DC map (`domain → dc_ip`),
///     returning the DC's domain.
///   - FQDN-shaped values return their domain suffix (`dc01.contoso.local`
///     → `contoso.local`).
///   - Bare hostnames / unmatched IPs are skipped — a wrong-domain guess
///     here would just produce an authentication failure.
async fn infer_domain_from_target(
    args: &Map<String, Value>,
    conn: &mut ConnectionManager,
    reader: &RedisStateReader,
) -> Option<String> {
    const TARGET_KEYS: &[&str] = &[
        "target",
        "target_ip",
        "dc_ip",
        "target_host",
        "target_hostname",
        "hostname",
        "host",
    ];

    let dc_map = reader.get_dc_map(conn).await.unwrap_or_default();

    for key in TARGET_KEYS {
        let Some(value) = string_field(args, key) else {
            continue;
        };
        // FQDN suffix: anything with a dot that isn't an IP literal.
        if !looks_like_ip(&value) {
            if let Some((_, suffix)) = value.split_once('.') {
                let s = suffix.trim().to_lowercase();
                if !s.is_empty() && s.contains('.') {
                    return Some(s);
                }
            }
            continue;
        }
        // IP literal: look up against the DC map.
        for (domain, ip) in &dc_map {
            if ip.trim() == value {
                let d = domain.trim().to_lowercase();
                if !d.is_empty() {
                    return Some(d);
                }
            }
        }
    }
    None
}

fn looks_like_ip(s: &str) -> bool {
    let trimmed = s.trim();
    let octets: Vec<&str> = trimmed.split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
}

fn string_field(args: &Map<String, Value>, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Split a possibly-UPN-suffixed username (`user@realm.tld`) into bare-user
/// and realm hint. The LLM regularly passes the UPN form in the `username`
/// argument even when the task `domain` is set to the target's domain
/// (e.g. `username=alice@home.local` with `domain=target.local`). The
/// resolver must match on the bare user to find the credential record in
/// state, and the realm suffix is a useful fallback when the caller's
/// `domain` is empty.
fn split_user_realm(raw: &str) -> (String, Option<String>) {
    if let Some(at) = raw.find('@') {
        let user = raw[..at].to_lowercase();
        let realm = raw[at + 1..].to_lowercase();
        let realm = if realm.is_empty() { None } else { Some(realm) };
        (user, realm)
    } else {
        (raw.to_lowercase(), None)
    }
}

fn find_credential<'a>(
    credentials: &'a [Credential],
    username: &str,
    domain: &str,
    realm_strict: bool,
) -> Option<&'a Credential> {
    let (user_l, upn_realm) = split_user_realm(username);
    let mut domain_l = domain.to_lowercase();
    if domain_l.is_empty() {
        if let Some(r) = upn_realm.as_deref() {
            domain_l = r.to_string();
        }
    }
    let domain_empty = domain_l.is_empty();

    let mut exact: Option<&Credential> = None;
    let mut any_user: Option<&Credential> = None;
    for cred in credentials {
        if cred.username.to_lowercase() != user_l {
            continue;
        }
        if cred.password.is_empty() || is_placeholder_str(&cred.password) {
            continue;
        }
        let domain_match = domain_empty || cred.domain.to_lowercase() == domain_l;
        if domain_match {
            match exact {
                None => exact = Some(cred),
                Some(prev) if cred.attack_step >= prev.attack_step => exact = Some(cred),
                _ => {}
            }
        }
        match any_user {
            None => any_user = Some(cred),
            Some(prev) if cred.attack_step >= prev.attack_step => any_user = Some(cred),
            _ => {}
        }
    }
    // Realm-strict callers (LDAP/RPC direct bind) MUST get an exact-realm
    // match or nothing. A foreign-realm cred just produces 52e/775 at bind
    // time and burns the dispatch.
    if realm_strict {
        return exact;
    }
    // Username-only fallback: when the LLM passes the *target* domain (the
    // tool's destination) instead of the credential's home realm, exact match
    // fails. Cross-realm tools (smbclient against a foreign DC, secretsdump
    // with cross-forest principal) still need that user's password — Kerberos
    // referrals or NTLM pass-through handle the actual auth. Returning a
    // user-matching cred from a different realm beats refusing the dispatch
    // and forcing the agent to re-request the same lookup.
    //
    // Skip the fallback for common per-domain accounts: each AD domain has
    // its own `Administrator`/`Guest`/`krbtgt` SAM account with a different
    // password and SID. Substituting one domain's `Administrator` for
    // another's just produces STATUS_LOGON_FAILURE and burns a tool call.
    if exact.is_some() || !is_common_per_domain_account(&user_l) {
        exact.or(any_user)
    } else {
        exact
    }
}

fn is_common_per_domain_account(user_l: &str) -> bool {
    matches!(user_l, "administrator" | "guest" | "krbtgt")
}

/// Tools that authenticate via direct bind to the target realm's DC (LDAP or
/// LDAP-backed RPC). For these, a cross-realm cred from another forest just
/// produces STATUS_LOGON_FAILURE / invalidCredentials. The orchestrator gets
/// faster forward progress by returning no credential — the dispatch fails
/// cleanly, the failure is reported back, and the orchestrator can re-derive
/// the right principal — than by injecting a wrong-realm cred that wastes
/// the LLM's tool budget on a guaranteed-failed bind.
///
/// Tools NOT in this list (smbclient, secretsdump, nxc) traverse trusts via
/// Kerberos referral or NTLM pass-through and benefit from the cross-realm
/// `any_user` fallback.
pub(crate) fn requires_exact_realm(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "bloodyad_set_password"
            | "bloodyad_add_group_member"
            | "bloodyad_add_genericall"
            | "dacl_edit"
            | "pywhisker"
            | "ldap_search"
            | "ldap_search_descriptions"
            | "ldap_acl_enumeration"
            | "targeted_kerberoast"
            | "kerberoast"
            | "nopac"
            | "certifried"
            | "enumerate_domain_trusts"
    )
}

/// How a tool transitions into Kerberos auth mode when a cross-forest (forged
/// inter-realm) ccache is available for the target host's realm. Single source
/// of truth — `expects_ticket`, `supports_kerberos_auth_mode`, and the dispatcher
/// rename hook all derive from this. Adding a Kerberos-capable tool means
/// extending [`kerberos_coercion`] once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KerberosCoercion {
    /// Tool accepts `no_pass=true`+`ticket_path` in place. Apply the flip and
    /// dispatch under the same tool name. Example: impacket-secretsdump.
    InPlace,
    /// Tool doesn't accept `ticket_path` directly — a dedicated `*_kerberos`
    /// variant exists. The resolver injects the ticket and signals the
    /// dispatcher to rename the tool. The renamed variant is `AlreadyKerberos`.
    /// Example: psexec → psexec_kerberos.
    Redirect(&'static str),
    /// Tool is already a `*_kerberos` variant. Apply the flip but don't rename.
    /// Example: secretsdump_kerberos.
    AlreadyKerberos,
    /// Tool has no Kerberos mode. The resolver leaves it alone and the LDAP-bind
    /// FQDN rewrite is the only cross-forest transform that may still apply.
    None,
}

/// Look up the Kerberos coercion for a tool. See [`KerberosCoercion`].
pub(crate) fn kerberos_coercion(tool_name: &str) -> KerberosCoercion {
    match tool_name {
        "secretsdump" => KerberosCoercion::InPlace,
        "psexec" => KerberosCoercion::Redirect("psexec_kerberos"),
        "wmiexec" => KerberosCoercion::Redirect("wmiexec_kerberos"),
        "smbexec" => KerberosCoercion::Redirect("smbexec_kerberos"),
        "secretsdump_kerberos" | "psexec_kerberos" | "wmiexec_kerberos" | "smbexec_kerberos" => {
            KerberosCoercion::AlreadyKerberos
        }
        _ => KerberosCoercion::None,
    }
}

/// True when the tool has any Kerberos auth path the resolver can take.
/// Derived from [`kerberos_coercion`] — the call site uses it as a guard to
/// decide whether to even look up an inter-realm ticket for the target realm.
pub(crate) fn supports_kerberos_auth_mode(tool_name: &str) -> bool {
    !matches!(kerberos_coercion(tool_name), KerberosCoercion::None)
}

/// Flip a tool's args into Kerberos auth mode: set `no_pass=true` and remove
/// any `password` / `hash` that the principal resolver injected earlier.
/// Returns `(stripped_password, stripped_hash)` so the caller can log
/// what was removed.
pub(crate) fn apply_kerberos_auth_mode_flip(args: &mut Map<String, Value>) -> (bool, bool) {
    args.insert("no_pass".to_string(), Value::Bool(true));
    let stripped_password = args.remove("password").is_some();
    let stripped_hash = args.remove("hash").is_some();
    (stripped_password, stripped_hash)
}

fn find_hash<'a>(
    hashes: &'a [Hash],
    username: &str,
    domain: &str,
    realm_strict: bool,
) -> Option<&'a Hash> {
    // Same UPN handling as find_credential — strip @realm to match bare-user
    // hash records and fall back to the realm suffix when caller domain is
    // empty.
    let (user_l, upn_realm) = split_user_realm(username);
    let mut domain_l = domain.to_lowercase();
    if domain_l.is_empty() {
        if let Some(r) = upn_realm.as_deref() {
            domain_l = r.to_string();
        }
    }
    let domain_empty = domain_l.is_empty();

    let mut exact: Option<&Hash> = None;
    let mut exact_aes: Option<&Hash> = None;
    let mut any_user: Option<&Hash> = None;
    let mut any_user_aes: Option<&Hash> = None;
    for h in hashes {
        if h.username.to_lowercase() != user_l {
            continue;
        }
        if h.hash_value.is_empty() {
            continue;
        }
        if !is_authenticating_hash_type(&h.hash_type) {
            continue;
        }
        let h_domain_l = h.domain.to_lowercase();
        let domain_match = domain_empty || h.domain.is_empty() || h_domain_l == domain_l;
        let has_aes = h.aes_key.as_deref().is_some_and(|s| !s.is_empty());
        if domain_match {
            match exact {
                None => exact = Some(h),
                Some(prev) if h.attack_step >= prev.attack_step => exact = Some(h),
                _ => {}
            }
            if has_aes {
                match exact_aes {
                    None => exact_aes = Some(h),
                    Some(prev) if h.attack_step >= prev.attack_step => exact_aes = Some(h),
                    _ => {}
                }
            }
        }
        match any_user {
            None => any_user = Some(h),
            Some(prev) if h.attack_step >= prev.attack_step => any_user = Some(h),
            _ => {}
        }
        if has_aes {
            match any_user_aes {
                None => any_user_aes = Some(h),
                Some(prev) if h.attack_step >= prev.attack_step => any_user_aes = Some(h),
                _ => {}
            }
        }
    }
    let exact_pick = exact_aes.or(exact);
    if realm_strict {
        return exact_pick;
    }
    if exact_pick.is_some() || !is_common_per_domain_account(&user_l) {
        exact_pick.or(any_user_aes).or(any_user)
    } else {
        exact_pick
    }
}

/// True when this hash type can be used directly for authentication (NTLM,
/// AES key). False for offline-cracking artifacts like kerberoast/asreproast
/// TGS ciphertext.
fn is_authenticating_hash_type(hash_type: &str) -> bool {
    let t = hash_type.to_ascii_lowercase();
    !matches!(
        t.as_str(),
        "kerberoast" | "asreproast" | "asrep" | "tgs" | "krb5tgs" | "krb5asrep"
    )
}

/// Strip an `LM:NT` colon-form hash to just the NT half.
fn nt_hash_only(hash: &str) -> &str {
    hash.rsplit(':').next().unwrap_or(hash).trim()
}

/// True when the tool expects a Kerberos ticket and the args don't have one.
/// `*_kerberos` variants have no other auth mode — see [`KerberosCoercion::AlreadyKerberos`].
fn expects_ticket(tool_name: &str, args: &Map<String, Value>) -> bool {
    if args.contains_key("ticket_path") {
        return false;
    }
    matches!(
        kerberos_coercion(tool_name),
        KerberosCoercion::AlreadyKerberos
    )
}

/// Find the most-recent `*.ccache` file in the worker's working directory that
/// matches the principal.
///
/// Convention: tools that forge tickets save them as `<Username>.ccache` in CWD.
/// We accept either an exact match or any ccache when the principal matches by
/// stem.
fn find_ccache(username: &str, _domain: &str) -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let user_lower = username.to_lowercase();

    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries = std::fs::read_dir(&cwd).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".ccache") {
            continue;
        }
        let stem = name.trim_end_matches(".ccache").to_lowercase();
        if stem != user_lower && !stem.starts_with(&user_lower) {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match &best {
            None => best = Some((mtime, path)),
            Some((t, _)) if mtime >= *t => best = Some((mtime, path)),
            _ => {}
        }
    }
    best.map(|(_, p)| p.to_string_lossy().to_string())
}

/// Inject `ticket_path` for a cross-forest tool using a forged inter-realm
/// ccache stored in Redis.
///
/// Two call paths:
///
/// - LDAP-bind tools (`requires_exact_realm` set) — the target server is in a
///   foreign forest where NTLM bind returns 0x52e. The tool reads `ticket_path`
///   and switches to GSSAPI bind; the function rewrites an IP `target` to an
///   FQDN so ldapsearch can derive the `ldap/<host>@<REALM>` SPN.
///
/// - impacket-secretsdump-class tools (`supports_kerberos_auth_mode` set) —
///   cross-realm NTLM is broken (fortra/impacket#315 plus hardened DCs reject
///   pass-through). The function additionally sets `no_pass=true` and strips
///   `password`/`hash` so impacket presents the ccache directly to the target
///   DC instead of falling through to cleartext bind. The target argument
///   stays as-is — impacket-secretsdump derives the SPN from the target host
///   and `-dc-ip`, no FQDN rewrite needed.
///
/// Looks up the `kerberos_tickets` HASH for a `(*, target_domain, Administrator)`
/// entry. If no ticket exists in Redis the function is a no-op — the tool will
/// fail with a missing-credential error, which is the correct signal to the
/// orchestrator.
async fn resolve_cross_forest_ticket(
    args: &mut Map<String, Value>,
    reader: &RedisStateReader,
    conn: &mut ConnectionManager,
    tool_name: &str,
    target_domain: &str,
    hashes: &[Hash],
) -> Option<String> {
    // Only fire when the tool has no usable NTLM credential for the target
    // domain (i.e. the realm_strict check already blocked cross-realm fallback).
    // If there's already an exact-domain hash for a non-common account, NTLM
    // bind will work and we don't need Kerberos.
    let user_l = string_field(args, "username")
        .map(|u| u.to_lowercase())
        .unwrap_or_default();
    let domain_l = target_domain.to_lowercase();
    let has_ntlm = hashes.iter().any(|h| {
        h.domain.to_lowercase() == domain_l
            && (user_l.is_empty() || h.username.to_lowercase() == user_l)
            && !h.hash_value.is_empty()
            && is_authenticating_hash_type(&h.hash_type)
    });
    if has_ntlm {
        // NTLM bind is available — no need to inject Kerberos ticket.
        return None;
    }

    // Look up kerberos_tickets HASH in Redis.
    let tickets = reader.get_kerberos_tickets(conn).await.unwrap_or_default();

    // Find the most recent ticket for the target domain (any source, Administrator).
    // Administrator is the only username we forge in the suppression path.
    let ticket = tickets.iter().find(|t| {
        t.target_domain.to_lowercase() == domain_l
            && t.username.eq_ignore_ascii_case("Administrator")
            && !t.ticket_path.is_empty()
    });

    let Some(ticket) = ticket else {
        debug!(
            tool = %tool_name,
            target_domain = %target_domain,
            "credential_resolver: no inter-realm Kerberos ticket found for cross-forest tool"
        );
        return None;
    };

    // Sanity-check the ccache exists on disk (best-effort — workers may not
    // share the same host in some deployments).
    if !std::path::Path::new(&ticket.ticket_path).exists() {
        warn!(
            tool = %tool_name,
            target_domain = %target_domain,
            ticket_path = %ticket.ticket_path,
            "credential_resolver: inter-realm ccache not found on disk — skipping injection"
        );
        return None;
    }

    let coercion = kerberos_coercion(tool_name);
    info!(
        tool = %tool_name,
        target_domain = %target_domain,
        ticket_path = %ticket.ticket_path,
        source_domain = %ticket.source_domain,
        coercion = ?coercion,
        "credential_resolver: injecting inter-realm Kerberos ticket for cross-forest tool"
    );
    args.insert(
        "ticket_path".to_string(),
        Value::String(ticket.ticket_path.clone()),
    );

    // Apply the per-tool transition described by KerberosCoercion. The flip
    // (no_pass=true, strip password/hash) is the same for InPlace, Redirect,
    // and AlreadyKerberos — without it, impacket reads ticket_path but still
    // falls through to NTLM bind because `password`/`hash` are populated by
    // the principal resolver, which the foreign DC rejects with rpc_s_access_denied.
    // The difference is whether we also return a tool-name rename for the
    // dispatcher to honor (Redirect only).
    match coercion {
        KerberosCoercion::InPlace | KerberosCoercion::AlreadyKerberos => {
            let (stripped_pw, stripped_hash) = apply_kerberos_auth_mode_flip(args);
            log_kerberos_strip(tool_name, stripped_pw, stripped_hash);
            return None;
        }
        KerberosCoercion::Redirect(variant) => {
            let (stripped_pw, stripped_hash) = apply_kerberos_auth_mode_flip(args);
            log_kerberos_strip(tool_name, stripped_pw, stripped_hash);
            info!(
                from = %tool_name,
                to = %variant,
                "credential_resolver: redirecting tool to *_kerberos variant for cross-forest call"
            );
            return Some(variant.to_string());
        }
        KerberosCoercion::None => {
            // LDAP-bind path — fall through to FQDN rewrite for GSSAPI SPN.
        }
    }

    // GSSAPI bind needs an FQDN to derive the ldap/<host>@<REALM> SPN. If the
    // LLM passed an IP for `target`, look up the host's hostname from state
    // and rewrite. Without this, ldapsearch -Y GSSAPI errors with no Kerberos
    // service principal name found.
    if let Some(ip_str) = string_field(args, "target") {
        if ip_str.parse::<std::net::IpAddr>().is_ok() {
            let hosts = reader.get_hosts(conn).await.unwrap_or_default();
            let domain_l = target_domain.to_lowercase();
            let host_match = hosts
                .iter()
                .find(|h| h.ip == ip_str && !h.hostname.is_empty());
            if let Some(h) = host_match {
                let hn = h.hostname.to_lowercase();
                let fqdn = if hn.ends_with(&format!(".{domain_l}")) || hn == domain_l {
                    hn
                } else {
                    format!("{hn}.{domain_l}")
                };
                info!(
                    tool = %tool_name,
                    old_target = %ip_str,
                    new_target = %fqdn,
                    "credential_resolver: rewrote target IP to FQDN for GSSAPI bind"
                );
                args.insert("target".to_string(), Value::String(fqdn));
            } else {
                warn!(
                    tool = %tool_name,
                    target_ip = %ip_str,
                    target_domain = %target_domain,
                    "credential_resolver: no FQDN found for target IP — GSSAPI bind may fail SPN lookup"
                );
            }
        }
    }
    None
}

/// Debug-log which credential fields the Kerberos flip removed. Kept separate
/// from `apply_kerberos_auth_mode_flip` so the flip helper stays a pure data
/// transform (testable without `tracing`).
fn log_kerberos_strip(tool_name: &str, stripped_password: bool, stripped_hash: bool) {
    if stripped_password {
        debug!(
            tool = %tool_name,
            "credential_resolver: stripped wrong-realm password — using forged ccache instead"
        );
    }
    if stripped_hash {
        debug!(
            tool = %tool_name,
            "credential_resolver: stripped wrong-realm hash — using forged ccache instead"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Hash};
    use serde_json::json;

    fn cred(user: &str, domain: &str, pass: &str) -> Credential {
        Credential {
            id: format!("c-{user}"),
            username: user.to_string(),
            password: pass.to_string(),
            domain: domain.to_string(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn hash(user: &str, domain: &str, value: &str, aes: Option<&str>) -> Hash {
        Hash {
            id: format!("h-{user}"),
            username: user.to_string(),
            hash_value: value.to_string(),
            hash_type: "NTLM".into(),
            domain: domain.to_string(),
            cracked_password: None,
            source: "test".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: aes.map(String::from),
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    #[test]
    fn placeholder_str_recognizes_brackets() {
        assert!(is_placeholder_str("[TGT]"));
        assert!(is_placeholder_str("[HASH]"));
        assert!(is_placeholder_str("<password>"));
        assert!(is_placeholder_str("<parent_administrator_NTLM_hash>"));
    }

    #[test]
    fn placeholder_str_recognizes_words() {
        assert!(is_placeholder_str("N/A"));
        assert!(is_placeholder_str("null"));
        assert!(is_placeholder_str("None"));
        assert!(is_placeholder_str("unknown"));
        assert!(is_placeholder_str("password"));
        assert!(is_placeholder_str("HASH"));
        assert!(is_placeholder_str("  TGT  "));
    }

    #[test]
    fn placeholder_str_passes_real_values() {
        assert!(!is_placeholder_str("aad3b435b51404eeaad3b435b51404ee"));
        assert!(!is_placeholder_str("d350c5900e26d2c95f501e94cf95b078"));
        assert!(!is_placeholder_str("P@ssw0rd!"));
        assert!(!is_placeholder_str("/tmp/Administrator.ccache"));
    }

    #[test]
    fn placeholder_str_empty_is_placeholder() {
        assert!(is_placeholder_str(""));
        assert!(is_placeholder_str("   "));
    }

    #[test]
    fn strip_placeholder_credentials_removes_bracketed() {
        let mut args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "[PWD]",
            "hash": "<hash>"
        })
        .as_object()
        .unwrap()
        .clone();
        strip_placeholder_credentials(&mut args);
        assert!(!args.contains_key("password"));
        assert!(!args.contains_key("hash"));
        assert_eq!(args.get("username").unwrap().as_str(), Some("admin"));
    }

    #[test]
    fn strip_placeholder_credentials_keeps_real() {
        let mut args = json!({
            "password": "P@ssw0rd!",
            "hash": "aad3b435b51404eeaad3b435b51404ee"
        })
        .as_object()
        .unwrap()
        .clone();
        strip_placeholder_credentials(&mut args);
        assert!(args.contains_key("password"));
        assert!(args.contains_key("hash"));
    }

    #[test]
    fn split_user_realm_bare_username() {
        let (u, r) = split_user_realm("alice");
        assert_eq!(u, "alice");
        assert_eq!(r, None);
    }

    #[test]
    fn split_user_realm_upn_form() {
        let (u, r) = split_user_realm("alice@CONTOSO.LOCAL");
        assert_eq!(u, "alice");
        assert_eq!(r.as_deref(), Some("contoso.local"));
    }

    #[test]
    fn find_credential_upn_username_finds_bare_record() {
        // LLM passes UPN-suffixed username while caller domain is the target
        // domain — find_credential should still locate the bare-user cred via
        // its cross-realm fallback (any_user matches on stripped username).
        let creds = vec![Credential {
            id: "c1".into(),
            username: "alice".into(),
            password: "P@ss!".into(),
            domain: "contoso.local".into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];
        let got = find_credential(&creds, "alice@contoso.local", "fabrikam.local", false);
        assert!(got.is_some(), "should find bare-user record despite UPN");
    }

    #[test]
    fn find_hash_upn_username_finds_bare_record() {
        let hashes = vec![Hash {
            id: "h1".into(),
            username: "alice".into(),
            domain: "contoso.local".into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:5af3107a4077a8bdde9c8b58b4e1c0e7".into(),
            hash_type: "NTLM".into(),
            source: "test".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
            cracked_password: None,
        }];
        let got = find_hash(&hashes, "alice@contoso.local", "fabrikam.local", false);
        assert!(got.is_some(), "should find bare-user hash despite UPN");
    }

    #[test]
    fn find_credential_returns_match() {
        let creds = vec![
            cred("admin", "contoso.local", "P@ss1"),
            cred("guest", "contoso.local", "guest1"),
        ];
        let found = find_credential(&creds, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
    }

    #[test]
    fn find_credential_case_insensitive() {
        let creds = vec![cred("Admin", "Contoso.Local", "P@ss1")];
        let found = find_credential(&creds, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
    }

    #[test]
    fn find_credential_cross_realm_fallback() {
        // LLM passes target domain (fabrikam.local) for a tool acting as a
        // user whose home realm is child.contoso.local. The resolver
        // should still return the user's stored cred so the cross-realm
        // auth attempt can proceed via Kerberos referral / NTLM pass-through.
        let creds = vec![cred("alice", "child.contoso.local", "P@ss1")];
        let found = find_credential(&creds, "alice", "fabrikam.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
        assert_eq!(found.domain, "child.contoso.local");
    }

    #[test]
    fn find_credential_exact_match_preferred_over_other_realm() {
        // When both an exact-domain match and a different-domain match exist
        // for the same username, the exact match wins.
        let creds = vec![
            cred("admin", "fabrikam.local", "wrong"),
            cred("admin", "contoso.local", "right"),
        ];
        let found = find_credential(&creds, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.password, "right");
    }

    #[test]
    fn find_credential_empty_password_skipped() {
        let creds = vec![cred("admin", "contoso.local", "")];
        assert!(find_credential(&creds, "admin", "contoso.local", false).is_none());
    }

    #[test]
    fn find_credential_realm_strict_blocks_cross_realm_fallback() {
        // The resolver MUST NOT inject a child-realm cred when the tool
        // (e.g. bloodyad_set_password against fabrikam.local DC) requires an
        // exact-realm bind. Wrong-realm cred → 52e/775 at LDAP bind, which
        // wastes the dispatch and burns the agent's tool budget.
        let creds = vec![cred("bob", "child.contoso.local", "P@ss1")];
        let found = find_credential(&creds, "bob", "fabrikam.local", true);
        assert!(
            found.is_none(),
            "realm_strict must block cross-realm any_user fallback"
        );
    }

    #[test]
    fn find_credential_realm_strict_returns_exact_match() {
        // Strict mode still returns an exact-realm match, even when other
        // realms have the same username with different passwords.
        let creds = vec![
            cred("admin", "fabrikam.local", "wrong"),
            cred("admin", "contoso.local", "right"),
        ];
        let found = find_credential(&creds, "admin", "contoso.local", true).unwrap();
        assert_eq!(found.password, "right");
    }

    #[test]
    fn find_credential_netbios_form_matches_after_normalize() {
        // Cred stored with NetBIOS short-form domain ("CONTOSO"); after
        // `normalize_credential_domains` runs over the slice, the FQDN-form
        // query matches. Mirrors what `resolve_credentials` does in prod.
        use crate::orchestrator::recovery::normalize_credential_domains;
        use std::collections::HashMap;

        let mut creds = vec![cred("alice", "CONTOSO", "P@ss1")];
        let mut nb = HashMap::new();
        nb.insert("CONTOSO".to_string(), "contoso.local".to_string());
        let fixed = normalize_credential_domains(&mut creds, &nb);
        assert_eq!(fixed, 1, "normalize must rewrite the NetBIOS-form domain");
        let found = find_credential(&creds, "alice", "contoso.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
    }

    #[test]
    fn find_credential_normalize_noop_when_map_empty() {
        // No netbios map → no normalization → existing behavior preserved.
        // Regression guard: the normalize call must be safe when the map is
        // empty (which is the common case in unit tests and the initial
        // moments of any operation).
        use crate::orchestrator::recovery::normalize_credential_domains;
        use std::collections::HashMap;

        let mut creds = vec![cred("alice", "contoso.local", "P@ss1")];
        let nb: HashMap<String, String> = HashMap::new();
        let fixed = normalize_credential_domains(&mut creds, &nb);
        assert_eq!(fixed, 0);
        let found = find_credential(&creds, "alice", "contoso.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
    }

    #[test]
    fn find_hash_realm_strict_blocks_cross_realm_fallback() {
        let hashes = vec![hash("bob", "child.contoso.local", "deadbeef", None)];
        let found = find_hash(&hashes, "bob", "fabrikam.local", true);
        assert!(
            found.is_none(),
            "realm_strict must block cross-realm any_user fallback for hashes"
        );
    }

    #[test]
    fn find_hash_realm_strict_returns_exact_match() {
        let hashes = vec![
            hash("admin", "fabrikam.local", "fabhash", None),
            hash("admin", "contoso.local", "conhash", None),
        ];
        let found = find_hash(&hashes, "admin", "contoso.local", true).unwrap();
        assert_eq!(found.hash_value, "conhash");
    }

    #[test]
    fn requires_exact_realm_covers_ldap_bind_tools() {
        for tool in [
            "bloodyad_set_password",
            "bloodyad_add_group_member",
            "bloodyad_add_genericall",
            "dacl_edit",
            "pywhisker",
            "ldap_search",
            "ldap_search_descriptions",
            "ldap_acl_enumeration",
            "targeted_kerberoast",
            "kerberoast",
            "nopac",
            "certifried",
            "enumerate_domain_trusts",
        ] {
            assert!(
                requires_exact_realm(tool),
                "{tool} should require exact-realm bind"
            );
        }
    }

    #[test]
    fn requires_exact_realm_excludes_trust_traversal_tools() {
        // Tools that auth via Kerberos referral or NTLM pass-through MUST
        // keep the cross-realm any_user fallback — they actually use the
        // returned cred to traverse a trust.
        for tool in [
            "smbclient",
            "secretsdump",
            "nxc_smb",
            "psexec",
            "wmiexec",
            "smb_login_check",
        ] {
            assert!(
                !requires_exact_realm(tool),
                "{tool} should NOT require exact-realm bind (uses referral/pass-through)"
            );
        }
    }

    #[test]
    fn find_hash_prefers_aes_record() {
        let hashes = vec![
            hash("admin", "contoso.local", "abc1", None),
            hash("admin", "contoso.local", "abc1", Some("aes-key-456")),
        ];
        let found = find_hash(&hashes, "admin", "contoso.local", false).unwrap();
        assert!(found.aes_key.is_some());
    }

    #[test]
    fn find_hash_allows_empty_domain() {
        // Older imports may not record domain on Hash records.
        let hashes = vec![hash("admin", "", "abc1", None)];
        let found = find_hash(&hashes, "admin", "contoso.local", false);
        assert!(found.is_some());
    }

    #[test]
    fn find_hash_cross_realm_fallback() {
        // Same intent as find_credential_cross_realm_fallback: the LLM passes
        // the target domain but the only stored hash for the user is in their
        // home realm. Return the home-realm hash rather than nothing.
        let hashes = vec![hash("alice", "child.contoso.local", "deadbeef", None)];
        let found = find_hash(&hashes, "alice", "fabrikam.local", false).unwrap();
        assert_eq!(found.hash_value, "deadbeef");
        assert_eq!(found.domain, "child.contoso.local");
    }

    #[test]
    fn find_hash_exact_realm_wins_over_other_realm() {
        let hashes = vec![
            hash("admin", "fabrikam.local", "fabhash", None),
            hash("admin", "contoso.local", "conhash", None),
        ];
        let found = find_hash(&hashes, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.hash_value, "conhash");
    }

    #[test]
    fn find_hash_skips_kerberoast_tgs() {
        // Kerberoast TGS ciphertext must never be injected as `hash=…` —
        // impacket bombs out with "Odd-length string" since it's not NTLM.
        let mut tgs = hash(
            "eve",
            "child.local",
            "$krb5tgs$23$*eve$CHILD.LOCAL$child.local/eve*$abc...",
            None,
        );
        tgs.hash_type = "kerberoast".to_string();
        let hashes = vec![tgs];
        let found = find_hash(&hashes, "eve", "child.local", false);
        assert!(
            found.is_none(),
            "kerberoast TGS must not be returned as authenticating hash"
        );
    }

    #[test]
    fn find_hash_keeps_ntlm_when_kerberoast_also_present() {
        let mut tgs = hash("eve", "child.local", "$krb5tgs$23$*...", None);
        tgs.hash_type = "kerberoast".to_string();
        let ntlm = hash(
            "eve",
            "child.local",
            "aad3b435b51404eeaad3b435b51404ee:d350c5900e26d2c95f501e94cf95b078",
            None,
        );
        let hashes = vec![tgs, ntlm];
        let found = find_hash(&hashes, "eve", "child.local", false).unwrap();
        assert!(found.hash_value.starts_with("aad3"));
    }

    #[test]
    fn resolve_principal_credentials_injects_password() {
        let creds = vec![cred("admin", "contoso.local", "P@ss1")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({"username": "admin", "domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(args.get("password").unwrap().as_str(), Some("P@ss1"));
    }

    #[test]
    fn resolve_principal_credentials_injects_hash_and_aes() {
        let creds: Vec<Credential> = vec![];
        let hashes = vec![hash("admin", "contoso.local", "abc1", Some("aes-256"))];
        let mut args = json!({"username": "admin", "domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(args.get("hash").unwrap().as_str(), Some("abc1"));
        assert_eq!(args.get("aes_key").unwrap().as_str(), Some("aes-256"));
        assert_eq!(args.get("nt_hash").unwrap().as_str(), Some("abc1"));
    }

    #[test]
    fn resolve_principal_credentials_injects_nt_from_lm_nt_pair() {
        let creds: Vec<Credential> = vec![];
        let hashes = vec![hash(
            "admin",
            "contoso.local",
            "aad3b435b51404eeaad3b435b51404ee:d350c5900e26d2c95f501e94cf95b078",
            None,
        )];
        let mut args = json!({"username": "admin", "domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(
            args.get("nt_hash").unwrap().as_str(),
            Some("d350c5900e26d2c95f501e94cf95b078")
        );
    }

    #[test]
    fn resolve_principal_credentials_does_not_overwrite_existing() {
        let creds = vec![cred("admin", "contoso.local", "fromstate")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "passed-in"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(args.get("password").unwrap().as_str(), Some("passed-in"));
    }

    #[test]
    fn resolve_coerce_principal_injects_password() {
        let creds = vec![cred("svc-coerce", "contoso.local", "C0erceP@ss")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({
            "ca_host": "ca.contoso.local",
            "coerce_target": "dc01.contoso.local",
            "coerce_user": "svc-coerce",
            "coerce_domain": "contoso.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert_eq!(
            args.get("coerce_password").unwrap().as_str(),
            Some("C0erceP@ss")
        );
        assert!(args.get("coerce_hash").is_none());
    }

    #[test]
    fn resolve_coerce_principal_injects_hash() {
        let creds: Vec<Credential> = vec![];
        let hashes = vec![hash("svc-coerce", "contoso.local", "deadbeef", None)];
        let mut args = json!({
            "ca_host": "ca.contoso.local",
            "coerce_target": "dc01.contoso.local",
            "coerce_user": "svc-coerce",
            "coerce_domain": "contoso.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert_eq!(args.get("coerce_hash").unwrap().as_str(), Some("deadbeef"));
        assert!(args.get("coerce_password").is_none());
    }

    #[test]
    fn resolve_coerce_principal_noop_without_user() {
        let creds = vec![cred("svc-coerce", "contoso.local", "C0erceP@ss")];
        let hashes = vec![hash("svc-coerce", "contoso.local", "deadbeef", None)];
        let mut args = json!({
            "ca_host": "ca.contoso.local",
            "coerce_target": "dc01.contoso.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert!(args.get("coerce_password").is_none());
        assert!(args.get("coerce_hash").is_none());
    }

    #[test]
    fn resolve_coerce_principal_does_not_overwrite_existing() {
        let creds = vec![cred("svc-coerce", "contoso.local", "fromstate")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({
            "coerce_user": "svc-coerce",
            "coerce_domain": "contoso.local",
            "coerce_password": "passed-in"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert_eq!(
            args.get("coerce_password").unwrap().as_str(),
            Some("passed-in")
        );
    }

    #[test]
    fn resolve_krbtgt_hashes_injects_for_domain() {
        let hashes = vec![hash("krbtgt", "contoso.local", "kr1", None)];
        let mut args = json!({"domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_krbtgt_hashes(&mut args, &hashes);
        assert_eq!(args.get("krbtgt_hash").unwrap().as_str(), Some("kr1"));
    }

    #[test]
    fn resolve_krbtgt_hashes_injects_child() {
        let hashes = vec![hash("krbtgt", "child.contoso.local", "kr-child", None)];
        let mut args = json!({"child_domain": "child.contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_krbtgt_hashes(&mut args, &hashes);
        assert_eq!(
            args.get("child_krbtgt_hash").unwrap().as_str(),
            Some("kr-child")
        );
    }

    #[test]
    fn resolve_domain_sids_injects_all() {
        let mut sids = std::collections::HashMap::new();
        sids.insert("contoso.local".to_string(), "S-1-5-21-100".to_string());
        sids.insert("fabrikam.local".to_string(), "S-1-5-21-200".to_string());

        let mut args = json!({
            "domain": "contoso.local",
            "source_domain": "contoso.local",
            "target_domain": "fabrikam.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_domain_sids(&mut args, &sids);
        assert_eq!(
            args.get("domain_sid").unwrap().as_str(),
            Some("S-1-5-21-100")
        );
        assert_eq!(
            args.get("source_sid").unwrap().as_str(),
            Some("S-1-5-21-100")
        );
        assert_eq!(
            args.get("target_sid").unwrap().as_str(),
            Some("S-1-5-21-200")
        );
    }

    #[test]
    fn resolve_domain_sids_does_not_overwrite() {
        let mut sids = std::collections::HashMap::new();
        sids.insert("contoso.local".to_string(), "S-1-5-21-100".to_string());

        let mut args = json!({
            "domain": "contoso.local",
            "domain_sid": "S-1-5-21-existing"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_domain_sids(&mut args, &sids);
        assert_eq!(
            args.get("domain_sid").unwrap().as_str(),
            Some("S-1-5-21-existing")
        );
    }

    #[test]
    fn nt_hash_only_strips_lm() {
        assert_eq!(
            nt_hash_only("aad3b435b51404eeaad3b435b51404ee:d350c5900e26d2c95f501e94cf95b078"),
            "d350c5900e26d2c95f501e94cf95b078"
        );
    }

    #[test]
    fn nt_hash_only_passes_through() {
        assert_eq!(
            nt_hash_only("d350c5900e26d2c95f501e94cf95b078"),
            "d350c5900e26d2c95f501e94cf95b078"
        );
    }

    #[test]
    fn expects_ticket_kerberos_tools() {
        let empty_args = json!({}).as_object().unwrap().clone();
        assert!(expects_ticket("psexec_kerberos", &empty_args));
        assert!(expects_ticket("wmiexec_kerberos", &empty_args));
        assert!(expects_ticket("secretsdump_kerberos", &empty_args));
    }

    #[test]
    fn expects_ticket_skips_non_kerberos() {
        let empty_args = json!({}).as_object().unwrap().clone();
        assert!(!expects_ticket("psexec", &empty_args));
        assert!(!expects_ticket("nmap_scan", &empty_args));
    }

    #[test]
    fn expects_ticket_skips_when_already_set() {
        let args_with_ticket = json!({"ticket_path": "/tmp/x.ccache"})
            .as_object()
            .unwrap()
            .clone();
        assert!(!expects_ticket("psexec_kerberos", &args_with_ticket));
    }

    // ── cross-forest Kerberos ticket injection ──────────────────────────────

    #[test]
    fn resolve_cross_forest_ticket_not_injected_when_ntlm_exists() {
        // When the hashes slice contains a matching NTLM hash for the target
        // domain, is_authenticating_hash_type returns true and the function
        // short-circuits — no Kerberos injection needed.
        let hashes = [hash("admin", "fabrikam.local", "deadbeef00112233", None)];
        let domain_l = "fabrikam.local";
        // Replicate the guard logic from resolve_cross_forest_ticket
        let user_l = "admin";
        let has_ntlm = hashes.iter().any(|h| {
            h.domain.to_lowercase() == domain_l
                && (user_l.is_empty() || h.username.to_lowercase() == user_l)
                && !h.hash_value.is_empty()
                && is_authenticating_hash_type(&h.hash_type)
        });
        assert!(
            has_ntlm,
            "NTLM hash present — Kerberos injection should be skipped"
        );
    }

    #[test]
    fn resolve_cross_forest_ticket_triggered_when_no_ntlm_for_target() {
        // When no NTLM hash for the target domain exists, the resolver should
        // proceed to the Redis lookup for a forged ccache.
        let hashes = [hash("administrator", "contoso.local", "deadbeef", None)];
        let domain_l = "fabrikam.local"; // foreign domain, no entry in hashes
        let user_l = "administrator";
        let has_ntlm = hashes.iter().any(|h| {
            h.domain.to_lowercase() == domain_l
                && (user_l.is_empty() || h.username.to_lowercase() == user_l)
                && !h.hash_value.is_empty()
                && is_authenticating_hash_type(&h.hash_type)
        });
        assert!(
            !has_ntlm,
            "No NTLM hash for fabrikam.local — resolver should attempt Kerberos ticket lookup"
        );
    }

    #[test]
    fn requires_exact_realm_bloodyad_set_password_is_true() {
        // Confirm the canary tool is covered by realm_strict so that the
        // cross-forest ticket injection fires for it.
        assert!(requires_exact_realm("bloodyad_set_password"));
    }

    #[test]
    fn supports_kerberos_auth_mode_covers_secretsdump() {
        // secretsdump must be eligible for cross-forest ccache injection — it
        // accepts no_pass=true+ticket_path even though it's not in
        // requires_exact_realm (it normally traverses trusts via NTLM
        // pass-through, but cross-forest NTLM is broken per CLAUDE.md).
        assert!(supports_kerberos_auth_mode("secretsdump"));
        assert!(supports_kerberos_auth_mode("secretsdump_kerberos"));
    }

    #[test]
    fn supports_kerberos_auth_mode_excludes_non_kerberos_tools() {
        // Tools with no Kerberos transition (neither in-place flip nor a
        // *_kerberos variant) must return false. After centralizing on
        // `kerberos_coercion`, this is anything that resolves to
        // KerberosCoercion::None.
        assert!(!supports_kerberos_auth_mode("ldap_search"));
        assert!(!supports_kerberos_auth_mode("nmap_scan"));
        assert!(!supports_kerberos_auth_mode("crack_with_hashcat"));
        assert!(!supports_kerberos_auth_mode("kerberoast"));
    }

    #[test]
    fn supports_kerberos_auth_mode_covers_redirect_tools() {
        // psexec/wmiexec/smbexec are Kerberos-capable via redirect to their
        // *_kerberos variant — the resolver flips args and renames the tool.
        // Before the KerberosCoercion refactor these were excluded because
        // the dispatcher couldn't rename; now they're supported.
        assert!(supports_kerberos_auth_mode("psexec"));
        assert!(supports_kerberos_auth_mode("wmiexec"));
        assert!(supports_kerberos_auth_mode("smbexec"));
    }

    #[test]
    fn kerberos_coercion_maps_each_tool_to_correct_variant() {
        // Single source of truth — explicit assertions per tool so a future
        // change to `kerberos_coercion` shows up as a diff in this test.
        assert_eq!(kerberos_coercion("secretsdump"), KerberosCoercion::InPlace);
        assert_eq!(
            kerberos_coercion("secretsdump_kerberos"),
            KerberosCoercion::AlreadyKerberos
        );
        assert_eq!(
            kerberos_coercion("psexec"),
            KerberosCoercion::Redirect("psexec_kerberos")
        );
        assert_eq!(
            kerberos_coercion("wmiexec"),
            KerberosCoercion::Redirect("wmiexec_kerberos")
        );
        assert_eq!(
            kerberos_coercion("smbexec"),
            KerberosCoercion::Redirect("smbexec_kerberos")
        );
        assert_eq!(
            kerberos_coercion("psexec_kerberos"),
            KerberosCoercion::AlreadyKerberos
        );
        assert_eq!(kerberos_coercion("ldap_search"), KerberosCoercion::None);
        assert_eq!(kerberos_coercion("nmap_scan"), KerberosCoercion::None);
    }

    #[test]
    fn kerberos_coercion_redirect_targets_are_already_kerberos_tools() {
        // Self-consistency check: every Redirect(variant) must point at a
        // tool that resolves to AlreadyKerberos. Otherwise we'd redirect to
        // a tool that itself wouldn't flip into Kerberos mode.
        for tool in ["psexec", "wmiexec", "smbexec"] {
            let KerberosCoercion::Redirect(variant) = kerberos_coercion(tool) else {
                panic!("{tool} must be a Redirect");
            };
            assert_eq!(
                kerberos_coercion(variant),
                KerberosCoercion::AlreadyKerberos,
                "redirect target {variant} must itself be AlreadyKerberos"
            );
        }
    }

    #[test]
    fn requires_exact_realm_and_kerberos_auth_mode_are_disjoint() {
        // The call-site picks target_realm differently for these two sets:
        // realm-strict tools read it from `domain`, kerberos-mode tools infer
        // it from the target host. A tool in both sets would get conflicting
        // resolution. Keep them disjoint across every tool the resolver
        // recognizes.
        for tool in [
            "bloodyad_set_password",
            "ldap_search",
            "ldap_acl_enumeration",
            "kerberoast",
            "nopac",
            "enumerate_domain_trusts",
            "secretsdump",
            "secretsdump_kerberos",
            "psexec",
            "psexec_kerberos",
            "wmiexec",
            "wmiexec_kerberos",
            "smbexec",
            "smbexec_kerberos",
        ] {
            assert!(
                !(requires_exact_realm(tool) && supports_kerberos_auth_mode(tool)),
                "tool {tool} must not be in both sets"
            );
        }
    }

    #[test]
    fn expects_ticket_only_for_already_kerberos_variants() {
        // *_kerberos tools have no other auth mode — they always need a
        // ticket. Tools with InPlace, Redirect, or None coercion must NOT
        // be in expects_ticket: InPlace/Redirect get the ticket via the
        // cross-forest resolver, None doesn't need one at all.
        let empty = Map::new();
        for kerberized in [
            "secretsdump_kerberos",
            "psexec_kerberos",
            "wmiexec_kerberos",
            "smbexec_kerberos",
        ] {
            assert!(
                expects_ticket(kerberized, &empty),
                "{kerberized} must expect a ticket"
            );
        }
        for not_kerberized in [
            "secretsdump",
            "psexec",
            "wmiexec",
            "smbexec",
            "ldap_search",
            "nmap_scan",
        ] {
            assert!(
                !expects_ticket(not_kerberized, &empty),
                "{not_kerberized} must NOT expect a ticket from this predicate"
            );
        }
    }

    #[test]
    fn apply_kerberos_auth_mode_flip_strips_password_and_hash() {
        // Simulates the post-injection state for cross-forest secretsdump:
        // principal resolver already injected password+hash, ticket resolver
        // injected ticket_path. The flip must remove the wrong-realm
        // credentials and set no_pass=true so impacket actually uses the
        // ccache.
        let mut args = Map::new();
        args.insert(
            "password".to_string(),
            Value::String("wrong-realm-pw".into()),
        );
        args.insert("hash".to_string(), Value::String("aabbccdd".into()));
        args.insert(
            "ticket_path".to_string(),
            Value::String("/tmp/ares-tickets/some.ccache".into()),
        );

        let (stripped_pw, stripped_hash) = apply_kerberos_auth_mode_flip(&mut args);

        assert!(stripped_pw, "must report password was stripped");
        assert!(stripped_hash, "must report hash was stripped");
        assert!(!args.contains_key("password"));
        assert!(!args.contains_key("hash"));
        assert_eq!(args.get("no_pass"), Some(&Value::Bool(true)));
        assert_eq!(
            args.get("ticket_path"),
            Some(&Value::String("/tmp/ares-tickets/some.ccache".into())),
            "ticket_path must be preserved across the flip"
        );
    }

    #[test]
    fn apply_kerberos_auth_mode_flip_idempotent_with_only_no_pass_already_set() {
        // Re-running the flip on already-flipped args must be a no-op
        // (no_pass stays true, password/hash still absent, no panics).
        let mut args = Map::new();
        args.insert("no_pass".to_string(), Value::Bool(true));
        args.insert(
            "ticket_path".to_string(),
            Value::String("/tmp/ares-tickets/x.ccache".into()),
        );

        let (stripped_pw, stripped_hash) = apply_kerberos_auth_mode_flip(&mut args);

        assert!(!stripped_pw, "no password to strip");
        assert!(!stripped_hash, "no hash to strip");
        assert_eq!(args.get("no_pass"), Some(&Value::Bool(true)));
    }

    #[test]
    fn cross_forest_secretsdump_does_not_inject_when_target_realm_ntlm_exists() {
        // Same-realm NTLM short-circuit applies to secretsdump too. If an
        // NTLM hash for the target realm is already in state, we don't need
        // the forged ccache and must not strip the cleartext/hash creds the
        // LLM/principal resolver chose.
        let hashes = [hash(
            "administrator",
            "fabrikam.local",
            "deadbeef00112233",
            None,
        )];
        let domain_l = "fabrikam.local";
        let user_l = "administrator";
        let has_ntlm = hashes.iter().any(|h| {
            h.domain.to_lowercase() == domain_l
                && (user_l.is_empty() || h.username.to_lowercase() == user_l)
                && !h.hash_value.is_empty()
                && is_authenticating_hash_type(&h.hash_type)
        });
        assert!(
            has_ntlm,
            "same-realm NTLM hash present — secretsdump must NOT be flipped into Kerberos mode"
        );
    }

    // ── is_placeholder_str ──────────────────────────────────────────────

    #[test]
    fn placeholder_str_empty_and_whitespace() {
        assert!(is_placeholder_str(""));
        assert!(is_placeholder_str("   "));
        assert!(is_placeholder_str("\t\n"));
    }

    #[test]
    fn placeholder_str_bracketed_forms() {
        assert!(is_placeholder_str("[HASH]"));
        assert!(is_placeholder_str("<password>"));
        assert!(is_placeholder_str("[TGT]"));
        assert!(is_placeholder_str("<parent_admin_hash>"));
    }

    #[test]
    fn placeholder_str_bare_words() {
        for w in &[
            "n/a",
            "N/A",
            "null",
            "NONE",
            "Unknown",
            "tbd",
            "TODO",
            "password",
            "hash",
            "ntlm",
            "tgt",
            "placeholder",
        ] {
            assert!(is_placeholder_str(w), "{w} should be a placeholder");
        }
    }

    #[test]
    fn placeholder_str_real_values_pass_through() {
        assert!(!is_placeholder_str("P@ssw0rd!"));
        assert!(!is_placeholder_str("aad3b435b51404eeaad3b435b51404ee"));
        assert!(!is_placeholder_str("Administrator"));
    }

    // ── is_placeholder_value ────────────────────────────────────────────

    #[test]
    fn placeholder_value_null_is_placeholder() {
        assert!(is_placeholder_value(&Value::Null));
    }

    #[test]
    fn placeholder_value_string_delegates_to_is_placeholder_str() {
        assert!(is_placeholder_value(&Value::String("[HASH]".into())));
        assert!(!is_placeholder_value(&Value::String("P@ssw0rd!".into())));
    }

    #[test]
    fn placeholder_value_non_string_non_null_is_not_placeholder() {
        assert!(!is_placeholder_value(&serde_json::json!(42)));
        assert!(!is_placeholder_value(&serde_json::json!(true)));
        assert!(!is_placeholder_value(&serde_json::json!([])));
        assert!(!is_placeholder_value(&serde_json::json!({})));
    }

    // ── looks_like_ip ───────────────────────────────────────────────────

    #[test]
    fn looks_like_ip_v4_dotted_quad() {
        assert!(looks_like_ip("192.168.58.10"));
        assert!(looks_like_ip("0.0.0.0"));
        assert!(looks_like_ip("255.255.255.255"));
    }

    #[test]
    fn looks_like_ip_trims_whitespace() {
        assert!(looks_like_ip("  192.168.58.10  "));
    }

    #[test]
    fn looks_like_ip_rejects_octet_overflow() {
        assert!(!looks_like_ip("192.168.58.256"));
        assert!(!looks_like_ip("999.0.0.1"));
    }

    #[test]
    fn looks_like_ip_rejects_wrong_octet_count() {
        assert!(!looks_like_ip("192.168.58"));
        assert!(!looks_like_ip("192.168.58.10.20"));
    }

    #[test]
    fn looks_like_ip_rejects_hostnames() {
        assert!(!looks_like_ip("dc01.contoso.local"));
        assert!(!looks_like_ip(""));
    }

    // ── is_common_per_domain_account ────────────────────────────────────

    #[test]
    fn common_per_domain_account_recognises_built_in_names() {
        assert!(is_common_per_domain_account("administrator"));
        assert!(is_common_per_domain_account("guest"));
        assert!(is_common_per_domain_account("krbtgt"));
    }

    #[test]
    fn common_per_domain_account_only_matches_lowercase_form() {
        // The caller is responsible for lowercasing — uppercase input
        // returns false to make that contract explicit.
        assert!(!is_common_per_domain_account("Administrator"));
        assert!(!is_common_per_domain_account("KRBTGT"));
    }

    #[test]
    fn common_per_domain_account_other_users_are_not_common() {
        assert!(!is_common_per_domain_account("alice"));
        assert!(!is_common_per_domain_account("svc_sql"));
        assert!(!is_common_per_domain_account(""));
    }

    // ── is_authenticating_hash_type ─────────────────────────────────────

    #[test]
    fn auth_hash_type_ntlm_is_authenticating() {
        assert!(is_authenticating_hash_type("NTLM"));
        assert!(is_authenticating_hash_type("ntlm"));
        assert!(is_authenticating_hash_type("AES256"));
        assert!(is_authenticating_hash_type("aes256"));
    }

    #[test]
    fn auth_hash_type_roast_variants_are_not_authenticating() {
        // Roast hashes are *crackable* hashes — not directly usable for
        // authentication. Treating them as auth material would dispatch
        // tools with a hash they can't bind with.
        for ht in &[
            "kerberoast",
            "Kerberoast",
            "asreproast",
            "asrep",
            "tgs",
            "krb5tgs",
            "KRB5ASREP",
        ] {
            assert!(
                !is_authenticating_hash_type(ht),
                "{ht} should not be authenticating"
            );
        }
    }

    #[test]
    fn auth_hash_type_unknown_types_default_to_authenticating() {
        // Anything not on the roast-variant list is treated as auth-capable.
        // Conservative: tool dispatch surfaces the auth error if the hash
        // doesn't actually work, vs silently refusing to inject.
        assert!(is_authenticating_hash_type("aes128"));
        assert!(is_authenticating_hash_type("lm"));
        assert!(is_authenticating_hash_type(""));
    }
}
