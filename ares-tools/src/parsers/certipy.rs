//! Certipy (ADCS) output parser.

use serde_json::{json, Value};

/// All ESC types that certipy can detect.
pub const ESC_TYPES: &[&str] = &[
    "esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8", "esc9", "esc10", "esc11",
    "esc13", "esc14", "esc15",
];

const SID_SECURITY_EXTENSION_OID: &str = "1.3.6.1.4.1.311.25.2";

const MAX_DISABLED_EXTENSION_CONTINUATION: usize = 16;

/// Read the CA-wide SID security-extension state out of a `certipy find`
/// transcript.
///
/// Returns `Some(true)` when the issuing CA omits `szOID_NTDS_CA_SECURITY_EXT`
/// from **every** certificate it issues (certipy v5 reports this as ESC16),
/// `Some(false)` when the CA is known to stamp it, and `None` when the
/// transcript does not say. The three answers are distinct: only the first two
/// license a decision about whether a spoofed UPN survives KB5014754 strong
/// mapping.
///
/// ESC16 is read as a fact about the CA rather than emitted as a vulnerability,
/// because it has no exploit primitive of its own. Two independent markers are
/// accepted: the `ESC16` vulnerability label, which certipy prints only when the
/// bound principal can also enroll, and the raw `Disabled Extensions` property,
/// which it prints either way.
pub fn ca_security_extension_state(output: &str) -> Option<bool> {
    if esc16_reported(output) {
        return Some(true);
    }
    let oids = disabled_extension_oids(output)?;
    Some(
        oids.iter()
            .any(|oid| oid.contains(SID_SECURITY_EXTENSION_OID)),
    )
}

fn esc16_reported(output: &str) -> bool {
    for line in output.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("ESC16") else {
            continue;
        };
        if rest.is_empty() || rest.starts_with(' ') || rest.starts_with(':') {
            return true;
        }
    }
    false
}

fn disabled_extension_oids(output: &str) -> Option<Vec<String>> {
    let mut lines = output.lines();
    let value = loop {
        let line = lines.next()?;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Disabled Extensions") {
            break rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
        }
    };
    if value.eq_ignore_ascii_case("Unknown") {
        return None;
    }
    let mut oids = Vec::new();
    if !value.is_empty() {
        oids.push(value.to_string());
    }
    for cont in lines.take(MAX_DISABLED_EXTENSION_CONTINUATION) {
        let trimmed = cont.trim();
        if trimmed.is_empty() || trimmed.contains(':') || trimmed.starts_with('[') {
            break;
        }
        oids.push(trimmed.to_string());
    }
    Some(oids)
}

pub fn parse_certipy_find(output: &str, params: &Value) -> Vec<Value> {
    // ca_host_ip is the ADCS CA server IP (where certs are enrolled).
    // target/target_ip is the DC IP used for LDAP queries.
    // For vuln target, prefer ca_host_ip so exploitation targets the CA, not the DC.
    let ca_host_ip = params
        .get("ca_host_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target_ip = if !ca_host_ip.is_empty() {
        ca_host_ip
    } else {
        params
            .get("target")
            .or_else(|| params.get("target_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    };

    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    // Extract CA name from output if present (e.g. "CA Name: CONTOSO-CA")
    let ca_name = extract_ca_name(output);
    // Extract the CA's real host FQDN (dNSHostName). The orchestrator resolves
    // this to an IP against known hosts so exploitation targets the CA server,
    // not the DC used for the LDAP bind — see `resolve_ca_host_from_dns_name`.
    let ca_dns_name = extract_ca_dns_name(output);

    let mut vulns = Vec::new();
    let output_lower = output.to_lowercase();
    let sid_extension_disabled = ca_security_extension_state(output);

    // Strategy 1: Look for "[!] Vulnerabilities" section (certipy text output)
    let has_vuln_header = output_lower.contains("[!] vulnerabilities");

    // Strategy 2: Look for "ESCn :" patterns (certipy find -vulnerable output)
    // These appear as "ESC1 : 'DOMAIN\\Group' can enroll..."
    for esc_type in ESC_TYPES {
        let esc_upper = esc_type.to_uppercase();
        let found = if has_vuln_header {
            // Use word-boundary-aware matching to avoid false positives
            // (e.g. "esc1" matching inside "esc13" or "esc15").
            // Certipy outputs "ESCn :" or "ESCn:" patterns.
            output.contains(&format!("{esc_upper} :"))
                || output.contains(&format!("{esc_upper}:"))
                || output.contains(&format!("{esc_upper} "))
                || esc_word_boundary_match(&output_lower, esc_type)
        } else {
            // Also detect ESC patterns without the header — certipy sometimes
            // outputs vulnerability info inline with template details.
            // Look for "ESCn" followed by ":" or "vulnerability" on the same or
            // nearby lines.
            output.contains(&format!("{esc_upper} :"))
                || output.contains(&format!("{esc_upper}:"))
                || (esc_word_boundary_match(&output_lower, esc_type)
                    && output_lower.contains("vulnerab"))
        };

        if found {
            // Extract template name if available (e.g., "Template Name : ESC1")
            let template_name = extract_template_for_esc(output, esc_type);

            let mut details = json!({
                "esc_type": esc_type,
            });
            if !domain.is_empty() {
                details["domain"] = json!(domain);
            }
            // Write-holder ESCs (GenericAll/Write on the template, ManageCA,
            // GenericAll-on-user) require a SPECIFIC principal's credential, not
            // just any domain user. Capture the holder certipy names on the ESC
            // line so credential selection targets it (e.g. ESC4 → carol).
            // find_adcs_credential falls back to any same-domain cred if the
            // holder's credential isn't available yet, so this never regresses
            // the any-user ESCs (esc1/2/3/6/13/15), which we leave unset.
            if matches!(*esc_type, "esc4" | "esc7" | "esc9" | "esc10") {
                if let Some(holder) = extract_esc_principal(output, esc_type) {
                    details["write_holder"] = json!(holder);
                    details["account_name"] = json!(holder);
                }
            }
            if let Some(ref ca) = ca_name {
                details["ca_name"] = json!(ca);
            }
            if let Some(ref dns) = ca_dns_name {
                details["ca_dns_name"] = json!(dns);
            }
            if let Some(ref tmpl) = template_name {
                details["template_name"] = json!(tmpl);
            }
            if !ca_host_ip.is_empty() {
                details["ca_host"] = json!(ca_host_ip);
            }
            if let Some(disabled) = sid_extension_disabled {
                details["ca_security_extension_disabled"] = json!(disabled);
            }

            // Include `template_name` in the vuln_id when present so two
            // distinct vulnerable templates of the same ESC type on the
            // same CA don't collapse onto one dedup entry — the previous
            // shape `adcs_{esc}_{ca_ip}` overwrote each other and the
            // exploitation chain only got one template per CA.
            let vuln_id = match template_name.as_ref() {
                Some(tmpl) => {
                    format!("adcs_{}_{}_{}", esc_type, target_ip, slugify_template(tmpl),)
                }
                None => format!("adcs_{}_{}", esc_type, target_ip),
            };

            vulns.push(json!({
                "vuln_id": vuln_id,
                "vuln_type": format!("adcs_{}", esc_type),
                "target": target_ip,
                "discovered_by": "certipy_find",
                "details": details,
                "recommended_agent": "privesc",
                "priority": esc_priority(esc_type, sid_extension_disabled == Some(true)),
            }));
        }
    }

    vulns
}

/// Check if `esc_type` (e.g. "esc1") appears as a whole word in `text`.
/// Prevents "esc1" from matching inside "esc13" or "esc15".
fn esc_word_boundary_match(text: &str, esc_type: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = text[start..].find(esc_type) {
        let abs_pos = start + pos;
        let end_pos = abs_pos + esc_type.len();
        // Check that the character after the match is not a digit
        let after_ok = end_pos >= text.len() || !text.as_bytes()[end_pos].is_ascii_digit();
        if after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

/// Extract the principal certipy names on an ESC line as holding the dangerous
/// right, e.g. `ESC4 : 'CONTOSO.LOCAL\carol' has dangerous permissions ...`.
/// Returns the bare sAMAccountName (portion after the domain backslash),
/// lowercased. Returns `None` if no single-quoted principal is found.
fn extract_esc_principal(output: &str, esc_type: &str) -> Option<String> {
    let esc_upper = esc_type.to_uppercase();
    for line in output.lines() {
        let trimmed = line.trim();
        if is_esc_header_line(trimmed, &esc_upper) {
            if let Some(p) = extract_quoted_principal(trimmed) {
                return Some(p);
            }
        }
    }
    acl_principal_for_esc(output, &esc_upper)
}

fn is_esc_header_line(trimmed: &str, esc_upper: &str) -> bool {
    trimmed
        .strip_prefix(esc_upper)
        .is_some_and(|rest| rest.starts_with(' ') || rest.starts_with(':'))
}

fn acl_principal_for_esc(output: &str, esc_upper: &str) -> Option<String> {
    let mut holder: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("CA Name") || trimmed.starts_with("Template Name") {
            holder = None;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("[+] User ACL Principals") {
            let value = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            let name = value.rsplit('\\').next().unwrap_or(value).trim();
            if !name.is_empty() {
                holder = Some(name.to_lowercase());
            }
            continue;
        }
        if is_esc_header_line(trimmed, esc_upper) && holder.is_some() {
            return holder;
        }
    }
    None
}

/// Pull the first single-quoted `DOMAIN\principal` (or `principal`) from a line
/// and return the name after the last backslash, lowercased.
fn extract_quoted_principal(line: &str) -> Option<String> {
    let start = line.find('\'')?;
    let rest = &line[start + 1..];
    let end = rest.find('\'')?;
    let principal = &rest[..end];
    let name = principal.rsplit('\\').next().unwrap_or(principal).trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_lowercase())
    }
}

/// Extract CA name from certipy output.
fn extract_ca_name(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("CA Name") {
            let name = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Extract the CA's DNS host name (its `dNSHostName`) from certipy output.
///
/// certipy `find` prints the issuing CA's real host in the "Certificate
/// Authorities" block as `DNS Name : <fqdn>`. This is the authoritative
/// source for WHERE certificates enroll — frequently a different box than the
/// DC used for the LDAP bind (a dedicated CA server). Exploitation must target
/// this host: aiming the MS-ICPR enrollment RPC at the DC instead hits a host
/// with no `certsvc`, and certipy exits 0 with no PFX ("EPT_S_NOT_REGISTERED").
/// Templates don't emit a `DNS Name` line, so the first match is the CA host.
fn extract_ca_dns_name(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("DNS Name") {
            let name = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Extract template name associated with an ESC type.
fn extract_template_for_esc(output: &str, esc_type: &str) -> Option<String> {
    let esc_upper = esc_type.to_uppercase();
    let mut template: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed == "Certificate Authorities" || trimmed.starts_with("CA Name") {
            template = None;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Template Name") {
            let name = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            template = (!name.is_empty()).then(|| name.to_string());
            continue;
        }
        if template.is_some()
            && (is_esc_header_line(trimmed, &esc_upper)
                || esc_word_boundary_match(trimmed, &esc_upper))
        {
            return template;
        }
    }
    None
}

/// Parse the combined output of `certipy_esc1_full_chain` and emit a `Hash`
/// discovery for the NTLM hash returned by the `certipy auth` step. Returns
/// an empty vec when the chain didn't actually yield a hash (request denied,
/// auth path bailed, etc.) — the caller treats that as "nothing to publish".
///
/// Lines we recognise from `certipy auth` output:
///   `[*] Got hash for 'administrator@<realm>': <lmhash>:<nthash>`
///
/// Realm in the principal comes from the cert's `-upn` flag — that's the
/// impersonated identity, NOT the requester's username. Both pieces matter:
/// `Hash.username = "administrator"`, `Hash.domain = "<realm>"`.
pub fn parse_certipy_esc1_chain(output: &str, params: &Value) -> Vec<Value> {
    let mut hashes = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        // Format examples (with quoted or unquoted principal):
        //   [*] Got hash for 'user@REALM.LOCAL': aad3...:31d6...
        //   [*] Got hash for user@REALM.LOCAL: aad3...:31d6...
        let Some(rest) = line
            .strip_prefix("[*] Got hash for ")
            .or_else(|| line.strip_prefix("Got hash for "))
        else {
            continue;
        };
        // Strip optional surrounding quotes from the principal.
        let rest = rest.trim_start_matches('\'').trim_start_matches('"');
        let Some((principal, hash_part)) = rest.split_once(':') else {
            continue;
        };
        let principal = principal
            .trim_end_matches('\'')
            .trim_end_matches('"')
            .trim();
        let hash_part = hash_part.trim();
        let Some((user, realm)) = principal.split_once('@') else {
            continue;
        };
        // hash_part should be lm:nt — accept either combined or split forms.
        let (lm, nt) = match hash_part.split_once(':') {
            Some((lm, nt)) => (lm.trim().to_string(), nt.trim().to_string()),
            // Some certipy builds emit just the NT half; fill in the empty LM.
            None => (
                "aad3b435b51404eeaad3b435b51404ee".to_string(),
                hash_part.trim().to_string(),
            ),
        };
        if nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let domain = realm.trim().to_lowercase();
        let user = user.trim().to_lowercase();
        hashes.push(json!({
            "username": user,
            "domain": domain,
            "hash_type": "NTLM",
            "hash_value": format!("{lm}:{nt}"),
            "source": "certipy_esc1_full_chain",
        }));
    }

    // DCSync tail (RC4-disabled KDCs): `certipy auth` yields only a TGT, so the
    // chain DCSyncs `krbtgt` with the ccache and the hash lands here as
    // secretsdump NTDS output — `krbtgt:502:<lm>:<nt>:::` plus an
    // `krbtgt:aes256-cts-hmac-sha1-96:<key>` line. Parse those so the krbtgt
    // hash is published (and marks the forest dominated) even when no
    // `Got hash for` line was ever printed. Domain comes from the request
    // params (the target realm), since NTDS `-just-dc-user` rows omit it.
    let dcsync_domain = params
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    // First pass: collect AES256 keys keyed by sAMAccountName so they can be
    // attached to the matching NTLM row.
    let mut aes_by_user: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 3 && parts[1].eq_ignore_ascii_case("aes256-cts-hmac-sha1-96") {
            let user = parts[0].trim();
            let key = parts[2].trim();
            if !user.is_empty() && key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
                aes_by_user.insert(user.to_lowercase(), key.to_string());
            }
        }
    }
    for line in output.lines() {
        // NTDS secretsdump row: `user:rid:lmhash:nthash:::`.
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let user = parts[0].trim();
        let rid = parts[1].trim();
        let lm = parts[2].trim();
        let nt = parts[3].trim();
        let is_ntds_row = !user.is_empty()
            && rid.chars().all(|c| c.is_ascii_digit())
            && !rid.is_empty()
            && lm.len() == 32
            && lm.chars().all(|c| c.is_ascii_hexdigit())
            && nt.len() == 32
            && nt.chars().all(|c| c.is_ascii_hexdigit());
        if !is_ntds_row {
            continue;
        }
        let mut hash = json!({
            "username": user.to_lowercase(),
            "domain": dcsync_domain,
            "hash_type": "NTLM",
            "hash_value": format!("{lm}:{nt}"),
            "source": "certipy_esc1_full_chain",
        });
        if let Some(aes) = aes_by_user.get(&user.to_lowercase()) {
            hash["aes_key"] = json!(aes);
        }
        hashes.push(hash);
    }
    hashes
}

const EMPTY_LM_HASH: &str = "aad3b435b51404eeaad3b435b51404ee";

fn strip_status_marker(line: &str) -> &str {
    let trimmed = line.trim();
    for marker in ["[*] ", "[+] ", "[-] ", "[!] "] {
        if let Some(rest) = trimmed.strip_prefix(marker) {
            return rest.trim_start();
        }
    }
    trimmed
}

fn is_ntlm_half(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn parse_certipy_shadow(output: &str, params: &Value) -> Vec<Value> {
    let param_domain = params
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let mut hashes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for raw in output.lines() {
        let line = strip_status_marker(raw);
        let Some(rest) = line
            .strip_prefix("NT hash for ")
            .or_else(|| line.strip_prefix("Got hash for "))
        else {
            continue;
        };
        let Some((principal, hash_part)) = rest.split_once(':') else {
            continue;
        };
        let principal = principal.trim().trim_matches(['\'', '"']).trim();
        if principal.is_empty() {
            continue;
        }
        let hash_part = hash_part.trim();
        let (lm, nt) = match hash_part.split_once(':') {
            Some((lm, nt)) => (lm.trim(), nt.trim()),
            None => (EMPTY_LM_HASH, hash_part),
        };
        if !is_ntlm_half(lm) || !is_ntlm_half(nt) {
            continue;
        }
        let (username, domain) = match principal.split_once('@') {
            Some((user, realm)) if !user.is_empty() && !realm.is_empty() => {
                (user.to_lowercase(), realm.to_lowercase())
            }
            _ => (principal.to_lowercase(), param_domain.clone()),
        };
        if !seen.insert(format!("{username}@{domain}")) {
            continue;
        }
        hashes.push(json!({
            "username": username,
            "domain": domain,
            "hash_type": "NTLM",
            "hash_value": format!("{lm}:{nt}"),
            "source": "certipy_shadow",
        }));
    }

    hashes
}

/// Normalise a certificate template name into a `vuln_id`-safe slug:
/// lowercase, with non-alphanumeric characters collapsed to underscores.
/// Preserves uniqueness across `WebServer`, `web-server`, `Web Server`
/// while keeping the result safe to use inside an identifier-like key.
fn slugify_template(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_underscore = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.extend(c.to_lowercase());
            prev_underscore = false;
        } else if !prev_underscore {
            out.push('_');
            prev_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// Priority for ESC types (lower = more urgent).
///
/// `ca_omits_sid_extension` is the ESC16 fact from
/// [`ca_security_extension_state`], and it only ever promotes: a CA that stamps
/// the extension does not kill ESC9 or ESC10, so the `false` case must leave
/// every rank alone.
fn esc_priority(esc_type: &str, ca_omits_sid_extension: bool) -> i32 {
    if ca_omits_sid_extension && matches!(esc_type, "esc9" | "esc10") {
        return 1;
    }
    match esc_type {
        "esc1" | "esc6" => 1,           // Direct enrollment → DA cert
        "esc4" | "esc8" => 2,           // Template abuse / relay
        "esc2" | "esc3" | "esc15" => 3, // Certificate agent / app policy OID
        "esc7" | "esc9" | "esc10" => 4, // ManageCA / UPN spoof / weak mapping
        "esc11" => 4,                   // RPC relay (needs coercion)
        "esc5" => 5,                    // Golden cert (requires CA compromise first)
        "esc13" => 4,                   // Issuance policy
        _ => 6,                         // ESC14 and unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_certipy_esc1() {
        let output = "[!] Vulnerabilities\nESC1: Template allows enrollment with low-priv";
        let params = json!({"target": "192.168.58.10", "domain": "contoso.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc1");
        assert_eq!(vulns[0]["target"], "192.168.58.10");
        assert_eq!(vulns[0]["details"]["domain"], "contoso.local");
    }

    #[test]
    fn parse_certipy_esc4_captures_write_holder() {
        let output = "[!] Vulnerabilities\n    ESC4 : 'CONTOSO.LOCAL\\carol' has dangerous permissions over the template";
        let params = json!({"target": "192.168.58.23", "domain": "contoso.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc4");
        // The GenericAll holder is captured so credential selection targets it.
        assert_eq!(vulns[0]["details"]["write_holder"], "carol");
        assert_eq!(vulns[0]["details"]["account_name"], "carol");
    }

    const CERTIPY_V5_FIND: &str = r#"Certipy v5.0.4

[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : CONTOSO-CA
    DNS Name                            : ca01.contoso.local
    Certificate Subject                 : CN=CONTOSO-CA, DC=contoso, DC=local
    Web Enrollment
      HTTP
        Enabled                         : True
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Permissions
      Owner                             : CONTOSO.LOCAL\Administrators
      Access Rights
        Enroll                          : CONTOSO.LOCAL\Authenticated Users
        ManageCa                        : CONTOSO.LOCAL\Administrators
                                          CONTOSO.LOCAL\Domain Admins
                                          CONTOSO.LOCAL\alice smith
        ManageCertificates              : CONTOSO.LOCAL\Administrators
                                          CONTOSO.LOCAL\alice smith
    [+] User Enrollable Principals      : CONTOSO.LOCAL\Authenticated Users
    [+] User ACL Principals             : CONTOSO.LOCAL\alice smith
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : CONTOSO-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-04-09T07:00:48+00:00
    Template Last Modified              : 2026-04-25T18:44:55+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CONTOSO.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : CONTOSO.LOCAL\Enterprise Admins
        Full Control Principals         : CONTOSO.LOCAL\Domain Admins
        Write Owner Principals          : CONTOSO.LOCAL\Domain Admins
        Write Dacl Principals           : CONTOSO.LOCAL\Domain Admins
    [+] User Enrollable Principals      : CONTOSO.LOCAL\Domain Users
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched.
"#;

    #[test]
    fn parse_certipy_v5_captures_esc7_holder_from_block_acl_line() {
        let params = json!({"target": "192.168.58.23", "domain": "contoso.local"});
        let vulns = parse_certipy_find(CERTIPY_V5_FIND, &params);
        let esc7 = vulns
            .iter()
            .find(|v| v["vuln_type"] == "adcs_esc7")
            .expect("esc7 discovered");
        assert_eq!(esc7["details"]["write_holder"], "alice smith");
        assert_eq!(esc7["details"]["account_name"], "alice smith");
    }

    #[test]
    fn parse_certipy_v5_associates_esc_with_enclosing_template_block() {
        let params = json!({"target": "192.168.58.23", "domain": "contoso.local"});
        let vulns = parse_certipy_find(CERTIPY_V5_FIND, &params);
        let esc15 = vulns
            .iter()
            .find(|v| v["vuln_type"] == "adcs_esc15")
            .expect("esc15 discovered");
        assert_eq!(esc15["details"]["template_name"], "WebServer");
    }

    #[test]
    fn extract_template_for_esc_spans_a_full_v5_template_block() {
        assert_eq!(
            extract_template_for_esc(CERTIPY_V5_FIND, "esc15"),
            Some("WebServer".to_string())
        );
    }

    #[test]
    fn extract_template_for_esc_leaves_ca_scoped_esc_unattributed() {
        assert_eq!(extract_template_for_esc(CERTIPY_V5_FIND, "esc7"), None);
        assert_eq!(extract_template_for_esc(CERTIPY_V5_FIND, "esc8"), None);
    }

    #[test]
    fn parse_certipy_v5_leaves_any_user_esc_unpinned() {
        let params = json!({"target": "192.168.58.23", "domain": "contoso.local"});
        let vulns = parse_certipy_find(CERTIPY_V5_FIND, &params);
        let esc15 = vulns
            .iter()
            .find(|v| v["vuln_type"] == "adcs_esc15")
            .expect("esc15 discovered");
        assert!(esc15["details"].get("account_name").is_none());
    }

    #[test]
    fn parse_certipy_esc1_no_write_holder() {
        // Any-user ESCs must NOT pin account_name (any domain cred works).
        let output = "[!] Vulnerabilities\nESC1 : 'CONTOSO.LOCAL\\Domain Users' can enroll";
        let params = json!({"target": "192.168.58.23", "domain": "contoso.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0]["details"].get("account_name").is_none());
    }

    #[test]
    fn parse_certipy_multiple_esc_types() {
        let output =
            "[!] Vulnerabilities\nESC1: ...\nESC4: Template is misconfigured\nESC8: Web enrollment";
        let params = json!({"target_ip": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 3);
        let types: Vec<&str> = vulns
            .iter()
            .map(|v| v["vuln_type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"adcs_esc1"));
        assert!(types.contains(&"adcs_esc4"));
        assert!(types.contains(&"adcs_esc8"));
    }

    #[test]
    fn parse_certipy_no_vulnerabilities_keyword() {
        // Without [!] Vulnerabilities header, only "ESCn :" pattern matches
        let output = "ESC1 : Template allows enrollment";
        let vulns = parse_certipy_find(output, &json!({"target": "192.168.58.10"}));
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn parse_certipy_no_esc_types() {
        let output = "[!] Vulnerabilities\nNo vulnerable templates found";
        let vulns = parse_certipy_find(output, &json!({"target": "192.168.58.10"}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_certipy_empty_output() {
        let vulns = parse_certipy_find("", &json!({}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_certipy_vuln_id_format() {
        let output = "[!] Vulnerabilities\nESC4: misconfigured template";
        let params = json!({"target": "192.168.58.20"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns[0]["vuln_id"], "adcs_esc4_192.168.58.20");
    }

    #[test]
    fn parse_certipy_extended_esc_types() {
        let output = "[!] Vulnerabilities\nESC1: ...\nESC6: EDITF flag\nESC9: UPN spoof\nESC13: issuance policy";
        let params = json!({"target_ip": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 4);
        let types: Vec<&str> = vulns
            .iter()
            .map(|v| v["vuln_type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"adcs_esc6"));
        assert!(types.contains(&"adcs_esc9"));
        assert!(types.contains(&"adcs_esc13"));
    }

    #[test]
    fn parse_certipy_with_ca_name() {
        let output = "CA Name                             : CONTOSO-CA\n[!] Vulnerabilities\nESC1: enrollee supplies subject";
        let params = json!({"target": "192.168.58.10", "domain": "fabrikam.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["details"]["ca_name"], "CONTOSO-CA");
        assert_eq!(vulns[0]["details"]["domain"], "fabrikam.local");
    }

    #[test]
    fn parse_certipy_inline_pattern() {
        // certipy find -vulnerable output format
        let output =
            "  ESC1 : 'FABRIKAM.LOCAL\\Domain Users' can enroll, enrollee supplies subject";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc1");
    }

    #[test]
    fn esc_priority_ordering() {
        assert!(esc_priority("esc1", false) < esc_priority("esc4", false));
        assert!(esc_priority("esc4", false) < esc_priority("esc5", false));
    }

    #[test]
    fn esc_priority_all_values() {
        assert_eq!(esc_priority("esc1", false), 1);
        assert_eq!(esc_priority("esc6", false), 1);
        assert_eq!(esc_priority("esc4", false), 2);
        assert_eq!(esc_priority("esc8", false), 2);
        assert_eq!(esc_priority("esc2", false), 3);
        assert_eq!(esc_priority("esc3", false), 3);
        assert_eq!(esc_priority("esc15", false), 3);
        assert_eq!(esc_priority("esc7", false), 4);
        assert_eq!(esc_priority("esc9", false), 4);
        assert_eq!(esc_priority("esc10", false), 4);
        assert_eq!(esc_priority("esc11", false), 4);
        assert_eq!(esc_priority("esc13", false), 4);
        assert_eq!(esc_priority("esc5", false), 5);
        assert_eq!(esc_priority("unknown", false), 6);
    }

    #[test]
    fn esc16_promotes_only_the_upn_spoof_family() {
        assert_eq!(esc_priority("esc9", true), 1);
        assert_eq!(esc_priority("esc10", true), 1);
        for other in [
            "esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8", "esc11",
        ] {
            assert_eq!(
                esc_priority(other, true),
                esc_priority(other, false),
                "{other} must not move on the ESC16 fact"
            );
        }
    }

    #[test]
    fn extract_ca_name_standard() {
        let output =
            "CA Name                             : CONTOSO-CA\nDNS Name  : ca01.contoso.local";
        assert_eq!(extract_ca_name(output), Some("CONTOSO-CA".to_string()));
    }

    #[test]
    fn extract_ca_name_no_spaces() {
        let output = "CA Name:MYCA\nother line";
        assert_eq!(extract_ca_name(output), Some("MYCA".to_string()));
    }

    #[test]
    fn extract_ca_name_missing() {
        assert_eq!(extract_ca_name("No CA info here"), None);
        assert_eq!(extract_ca_name(""), None);
    }

    #[test]
    fn extract_ca_name_empty_value() {
        assert_eq!(extract_ca_name("CA Name : "), None);
    }

    #[test]
    fn extract_ca_dns_name_standard() {
        let output =
            "CA Name                             : CONTOSO-CA\nDNS Name                            : ca01.contoso.local";
        assert_eq!(
            extract_ca_dns_name(output),
            Some("ca01.contoso.local".to_string())
        );
    }

    #[test]
    fn extract_ca_dns_name_missing_or_empty() {
        assert_eq!(extract_ca_dns_name("CA Name : CONTOSO-CA"), None);
        assert_eq!(extract_ca_dns_name("DNS Name : "), None);
        assert_eq!(extract_ca_dns_name(""), None);
    }

    #[test]
    fn parse_certipy_find_populates_ca_dns_name() {
        // CA runs on a dedicated host (ca01) distinct from the DC the LDAP
        // bind targets (192.168.58.10) — the exact split that broke ESC1.
        let output = "CA Name                             : CONTOSO-CA\n\
                      DNS Name                            : ca01.contoso.local\n\
                      [!] Vulnerabilities\n\
                      ESC1 : 'CONTOSO.LOCAL\\\\Domain Users' can enroll, enrollee supplies subject";
        let params = json!({ "domain": "contoso.local", "target": "192.168.58.10" });
        let vulns = parse_certipy_find(output, &params);
        assert!(
            vulns
                .iter()
                .any(|v| v["details"]["ca_dns_name"] == "ca01.contoso.local"),
            "expected ca_dns_name in vuln details, got {vulns:?}"
        );
    }

    #[test]
    fn extract_template_for_esc_basic() {
        let output = "Template Name                       : VulnTemplate\n    Permissions\n      ESC1 : 'DOMAIN\\Users' can enroll";
        assert_eq!(
            extract_template_for_esc(output, "esc1"),
            Some("VulnTemplate".to_string())
        );
    }

    #[test]
    fn extract_template_for_esc_not_found() {
        let output = "ESC1 : 'DOMAIN\\Users' can enroll";
        assert_eq!(extract_template_for_esc(output, "esc1"), None);
    }

    #[test]
    fn extract_template_for_esc_multiple_templates() {
        let output = "Template Name : Template1\n    ESC4 : misconfigured\nTemplate Name : Template2\n    ESC1 : enrollable";
        // ESC4 should get Template1
        assert_eq!(
            extract_template_for_esc(output, "esc4"),
            Some("Template1".to_string())
        );
        // ESC1 should get Template2
        assert_eq!(
            extract_template_for_esc(output, "esc1"),
            Some("Template2".to_string())
        );
    }

    #[test]
    fn extract_template_for_esc_does_not_match_longer_esc_number() {
        let output =
            "Template Name : Esc13Template\n    ESC13 : 'DOMAIN\\Users' issuance policy link";
        assert_eq!(extract_template_for_esc(output, "esc1"), None);
        assert_eq!(
            extract_template_for_esc(output, "esc13"),
            Some("Esc13Template".to_string())
        );
    }

    #[test]
    fn extract_template_for_esc_picks_own_template_when_esc13_precedes() {
        let output = "Template Name : Esc13Template\n    ESC13 : issuance policy link\nTemplate Name : Esc1Template\n    ESC1 : 'DOMAIN\\Users' can enroll";
        assert_eq!(
            extract_template_for_esc(output, "esc1"),
            Some("Esc1Template".to_string())
        );
    }

    #[test]
    fn esc_types_constant() {
        assert_eq!(ESC_TYPES.len(), 14);
        assert!(ESC_TYPES.contains(&"esc1"));
        assert!(ESC_TYPES.contains(&"esc8"));
        assert!(ESC_TYPES.contains(&"esc13"));
        assert!(ESC_TYPES.contains(&"esc15"));
        assert!(!ESC_TYPES.contains(&"esc12"));
        assert!(!ESC_TYPES.contains(&"esc16"));
    }

    #[test]
    fn parse_certipy_with_template_name() {
        let output = "Template Name                       : ESC1-Vuln\n    [!] Vulnerabilities\n    ESC1 : 'CONTOSO\\Users' can enroll";
        let params = json!({"target": "192.168.58.10", "domain": "contoso.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["details"]["template_name"], "ESC1-Vuln");
        // Template suffix included in vuln_id so multiple templates of the
        // same ESC type on the same CA don't collapse to one entry.
        assert_eq!(vulns[0]["vuln_id"], "adcs_esc1_192.168.58.10_esc1_vuln");
    }

    #[test]
    fn parse_certipy_two_templates_same_esc_type_dont_collapse() {
        // Two distinct vulnerable ESC1 templates on the same CA — without the
        // template suffix in vuln_id, the second would overwrite the first.
        let output =
            "Template Name                       : WebServer\n    [!] Vulnerabilities\n    ESC1 : 'CONTOSO\\Users' can enroll\nTemplate Name                       : User-AutoEnroll\n    [!] Vulnerabilities\n    ESC1 : 'CONTOSO\\Users' can enroll";
        let params = json!({"target": "192.168.58.10", "domain": "contoso.local"});
        let vulns = parse_certipy_find(output, &params);
        // Parser still emits one entry per matched ESC type per scan, but the
        // vuln_id MUST be template-qualified so re-runs across different CAs
        // / scans don't dedup-collapse onto the same key.
        assert!(
            vulns[0]["vuln_id"]
                .as_str()
                .unwrap()
                .starts_with("adcs_esc1_192.168.58.10_"),
            "vuln_id should include template slug: {}",
            vulns[0]["vuln_id"]
        );
    }

    #[test]
    fn slugify_template_basic() {
        assert_eq!(super::slugify_template("WebServer"), "webserver");
        assert_eq!(super::slugify_template("Web Server"), "web_server");
        assert_eq!(super::slugify_template("ESC1-Vuln"), "esc1_vuln");
        assert_eq!(super::slugify_template("a/b/c"), "a_b_c");
        assert_eq!(super::slugify_template("___leading"), "leading");
        assert_eq!(super::slugify_template("trailing___"), "trailing");
    }

    #[test]
    fn parse_certipy_vulnerability_inline_keyword() {
        // "vulnerab" keyword present alongside ESC type but no [!] Vulnerabilities header
        let output = "Certificate template is vulnerable to ESC1 attack";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn parse_certipy_colon_format() {
        // "ESC8:" format without spaces
        let output = "ESC8:web enrollment enabled";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc8");
    }

    #[test]
    fn parse_certipy_esc13_does_not_false_positive_esc1() {
        // ESC13 should not trigger false positive for ESC1
        let output = "[!] Vulnerabilities\nESC13 : Issuance Policy linked to group";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc13");
    }

    #[test]
    fn parse_certipy_ca_host_ip_used_as_target() {
        let output = "[!] Vulnerabilities\nESC1 : enrollee supplies subject";
        let params = json!({
            "target_ip": "192.168.58.10",  // DC IP
            "ca_host_ip": "192.168.58.50", // CA IP
            "domain": "contoso.local"
        });
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        // Should use ca_host_ip, not target_ip
        assert_eq!(vulns[0]["target"], "192.168.58.50");
        assert_eq!(vulns[0]["vuln_id"], "adcs_esc1_192.168.58.50");
        assert_eq!(vulns[0]["details"]["ca_host"], "192.168.58.50");
    }

    #[test]
    fn esc_word_boundary_match_basic() {
        assert!(super::esc_word_boundary_match("esc1 : vulnerable", "esc1"));
        assert!(super::esc_word_boundary_match("esc1:", "esc1"));
        assert!(!super::esc_word_boundary_match(
            "esc13 : vulnerable",
            "esc1"
        ));
        assert!(!super::esc_word_boundary_match(
            "esc15 : vulnerable",
            "esc1"
        ));
        assert!(super::esc_word_boundary_match(
            "esc13 : vulnerable",
            "esc13"
        ));
    }

    #[test]
    fn parse_certipy_esc1_chain_extracts_krbtgt_from_dcsync_tail() {
        // The essos forest root disables RC4, so `certipy auth` returns a TGT
        // but no NT hash (KDC_ERR_ETYPE_NOSUPP). The chain DCSyncs krbtgt with
        // the ccache; the krbtgt hash lands as secretsdump NTDS output. Domain
        // comes from the request params (NTDS `-just-dc-user` rows omit it).
        let output = "\
=== certipy req (ESC1, upn=administrator@contoso.local, sid=S-1-5-21-1-2-3-500) ===\n\
[*] Got certificate with UPN 'administrator@contoso.local'\n\
=== certipy auth (esc1_1.pfx) ===\n\
[*] Got TGT\n\
[*] Saving credential cache to 'administrator.ccache'\n\
[-] Failed to extract NT hash: Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)\n\
=== secretsdump krbtgt DCSync (target=contoso.local/administrator@dc01.contoso.local) ===\n\
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n\
[*] Using the DRSUAPI method to get NTDS.DIT secrets\n\
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9163a4143c00569b53db0feef6bdf2ad:::\n\
[*] Kerberos keys grabbed\n\
krbtgt:aes256-cts-hmac-sha1-96:ac960e5cfc69b6336f2ac9f4ba08aeda92ddb85c5607d0b6756a3e4c41a8adf9\n\
krbtgt:des-cbc-md5:ab7c3e43b5b07ca7\n\
[*] Cleaning up...";
        let params = json!({ "domain": "contoso.local" });
        let hashes = parse_certipy_esc1_chain(output, &params);
        assert_eq!(hashes.len(), 1, "expected one krbtgt hash, got {hashes:?}");
        let h = &hashes[0];
        assert_eq!(h["username"], "krbtgt");
        assert_eq!(h["domain"], "contoso.local");
        assert_eq!(h["hash_type"], "NTLM");
        assert_eq!(
            h["hash_value"],
            "aad3b435b51404eeaad3b435b51404ee:9163a4143c00569b53db0feef6bdf2ad"
        );
        assert_eq!(
            h["aes_key"],
            "ac960e5cfc69b6336f2ac9f4ba08aeda92ddb85c5607d0b6756a3e4c41a8adf9"
        );
    }

    #[test]
    fn parse_certipy_esc1_chain_still_parses_got_hash_line() {
        // RC4-enabled KDC path: `certipy auth` recovers the NT hash directly.
        // No DCSync tail runs; the "Got hash for" line must still be parsed.
        let output =
            "=== certipy auth (esc1_1.pfx) ===\n[*] Got hash for 'administrator@CONTOSO.LOCAL': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0";
        let hashes = parse_certipy_esc1_chain(output, &json!({ "domain": "contoso.local" }));
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "administrator");
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    fn shadow_auto_transcript(hash_line: &str) -> String {
        format!(
            "[*] Targeting user 'DC01$'\n\
[*] Generating certificate\n\
[*] Certificate generated\n\
[*] Generating Key Credential\n\
[*] Key Credential generated with DeviceID '4b1c9f2a-1234-4a2b-9c3d-abcdef012345'\n\
[*] Adding Key Credential with device ID '4b1c9f2a-1234-4a2b-9c3d-abcdef012345' to the Key Credentials for 'DC01$'\n\
[*] Successfully added Key Credential with device ID '4b1c9f2a-1234-4a2b-9c3d-abcdef012345' to the Key Credentials for 'DC01$'\n\
[*] Authenticating as 'DC01$' with the certificate\n\
[*] Using principal: 'dc01$@contoso.local'\n\
[*] Trying to get TGT...\n\
{hash_line}"
        )
    }

    fn shadow_auto_success() -> String {
        shadow_auto_transcript(
            "[*] Got TGT\n\
[*] Saving credential cache to 'dc01.ccache'\n\
[*] Wrote credential cache to 'dc01.ccache'\n\
[*] Trying to retrieve NT hash for 'DC01$'\n\
[*] Restoring the old Key Credentials for 'DC01$'\n\
[*] Successfully restored the old Key Credentials for 'DC01$'\n\
[*] NT hash for 'DC01$': 0123456789abcdef0123456789abcdef",
        )
    }

    fn shadow_auto_stage_one_only() -> String {
        shadow_auto_transcript(
            "[-] Got error while trying to request TGT: Kerberos SessionError: \
             KDC_ERR_CLIENT_NAME_MISMATCH(Requested certificate does not match the account)\n\
[*] Restoring the old Key Credentials for 'DC01$'\n\
[*] Successfully restored the old Key Credentials for 'DC01$'\n\
[*] NT hash for 'DC01$': None",
        )
    }

    #[test]
    fn parse_certipy_shadow_extracts_the_recovered_machine_account_hash() {
        let hashes = parse_certipy_shadow(
            &shadow_auto_success(),
            &json!({ "domain": "contoso.local", "target": "dc01$" }),
        );
        assert_eq!(hashes.len(), 1, "expected one NT hash, got {hashes:?}");
        assert_eq!(hashes[0]["username"], "dc01$");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(hashes[0]["hash_type"], "NTLM");
        assert_eq!(
            hashes[0]["hash_value"],
            "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
        );
        assert_eq!(hashes[0]["source"], "certipy_shadow");
    }

    #[test]
    fn parse_certipy_shadow_ignores_a_stage_one_only_run() {
        let hashes = parse_certipy_shadow(
            &shadow_auto_stage_one_only(),
            &json!({ "domain": "contoso.local", "target": "dc01$" }),
        );
        assert!(
            hashes.is_empty(),
            "a Key Credential write that never recovered a hash must publish nothing, got {hashes:?}"
        );
    }

    #[test]
    fn parse_certipy_shadow_reads_the_qualified_auth_line() {
        let output = "[*] Got hash for 'bob@FABRIKAM.LOCAL': \
                      aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef";
        let hashes = parse_certipy_shadow(output, &json!({ "domain": "contoso.local" }));
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "bob");
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
    }

    #[test]
    fn parse_certipy_shadow_rejects_a_truncated_hash() {
        let output = "[*] NT hash for 'DC01$': 0123456789abcdef";
        let hashes = parse_certipy_shadow(output, &json!({ "domain": "contoso.local" }));
        assert!(hashes.is_empty(), "got {hashes:?}");
    }

    #[test]
    fn parse_certipy_shadow_dedups_repeated_hash_lines() {
        let output = "[*] NT hash for 'DC01$': 0123456789abcdef0123456789abcdef\n\
                      [*] NT hash for 'dc01$': 0123456789abcdef0123456789abcdef";
        let hashes = parse_certipy_shadow(output, &json!({ "domain": "contoso.local" }));
        assert_eq!(hashes.len(), 1, "got {hashes:?}");
    }

    #[test]
    fn parse_certipy_find_padded_esc1_with_template() {
        // The real `certipy find -vulnerable -text -stdout` format pads the ESC
        // label with many spaces before the colon, and the vulnerable template
        // is literally named ESC1 (both Template Name and the vuln id are the
        // string "ESC1"). The parser must still surface adcs_esc1 with
        // template_name="ESC1" and target the CA host, not the DC.
        let output = "\
Certificate Authorities\n  0\n    CA Name                             : CONTOSO-CA\n    DNS Name                            : ca01.contoso.local\n\
Certificate Templates\n  0\n    Template Name                       : ESC1\n    [!] Vulnerabilities\n      ESC1                              : 'CONTOSO.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication";
        let params = json!({
            "domain": "contoso.local",
            "target": "192.168.58.10",   // DC (LDAP bind)
            "ca_host_ip": "192.168.58.50" // CA host (enrollment)
        });
        let vulns = parse_certipy_find(output, &params);
        let esc1 = vulns
            .iter()
            .find(|v| v["vuln_type"] == "adcs_esc1")
            .unwrap_or_else(|| panic!("expected adcs_esc1 in {vulns:?}"));
        assert_eq!(esc1["details"]["template_name"], "ESC1");
        assert_eq!(esc1["details"]["ca_name"], "CONTOSO-CA");
        assert_eq!(esc1["details"]["ca_dns_name"], "ca01.contoso.local");
        // Exploitation must target the CA host, not the DC used for LDAP.
        assert_eq!(esc1["target"], "192.168.58.50");
    }

    fn ca_block_with_esc16() -> String {
        "\
Certificate Authorities\n  0\n\
    CA Name                             : CONTOSO-CA\n\
    DNS Name                            : ca01.contoso.local\n\
    Request Disposition                 : Issue\n\
    Enforce Encryption for Requests     : Enabled\n\
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy\n\
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2\n\
    [!] Vulnerabilities\n\
      ESC16                             : Security Extension is disabled.\n"
            .to_string()
    }

    #[test]
    fn ca_security_extension_state_reads_the_esc16_label() {
        assert_eq!(
            ca_security_extension_state(&ca_block_with_esc16()),
            Some(true)
        );
    }

    #[test]
    fn ca_security_extension_state_reads_the_oid_without_the_esc16_label() {
        let output = "\
    CA Name                             : CONTOSO-CA\n\
    Request Disposition                 : Issue\n\
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2\n";
        assert_eq!(ca_security_extension_state(output), Some(true));
    }

    #[test]
    fn ca_security_extension_state_reads_a_wrapped_oid_list() {
        let output = "\
    Disabled Extensions                 : 1.3.6.1.4.1.311.21.7\n\
                                          1.3.6.1.4.1.311.25.2\n\
    [!] Vulnerabilities\n";
        assert_eq!(ca_security_extension_state(output), Some(true));
    }

    #[test]
    fn ca_security_extension_state_is_false_when_the_ca_stamps_the_sid() {
        let output = "\
    CA Name                             : CONTOSO-CA\n\
    Disabled Extensions                 : 1.3.6.1.4.1.311.21.7\n\
    [!] Vulnerabilities\n\
      ESC1                              : 'CONTOSO.LOCAL\\Domain Users' can enroll\n";
        assert_eq!(ca_security_extension_state(output), Some(false));
    }

    #[test]
    fn ca_security_extension_state_is_unknown_when_the_transcript_does_not_say() {
        assert_eq!(ca_security_extension_state(""), None);
        assert_eq!(
            ca_security_extension_state("    CA Name : CONTOSO-CA\n"),
            None
        );
        assert_eq!(
            ca_security_extension_state("    Disabled Extensions                 : Unknown\n"),
            None
        );
    }

    #[test]
    fn esc16_produces_no_vulnerability_record() {
        let vulns = parse_certipy_find(
            &ca_block_with_esc16(),
            &json!({ "target": "192.168.58.50", "domain": "contoso.local" }),
        );
        assert!(
            vulns.is_empty(),
            "ESC16 must not emit a vulnerability record, got {vulns:?}"
        );
    }

    #[test]
    fn parse_certipy_find_stamps_the_ca_fact_on_every_record() {
        let output = format!(
            "{}Certificate Templates\n  0\n\
    Template Name                       : UserAuth\n\
    [!] Vulnerabilities\n\
      ESC9                              : 'CONTOSO.LOCAL\\alice' has dangerous permissions\n\
  1\n\
    Template Name                       : WebServer\n\
    [!] Vulnerabilities\n\
      ESC3                              : 'CONTOSO.LOCAL\\Domain Users' can enroll\n",
            ca_block_with_esc16()
        );
        let vulns = parse_certipy_find(
            &output,
            &json!({ "target": "192.168.58.50", "domain": "contoso.local" }),
        );
        assert_eq!(
            vulns.len(),
            2,
            "ESC16 must not inflate the record set, got {vulns:?}"
        );
        for v in &vulns {
            assert_eq!(
                v["details"]["ca_security_extension_disabled"], true,
                "missing CA fact on {}",
                v["vuln_id"]
            );
        }
        let esc9 = vulns
            .iter()
            .find(|v| v["vuln_type"] == "adcs_esc9")
            .unwrap_or_else(|| panic!("expected adcs_esc9 in {vulns:?}"));
        assert_eq!(esc9["priority"], 1);
        let esc3 = vulns
            .iter()
            .find(|v| v["vuln_type"] == "adcs_esc3")
            .unwrap_or_else(|| panic!("expected adcs_esc3 in {vulns:?}"));
        assert_eq!(esc3["priority"], 3);
    }

    #[test]
    fn ca_that_stamps_the_sid_records_the_fact_without_reordering() {
        let output = "\
    CA Name                             : CONTOSO-CA\n\
    Disabled Extensions                 : 1.3.6.1.4.1.311.21.7\n\
Certificate Templates\n  0\n\
    Template Name                       : UserAuth\n\
    [!] Vulnerabilities\n\
      ESC9                              : 'CONTOSO.LOCAL\\alice' has dangerous permissions\n";
        let vulns = parse_certipy_find(
            output,
            &json!({ "target": "192.168.58.50", "domain": "contoso.local" }),
        );
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["details"]["ca_security_extension_disabled"], false);
        assert_eq!(vulns[0]["priority"], 4);
    }

    #[test]
    fn unknown_ca_state_leaves_records_untouched() {
        let output = "[!] Vulnerabilities\nESC9 : 'CONTOSO.LOCAL\\alice' has dangerous permissions";
        let vulns = parse_certipy_find(
            output,
            &json!({ "target": "192.168.58.50", "domain": "contoso.local" }),
        );
        assert_eq!(vulns.len(), 1);
        assert!(
            vulns[0]["details"]
                .get("ca_security_extension_disabled")
                .is_none(),
            "an unread CA must not assert either state"
        );
        assert_eq!(vulns[0]["priority"], 4);
    }
}
