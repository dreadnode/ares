//! Delegation vulnerability parser.

use serde_json::{json, Value};

pub fn parse_delegation(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let target_ip = params
        .get("target")
        .or_else(|| params.get("target_ip"))
        .or_else(|| params.get("dc_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut vulns = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        let trimmed = line.trim();
        let line_lower = trimmed.to_lowercase();

        // Skip header, separator, and noise lines
        if trimmed.starts_with("AccountName")
            || trimmed.starts_with("---")
            || trimmed.starts_with("[")
            || trimmed.starts_with("Impacket")
            || trimmed.is_empty()
        {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        // Determine delegation type from keywords in the line. "resource" /
        // "rbcd" MUST be checked before "constrained" because findDelegation
        // prints "Resource-Based Constrained Delegation" which also contains
        // "constrained" — matching constrained first would misroute RBCD rows to
        // the S4U automation, which always fails on them.
        let delegation_type = if line_lower.contains("unconstrained") {
            "unconstrained"
        } else if line_lower.contains("resource") || line_lower.contains("rbcd") {
            "rbcd"
        } else if line_lower.contains("constrained") {
            "constrained"
        } else {
            continue;
        };

        // For constrained delegation, distinguish protocol-transition
        // (S4U2Self+S4U2Proxy works from a cleartext/hash) from kerberos-only
        // (S4U2Self is rejected — needs an existing TGT, e.g. a machine account).
        // findDelegation annotates this as "w/ Protocol Transition" vs
        // "w/o Protocol Transition". Default true (the common, plain-"Constrained"
        // case) preserves prior behaviour; only an explicit "w/o" flips it.
        let protocol_transition =
            !(line_lower.contains("w/o protocol") || line_lower.contains("without protocol"));

        let account = extract_delegation_account(trimmed);
        if account.is_empty() {
            continue;
        }

        // Extract delegation target SPN by scanning for "service/host" pattern.
        // This handles variable-width DelegationType columns like
        // "Constrained w/ Protocol Transition" that break simple column indexing.
        let delegation_target = extract_spn_from_parts(&parts);

        // RBCD uses the bare "rbcd" vuln_type that auto_rbcd_exploitation
        // watches; constrained/unconstrained use the "{type}_delegation" form.
        let vuln_type = if delegation_type == "rbcd" {
            "rbcd".to_string()
        } else {
            format!("{delegation_type}_delegation")
        };
        let dedup_key = format!("{}:{}", account.to_lowercase(), vuln_type);
        if !seen.insert(dedup_key) {
            continue; // skip duplicate account+type
        }

        let mut details = json!({
            "account_name": account,
            "domain": domain,
            "delegation_type": delegation_type,
        });
        if let Some(ref spn) = delegation_target {
            details["delegation_target"] = json!(spn);
        }
        if delegation_type == "constrained" {
            details["protocol_transition"] = json!(protocol_transition);
        }

        vulns.push(json!({
            "vuln_id": format!("{}_{}", vuln_type, account),
            "vuln_type": vuln_type,
            "target": target_ip,
            "discovered_by": "find_delegation",
            "details": details,
            "recommended_agent": "privesc",
            "priority": match delegation_type {
                "constrained" => 8,
                "rbcd" => 6,
                _ => 7,
            },
        }));
    }

    vulns
}

/// Extract `service/host` SPN from whitespace-split parts.
/// Skips tokens like "w/", "w/o", and bracket-prefixed items.
fn extract_spn_from_parts(parts: &[&str]) -> Option<String> {
    for part in parts {
        if !part.contains('/') {
            continue;
        }
        // Skip "w/", "w/o", "N/A"
        if *part == "w/" || *part == "w/o" || part.eq_ignore_ascii_case("n/a") {
            continue;
        }
        // Skip bracket-prefixed tokens like "[*]"
        if part.starts_with('[') {
            continue;
        }
        // Must look like service/host (alphabetic after the slash)
        if let Some(slash_idx) = part.find('/') {
            if slash_idx + 1 < part.len() && part.as_bytes()[slash_idx + 1].is_ascii_alphabetic() {
                return Some(part.to_string());
            }
        }
    }
    None
}

pub fn extract_delegation_account(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if !parts.is_empty() {
        // Account might be "DOMAIN/account$" or just "account$"
        let account = parts[0];
        if account.contains('/') {
            account
                .split('/')
                .next_back()
                .unwrap_or(account)
                .to_string()
        } else {
            account.to_string()
        }
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_delegation_constrained() {
        let output = "\
AccountName                    AccountType  DelegationType       DelegationRightsTo
svc_sql$                       Computer     Constrained          CIFS/dc01.contoso.local";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[0]["target"], "192.168.58.10");
        assert_eq!(vulns[0]["details"]["account_name"], "svc_sql$");
        assert_eq!(vulns[0]["details"]["domain"], "contoso.local");
        assert_eq!(
            vulns[0]["details"]["delegation_target"],
            "CIFS/dc01.contoso.local"
        );
        assert_eq!(vulns[0]["discovered_by"], "find_delegation");
    }

    #[test]
    fn parse_delegation_unconstrained() {
        let output = "DC01$  Computer  Unconstrained  N/A";
        let params = json!({"domain": "contoso.local", "target": "192.168.58.10"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "unconstrained_delegation");
        assert_eq!(vulns[0]["discovered_by"], "find_delegation");
    }

    #[test]
    fn parse_delegation_mixed() {
        let output = "\
AccountName  AccountType  DelegationType  DelegationRightsTo
svc_sql$     Computer     Constrained     CIFS/dc01.contoso.local
DC01$        Computer     Unconstrained   N/A";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[1]["vuln_type"], "unconstrained_delegation");
    }

    #[test]
    fn parse_delegation_no_results() {
        let vulns = parse_delegation("[*] No delegation found", &json!({}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn extract_delegation_account_with_domain_prefix() {
        assert_eq!(
            extract_delegation_account("CONTOSO/svc_sql$  Computer  Constrained"),
            "svc_sql$"
        );
    }

    #[test]
    fn extract_delegation_account_without_prefix() {
        assert_eq!(
            extract_delegation_account("svc_sql$  Computer  Constrained"),
            "svc_sql$"
        );
    }

    #[test]
    fn extract_delegation_account_empty() {
        assert_eq!(extract_delegation_account(""), "");
    }

    /// Test with "SPN Exists" column and multi-word DelegationType
    /// like "Constrained w/ Protocol Transition".
    #[test]
    fn parse_delegation_extended_format() {
        let output = "\
Impacket v0.13.0.dev0+20251022.125034.d843881f - Copyright Fortra, LLC and its affiliated companies

AccountName   AccountType  DelegationType                       DelegationRightsTo                         SPN Exists
------------  -----------  -----------------------------------  -----------------------------------------  ----------
sarah.connor   Person       Unconstrained                        N/A                                        No
john.smith      Person       Constrained w/ Protocol Transition   CIFS/dc02                            No
john.smith      Person       Constrained w/ Protocol Transition   CIFS/dc02.child.contoso.local  No
SRV01$  Computer     Constrained w/o Protocol Transition  HTTP/dc02                            No
SRV01$  Computer     Constrained w/o Protocol Transition  HTTP/dc02.child.contoso.local  Yes
DC02$   Computer     Unconstrained                        N/A                                        Yes

";
        let params = json!({"domain": "child.contoso.local", "target_ip": "192.168.58.11"});
        let vulns = parse_delegation(output, &params);

        // Dedup: sarah.connor unconstrained, john.smith constrained,
        // SRV01$ constrained, DC02$ unconstrained = 4
        assert_eq!(vulns.len(), 4, "Expected 4 deduped vulns, got {:?}", vulns);

        // sarah.connor → unconstrained
        assert_eq!(vulns[0]["vuln_type"], "unconstrained_delegation");
        assert_eq!(vulns[0]["details"]["account_name"], "sarah.connor");

        // john.smith → constrained with SPN
        assert_eq!(vulns[1]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[1]["details"]["account_name"], "john.smith");
        let spn = vulns[1]["details"]["delegation_target"].as_str().unwrap();
        assert!(
            spn.starts_with("CIFS/dc02"),
            "Expected CIFS/dc02 SPN, got {}",
            spn
        );

        // SRV01$ → constrained with HTTP SPN
        assert_eq!(vulns[2]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[2]["details"]["account_name"], "SRV01$");
        let spn = vulns[2]["details"]["delegation_target"].as_str().unwrap();
        assert!(
            spn.starts_with("HTTP/dc02"),
            "Expected HTTP/dc02 SPN, got {}",
            spn
        );

        // DC02$ → unconstrained
        assert_eq!(vulns[3]["vuln_type"], "unconstrained_delegation");
        assert_eq!(vulns[3]["details"]["account_name"], "DC02$");

        // All should have discovered_by
        for v in &vulns {
            assert_eq!(v["discovered_by"], "find_delegation");
        }
    }

    #[test]
    fn parse_delegation_rbcd_not_misclassified_as_constrained() {
        // findDelegation prints "Resource-Based Constrained Delegation" — must
        // classify as rbcd, not constrained (which would misroute to S4U).
        let output = "\
AccountName  AccountType  DelegationType                          DelegationRightsTo
svc$         Computer     Resource-Based Constrained Delegation   dc01$";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.1"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "rbcd");
    }

    #[test]
    fn parse_delegation_protocol_transition_flag() {
        let output = "\
AccountName  AccountType  DelegationType                       DelegationRightsTo
alice        Person       Constrained w/ Protocol Transition   HTTP/web01
ws01$        Computer     Constrained w/o Protocol Transition  HTTP/web01";
        let params = json!({"domain": "child.contoso.local", "target_ip": "192.168.58.2"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0]["details"]["protocol_transition"], true);
        assert_eq!(vulns[1]["details"]["protocol_transition"], false);
    }

    #[test]
    fn spn_basic() {
        let parts = vec!["Constrained", "CIFS/dc01.contoso.local"];
        assert_eq!(
            extract_spn_from_parts(&parts),
            Some("CIFS/dc01.contoso.local".to_string())
        );
    }

    #[test]
    fn spn_skips_w_slash() {
        let parts = vec!["Constrained", "w/", "Protocol", "CIFS/dc01"];
        assert_eq!(
            extract_spn_from_parts(&parts),
            Some("CIFS/dc01".to_string())
        );
    }

    #[test]
    fn spn_skips_w_slash_o() {
        let parts = vec!["Constrained", "w/o", "Protocol", "HTTP/web01"];
        assert_eq!(
            extract_spn_from_parts(&parts),
            Some("HTTP/web01".to_string())
        );
    }

    #[test]
    fn spn_skips_bracket_tokens() {
        let parts = vec!["[*]", "CIFS/dc01"];
        assert_eq!(
            extract_spn_from_parts(&parts),
            Some("CIFS/dc01".to_string())
        );
    }

    #[test]
    fn spn_no_valid_spn() {
        let parts = vec!["N/A", "w/", "w/o"];
        assert_eq!(extract_spn_from_parts(&parts), None);
    }

    #[test]
    fn spn_empty() {
        let parts: Vec<&str> = vec![];
        assert_eq!(extract_spn_from_parts(&parts), None);
    }

    #[test]
    fn spn_numeric_after_slash_skipped() {
        // "3/4" has a digit after slash, not alphabetic
        let parts = vec!["3/4", "LDAP/dc01"];
        assert_eq!(
            extract_spn_from_parts(&parts),
            Some("LDAP/dc01".to_string())
        );
    }
}

/// Banner impacket-addcomputer prints on a successful creation, carrying the
/// account name and password it actually used.
pub(crate) const ADD_COMPUTER_BANNER: &str = "Successfully added machine account ";

/// Pull `(name, password)` out of impacket-addcomputer's success banner
/// (`Successfully added machine account WS01$ with password P@ssw0rd!.`).
pub fn scrape_added_machine_account(output: &str) -> Option<(&str, &str)> {
    let i = output.find(ADD_COMPUTER_BANNER)?;
    let line = output[i + ADD_COMPUTER_BANNER.len()..].lines().next()?;
    let (name, password) = line.split_once(" with password ")?;
    let password = password.trim();
    let password = password.strip_suffix('.').unwrap_or(password);
    let name = name.trim();
    (!name.is_empty() && !password.is_empty()).then_some((name, password))
}

/// Recover the machine account created by `add_computer`.
///
/// The name and password are read back out of the success banner rather than
/// echoed from the call's params: `build_add_computer` mints both on the add
/// path, so the params the agent supplied are not what ended up in the
/// directory. Without this credential the account is unusable by later RBCD
/// steps, which look the principal up in operation state rather than
/// re-reading tool text.
pub fn parse_add_computer(output: &str, params: &Value) -> Vec<Value> {
    let Some((name, password)) = scrape_added_machine_account(output) else {
        return Vec::new();
    };
    let username = if name.ends_with('$') {
        name.to_string()
    } else {
        format!("{name}$")
    };
    vec![json!({
        "username": username,
        "password": password,
        "domain": params.get("domain").and_then(|v| v.as_str()).unwrap_or(""),
        "source": "add_computer",
        "is_admin": false,
    })]
}

/// Marker `privesc::delegation::generate_silver_ticket` appends to ticketer's
/// stdout carrying the SPN the ticket was scoped to.
///
/// ticketer prints the same `Saving ticket in <principal>.ccache` line for a
/// TGT and a TGS, so the SPN is the only thing that identifies a forge as a
/// silver ticket. Both the parser below and the orchestrator's golden-ticket
/// completion check key off this marker.
pub const SILVER_TICKET_SPN_MARKER: &str = "[ares] silver_ticket_spn: ";

/// Extract the forged service ticket from `generate_silver_ticket` output.
///
/// A silver ticket produces no credential, hash, or host — its whole result is
/// a ccache on disk bound to one SPN. The orchestrator's exploit evidence gate
/// only credits a task when `discoveries` carries something a parser put there,
/// so without this the forge lands as a *failed* exploit despite ticketer
/// exiting 0. The record goes under `spns` because that is an evidence-only
/// discovery key: it satisfies the gate without being re-queued for
/// exploitation the way a `vulnerabilities` entry would be.
pub fn parse_silver_ticket(output: &str, params: &Value) -> Vec<Value> {
    let Some(spn) = output
        .lines()
        .find_map(|l| l.trim().strip_prefix(SILVER_TICKET_SPN_MARKER))
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Vec::new();
    };
    let ccache = output
        .lines()
        .find_map(|l| l.trim().rsplit_once("Saving ticket in "))
        .map(|(_, path)| path.trim())
        .filter(|p| p.ends_with(".ccache"));
    let Some(ccache) = ccache else {
        return Vec::new();
    };
    let param = |key: &str| params.get(key).and_then(|v| v.as_str()).unwrap_or("");
    vec![json!({
        "spn": spn,
        "service_account": param("username"),
        "domain": param("domain"),
        "impersonated": params
            .get("impersonate")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("Administrator"),
        "ticket_path": ccache,
        "source": "generate_silver_ticket",
    })]
}

#[cfg(test)]
mod silver_ticket_tests {
    use super::*;

    fn params() -> Value {
        json!({
            "username": "SQL01$",
            "domain": "contoso.local",
            "spn": "MSSQLSvc/sql01.contoso.local:1433",
        })
    }

    fn forged(spn: &str) -> String {
        format!(
            "Impacket v0.13.0\n\
             [*] Creating basic skeleton ticket and PAC Infos\n\
             [*] Signing/Encrypting final ticket\n\
             [*] Saving ticket in Administrator.ccache\n\
             {SILVER_TICKET_SPN_MARKER}{spn}\n"
        )
    }

    #[test]
    fn records_the_forged_service_ticket() {
        let out = forged("MSSQLSvc/sql01.contoso.local:1433");
        let spns = parse_silver_ticket(&out, &params());
        assert_eq!(spns.len(), 1);
        assert_eq!(spns[0]["spn"], "MSSQLSvc/sql01.contoso.local:1433");
        assert_eq!(spns[0]["service_account"], "SQL01$");
        assert_eq!(spns[0]["domain"], "contoso.local");
        assert_eq!(spns[0]["impersonated"], "Administrator");
        assert_eq!(spns[0]["ticket_path"], "Administrator.ccache");
        assert_eq!(spns[0]["source"], "generate_silver_ticket");
    }

    #[test]
    fn carries_the_impersonated_principal_from_params() {
        let mut p = params();
        p.as_object_mut()
            .unwrap()
            .insert("impersonate".into(), json!("alice"));
        let spns = parse_silver_ticket(&forged("cifs/sql01.contoso.local"), &p);
        assert_eq!(spns[0]["impersonated"], "alice");
    }

    /// ticketer exits 0 on some failures and the marker is only appended on
    /// success, so evidence must require BOTH the marker and the saved ccache.
    #[test]
    fn requires_both_the_marker_and_a_saved_ccache() {
        let no_marker = "[*] Saving ticket in Administrator.ccache\n";
        assert!(parse_silver_ticket(no_marker, &params()).is_empty());

        let no_ccache =
            format!("[-] Kerberos SessionError\n{SILVER_TICKET_SPN_MARKER}cifs/sql01\n");
        assert!(parse_silver_ticket(&no_ccache, &params()).is_empty());
    }

    #[test]
    fn ignores_a_ticket_saved_to_a_non_ccache_path() {
        let kirbi = format!(
            "[*] Saving ticket in Administrator.kirbi\n{SILVER_TICKET_SPN_MARKER}cifs/sql01\n"
        );
        assert!(parse_silver_ticket(&kirbi, &params()).is_empty());
    }

    #[test]
    fn empty_marker_value_yields_no_evidence() {
        let blank = format!("[*] Saving ticket in a.ccache\n{SILVER_TICKET_SPN_MARKER}\n");
        assert!(parse_silver_ticket(&blank, &params()).is_empty());
    }
}

#[cfg(test)]
mod add_computer_tests {
    use super::*;

    fn params() -> Value {
        json!({ "domain": "contoso.local" })
    }

    fn banner(name: &str, password: &str) -> String {
        format!("[*] Successfully added machine account {name} with password {password}.")
    }

    #[test]
    fn recovers_machine_account_on_success() {
        let creds = parse_add_computer(&banner("ARES-1A2B3C4D$", "P@ssw0rd!"), &params());
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "ARES-1A2B3C4D$");
        assert_eq!(creds[0]["password"], "P@ssw0rd!");
        assert_eq!(creds[0]["domain"], "contoso.local");
        assert_eq!(creds[0]["source"], "add_computer");
    }

    /// The banner is authoritative: `build_add_computer` mints the identity, so
    /// a name the agent asked for is not what reached the directory. Trusting
    /// params here stored a lab-flavoured name that no such account ever had.
    #[test]
    fn banner_wins_over_caller_supplied_params() {
        let mut p = params();
        p["computer_name"] = json!("ws01");
        p["computer_password"] = json!("Requested123!");
        let creds = parse_add_computer(&banner("ARES-1A2B3C4D$", "Minted123!"), &p);
        assert_eq!(creds[0]["username"], "ARES-1A2B3C4D$");
        assert_eq!(creds[0]["password"], "Minted123!");
    }

    #[test]
    fn appends_missing_trailing_dollar() {
        let creds = parse_add_computer(&banner("ARES-1A2B3C4D", "P@ssw0rd!"), &params());
        assert_eq!(creds[0]["username"], "ARES-1A2B3C4D$");
    }

    /// impacket terminates the banner with a period; it is punctuation, not
    /// part of the password, but only the last one is.
    #[test]
    fn strips_only_the_banner_terminator() {
        let creds = parse_add_computer(&banner("ARES-1A2B3C4D$", "pass."), &params());
        assert_eq!(creds[0]["password"], "pass.");
    }

    #[test]
    fn ignores_refusal_that_still_exits_zero() {
        let refused = "[-] Could not add machine account: ACCESS_DENIED";
        assert!(parse_add_computer(refused, &params()).is_empty());
    }

    /// A banner without the password clause cannot yield a usable credential,
    /// and params are no longer a fallback.
    #[test]
    fn requires_the_password_clause() {
        let truncated = "[*] Successfully added machine account ARES-1A2B3C4D$";
        assert!(parse_add_computer(truncated, &params()).is_empty());
    }
}
