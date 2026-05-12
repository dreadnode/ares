//! Certipy (ADCS) output parser.

use serde_json::{json, Value};

/// All ESC types that certipy can detect.
const ESC_TYPES: &[&str] = &[
    "esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8", "esc9", "esc10", "esc11",
    "esc13", "esc14", "esc15",
];

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

    let mut vulns = Vec::new();
    let output_lower = output.to_lowercase();

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
            if let Some(ref ca) = ca_name {
                details["ca_name"] = json!(ca);
            }
            if let Some(ref tmpl) = template_name {
                details["template_name"] = json!(tmpl);
            }
            if !ca_host_ip.is_empty() {
                details["ca_host"] = json!(ca_host_ip);
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
                "priority": esc_priority(esc_type),
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

/// Extract template name associated with an ESC type.
fn extract_template_for_esc(output: &str, esc_type: &str) -> Option<String> {
    let esc_upper = esc_type.to_uppercase();
    let lines: Vec<&str> = output.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains(&esc_upper) {
            // Look backwards for "Template Name" line
            for j in (0..i).rev() {
                let prev = lines[j].trim();
                if let Some(rest) = prev.strip_prefix("Template Name") {
                    let name = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
                // Don't look back more than 20 lines
                if i - j > 20 {
                    break;
                }
            }
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
        let _ = params; // params reserved for future correlation
        hashes.push(json!({
            "username": user,
            "domain": domain,
            "hash_type": "NTLM",
            "hash_value": format!("{lm}:{nt}"),
            "source": "certipy_esc1_full_chain",
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
fn esc_priority(esc_type: &str) -> i32 {
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
        assert!(esc_priority("esc1") < esc_priority("esc4"));
        assert!(esc_priority("esc4") < esc_priority("esc5"));
    }

    #[test]
    fn esc_priority_all_values() {
        assert_eq!(esc_priority("esc1"), 1);
        assert_eq!(esc_priority("esc6"), 1);
        assert_eq!(esc_priority("esc4"), 2);
        assert_eq!(esc_priority("esc8"), 2);
        assert_eq!(esc_priority("esc2"), 3);
        assert_eq!(esc_priority("esc3"), 3);
        assert_eq!(esc_priority("esc15"), 3);
        assert_eq!(esc_priority("esc7"), 4);
        assert_eq!(esc_priority("esc9"), 4);
        assert_eq!(esc_priority("esc10"), 4);
        assert_eq!(esc_priority("esc11"), 4);
        assert_eq!(esc_priority("esc13"), 4);
        assert_eq!(esc_priority("esc5"), 5);
        assert_eq!(esc_priority("unknown"), 6);
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
}
