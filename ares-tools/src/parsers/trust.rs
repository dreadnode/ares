//! Parser for `enumerate_domain_trusts` (ldapsearch trustedDomain) output.

use serde_json::{json, Value};

/// LDAP trustDirection values (MS-ADTS 6.1.6.7.9).
const TRUST_DIRECTION_INBOUND: u32 = 1;
const TRUST_DIRECTION_OUTBOUND: u32 = 2;
const TRUST_DIRECTION_BIDIRECTIONAL: u32 = 3;

/// LDAP trustType values (MS-ADTS 6.1.6.7.10).
const TRUST_TYPE_PARENT_CHILD: u32 = 1; // same forest
const TRUST_TYPE_TREE_ROOT: u32 = 2; // tree root (also intra-forest)

/// LDAP trustAttributes (MS-ADTS 6.1.6.7.9) flags.
const TRUST_ATTR_FOREST_TRANSITIVE: u32 = 0x00000008;
const TRUST_ATTR_WITHIN_FOREST: u32 = 0x00000020;
const TRUST_ATTR_QUARANTINED_DOMAIN: u32 = 0x00000004;

/// Parse `enumerate_domain_trusts` ldapsearch output into TrustInfo-compatible JSON values.
///
/// Returns JSON objects matching the `TrustInfo` schema:
/// `{ "domain", "flat_name", "direction", "trust_type", "sid_filtering" }`
pub fn parse_domain_trusts(output: &str) -> Vec<Value> {
    let mut results = Vec::new();

    let mut cn = String::new();
    let mut trust_direction: u32 = 0;
    let mut trust_type: u32 = 0;
    let mut trust_attributes: u32 = 0;
    let mut flat_name = String::new();
    let mut security_identifier: Option<String> = None;

    let flush = |cn: &str,
                 trust_direction: u32,
                 trust_type: u32,
                 trust_attributes: u32,
                 flat_name: &str,
                 security_identifier: &Option<String>|
     -> Option<Value> {
        if cn.is_empty() {
            return None;
        }

        let direction = match trust_direction {
            TRUST_DIRECTION_INBOUND => "inbound",
            TRUST_DIRECTION_OUTBOUND => "outbound",
            TRUST_DIRECTION_BIDIRECTIONAL => "bidirectional",
            _ => "unknown",
        };

        let classified_type = classify_trust_type(trust_type, trust_attributes, cn);

        // Modern AD defaults to SID filtering on cross-forest/external trusts,
        // but `netdom trust /SidFiltering /Disable` is a common lab and
        // production reconfiguration with no corresponding LDAP attribute. The
        // only authoritative LDAP-visible signal that filtering is *on* is the
        // QUARANTINED_DOMAIN bit, which AD sets when a trust has been
        // explicitly quarantined. Inferring filtering from FOREST_TRANSITIVE
        // alone (or from classified_type) is a false-positive that
        // permanently suppresses `forge_inter_realm_and_dump` against any
        // misconfigured cross-forest trust — losing the entire foreign forest
        // (the op-20260502-185055 fabrikam regression). The forge's
        // dedup-on-empty-output path already handles the false-negative case
        // (~30s doomed DCSync, then dedup locks and fallbacks fire).
        let sid_filtering = trust_attributes & TRUST_ATTR_QUARANTINED_DOMAIN != 0;

        let mut obj = serde_json::Map::new();
        obj.insert("domain".into(), json!(cn.to_lowercase()));
        obj.insert("flat_name".into(), json!(flat_name));
        obj.insert("direction".into(), json!(direction));
        obj.insert("trust_type".into(), json!(classified_type));
        obj.insert("sid_filtering".into(), json!(sid_filtering));
        if let Some(sid) = security_identifier {
            obj.insert("security_identifier".into(), json!(sid));
        }
        Some(Value::Object(obj))
    };

    for line in output.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            if let Some(trust) = flush(
                &cn,
                trust_direction,
                trust_type,
                trust_attributes,
                &flat_name,
                &security_identifier,
            ) {
                results.push(trust);
            }
            cn.clear();
            trust_direction = 0;
            trust_type = 0;
            trust_attributes = 0;
            flat_name.clear();
            security_identifier = None;
            continue;
        }

        if line.starts_with("dn:") || line.starts_with("objectClass:") {
            continue;
        }

        if let Some(val) = line.strip_prefix("cn: ") {
            cn = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("trustDirection: ") {
            trust_direction = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("trustType: ") {
            trust_type = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("trustAttributes: ") {
            trust_attributes = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("flatName: ") {
            flat_name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("securityIdentifier: ") {
            // Canonical text form, emitted by the impacket-LDAP variant of
            // `enumerate_domain_trusts` after `LDAP_SID.formatCanonical()`.
            security_identifier = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("securityIdentifier:: ") {
            // ldapsearch emits binary attrs as base64 with a `::` separator.
            // Decode to bytes and parse the SID structure
            // (S-1-<auth>-<sub_auth1>-...).
            if let Some(sid) = decode_ldap_sid_base64(val.trim()) {
                security_identifier = Some(sid);
            }
        }
    }

    // Flush last block
    if let Some(trust) = flush(
        &cn,
        trust_direction,
        trust_type,
        trust_attributes,
        &flat_name,
        &security_identifier,
    ) {
        results.push(trust);
    }

    results
}

/// Decode a base64-encoded binary SID (as emitted by ldapsearch's `attr:: <b64>`
/// output format) into the canonical `S-1-<auth>-<sub_1>-<sub_2>-...` string.
///
/// The Microsoft binary SID format (MS-DTYP 2.4.2):
///   - Byte 0: revision (always 1 for AD SIDs)
///   - Byte 1: SubAuthorityCount (number of 32-bit sub-authority values)
///   - Bytes 2-7: IdentifierAuthority (6 bytes, big-endian)
///   - Bytes 8+: SubAuthority array (4 bytes each, little-endian)
///
/// Returns `None` when the input isn't a well-formed SID — better to drop the
/// SID and let the trust load without it than to inject a malformed value
/// that the downstream `auto_trust_follow` would feed into ticketer's
/// `extra_sid` arg as `<bad_sid>-519`.
fn decode_ldap_sid_base64(b64: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    if revision != 1 {
        return None;
    }
    let sub_count = bytes[1] as usize;
    // Need 8 bytes header + 4 bytes per sub-authority.
    if bytes.len() < 8 + 4 * sub_count {
        return None;
    }
    // IdentifierAuthority is 6 bytes big-endian. In practice it fits in u32
    // for all AD SIDs (the top two bytes are always zero), but we read all 6
    // for safety in case a non-AD SID slips through.
    let mut auth_value: u64 = 0;
    for &b in &bytes[2..8] {
        auth_value = (auth_value << 8) | u64::from(b);
    }
    let mut s = format!("S-{revision}-{auth_value}");
    for i in 0..sub_count {
        let off = 8 + 4 * i;
        let sub = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

/// Classify trust type from LDAP trustType and trustAttributes values.
///
/// trustAttributes is the authoritative signal:
/// - WITHIN_FOREST (0x20) → intra-forest (parent_child or tree_root)
/// - FOREST_TRANSITIVE (0x08) → cross-forest
/// - QUARANTINED_DOMAIN (0x04) → external (with SID filtering)
///
/// trustType is largely informational in modern AD (almost always 2 = uplevel).
/// Fall back to cn-label heuristics only when attributes are missing.
fn classify_trust_type(trust_type: u32, trust_attributes: u32, cn: &str) -> String {
    // Authoritative attribute checks first.
    if trust_attributes & TRUST_ATTR_WITHIN_FOREST != 0 {
        return "parent_child".to_string();
    }
    if trust_attributes & TRUST_ATTR_FOREST_TRANSITIVE != 0 {
        return "forest".to_string();
    }
    if trust_attributes & TRUST_ATTR_QUARANTINED_DOMAIN != 0 {
        return "external".to_string();
    }

    // Fall back to legacy trustType-based heuristics.
    match trust_type {
        TRUST_TYPE_PARENT_CHILD => "parent_child".to_string(),
        TRUST_TYPE_TREE_ROOT => {
            let parts: Vec<&str> = cn.split('.').collect();
            if parts.len() >= 3 {
                "parent_child".to_string()
            } else {
                "forest".to_string()
            }
        }
        _ => "external".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cross_forest_trust() {
        let output = r#"dn: CN=fabrikam.local,CN=System,DC=contoso,DC=local
cn: fabrikam.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: FABRIKAM
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["domain"], "fabrikam.local");
        assert_eq!(trusts[0]["flat_name"], "FABRIKAM");
        assert_eq!(trusts[0]["direction"], "bidirectional");
        assert_eq!(trusts[0]["trust_type"], "forest");
        // FOREST_TRANSITIVE (0x08) alone does NOT imply SID filtering — only
        // QUARANTINED_DOMAIN (0x04) is authoritative. See parse_domain_trusts.
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_parent_child_trust() {
        let output = r#"dn: CN=child.contoso.local,CN=System,DC=contoso,DC=local
cn: child.contoso.local
trustDirection: 3
trustType: 1
trustAttributes: 0
flatName: CHILD
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["domain"], "child.contoso.local");
        assert_eq!(trusts[0]["trust_type"], "parent_child");
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_multiple_trusts() {
        let output = r#"dn: CN=fabrikam.local,CN=System,DC=contoso,DC=local
cn: fabrikam.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: FABRIKAM

dn: CN=child.contoso.local,CN=System,DC=contoso,DC=local
cn: child.contoso.local
trustDirection: 3
trustType: 1
trustAttributes: 0
flatName: CHILD
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 2);
        assert_eq!(trusts[0]["trust_type"], "forest");
        assert_eq!(trusts[1]["trust_type"], "parent_child");
    }

    #[test]
    fn parse_inbound_trust() {
        let output =
            "cn: partner.com\ntrustDirection: 1\ntrustType: 3\ntrustAttributes: 0\nflatName: PARTNER\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["direction"], "inbound");
        assert_eq!(trusts[0]["trust_type"], "external");
    }

    #[test]
    fn parse_empty_output() {
        let trusts = parse_domain_trusts("");
        assert!(trusts.is_empty());
    }

    #[test]
    fn parse_no_trusts_search_result() {
        let output = "# search result\nsearch: 2\nresult: 0 Success\n";
        let trusts = parse_domain_trusts(output);
        assert!(trusts.is_empty());
    }

    #[test]
    fn parse_outbound_trust() {
        let output = "cn: external.com\ntrustDirection: 2\ntrustType: 3\ntrustAttributes: 0\nflatName: EXTERNAL\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["direction"], "outbound");
        assert_eq!(trusts[0]["trust_type"], "external");
        // Without QUARANTINED_DOMAIN we don't infer SID filtering — labs and
        // misconfigured prod often have it disabled and there's no other
        // LDAP-visible signal. The forge will attempt and dedup-on-empty if
        // filtering is actually on.
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_trust_unknown_direction() {
        let output = "cn: mystery.local\ntrustDirection: 99\ntrustType: 1\ntrustAttributes: 0\nflatName: MYSTERY\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["direction"], "unknown");
    }

    #[test]
    fn parse_trust_tree_root_short_domain() {
        // trustType=2 with short domain (< 3 labels) → forest
        let output = "cn: fabrikam.com\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 0\nflatName: FABRIKAM\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "forest");
    }

    #[test]
    fn parse_trust_tree_root_long_domain() {
        // trustType=2 with 3+ labels → parent_child
        let output = "cn: child.contoso.local\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 0\nflatName: CHILD\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "parent_child");
    }

    #[test]
    fn parse_trust_within_forest_from_child_view() {
        // When enumerating from child looking up to parent, cn is short
        // ("contoso.local") but trustAttributes has WITHIN_FOREST (0x20).
        // The attribute is authoritative and should yield parent_child.
        let output =
            "cn: contoso.local\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 32\nflatName: CONTOSO\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "parent_child");
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_trust_quarantined_external() {
        // QUARANTINED_DOMAIN (0x04) → external trust with SID filtering.
        let output =
            "cn: partner.com\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 4\nflatName: PARTNER\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "external");
        assert!(trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_trust_domain_lowercased() {
        let output = "cn: FABRIKAM.LOCAL\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 8\nflatName: FABRIKAM\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts[0]["domain"], "fabrikam.local");
    }

    // ── securityIdentifier extraction ──────────────────────────────────

    #[test]
    fn parse_trust_captures_canonical_sid_from_impacket_path() {
        // impacket-LDAP variant of enumerate_domain_trusts decodes the SID
        // inline and emits the canonical `S-1-...` text form.
        let output = r#"dn: CN=contoso.local,CN=System,DC=child,DC=contoso,DC=local
cn: contoso.local
trustDirection: 3
trustType: 2
trustAttributes: 32
flatName: CONTOSO
securityIdentifier: S-1-5-21-1111111111-2222222222-3333333333
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(
            trusts[0]["security_identifier"],
            "S-1-5-21-1111111111-2222222222-3333333333"
        );
    }

    #[test]
    fn parse_trust_decodes_base64_sid_from_ldapsearch_path() {
        // ldapsearch emits binary attrs as `attr:: <base64>`. The decoded
        // bytes form a canonical AD domain SID:
        //   revision=1, sub_count=4, identifier_authority=5,
        //   sub_auths = [21, X, Y, Z]
        let output = r#"dn: CN=contoso.local,CN=System,DC=child
cn: contoso.local
trustDirection: 3
trustType: 2
trustAttributes: 32
flatName: CONTOSO
securityIdentifier:: AQQAAAAAAAUVAAAAR0Y5Qog0dITLE7PG
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        let sid = trusts[0]["security_identifier"]
            .as_str()
            .expect("SID present");
        assert!(
            sid.starts_with("S-1-5-21-"),
            "decoded SID should be a canonical domain SID, got {sid}"
        );
        // 3 sub-authorities after the leading 21 → 6 dashes total
        // (S-1-5-21-X-Y-Z).
        let dashes = sid.matches('-').count();
        assert_eq!(dashes, 6, "canonical domain SID has 6 dashes, got {sid}");
    }

    #[test]
    fn parse_trust_security_identifier_absent_when_not_emitted() {
        // Older trust enum runs (or LDAP queries without the attribute)
        // produce no securityIdentifier line — the parsed object should
        // omit the field entirely so the orchestrator's
        // `from_value::<TrustInfo>` deserialises it to None.
        let output = r#"dn: CN=fabrikam.local,CN=System
cn: fabrikam.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: FABRIKAM
"#;
        let trusts = parse_domain_trusts(output);
        assert!(
            trusts[0].get("security_identifier").is_none(),
            "absent SID must not emit the JSON key"
        );
    }

    #[test]
    fn parse_trust_multiple_blocks_carry_independent_sids() {
        // Two trust entries in one LDAP response — each must keep its own
        // SID; state must reset between blocks.
        let output = r#"dn: CN=a.local,CN=System
cn: a.local
trustDirection: 3
trustType: 2
trustAttributes: 32
flatName: A
securityIdentifier: S-1-5-21-1-2-3

dn: CN=b.local,CN=System
cn: b.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: B
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 2);
        assert_eq!(trusts[0]["security_identifier"], "S-1-5-21-1-2-3");
        assert!(
            trusts[1].get("security_identifier").is_none(),
            "second trust without SID line must not inherit the first's SID"
        );
    }

    // ── decode_ldap_sid_base64 unit tests ──────────────────────────────

    #[test]
    fn decode_sid_b64_rejects_too_short_input() {
        assert!(decode_ldap_sid_base64("").is_none());
        // 4 bytes of base64 → 3 bytes decoded, well below the 8-byte minimum.
        assert!(decode_ldap_sid_base64("AAAA").is_none());
    }

    #[test]
    fn decode_sid_b64_rejects_invalid_base64() {
        assert!(decode_ldap_sid_base64("not!valid!base64!").is_none());
    }

    #[test]
    fn decode_sid_b64_rejects_wrong_revision() {
        // Revision byte = 2 (only 1 is valid for AD SIDs).
        use base64::Engine;
        let bad = base64::engine::general_purpose::STANDARD
            .encode([2u8, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0]);
        assert!(decode_ldap_sid_base64(&bad).is_none());
    }
}
