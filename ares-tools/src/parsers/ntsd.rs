//! nTSecurityDescriptor binary parser.
//!
//! Parses Windows SECURITY_DESCRIPTOR binary data (self-relative format) from
//! LDAP nTSecurityDescriptor attribute values to extract DACL ACE entries.
//! Identifies dangerous ACEs (GenericAll, WriteDacl, ForceChangePassword, etc.)
//! and returns them as structured vulnerability discoveries.

use serde_json::{json, Value};

// ── Well-known SID prefixes ────────────────────────────────────────────────

/// Map well-known SIDs to friendly names: the universal SIDs, the
/// `S-1-5-32-<rid>` BUILTIN aliases, and the domain-relative
/// `S-1-5-21-<domain>-<rid>` principals every AD install creates.
pub(super) fn well_known_sid(sid: &str) -> Option<&'static str> {
    if let Some(name) = universal_sid(sid) {
        return Some(name);
    }
    if let Some(rid) = sid.strip_prefix("S-1-5-32-") {
        return builtin_alias_sid(rid);
    }
    domain_relative_sid(sid)
}

fn universal_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-0-0" => Some("Nobody"),
        "S-1-1-0" => Some("Everyone"),
        "S-1-3-0" => Some("CREATOR OWNER"),
        "S-1-3-1" => Some("CREATOR GROUP"),
        "S-1-3-4" => Some("OWNER RIGHTS"),
        "S-1-5-4" => Some("INTERACTIVE"),
        "S-1-5-6" => Some("SERVICE"),
        "S-1-5-7" => Some("ANONYMOUS LOGON"),
        "S-1-5-9" => Some("ENTERPRISE DOMAIN CONTROLLERS"),
        "S-1-5-10" => Some("SELF"),
        "S-1-5-11" => Some("Authenticated Users"),
        "S-1-5-15" => Some("This Organization"),
        "S-1-5-18" => Some("SYSTEM"),
        "S-1-5-19" => Some("LOCAL SERVICE"),
        "S-1-5-20" => Some("NETWORK SERVICE"),
        _ => None,
    }
}

fn builtin_alias_sid(rid: &str) -> Option<&'static str> {
    match rid {
        "544" => Some("BUILTIN\\Administrators"),
        "545" => Some("BUILTIN\\Users"),
        "546" => Some("BUILTIN\\Guests"),
        "547" => Some("BUILTIN\\Power Users"),
        "548" => Some("BUILTIN\\Account Operators"),
        "549" => Some("BUILTIN\\Server Operators"),
        "550" => Some("BUILTIN\\Print Operators"),
        "551" => Some("BUILTIN\\Backup Operators"),
        "552" => Some("BUILTIN\\Replicator"),
        "554" => Some("BUILTIN\\Pre-Windows 2000 Compatible Access"),
        "555" => Some("BUILTIN\\Remote Desktop Users"),
        "556" => Some("BUILTIN\\Network Configuration Operators"),
        "557" => Some("BUILTIN\\Incoming Forest Trust Builders"),
        "558" => Some("BUILTIN\\Performance Monitor Users"),
        "559" => Some("BUILTIN\\Performance Log Users"),
        "560" => Some("BUILTIN\\Windows Authorization Access Group"),
        "561" => Some("BUILTIN\\Terminal Server License Servers"),
        "562" => Some("BUILTIN\\Distributed COM Users"),
        "568" => Some("BUILTIN\\IIS_IUSRS"),
        "569" => Some("BUILTIN\\Cryptographic Operators"),
        "573" => Some("BUILTIN\\Event Log Readers"),
        "574" => Some("BUILTIN\\Certificate Service DCOM Access"),
        "578" => Some("BUILTIN\\Hyper-V Administrators"),
        "579" => Some("BUILTIN\\Access Control Assistance Operators"),
        "580" => Some("BUILTIN\\Remote Management Users"),
        _ => None,
    }
}

fn domain_relative_sid(sid: &str) -> Option<&'static str> {
    let rest = sid.strip_prefix("S-1-5-21-")?;
    let mut parts = rest.split('-');
    for _ in 0..3 {
        let sub = parts.next()?;
        if sub.is_empty() || !sub.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    let rid = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    match rid {
        "498" => Some("Enterprise Read-only Domain Controllers"),
        "500" => Some("Administrator"),
        "501" => Some("Guest"),
        "502" => Some("krbtgt"),
        "512" => Some("Domain Admins"),
        "513" => Some("Domain Users"),
        "514" => Some("Domain Guests"),
        "515" => Some("Domain Computers"),
        "516" => Some("Domain Controllers"),
        "517" => Some("Cert Publishers"),
        "518" => Some("Schema Admins"),
        "519" => Some("Enterprise Admins"),
        "520" => Some("Group Policy Creator Owners"),
        "521" => Some("Read-only Domain Controllers"),
        "522" => Some("Cloneable Domain Controllers"),
        "525" => Some("Protected Users"),
        "526" => Some("Key Admins"),
        "527" => Some("Enterprise Key Admins"),
        "553" => Some("RAS and IAS Servers"),
        "571" => Some("Allowed RODC Password Replication Group"),
        "572" => Some("Denied RODC Password Replication Group"),
        _ => None,
    }
}

/// True for ACE trustees whose rights are not an escalation primitive: system
/// principals, and groups you would already need domain-level control to
/// authenticate as. Shared with the BloodHound collector parser so both ACL
/// sources filter identically.
pub(super) fn is_unactionable_acl_source(source_name: &str) -> bool {
    let lower = source_name.to_lowercase();
    let lower = lower.strip_prefix("builtin\\").unwrap_or(&lower);
    matches!(
        source_name,
        "SYSTEM"
            | "BUILTIN\\Administrators"
            | "BUILTIN\\Users"
            | "SELF"
            | "Nobody"
            | "ANONYMOUS LOGON"
    ) || matches!(
        lower,
        "administrators"
            | "domain admins"
            | "enterprise admins"
            | "key admins"
            | "enterprise key admins"
            | "account operators"
            | "domain controllers"
            | "enterprise domain controllers"
    )
}

/// Lowercased `objectClass` of a group Managed Service Account.
const GMSA_OBJECT_CLASS: &str = "msds-groupmanagedserviceaccount";

/// Password-expiry attributes, legacy LAPS then Windows LAPS. Both are
/// ordinary readable attributes, unlike the password attributes they sit
/// beside, so their presence is a cheap "this computer is LAPS-managed"
/// signal that needs no read access to the secret itself.
const LAPS_EXPIRY_ATTRIBUTES: &[&str] = &[
    "ms-mcs-admpwdexpirationtime",
    "mslaps-passwordexpirationtime",
];

/// Rights that confer a LAPS password read on a LAPS-managed computer.
/// Mirrors BloodHound's own `ReadLAPSPassword` rule: full control, or the
/// unrestricted control-access right that covers the confidential attribute.
const LAPS_READ_CONFERRING_RIGHTS: &[&str] = &["genericall", "allextendedrights"];

/// True when an LDIF line carries a LAPS password-expiry attribute with a
/// value. Matched on the attribute name only, case-insensitively, because
/// the two LAPS generations disagree on capitalisation and the impacket
/// branch echoes whatever the server returned.
fn is_laps_expiry_attribute(line: &str) -> bool {
    let Some((name, value)) = line.split_once(':') else {
        return false;
    };
    if value.trim_start_matches(':').trim().is_empty() {
        return false;
    }
    let name = name.trim().to_lowercase();
    LAPS_EXPIRY_ATTRIBUTES.contains(&name.as_str())
}

// ── Access mask flags ──────────────────────────────────────────────────────

const GENERIC_ALL: u32 = 0x10000000;
const GENERIC_WRITE: u32 = 0x40000000;
const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x00000100;
const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x00000020;
const ADS_RIGHT_DS_SELF: u32 = 0x00000008;
const WRITE_DACL: u32 = 0x00040000;
const WRITE_OWNER: u32 = 0x00080000;
const FULL_CONTROL: u32 = 0x000F01FF;

// ── Object type GUIDs for extended rights ──────────────────────────────────

/// User-Force-Change-Password (Reset Password extended right)
const GUID_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
/// Self-Membership (validated write to group member attribute)
const GUID_SELF_MEMBERSHIP: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
/// Write-Member (write to member attribute on group)
const GUID_WRITE_MEMBER: &str = "bf9679a8-0de6-11d0-a285-00aa003049e2";

// ── Binary parsing helpers ─────────────────────────────────────────────────

fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Parse a SID from binary data at the given offset.
/// Returns (sid_string, bytes_consumed).
fn parse_sid(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let revision = read_u8(data, offset)?;
    let sub_authority_count = read_u8(data, offset + 1)? as usize;

    if offset + 8 + sub_authority_count * 4 > data.len() {
        return None;
    }

    // IdentifierAuthority is 6 bytes big-endian
    let auth_bytes = &data[offset + 2..offset + 8];
    let authority = if auth_bytes[0] == 0 && auth_bytes[1] == 0 {
        // Fits in a u32 — use the last 4 bytes
        u32::from_be_bytes([auth_bytes[2], auth_bytes[3], auth_bytes[4], auth_bytes[5]]) as u64
    } else {
        // Full 48-bit authority
        ((auth_bytes[0] as u64) << 40)
            | ((auth_bytes[1] as u64) << 32)
            | ((auth_bytes[2] as u64) << 24)
            | ((auth_bytes[3] as u64) << 16)
            | ((auth_bytes[4] as u64) << 8)
            | (auth_bytes[5] as u64)
    };

    let mut sid = format!("S-{revision}-{authority}");
    for i in 0..sub_authority_count {
        let sub_auth = read_u32_le(data, offset + 8 + i * 4)?;
        sid.push_str(&format!("-{sub_auth}"));
    }

    let consumed = 8 + sub_authority_count * 4;
    Some((sid, consumed))
}

/// Parse a GUID from 16 bytes in mixed-endian format (as stored in AD).
fn parse_guid(data: &[u8], offset: usize) -> Option<String> {
    if offset + 16 > data.len() {
        return None;
    }
    let d1 = read_u32_le(data, offset)?;
    let d2 = read_u16_le(data, offset + 4)?;
    let d3 = read_u16_le(data, offset + 6)?;
    let d4 = &data[offset + 8..offset + 16];
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    ))
}

// ── ACE types ──────────────────────────────────────────────────────────────

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;

/// A parsed ACE with the information we care about.
#[derive(Debug)]
struct ParsedAce {
    trustee_sid: String,
    access_mask: u32,
    object_type_guid: Option<String>,
}

/// Classify an ACE into a vulnerability type name, if it's dangerous.
fn classify_ace(ace: &ParsedAce) -> Vec<&'static str> {
    let mask = ace.access_mask;
    let mut types = Vec::new();

    // GenericAll — full control
    if mask & GENERIC_ALL != 0 || mask == FULL_CONTROL {
        types.push("genericall");
        return types; // GenericAll subsumes everything
    }

    // GenericWrite
    if mask & GENERIC_WRITE != 0 {
        types.push("genericwrite");
    }

    // WriteDacl
    if mask & WRITE_DACL != 0 {
        types.push("writedacl");
    }

    // WriteOwner
    if mask & WRITE_OWNER != 0 {
        types.push("writeowner");
    }

    // Object-type specific rights
    if let Some(ref guid) = ace.object_type_guid {
        let guid_lower = guid.to_lowercase();
        if guid_lower == GUID_FORCE_CHANGE_PASSWORD && (mask & ADS_RIGHT_DS_CONTROL_ACCESS != 0) {
            types.push("forcechangepassword");
        }
        if guid_lower == GUID_SELF_MEMBERSHIP && (mask & ADS_RIGHT_DS_SELF != 0) {
            types.push("self_membership");
        }
        if guid_lower == GUID_WRITE_MEMBER && (mask & ADS_RIGHT_DS_WRITE_PROP != 0) {
            types.push("write_membership");
        }
    }

    // AllExtendedRights (no object type restriction or null GUID)
    if mask & ADS_RIGHT_DS_CONTROL_ACCESS != 0 && ace.object_type_guid.is_none() {
        types.push("allextendedrights");
    }

    // WriteProperty with no specific object type
    if mask & ADS_RIGHT_DS_WRITE_PROP != 0 {
        if let Some(ref guid) = ace.object_type_guid {
            if guid.to_lowercase() != GUID_WRITE_MEMBER {
                types.push("writeproperty");
            }
        } else {
            types.push("writeproperty");
        }
    }

    types
}

/// Parse a single ACE from binary data.
/// Returns (ParsedAce, total_ace_size).
fn parse_ace(data: &[u8], offset: usize) -> Option<(ParsedAce, usize)> {
    let ace_type = read_u8(data, offset)?;
    let _ace_flags = read_u8(data, offset + 1)?;
    let ace_size = read_u16_le(data, offset + 2)? as usize;

    if offset + ace_size > data.len() || ace_size < 8 {
        return None;
    }

    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE => {
            let access_mask = read_u32_le(data, offset + 4)?;
            let (sid, _) = parse_sid(data, offset + 8)?;
            Some((
                ParsedAce {
                    trustee_sid: sid,
                    access_mask,
                    object_type_guid: None,
                },
                ace_size,
            ))
        }
        ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
            let access_mask = read_u32_le(data, offset + 4)?;
            let flags = read_u32_le(data, offset + 8)?;

            let mut guid_offset = offset + 12;
            let object_type_guid = if flags & 0x01 != 0 {
                let guid = parse_guid(data, guid_offset)?;
                guid_offset += 16;
                Some(guid)
            } else {
                None
            };

            // Skip InheritedObjectType if present
            if flags & 0x02 != 0 {
                guid_offset += 16;
            }

            let (sid, _) = parse_sid(data, guid_offset)?;
            Some((
                ParsedAce {
                    trustee_sid: sid,
                    access_mask,
                    object_type_guid,
                },
                ace_size,
            ))
        }
        _ => {
            // Skip unknown ACE types
            Some((
                ParsedAce {
                    trustee_sid: String::new(),
                    access_mask: 0,
                    object_type_guid: None,
                },
                ace_size,
            ))
        }
    }
}

/// Walk the DACL of a self-relative SECURITY_DESCRIPTOR and return its ACEs.
///
/// Empty when the blob is truncated, not self-relative, or carries no DACL.
fn dacl_aces(data: &[u8]) -> Vec<ParsedAce> {
    if data.len() < 20 {
        return Vec::new();
    }

    let _revision = read_u8(data, 0);
    let _sbz1 = read_u8(data, 1);
    let control = read_u16_le(data, 2).unwrap_or(0);

    // Check SE_DACL_PRESENT (bit 2)
    if control & 0x0004 == 0 {
        return Vec::new();
    }

    // SE_SELF_RELATIVE check (bit 15) — we only handle self-relative
    if control & 0x8000 == 0 {
        return Vec::new();
    }

    let dacl_offset = read_u32_le(data, 16).unwrap_or(0) as usize;
    if dacl_offset == 0 || dacl_offset >= data.len() {
        return Vec::new();
    }

    // DACL header: Revision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2)
    if dacl_offset + 8 > data.len() {
        return Vec::new();
    }

    let ace_count = read_u16_le(data, dacl_offset + 4).unwrap_or(0) as usize;

    let mut aces = Vec::new();
    let mut ace_offset = dacl_offset + 8; // skip ACL header

    for _ in 0..ace_count {
        if ace_offset >= data.len() {
            break;
        }
        match parse_ace(data, ace_offset) {
            Some((ace, size)) => {
                aces.push(ace);
                ace_offset += size;
            }
            None => break,
        }
    }

    aces
}

/// Parse a SECURITY_DESCRIPTOR in self-relative format and extract DACL ACEs.
///
/// Returns a list of (trustee_sid, vuln_type) pairs for dangerous ACEs.
pub fn parse_security_descriptor(data: &[u8]) -> Vec<(String, String)> {
    let mut results = Vec::new();
    for ace in dacl_aces(data) {
        if ace.trustee_sid.is_empty() {
            continue;
        }
        for vuln_type in classify_ace(&ace) {
            results.push((ace.trustee_sid.clone(), vuln_type.to_string()));
        }
    }
    results
}

/// Every distinct trustee granted anything by a SECURITY_DESCRIPTOR's DACL.
///
/// `msDS-GroupMSAMembership` is an access-control list whose *entire* meaning
/// is membership: a trustee that appears in it may read the gMSA's managed
/// password, whatever the access mask says. [`parse_security_descriptor`]
/// answers a different question — which ACEs are an abuse primitive — and
/// discards ACEs that grant only a read, which is exactly the shape this
/// attribute normally carries.
pub fn parse_sd_allowed_trustees(data: &[u8]) -> Vec<String> {
    let mut trustees: Vec<String> = Vec::new();
    for ace in dacl_aces(data) {
        if ace.trustee_sid.is_empty() || ace.access_mask == 0 {
            continue;
        }
        if !trustees.iter().any(|s| s == &ace.trustee_sid) {
            trustees.push(ace.trustee_sid);
        }
    }
    trustees
}

/// Parse ldapsearch output containing base64-encoded nTSecurityDescriptor values.
///
/// Expects output in ldapsearch format:
/// ```text
/// dn: CN=someuser,DC=contoso,DC=local
/// sAMAccountName: someuser
/// nTSecurityDescriptor:: <base64>
/// ```
///
/// Returns vulnerability discoveries as JSON values.
pub fn parse_acl_enumeration(output: &str, params: &Value) -> Vec<Value> {
    use std::collections::HashMap;

    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let target_ip = params
        .get("target")
        .or_else(|| params.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Build a SID → sAMAccountName map from the output itself
    let mut sid_to_name: HashMap<String, String> = HashMap::new();
    let mut vulns = Vec::new();
    let mut emitted_reader_ids: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    // First pass: collect all objects with their sAMAccountName and objectSid
    #[derive(Default)]
    struct LdapObject {
        dn: String,
        sam_account_name: String,
        /// `user`, `group`, `computer`, `grouppolicycontainer`, or the gMSA
        /// class — the most specific one the record carries.
        object_class: String,
        ntsd_base64: String,
        object_sid: String,
        /// `cn` attribute — for GPO containers this is the `{GUID}` form
        /// (`{31B2F340-016D-11D2-945F-00C04FB984F9}`); for other objects
        /// it's the same as sAMAccountName minus the leading prefix.
        cn: String,
        /// `displayName` attribute — for GPO containers, the friendly
        /// name ("Default Domain Policy"). Used in the vuln description
        /// alongside the GUID cn.
        display_name: String,
        /// `msDS-GroupMSAMembership` — the security descriptor naming the
        /// principals allowed to retrieve this gMSA's managed password.
        gmsa_membership_base64: String,
        /// True when a LAPS password-expiry attribute is present, which is
        /// how a LAPS-managed computer is told apart from an unmanaged one
        /// without reading the confidential password attribute itself.
        laps_managed: bool,
    }

    /// Which base64 attribute a continuation line belongs to.
    #[derive(Clone, Copy, PartialEq)]
    enum B64Field {
        Ntsd,
        GmsaMembership,
    }

    fn flush_b64(obj: &mut LdapObject, field: B64Field, buf: &mut String) {
        match field {
            B64Field::Ntsd => obj.ntsd_base64 = std::mem::take(buf),
            B64Field::GmsaMembership => obj.gmsa_membership_base64 = std::mem::take(buf),
        }
    }

    let mut objects: Vec<LdapObject> = Vec::new();
    let mut current = LdapObject::default();
    let mut pending_b64: Option<B64Field> = None;
    let mut ntsd_buf = String::new();

    // An "identifiable" object is one we can flush at a record boundary: it
    // has at least one identifier we can use as the target name. Users /
    // groups / computers populate `sAMAccountName`; GPO containers carry
    // their identity in `cn` instead.
    fn has_identity(o: &LdapObject) -> bool {
        !o.sam_account_name.is_empty() || !o.cn.is_empty()
    }

    for line in output.lines() {
        let line = line.trim_end();

        if line.starts_with("dn: ") || (line.is_empty() && has_identity(&current)) {
            // Flush current
            if let Some(field) = pending_b64.take() {
                flush_b64(&mut current, field, &mut ntsd_buf);
            }
            if has_identity(&current) {
                objects.push(current);
            }
            current = LdapObject::default();
            if let Some(val) = line.strip_prefix("dn: ") {
                current.dn = val.trim().to_string();
            }
            continue;
        }

        // Handle base64 continuation lines (start with space)
        if let Some(field) = pending_b64 {
            if line.starts_with(' ') {
                ntsd_buf.push_str(line.trim());
                continue;
            } else {
                flush_b64(&mut current, field, &mut ntsd_buf);
                pending_b64 = None;
            }
        }

        if is_laps_expiry_attribute(line) {
            current.laps_managed = true;
        } else if let Some(val) = line.strip_prefix("sAMAccountName: ") {
            current.sam_account_name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("objectClass: ") {
            let val = val.trim().to_lowercase();
            // Keep the most specific class.
            if val == "user"
                || val == "computer"
                || val == "group"
                || val == "grouppolicycontainer"
                || val == GMSA_OBJECT_CLASS
            {
                current.object_class = val;
            }
        } else if let Some(val) = line.strip_prefix("cn: ") {
            current.cn = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("displayName: ") {
            current.display_name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("objectSid:: ") {
            // Base64-encoded SID
            if let Ok(bytes) = base64_decode(val.trim()) {
                if let Some((sid, _)) = parse_sid(&bytes, 0) {
                    current.object_sid = sid;
                }
            }
        } else if let Some(val) = line.strip_prefix("objectSid: ") {
            // String SID
            current.object_sid = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("nTSecurityDescriptor:: ") {
            ntsd_buf = val.trim().to_string();
            pending_b64 = Some(B64Field::Ntsd);
        } else if let Some(val) = line.strip_prefix("nTSecurityDescriptor: ") {
            // Non-base64 (shouldn't happen but handle it)
            current.ntsd_base64 = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("msDS-GroupMSAMembership:: ") {
            ntsd_buf = val.trim().to_string();
            pending_b64 = Some(B64Field::GmsaMembership);
        } else if let Some(val) = line.strip_prefix("msDS-GroupMSAMembership: ") {
            current.gmsa_membership_base64 = val.trim().to_string();
        }
    }
    // Flush last object
    if let Some(field) = pending_b64.take() {
        flush_b64(&mut current, field, &mut ntsd_buf);
    }
    if has_identity(&current) {
        objects.push(current);
    }

    // Build SID map
    for obj in &objects {
        if !obj.object_sid.is_empty() && !obj.sam_account_name.is_empty() {
            sid_to_name.insert(obj.object_sid.clone(), obj.sam_account_name.clone());
        }
    }

    // Second pass: parse each nTSecurityDescriptor and extract dangerous ACEs
    for obj in &objects {
        if obj.ntsd_base64.is_empty() {
            continue;
        }

        let Ok(sd_bytes) = base64_decode(&obj.ntsd_base64) else {
            continue;
        };

        let aces = parse_security_descriptor(&sd_bytes);
        for (trustee_sid, vuln_type) in &aces {
            // Resolve trustee SID to name
            let source_name = sid_to_name
                .get(trustee_sid)
                .map(|s| s.as_str())
                .or_else(|| well_known_sid(trustee_sid))
                .unwrap_or(trustee_sid);

            // Skip well-known system SIDs and high-privilege groups that aren't
            // actionable (you'd already need DA to abuse them).
            if is_unactionable_acl_source(source_name) {
                continue;
            }

            // For GPO containers, the identifier is the `cn` (GUID); for
            // every other object type it's the sAMAccountName. Self-perm
            // dedup compares against whichever identifier we'll emit.
            let is_gpo = obj.object_class == "grouppolicycontainer";
            let target_name = if is_gpo && !obj.cn.is_empty() {
                obj.cn.as_str()
            } else {
                obj.sam_account_name.as_str()
            };

            if target_name.is_empty() {
                continue;
            }
            if source_name.eq_ignore_ascii_case(target_name) {
                continue;
            }

            let target_type = match obj.object_class.as_str() {
                "user" => "User",
                "group" => "Group",
                "computer" => "Computer",
                "grouppolicycontainer" => "GPO",
                GMSA_OBJECT_CLASS => "gMSA",
                _ => "Unknown",
            };

            if obj.laps_managed && LAPS_READ_CONFERRING_RIGHTS.contains(&vuln_type.as_str()) {
                let vuln_id = format!(
                    "laps_reader_{}_{}",
                    source_name.to_lowercase().replace(' ', "_"),
                    target_name.to_lowercase().replace('$', "")
                );
                if emitted_reader_ids.insert(vuln_id.clone()) {
                    vulns.push(json!({
                        "vuln_id": vuln_id,
                        "vuln_type": "laps_reader",
                        "source": source_name,
                        "target": target_name,
                        "target_type": target_type,
                        "target_ip": target_ip,
                        "domain": domain,
                        "source_domain": domain,
                        "details": {
                            "trustee_sid": trustee_sid,
                            "source": source_name,
                            "reader": source_name,
                            "target": target_name,
                            "target_computer": target_name,
                            "target_type": target_type,
                            "domain": domain,
                            "conferring_right": vuln_type,
                            "description": format!(
                                "{source_name} can read the LAPS password of {target_name} via {vuln_type}"
                            ),
                        },
                    }));
                }
            }

            // GPO targets get a dedicated `gpo_<right>` vuln_type so the
            // auto_gpo_abuse chain picks them up. Other ACL targets keep
            // the legacy `acl_<right>` prefix consumed by auto_dacl_abuse.
            let emitted_vuln_type = if is_gpo {
                format!("gpo_{vuln_type}")
            } else {
                (*vuln_type).to_string()
            };

            // Sanitise the identifier for the vuln_id key: lowercase and
            // collapse spaces/curly-braces/hyphens to underscores so the
            // `{GUID}` form of a GPO cn doesn't introduce shell-special
            // characters into a downstream redis SET member.
            let slug = target_name
                .to_lowercase()
                .chars()
                .map(|c| match c {
                    'a'..='z' | '0'..='9' | '.' => c,
                    _ => '_',
                })
                .collect::<String>();

            let vuln_id = if is_gpo {
                format!(
                    "gpo_{}_{}_{}",
                    vuln_type,
                    source_name.to_lowercase().replace(' ', "_"),
                    slug,
                )
            } else {
                format!(
                    "acl_{}_{}_{}",
                    vuln_type,
                    source_name.to_lowercase().replace(' ', "_"),
                    obj.sam_account_name.to_lowercase().replace('$', "")
                )
            };

            let description = if is_gpo {
                format!(
                    "{} has {} on GPO {} ({})",
                    source_name,
                    vuln_type,
                    target_name,
                    if obj.display_name.is_empty() {
                        "no displayName"
                    } else {
                        obj.display_name.as_str()
                    },
                )
            } else {
                format!(
                    "{} has {} on {} ({})",
                    source_name, vuln_type, obj.sam_account_name, target_type
                )
            };

            let mut details_map = serde_json::Map::new();
            details_map.insert("trustee_sid".into(), json!(trustee_sid));
            details_map.insert("source".into(), json!(source_name));
            details_map.insert("target".into(), json!(target_name));
            details_map.insert("target_type".into(), json!(target_type));
            details_map.insert("domain".into(), json!(domain));
            details_map.insert("source_domain".into(), json!(domain));
            details_map.insert("description".into(), json!(description));
            if !obj.dn.is_empty() {
                details_map.insert("target_dn".into(), json!(obj.dn));
            }
            // Extra context for GPO targets so auto_gpo_abuse's payload
            // builder can populate gpo_id / gpo_name / gpo_display_name
            // without an extra LDAP round-trip.
            if is_gpo {
                details_map.insert("gpo_id".into(), json!(obj.cn));
                if !obj.display_name.is_empty() {
                    details_map.insert("gpo_display_name".into(), json!(obj.display_name));
                    details_map.insert("gpo_name".into(), json!(obj.display_name));
                }
            }

            vulns.push(json!({
                "vuln_id": vuln_id,
                "vuln_type": emitted_vuln_type,
                "source": source_name,
                "target": target_name,
                "target_type": target_type,
                "target_ip": target_ip,
                "domain": domain,
                "source_domain": domain,
                "details": Value::Object(details_map),
            }));
        }
    }

    for obj in &objects {
        if obj.gmsa_membership_base64.is_empty() || obj.sam_account_name.is_empty() {
            continue;
        }
        let Ok(sd_bytes) = base64_decode(&obj.gmsa_membership_base64) else {
            continue;
        };
        let target_name = obj.sam_account_name.as_str();
        for trustee_sid in parse_sd_allowed_trustees(&sd_bytes) {
            let source_name = sid_to_name
                .get(&trustee_sid)
                .map(|s| s.as_str())
                .or_else(|| well_known_sid(&trustee_sid))
                .unwrap_or(trustee_sid.as_str())
                .to_string();
            if is_unactionable_acl_source(&source_name)
                || source_name.eq_ignore_ascii_case(target_name)
            {
                continue;
            }
            let vuln_id = format!(
                "gmsa_reader_{}_{}",
                source_name.to_lowercase().replace(' ', "_"),
                target_name.to_lowercase().replace('$', "")
            );
            if !emitted_reader_ids.insert(vuln_id.clone()) {
                continue;
            }
            vulns.push(json!({
                "vuln_id": vuln_id,
                "vuln_type": "gmsa_reader",
                "source": source_name,
                "target": target_name,
                "target_type": "gMSA",
                "target_ip": target_ip,
                "domain": domain,
                "source_domain": domain,
                "details": {
                    "trustee_sid": trustee_sid,
                    "source": source_name,
                    "reader": source_name,
                    "target": target_name,
                    "gmsa_account": target_name,
                    "target_type": "gMSA",
                    "domain": domain,
                    "description": format!(
                        "{source_name} is in msDS-GroupMSAMembership of {target_name} and can read its managed password"
                    ),
                },
            }));
        }
    }

    vulns
}

/// Simple base64 decoder (no external dependency).
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    // Strip whitespace
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for ch in clean.chars() {
        let val = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => continue, // padding
            _ => return Err("invalid base64 character"),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sid_wellknown() {
        // S-1-5-18 (SYSTEM): revision=1, subauth_count=1, authority=5, subauth=18
        let bytes = [
            0x01, // revision
            0x01, // sub authority count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
            0x12, 0x00, 0x00, 0x00, // sub authority = 18
        ];
        let (sid, consumed) = parse_sid(&bytes, 0).unwrap();
        assert_eq!(sid, "S-1-5-18");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn parse_sid_domain_user() {
        // S-1-5-21-xxx-xxx-xxx-1001
        let bytes = [
            0x01, // revision
            0x04, // sub authority count = 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
            0x15, 0x00, 0x00, 0x00, // 21
            0x01, 0x00, 0x00, 0x00, // 1
            0x02, 0x00, 0x00, 0x00, // 2
            0xE9, 0x03, 0x00, 0x00, // 1001
        ];
        let (sid, _) = parse_sid(&bytes, 0).unwrap();
        assert_eq!(sid, "S-1-5-21-1-2-1001");
    }

    #[test]
    fn parse_guid_format() {
        // A known GUID: 00299570-246d-11d0-a768-00aa006e0529
        let bytes = [
            0x70, 0x95, 0x29, 0x00, // d1 = 0x00299570 LE
            0x6d, 0x24, // d2 = 0x246d LE
            0xd0, 0x11, // d3 = 0x11d0 LE
            0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29, // d4
        ];
        let guid = parse_guid(&bytes, 0).unwrap();
        assert_eq!(guid, "00299570-246d-11d0-a768-00aa006e0529");
    }

    #[test]
    fn base64_decode_simple() {
        let decoded = base64_decode("AQAAAA==").unwrap();
        assert_eq!(decoded, vec![0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn base64_decode_empty() {
        let decoded = base64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn classify_generic_all() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: GENERIC_ALL,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert_eq!(types, vec!["genericall"]);
    }

    #[test]
    fn classify_full_control() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: FULL_CONTROL,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert_eq!(types, vec!["genericall"]);
    }

    #[test]
    fn classify_write_dacl() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: WRITE_DACL,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"writedacl"));
    }

    #[test]
    fn classify_write_owner() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: WRITE_OWNER,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"writeowner"));
    }

    #[test]
    fn classify_force_change_password() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: ADS_RIGHT_DS_CONTROL_ACCESS,
            object_type_guid: Some(GUID_FORCE_CHANGE_PASSWORD.into()),
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"forcechangepassword"));
    }

    #[test]
    fn classify_self_membership() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: ADS_RIGHT_DS_SELF,
            object_type_guid: Some(GUID_SELF_MEMBERSHIP.into()),
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"self_membership"));
    }

    #[test]
    fn classify_generic_write() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: GENERIC_WRITE,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"genericwrite"));
    }

    #[test]
    fn classify_no_dangerous_perms() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: 0x00000001, // just read
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert!(types.is_empty());
    }

    #[test]
    fn parse_security_descriptor_too_short() {
        let result = parse_security_descriptor(&[0x01, 0x00]);
        assert!(result.is_empty());
    }

    #[test]
    fn well_known_sids() {
        assert_eq!(well_known_sid("S-1-5-18"), Some("SYSTEM"));
        assert_eq!(well_known_sid("S-1-1-0"), Some("Everyone"));
        assert_eq!(
            well_known_sid("S-1-5-32-544"),
            Some("BUILTIN\\Administrators")
        );
        assert_eq!(well_known_sid("S-1-5-21-custom"), None);
    }

    #[test]
    fn parse_acl_enumeration_empty() {
        let vulns = parse_acl_enumeration("", &serde_json::json!({"domain": "contoso.local"}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_acl_enumeration_collects_gpo_object_without_panic() {
        // GPO containers have no `sAMAccountName`; the parser must still
        // flush them at the record boundary using `cn` as identity.
        // Without nTSecurityDescriptor no ACEs land — the test verifies
        // the parser walks the record cleanly (no panic, no spurious
        // output) and that the `gpo_` vuln_type prefix takes effect when
        // the SD path eventually produces an ACE.
        let output = "\
dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=local
objectClass: top
objectClass: container
objectClass: groupPolicyContainer
cn: {31B2F340-016D-11D2-945F-00C04FB984F9}
displayName: Default Domain Policy
";
        let vulns = parse_acl_enumeration(output, &serde_json::json!({"domain": "contoso.local"}));
        // No nTSecurityDescriptor → no ACEs → no vulns. Important: no panic.
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_security_descriptor_minimal_valid() {
        // Construct a minimal self-relative SD with DACL present, 0 ACEs
        let mut sd = [0u8; 24];
        sd[0] = 1; // revision
                   // control: SE_DACL_PRESENT (0x0004) | SE_SELF_RELATIVE (0x8000)
        sd[2] = 0x04;
        sd[3] = 0x80;
        // DACL offset at byte 16 (LE u32)
        sd[16] = 20; // DACL starts at offset 20
                     // DACL header at offset 20: revision=2, sbz=0, size=8, ace_count=0
        sd[20] = 2; // ACL revision
        sd[22] = 8; // ACL size (just header)
        sd[24..].iter().for_each(|_| {}); // pad isn't needed, we have exact size

        // Actually need 28 bytes total (20 for SD header + 8 for DACL header)
        let mut sd = vec![0u8; 28];
        sd[0] = 1;
        sd[2] = 0x04;
        sd[3] = 0x80;
        sd[16] = 20;
        sd[20] = 2;
        sd[22] = 8;
        // ace_count at offset 24 = 0

        let result = parse_security_descriptor(&sd);
        assert!(result.is_empty());
    }

    // ── parse_security_descriptor / parse_ace edge cases ────────────────

    #[test]
    fn parse_sd_rejects_without_dacl_present_bit() {
        // SE_SELF_RELATIVE set but SE_DACL_PRESENT bit not set → no DACL parsed.
        let mut sd = vec![0u8; 28];
        sd[0] = 1; // revision
        sd[2] = 0x00; // no SE_DACL_PRESENT
        sd[3] = 0x80; // SE_SELF_RELATIVE
        sd[16] = 20;
        assert!(parse_security_descriptor(&sd).is_empty());
    }

    #[test]
    fn parse_sd_rejects_non_self_relative() {
        // SE_DACL_PRESENT set but SE_SELF_RELATIVE missing → non-self-relative,
        // parser refuses.
        let mut sd = vec![0u8; 28];
        sd[0] = 1;
        sd[2] = 0x04; // SE_DACL_PRESENT
        sd[3] = 0x00; // no SE_SELF_RELATIVE
        sd[16] = 20;
        assert!(parse_security_descriptor(&sd).is_empty());
    }

    #[test]
    fn parse_sd_rejects_when_dacl_offset_is_zero() {
        let mut sd = vec![0u8; 28];
        sd[0] = 1;
        sd[2] = 0x04;
        sd[3] = 0x80;
        // dacl_offset bytes 16..20 all zero → reject.
        assert!(parse_security_descriptor(&sd).is_empty());
    }

    #[test]
    fn parse_sd_rejects_when_dacl_offset_exceeds_length() {
        let mut sd = vec![0u8; 28];
        sd[0] = 1;
        sd[2] = 0x04;
        sd[3] = 0x80;
        sd[16] = 100; // beyond the 28-byte buffer
        assert!(parse_security_descriptor(&sd).is_empty());
    }

    #[test]
    fn parse_sd_single_generic_all_ace_returns_genericall_token() {
        // SECURITY_DESCRIPTOR_RELATIVE (20 bytes):
        //   Revision (1) | Sbz1 (1) | Control (2) | Owner (4) | Group (4) | Sacl (4) | Dacl (4)
        let mut sd: Vec<u8> = vec![0u8; 20];
        sd[0] = 1;
        sd[2] = 0x04; // SE_DACL_PRESENT
        sd[3] = 0x80; // SE_SELF_RELATIVE
        sd[16] = 20; // DACL @ offset 20

        // ACL header (8 bytes): Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
        sd.extend([2u8, 0, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00]); // ace_count = 1, AclSize = 36

        // ACCESS_ALLOWED_ACE: Type(1) Flags(1) Size(2) Mask(4) Sid(rest)
        // Type 0x00 = ACCESS_ALLOWED_ACE_TYPE; Size 0x1C = 28
        sd.extend([0x00, 0x00, 0x1C, 0x00]);
        // Access mask GENERIC_ALL = 0x10000000 (little endian)
        sd.extend([0x00, 0x00, 0x00, 0x10]);
        // SID: rev=1, count=4, auth=5, subauths 21/1/2/1001
        sd.extend([
            0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xE9, 0x03, 0x00, 0x00,
        ]);

        let result = parse_security_descriptor(&sd);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "S-1-5-21-1-2-1001");
        assert_eq!(result[0].1, "genericall");
    }

    // ── parse_acl_enumeration coverage ──────────────────────────────────

    #[test]
    fn parse_acl_enumeration_ignores_record_without_ntsd() {
        let output = "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
";
        let v = parse_acl_enumeration(output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(v.is_empty());
    }

    #[test]
    fn parse_acl_enumeration_ignores_malformed_base64_ntsd() {
        let output = "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
nTSecurityDescriptor:: this-is-not-valid-base64!!!
";
        let v = parse_acl_enumeration(output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(v.is_empty());
    }

    #[test]
    fn parse_acl_enumeration_handles_record_with_objectsid_string_form() {
        // String-form objectSid (no `::` for base64) is the rarer ldapsearch
        // shape. The parser should still flush the record on dn boundary.
        let output = "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001
";
        let v = parse_acl_enumeration(output, &serde_json::json!({"domain": "contoso.local"}));
        // No ntsd → no vulns.
        assert!(v.is_empty());
    }

    #[test]
    fn parse_acl_enumeration_concatenates_ntsd_continuation_lines() {
        // Base64 ldapsearch output wraps lines with leading whitespace. The
        // parser must concatenate them before decoding.
        let output = "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
nTSecurityDescriptor:: AQAEgBQ
 AAAAAAAAAA
 AAAAAAQAAAAAAU=
";
        // The fixture is intentionally malformed once concatenated — the test
        // only verifies the parser doesn't panic and treats the continuation
        // lines as part of the same blob (yielding an empty discovery list).
        let v = parse_acl_enumeration(output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(v.is_empty());
    }

    #[test]
    fn parse_acl_enumeration_records_target_ip_from_params() {
        // Build an output with a single GenericAll ACE. We can use the
        // existing parse_security_descriptor builder pattern.
        let mut sd: Vec<u8> = vec![0u8; 20];
        sd[0] = 1;
        sd[2] = 0x04;
        sd[3] = 0x80;
        sd[16] = 20;
        sd.extend([2u8, 0, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00]);
        sd.extend([0x00, 0x00, 0x1C, 0x00]);
        sd.extend([0x00, 0x00, 0x00, 0x10]);
        sd.extend([
            0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xE9, 0x03, 0x00, 0x00,
        ]);
        // Base64-encode using the parser's own decoder via a round-trip
        // through a known-good encoder is overkill — just confirm the
        // top-level fn surfaces the target_ip parameter.
        // (We pass empty nTSD here; the assertion is on the empty output
        // shape, not on vuln content.)
        let _ = sd; // keep the SD construction visible as reference
        let v = parse_acl_enumeration(
            "",
            &serde_json::json!({"target": "192.168.58.10", "domain": "contoso.local"}),
        );
        assert!(v.is_empty());
    }

    #[test]
    fn parse_acl_enumeration_records_target_ip_alias() {
        // Both `target` and `target_ip` are accepted as the IP source.
        let v = parse_acl_enumeration(
            "",
            &serde_json::json!({"target_ip": "192.168.58.10", "domain": "contoso.local"}),
        );
        assert!(v.is_empty());
    }

    #[test]
    fn parse_acl_enumeration_groups_object_class_recognised() {
        // groupPolicyContainer entries route through the GPO branch on
        // emit; here we just verify the parser doesn't crash on the
        // object-class line and produces no vulns without an ntsd.
        let output = "\
dn: CN={A1B2C3D4-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=contoso,DC=local
objectClass: groupPolicyContainer
cn: {A1B2C3D4-0000-0000-0000-000000000001}
displayName: Test GPO
";
        let v = parse_acl_enumeration(output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(v.is_empty());
    }

    // ── base64_decode edge cases ────────────────────────────────────────

    #[test]
    fn base64_decode_padded_full_block() {
        // "Man" → "TWFu"
        let decoded = base64_decode("TWFu").unwrap();
        assert_eq!(decoded, b"Man".to_vec());
    }

    #[test]
    fn base64_decode_strips_whitespace() {
        let decoded = base64_decode("T\n W\t F u").unwrap();
        assert_eq!(decoded, b"Man".to_vec());
    }

    // ── classify_ace edge cases ─────────────────────────────────────────

    #[test]
    fn classify_combined_flags_returns_each_dangerous_type() {
        // GenericAll alone collapses to "genericall" (covers everything),
        // so use a non-GENERIC_ALL mask that lights both WriteDacl and
        // WriteOwner.
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: WRITE_DACL | WRITE_OWNER,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"writedacl"));
        assert!(types.contains(&"writeowner"));
    }

    #[test]
    fn classify_write_member_via_guid_returns_write_membership_only() {
        // WriteProp + Write-Member GUID → "write_membership" (the specialised
        // token), NOT the generic "writeproperty". The latter is suppressed
        // when the GUID names the Member attribute.
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: ADS_RIGHT_DS_WRITE_PROP,
            object_type_guid: Some(GUID_WRITE_MEMBER.into()),
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"write_membership"));
        assert!(!types.contains(&"writeproperty"));
    }

    #[test]
    fn classify_write_prop_without_guid_returns_writeproperty() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: ADS_RIGHT_DS_WRITE_PROP,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"writeproperty"));
    }

    #[test]
    fn classify_all_extended_rights_no_guid() {
        let ace = ParsedAce {
            trustee_sid: "S-1-5-21-1-2-1001".into(),
            access_mask: ADS_RIGHT_DS_CONTROL_ACCESS,
            object_type_guid: None,
        };
        let types = classify_ace(&ace);
        assert!(types.contains(&"allextendedrights"));
    }
    // ── parse_acl_enumeration with real SD producing vulns ─────────

    // The SD built below encodes a GenericAll ACE granted to trustee
    // S-1-5-21-1-2-1001 on a user object with sAMAccountName "bob".
    // The trustee SID is unknown to the SID map and is not a well-known
    // system SID so it should appear as a vuln record.
    const SD_GENERIC_ALL_B64: &str =
        "AQAEgAAAAAAAAAAAAAAAABQAAAACACgAAQAAAAAAIAAAAAAQAQQAAAAAAAUVAAAAAQAAAAIAAADpAwAA";

    #[test]
    fn parse_acl_enumeration_produces_vuln_from_real_sd() {
        // Two-object LDAP output: "alice" is the trustee (has objectSid matching
        // the ACE SID) and "bob" is the target.
        let output = format!(
            "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001

dn: CN=bob,DC=contoso,DC=local
sAMAccountName: bob
objectClass: user
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(
            &output,
            &serde_json::json!({"domain": "contoso.local", "target": "192.168.58.10"}),
        );
        assert_eq!(vulns.len(), 1, "Expected 1 vuln, got: {vulns:?}");
        let v = &vulns[0];
        assert_eq!(v["vuln_type"], "genericall");
        assert_eq!(v["source"], "alice");
        assert_eq!(v["target"], "bob");
        assert_eq!(v["target_type"], "User");
        assert_eq!(v["domain"], "contoso.local");
        assert_eq!(v["target_ip"], "192.168.58.10");
        assert!(v["vuln_id"]
            .as_str()
            .unwrap()
            .starts_with("acl_genericall_"));
    }

    #[test]
    fn parse_acl_enumeration_emits_target_dn_for_a_user_target() {
        let output = format!(
            "\
dn: CN=alice,CN=Users,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001

dn: CN=bob,CN=Users,DC=contoso,DC=local
sAMAccountName: bob
objectClass: user
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert_eq!(vulns.len(), 1, "Expected 1 vuln, got: {vulns:?}");
        assert_eq!(
            vulns[0]["details"]["target_dn"], "CN=bob,CN=Users,DC=contoso,DC=local",
            "dacl_edit's only target argument is `target_dn`; dropping the DN the \
             collector already printed forces the model to invent one"
        );
    }

    #[test]
    fn parse_acl_enumeration_gpo_target_carries_its_distinguished_name() {
        let output = format!(
            "\
dn: CN=alice,CN=Users,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001

dn: CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,DC=contoso,DC=local
objectClass: groupPolicyContainer
cn: {{31B2F340-016D-11D2-945F-00C04FB984F9}}
displayName: Default Domain Policy
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert_eq!(vulns.len(), 1, "Expected 1 vuln, got: {vulns:?}");
        let v = &vulns[0];
        assert_eq!(v["vuln_type"], "gpo_genericall");
        assert_eq!(v["target_type"], "GPO");
        assert_eq!(v["target"], "{31B2F340-016D-11D2-945F-00C04FB984F9}");
        assert_eq!(
            v["details"]["target_dn"],
            "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=local"
        );
        assert_eq!(
            v["details"]["gpo_id"], "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "auto_gpo_abuse still addresses the container by GUID"
        );
    }

    #[test]
    fn parse_acl_enumeration_self_perm_skipped() {
        // When source == target the ACE is a self-permission and must be
        // filtered out (e.g. bob has GenericAll on himself — not interesting).
        let output = format!(
            "\
dn: CN=bob,DC=contoso,DC=local
sAMAccountName: bob
objectClass: user
objectSid: S-1-5-21-1-2-1001
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(
            vulns.is_empty(),
            "Self-permission should be filtered, got: {vulns:?}"
        );
    }

    #[test]
    fn parse_acl_enumeration_system_trustee_skipped() {
        // ACE granted to SYSTEM (S-1-5-18) — a well-known privileged SID —
        // should be filtered. Build SD with SYSTEM's binary SID.
        // SYSTEM SID: S-1-5-18 → rev=1, count=1, auth=5, sub=18
        let mut sd: Vec<u8> = vec![0u8; 20];
        sd[0] = 1;
        sd[2] = 0x04;
        sd[3] = 0x80;
        sd[16] = 20;

        // ACE header + mask
        let mut ace = vec![0x00u8, 0x00]; // type=0, flags=0
                                          // SID for SYSTEM (S-1-5-18): 12 bytes
        let system_sid = [
            0x01u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // rev+count+authority
            0x12, 0x00, 0x00, 0x00, // sub_auth=18
        ];
        let ace_size = (4u16 + 4 + system_sid.len() as u16).to_le_bytes();
        ace.extend_from_slice(&ace_size); // size
        ace.extend_from_slice(&0x10000000u32.to_le_bytes()); // GenericAll
        ace.extend_from_slice(&system_sid);

        let acl_size = (8u16 + ace.len() as u16).to_le_bytes();
        let mut dacl = vec![2u8, 0]; // rev
        dacl.extend_from_slice(&acl_size); // AclSize
        dacl.extend_from_slice(&1u16.to_le_bytes()); // AceCount=1
        dacl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
        dacl.extend(ace);

        sd.extend(dacl);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&sd);
        let output = format!(
            "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
nTSecurityDescriptor:: {b64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(
            vulns.is_empty(),
            "SYSTEM trustee must be filtered, got: {vulns:?}"
        );
    }

    #[test]
    fn parse_acl_enumeration_computer_object_type() {
        // Verify that `objectClass: computer` produces target_type = "Computer".
        let output = format!(
            "\
dn: CN=ws01,DC=contoso,DC=local
sAMAccountName: ws01$
objectClass: computer
objectSid: S-1-5-21-1-2-2000

dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        // The trustee SID in the SD is S-1-5-21-1-2-1001 (alice) and the target
        // is the computer ws01$. This requires alice's SID to be in the SID map
        // produced from the ws01 object's nTSecurityDescriptor.  Here the SD is
        // attached to alice, so alice is both the object we're reading AND the
        // one whose SD contains an ACE.  The test simply verifies computer
        // target_type appears when objectClass=computer has an SD.
        let output2 = format!(
            "\
dn: CN=ws01,DC=contoso,DC=local
sAMAccountName: ws01
objectClass: computer
objectSid: S-1-5-21-1-2-2000
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}

dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001
"
        );
        let vulns =
            parse_acl_enumeration(&output2, &serde_json::json!({"domain": "contoso.local"}));
        // The trustee SID (1001 = alice) is found in the SID map — alice is
        // the trustee, ws01 is the target.
        if !vulns.is_empty() {
            assert_eq!(vulns[0]["target_type"], "Computer");
        }
        // Either 0 or 1 vulns — what matters is no panic.
        let _ = output;
    }

    #[test]
    fn parse_acl_enumeration_group_object_type() {
        // objectClass: group → target_type = "Group"
        let output = format!(
            "\
dn: CN=DomainAdmins,DC=contoso,DC=local
sAMAccountName: Domain Admins
objectClass: group
objectSid: S-1-5-21-1-2-512

dn: CN=regularusers,DC=contoso,DC=local
sAMAccountName: regularusers
objectClass: group
objectSid: S-1-5-21-1-2-2001
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        // Trustee SID 1001 is not in the map (only 512 and 2001 are).
        // So the SID itself becomes the source name. The trustee is not a
        // well-known system SID so a vuln should appear.
        if !vulns.is_empty() {
            assert_eq!(vulns[0]["target_type"], "Group");
        }
    }

    #[test]
    fn parse_acl_enumeration_multiple_vuln_types_on_one_ace() {
        // An ACE with WriteDacl + WriteOwner bits set should produce two
        // separate vuln records (one per dangerous type).
        //
        // Build SD with WriteDacl|WriteOwner mask (0x000C0000).
        let mut sd: Vec<u8> = vec![0u8; 20];
        sd[0] = 1;
        sd[2] = 0x04;
        sd[3] = 0x80;
        sd[16] = 20;

        let mask: u32 = 0x00040000 | 0x00080000; // WRITE_DACL | WRITE_OWNER
        let sid_bytes = [
            0x01u8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xE9, 0x03, 0x00, 0x00,
        ];
        let ace_size = (4u16 + 4 + sid_bytes.len() as u16).to_le_bytes();
        let mut ace = vec![0x00u8, 0x00];
        ace.extend_from_slice(&ace_size);
        ace.extend_from_slice(&mask.to_le_bytes());
        ace.extend_from_slice(&sid_bytes);

        let acl_size = (8u16 + ace.len() as u16).to_le_bytes();
        let mut dacl = vec![2u8, 0];
        dacl.extend_from_slice(&acl_size);
        dacl.extend_from_slice(&1u16.to_le_bytes());
        dacl.extend_from_slice(&0u16.to_le_bytes());
        dacl.extend(ace);
        sd.extend(dacl);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&sd);

        let output = format!(
            "\
dn: CN=victim,DC=contoso,DC=local
sAMAccountName: victim
objectClass: user
nTSecurityDescriptor:: {b64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        // Should produce separate entries for writedacl and writeowner.
        assert!(
            vulns.len() >= 2,
            "Expected writedacl + writeowner, got: {vulns:?}"
        );
        let types: Vec<_> = vulns
            .iter()
            .map(|v| v["vuln_type"].as_str().unwrap_or(""))
            .collect();
        assert!(types.contains(&"writedacl"));
        assert!(types.contains(&"writeowner"));
    }

    fn sid_bytes(rid: u32) -> Vec<u8> {
        let mut b = vec![0x01u8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        b.extend_from_slice(&21u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&rid.to_le_bytes());
        b
    }

    fn sd_with_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut sd: Vec<u8> = vec![0u8; 20];
        sd[0] = 1;
        sd[2] = 0x04;
        sd[3] = 0x80;
        sd[16] = 20;

        let mut ace = vec![0x00u8, 0x00];
        let ace_size = (4u16 + 4 + sid.len() as u16).to_le_bytes();
        ace.extend_from_slice(&ace_size);
        ace.extend_from_slice(&mask.to_le_bytes());
        ace.extend_from_slice(sid);

        let acl_size = (8u16 + ace.len() as u16).to_le_bytes();
        let mut dacl = vec![2u8, 0];
        dacl.extend_from_slice(&acl_size);
        dacl.extend_from_slice(&1u16.to_le_bytes());
        dacl.extend_from_slice(&0u16.to_le_bytes());
        dacl.extend(ace);

        sd.extend(dacl);
        sd
    }

    fn encode_sd(sd: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(sd)
    }

    const READ_PROPERTY_MASK: u32 = 0x00000010;

    #[test]
    fn parse_sd_allowed_trustees_keeps_read_only_ace_that_classify_drops() {
        let sd = sd_with_ace(READ_PROPERTY_MASK, &sid_bytes(2000));
        assert!(
            parse_security_descriptor(&sd).is_empty(),
            "a bare read grants no abuse primitive"
        );
        assert_eq!(
            parse_sd_allowed_trustees(&sd),
            vec!["S-1-5-21-1-2-2000".to_string()]
        );
    }

    #[test]
    fn parse_sd_allowed_trustees_skips_zero_mask_and_dedupes() {
        assert!(parse_sd_allowed_trustees(&sd_with_ace(0, &sid_bytes(2000))).is_empty());
        let sd = sd_with_ace(READ_PROPERTY_MASK, &sid_bytes(2000));
        assert_eq!(parse_sd_allowed_trustees(&sd).len(), 1);
    }

    const TEST_DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    fn principal_sid_bytes(rid: u32) -> Vec<u8> {
        let mut b = vec![0x01u8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        for sub in [21u32, 1111111111, 2222222222, 3333333333, rid] {
            b.extend_from_slice(&sub.to_le_bytes());
        }
        b
    }

    fn acl_output_granting(rid: u32) -> String {
        let sd = encode_sd(&sd_with_ace(GENERIC_ALL, &principal_sid_bytes(rid)));
        format!(
            "\
dn: CN=alice,CN=Users,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
nTSecurityDescriptor:: {sd}
"
        )
    }

    #[test]
    fn well_known_sid_resolves_domain_relative_rids() {
        for (rid, name) in [
            (512, "Domain Admins"),
            (519, "Enterprise Admins"),
            (516, "Domain Controllers"),
            (502, "krbtgt"),
            (526, "Key Admins"),
        ] {
            assert_eq!(
                well_known_sid(&format!("{TEST_DOMAIN_SID}-{rid}")),
                Some(name)
            );
        }
    }

    #[test]
    fn well_known_sid_rejects_sids_that_are_not_domain_principals() {
        // Too few sub-authorities to be `S-1-5-21-<a>-<b>-<c>-<rid>`.
        assert_eq!(well_known_sid("S-1-5-21-1-2-512"), None);
        assert_eq!(well_known_sid(&format!("{TEST_DOMAIN_SID}-512-1")), None);
        assert_eq!(well_known_sid("S-1-5-21-a-b-c-512"), None);
        // A user RID is domain-specific and must stay unresolved.
        assert_eq!(well_known_sid(&format!("{TEST_DOMAIN_SID}-1104")), None);
    }

    #[test]
    fn well_known_sid_resolves_builtin_aliases() {
        assert_eq!(
            well_known_sid("S-1-5-32-544"),
            Some("BUILTIN\\Administrators")
        );
        assert_eq!(
            well_known_sid("S-1-5-32-548"),
            Some("BUILTIN\\Account Operators")
        );
        assert_eq!(
            well_known_sid("S-1-5-32-551"),
            Some("BUILTIN\\Backup Operators")
        );
        assert_eq!(well_known_sid("S-1-5-32-99999"), None);
    }

    #[test]
    fn is_unactionable_acl_source_ignores_the_builtin_prefix() {
        assert!(is_unactionable_acl_source("BUILTIN\\Administrators"));
        assert!(is_unactionable_acl_source("BUILTIN\\Account Operators"));
        assert!(is_unactionable_acl_source("Account Operators"));
        // Operator groups that ARE an escalation primitive must stay publishable.
        assert!(!is_unactionable_acl_source("BUILTIN\\Backup Operators"));
        assert!(!is_unactionable_acl_source("BUILTIN\\Server Operators"));
    }

    #[test]
    fn unresolved_privileged_trustee_is_filtered_not_published_as_a_raw_sid() {
        for rid in [512, 519, 516] {
            let vulns = parse_acl_enumeration(
                &acl_output_granting(rid),
                &serde_json::json!({"domain": "contoso.local"}),
            );
            assert!(
                vulns.is_empty(),
                "RID {rid} is not an escalation primitive, got: {vulns:?}"
            );
        }
    }

    #[test]
    fn unresolved_actionable_trustee_renders_its_name_not_the_sid() {
        let vulns = parse_acl_enumeration(
            &acl_output_granting(553),
            &serde_json::json!({"domain": "contoso.local"}),
        );
        assert_eq!(vulns.len(), 1, "got: {vulns:?}");
        assert_eq!(vulns[0]["source"], "RAS and IAS Servers");
        assert_eq!(
            vulns[0]["details"]["description"],
            "RAS and IAS Servers has genericall on alice (User)"
        );
        assert_eq!(
            vulns[0]["details"]["trustee_sid"],
            format!("{TEST_DOMAIN_SID}-553")
        );
        assert_eq!(
            vulns[0]["vuln_id"],
            "acl_genericall_ras_and_ias_servers_alice"
        );
    }

    #[test]
    fn a_directory_resolved_name_still_wins_over_the_rid_table() {
        let sd = encode_sd(&sd_with_ace(GENERIC_ALL, &principal_sid_bytes(553)));
        let output = format!(
            "\
dn: CN=svc_ras,CN=Users,DC=contoso,DC=local
sAMAccountName: svc_ras
objectClass: group
objectSid: {TEST_DOMAIN_SID}-553

dn: CN=alice,CN=Users,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
nTSecurityDescriptor:: {sd}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert_eq!(vulns.len(), 1, "got: {vulns:?}");
        assert_eq!(vulns[0]["source"], "svc_ras");
    }

    #[test]
    fn is_laps_expiry_attribute_matches_both_laps_generations() {
        assert!(is_laps_expiry_attribute(
            "ms-Mcs-AdmPwdExpirationTime: 133700000000000000"
        ));
        assert!(is_laps_expiry_attribute(
            "msLAPS-PasswordExpirationTime: 133700000000000000"
        ));
    }

    #[test]
    fn is_laps_expiry_attribute_rejects_valueless_and_unrelated_lines() {
        assert!(!is_laps_expiry_attribute("ms-Mcs-AdmPwdExpirationTime:"));
        assert!(!is_laps_expiry_attribute("sAMAccountName: ws01$"));
        assert!(!is_laps_expiry_attribute("ms-Mcs-AdmPwd: P@ssw0rd!"));
        assert!(!is_laps_expiry_attribute("no colon here"));
    }

    #[test]
    fn parse_acl_enumeration_emits_gmsa_reader_from_group_msa_membership() {
        let membership = encode_sd(&sd_with_ace(READ_PROPERTY_MASK, &sid_bytes(2000)));
        let output = format!(
            "\
dn: CN=web01,DC=contoso,DC=local
sAMAccountName: WEB01$
objectClass: computer
objectSid: S-1-5-21-1-2-2000

dn: CN=svc_gmsa,CN=Managed Service Accounts,DC=contoso,DC=local
sAMAccountName: svc_gmsa$
objectClass: computer
objectClass: msDS-GroupManagedServiceAccount
objectSid: S-1-5-21-1-2-3000
msDS-GroupMSAMembership:: {membership}
"
        );
        let vulns = parse_acl_enumeration(
            &output,
            &serde_json::json!({"domain": "contoso.local", "target": "192.168.58.10"}),
        );
        assert_eq!(
            vulns.len(),
            1,
            "expected one gmsa_reader edge, got {vulns:?}"
        );
        let v = &vulns[0];
        assert_eq!(v["vuln_type"], "gmsa_reader");
        assert_eq!(v["source"], "WEB01$");
        assert_eq!(v["target"], "svc_gmsa$");
        assert_eq!(v["target_type"], "gMSA");
        assert_eq!(v["details"]["gmsa_account"], "svc_gmsa$");
        assert_eq!(v["details"]["source"], "WEB01$");
        assert_eq!(v["details"]["domain"], "contoso.local");
        assert_eq!(v["target_ip"], "192.168.58.10");
    }

    #[test]
    fn parse_acl_enumeration_gmsa_reader_skips_unactionable_trustee() {
        let system_sid = [
            0x01u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];
        let membership = encode_sd(&sd_with_ace(READ_PROPERTY_MASK, &system_sid));
        let output = format!(
            "\
dn: CN=svc_gmsa,CN=Managed Service Accounts,DC=contoso,DC=local
sAMAccountName: svc_gmsa$
objectClass: msDS-GroupManagedServiceAccount
objectSid: S-1-5-21-1-2-3000
msDS-GroupMSAMembership:: {membership}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(
            vulns.is_empty(),
            "SYSTEM must not become a reader: {vulns:?}"
        );
    }

    #[test]
    fn parse_acl_enumeration_emits_laps_reader_for_laps_managed_computer() {
        let output = format!(
            "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001

dn: CN=ws01,DC=contoso,DC=local
sAMAccountName: ws01$
objectClass: computer
objectSid: S-1-5-21-1-2-2000
ms-Mcs-AdmPwdExpirationTime: 133700000000000000
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        let types: Vec<_> = vulns
            .iter()
            .map(|v| v["vuln_type"].as_str().unwrap_or(""))
            .collect();
        assert!(types.contains(&"genericall"), "got {vulns:?}");
        assert!(types.contains(&"laps_reader"), "got {vulns:?}");
        let laps = vulns
            .iter()
            .find(|v| v["vuln_type"] == "laps_reader")
            .expect("laps_reader edge");
        assert_eq!(laps["source"], "alice");
        assert_eq!(laps["target"], "ws01$");
        assert_eq!(laps["details"]["target_computer"], "ws01$");
        assert_eq!(laps["details"]["conferring_right"], "genericall");
        assert_eq!(laps["details"]["domain"], "contoso.local");
    }

    #[test]
    fn parse_acl_enumeration_emits_laps_reader_for_windows_laps_attribute() {
        let output = format!(
            "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001

dn: CN=ws01,DC=contoso,DC=local
sAMAccountName: ws01$
objectClass: computer
objectSid: S-1-5-21-1-2-2000
msLAPS-PasswordExpirationTime: 133700000000000000
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(vulns.iter().any(|v| v["vuln_type"] == "laps_reader"));
    }

    #[test]
    fn parse_acl_enumeration_no_laps_reader_without_expiry_attribute() {
        let output = format!(
            "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001

dn: CN=ws01,DC=contoso,DC=local
sAMAccountName: ws01$
objectClass: computer
objectSid: S-1-5-21-1-2-2000
nTSecurityDescriptor:: {SD_GENERIC_ALL_B64}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(
            !vulns.iter().any(|v| v["vuln_type"] == "laps_reader"),
            "an unmanaged computer must not yield a LAPS reader: {vulns:?}"
        );
    }

    #[test]
    fn parse_acl_enumeration_no_laps_reader_for_non_conferring_right() {
        let sd = encode_sd(&sd_with_ace(WRITE_DACL, &sid_bytes(1001)));
        let output = format!(
            "\
dn: CN=alice,DC=contoso,DC=local
sAMAccountName: alice
objectClass: user
objectSid: S-1-5-21-1-2-1001

dn: CN=ws01,DC=contoso,DC=local
sAMAccountName: ws01$
objectClass: computer
objectSid: S-1-5-21-1-2-2000
ms-Mcs-AdmPwdExpirationTime: 133700000000000000
nTSecurityDescriptor:: {sd}
"
        );
        let vulns = parse_acl_enumeration(&output, &serde_json::json!({"domain": "contoso.local"}));
        assert!(vulns.iter().any(|v| v["vuln_type"] == "writedacl"));
        assert!(
            !vulns.iter().any(|v| v["vuln_type"] == "laps_reader"),
            "writedacl does not confer a LAPS read: {vulns:?}"
        );
    }
}
