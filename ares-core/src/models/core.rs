//! Core data models: Target, Host, User, Credential, Hash, Share.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::util::{default_hash_type, new_uuid};

/// Primary target information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
}

/// Discovered host information.
///
/// Redis serialization: `{"ip","hostname","os","roles","services","is_dc"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Host {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(default)]
    pub is_dc: bool,
    #[serde(default)]
    pub owned: bool,
}

impl Host {
    /// Detect if this host is a domain controller based on services/hostname/roles.
    pub fn detect_dc(&self) -> bool {
        let hostname_lower = self.hostname.to_lowercase();
        let roles_lower = self.roles.join(" ").to_lowercase();

        if hostname_lower.contains("dc") || roles_lower.contains("domain controller") {
            return true;
        }

        let dc_port_prefixes = ["88/tcp", "389/tcp"];
        let dc_service_names = ["kerberos", "ldap"];

        for svc in &self.services {
            let svc_lower = svc.to_lowercase();
            if dc_port_prefixes.iter().any(|p| svc_lower.starts_with(p)) {
                return true;
            }
            if dc_service_names.iter().any(|name| svc_lower.contains(name)) {
                return true;
            }
        }
        false
    }
}

/// Discovered user account.
///
/// Redis serialization: `{"username","domain","source"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

/// AD built-in accounts that ship `userAccountControl & ACCOUNTDISABLE` set
/// out of the box. Spraying or otherwise auth'ing against these can never
/// succeed and just burns the per-account badPwdCount budget — which on
/// shared lockout policies trips real accounts in the same window.
pub fn is_always_disabled_account(username: &str) -> bool {
    matches!(
        username.to_lowercase().as_str(),
        "guest" | "defaultaccount" | "wdagutilityaccount" | "krbtgt"
    )
}

/// Discovered credential.
///
/// Redis serialization: `{"id","username","password","domain","source","parent_id","attack_step"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub attack_step: i32,
}

/// Discovered password hash.
///
/// Redis serialization: `{"id","username","hash_type","hash_value","domain","source","cracked_password","discovered_at","parent_id","attack_step"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hash {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub username: String,
    pub hash_value: String,
    #[serde(default = "default_hash_type")]
    pub hash_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cracked_password: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub attack_step: i32,
    /// AES256 key for Kerberos golden tickets (Windows 2016+ rejects RC4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aes_key: Option<String>,
    /// True when this is a previous (rotated-out) credential history entry —
    /// NTDS exposes `_history0`, `_history1`, etc. for trust accounts and user
    /// principals. Operationally, prefer current keys for ticket forging and
    /// fall back to history only when current fails (e.g. mid-rotation
    /// window). Defaults to `false` for forward compatibility with existing
    /// Redis records.
    #[serde(default)]
    pub is_previous: bool,
    /// Source host the hash was dumped from (IP or hostname). Threaded from
    /// the dispatcher seam so multiple local-SAM `Administrator` / `Guest` /
    /// `ssm-user` rows from different hosts don't collapse on dedup. Empty for
    /// domain-qualified (NTDS) rows where the realm already disambiguates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_host: Option<String>,
    /// True when the row's username ends in `$` AND the row's domain differs
    /// from the dumping machine's home domain — i.e. this is an inter-realm
    /// trust account hash (forging material), not the local machine account.
    /// Set by the secretsdump parser; renderers hoist these into a dedicated
    /// "Trust Keys / Forging Material" section.
    #[serde(default)]
    pub is_trust_key: bool,
    /// When `is_trust_key` is true, the NetBIOS label of the trust target
    /// (e.g. `FABRIKAM` for a `FABRIKAM$` row dumped from `contoso.local`).
    /// Used for symmetric-pair detection in the report renderer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_pair_label: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(hostname: &str, services: Vec<&str>, roles: Vec<&str>) -> Host {
        Host {
            ip: "192.168.58.10".to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: roles.into_iter().map(String::from).collect(),
            services: services.into_iter().map(String::from).collect(),
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn detect_dc_by_kerberos_service() {
        let host = make_host("srv01", vec!["88/tcp (kerberos-sec)"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_ldap_service() {
        let host = make_host("srv01", vec!["389/tcp (ldap)"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_hostname_prefix() {
        let host = make_host("dc01.contoso.local", vec![], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_role() {
        let host = make_host("srv01", vec![], vec!["domain controller"]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_not_dc() {
        let host = make_host(
            "srv01.contoso.local",
            vec!["445/tcp (microsoft-ds)"],
            vec![],
        );
        assert!(!host.detect_dc());
    }

    #[test]
    fn detect_dc_empty() {
        let host = make_host("", vec![], vec![]);
        assert!(!host.detect_dc());
    }

    #[test]
    fn detect_dc_case_insensitive() {
        let host = make_host("DC01.CONTOSO.LOCAL", vec![], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_kerberos_service_name() {
        let host = make_host("server", vec!["kerberos"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_by_ldap_service_name() {
        let host = make_host("server", vec!["ldap"], vec![]);
        assert!(host.detect_dc());
    }

    #[test]
    fn trust_info_is_parent_child() {
        let t = TrustInfo {
            domain: "child.contoso.local".to_string(),
            flat_name: "CHILD".to_string(),
            direction: "bidirectional".to_string(),
            trust_type: "parent_child".to_string(),
            sid_filtering: false,
            security_identifier: None,
        };
        assert!(t.is_parent_child());
        assert!(!t.is_cross_forest());
    }

    #[test]
    fn trust_info_is_cross_forest() {
        let t = TrustInfo {
            domain: "fabrikam.local".to_string(),
            flat_name: "FABRIKAM".to_string(),
            direction: "outbound".to_string(),
            trust_type: "forest".to_string(),
            sid_filtering: true,
            security_identifier: None,
        };
        assert!(t.is_cross_forest());
        assert!(!t.is_parent_child());
    }

    #[test]
    fn trust_info_external_is_cross_forest() {
        let t = TrustInfo {
            domain: "other.local".to_string(),
            flat_name: "OTHER".to_string(),
            direction: "inbound".to_string(),
            trust_type: "external".to_string(),
            sid_filtering: false,
            security_identifier: None,
        };
        assert!(t.is_cross_forest());
    }

    #[test]
    fn trust_info_unknown_type_not_cross_forest() {
        let t = TrustInfo {
            domain: "x.local".to_string(),
            flat_name: String::new(),
            direction: String::new(),
            trust_type: "unknown".to_string(),
            sid_filtering: false,
            security_identifier: None,
        };
        assert!(!t.is_cross_forest());
        assert!(!t.is_parent_child());
    }

    #[test]
    fn host_serde_roundtrip() {
        let host = Host {
            ip: "192.168.58.1".to_string(),
            hostname: "web01".to_string(),
            os: "Windows Server 2019".to_string(),
            roles: vec!["web".to_string()],
            services: vec!["80/tcp".to_string(), "443/tcp".to_string()],
            is_dc: false,
            owned: true,
        };
        let json = serde_json::to_string(&host).unwrap();
        let deser: Host = serde_json::from_str(&json).unwrap();
        assert_eq!(host, deser);
    }

    #[test]
    fn host_serde_defaults() {
        let json = r#"{"ip":"192.168.58.1"}"#;
        let host: Host = serde_json::from_str(json).unwrap();
        assert_eq!(host.ip, "192.168.58.1");
        assert!(host.hostname.is_empty());
        assert!(host.os.is_empty());
        assert!(host.roles.is_empty());
        assert!(host.services.is_empty());
        assert!(!host.is_dc);
        assert!(!host.owned);
    }

    #[test]
    fn credential_serde_roundtrip() {
        let cred = Credential {
            id: "test-id".to_string(),
            username: "admin".to_string(),
            password: "P@ssw0rd".to_string(),
            domain: "CONTOSO".to_string(),
            source: "secretsdump".to_string(),
            discovered_at: None,
            is_admin: true,
            parent_id: Some("parent-1".to_string()),
            attack_step: 2,
        };
        let json = serde_json::to_string(&cred).unwrap();
        let deser: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, deser);
    }

    #[test]
    fn hash_serde_defaults() {
        let json = r#"{"username":"admin","hash_value":"aad3b435"}"#;
        let hash: Hash = serde_json::from_str(json).unwrap();
        assert_eq!(hash.username, "admin");
        assert_eq!(hash.hash_value, "aad3b435");
        assert_eq!(hash.hash_type, "NTLM");
        assert!(hash.domain.is_empty());
        assert!(hash.cracked_password.is_none());
        assert!(hash.aes_key.is_none());
        assert_eq!(hash.attack_step, 0);
    }

    #[test]
    fn hash_serde_with_aes_key() {
        let hash = Hash {
            id: "h1".to_string(),
            username: "krbtgt".to_string(),
            hash_value: "abc123".to_string(),
            hash_type: "NTLM".to_string(),
            domain: "CONTOSO".to_string(),
            cracked_password: None,
            source: "dcsync".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 1,
            aes_key: Some("aes256key".to_string()),
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        };
        let json = serde_json::to_string(&hash).unwrap();
        assert!(json.contains("aes256key"));
        let deser: Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, deser);
    }

    #[test]
    fn share_serde_roundtrip() {
        let share = Share {
            host: "192.168.58.5".to_string(),
            name: "ADMIN$".to_string(),
            permissions: "READ".to_string(),
            comment: "Remote Admin".to_string(),
            authenticated_as: None,
        };
        let json = serde_json::to_string(&share).unwrap();
        let deser: Share = serde_json::from_str(&json).unwrap();
        assert_eq!(share, deser);
    }

    #[test]
    fn share_serde_defaults() {
        let json = r#"{"host":"192.168.58.5","name":"C$"}"#;
        let share: Share = serde_json::from_str(json).unwrap();
        assert_eq!(share.host, "192.168.58.5");
        assert_eq!(share.name, "C$");
        assert!(share.permissions.is_empty());
        assert!(share.comment.is_empty());
    }

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            username: "jdoe".to_string(),
            domain: "CONTOSO".to_string(),
            description: "John Doe".to_string(),
            is_admin: true,
            source: "ldap".to_string(),
        };
        let json = serde_json::to_string(&user).unwrap();
        let deser: User = serde_json::from_str(&json).unwrap();
        assert_eq!(user, deser);
    }

    #[test]
    fn user_serde_defaults() {
        let json = r#"{"username":"guest"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "guest");
        assert!(user.domain.is_empty());
        assert!(user.description.is_empty());
        assert!(!user.is_admin);
        assert!(user.source.is_empty());
    }

    #[test]
    fn target_serde_roundtrip() {
        let target = Target {
            ip: "192.168.58.1".to_string(),
            hostname: "dc01".to_string(),
            domain: "contoso.local".to_string(),
            environment: "prod".to_string(),
        };
        let json = serde_json::to_string(&target).unwrap();
        let deser: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deser);
    }

    #[test]
    fn target_serde_skip_empty() {
        let target = Target {
            ip: "192.168.58.1".to_string(),
            hostname: String::new(),
            domain: String::new(),
            environment: String::new(),
        };
        let json = serde_json::to_string(&target).unwrap();
        assert!(!json.contains("hostname"));
        assert!(!json.contains("domain"));
        assert!(!json.contains("environment"));
    }

    #[test]
    fn trust_info_serde_roundtrip() {
        let trust = TrustInfo {
            domain: "child.contoso.local".to_string(),
            flat_name: "CHILD".to_string(),
            direction: "bidirectional".to_string(),
            trust_type: "parent_child".to_string(),
            sid_filtering: true,
            security_identifier: None,
        };
        let json = serde_json::to_string(&trust).unwrap();
        let deser: TrustInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(trust, deser);
    }

    #[test]
    fn detect_dc_by_multiple_services() {
        let host = make_host(
            "srv01",
            vec!["88/tcp (kerberos)", "389/tcp (ldap)", "445/tcp"],
            vec![],
        );
        assert!(host.detect_dc());
    }

    #[test]
    fn detect_dc_non_dc_services_only() {
        let host = make_host(
            "fileserver",
            vec!["445/tcp (microsoft-ds)", "139/tcp (netbios-ssn)"],
            vec!["file server"],
        );
        assert!(!host.detect_dc());
    }

    #[test]
    fn host_skip_empty_fields_in_json() {
        let host = Host {
            ip: "192.168.58.1".to_string(),
            hostname: String::new(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(!json.contains("hostname"));
        assert!(!json.contains("os"));
        assert!(!json.contains("roles"));
        assert!(!json.contains("services"));
    }
}

/// Trust relationship metadata for an AD domain trust.
///
/// Stores structured trust information discovered via `enumerate_domain_trusts`
/// (LDAP `objectClass=trustedDomain`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustInfo {
    /// FQDN of the trusted domain (e.g. `fabrikam.local`).
    pub domain: String,
    /// NetBIOS / flat name (e.g. `FABRIKAM`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flat_name: String,
    /// Trust direction: `"inbound"`, `"outbound"`, or `"bidirectional"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub direction: String,
    /// Trust type: `"parent_child"`, `"forest"`, `"external"`, or `"unknown"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trust_type: String,
    /// Whether SID filtering is active (blocks RID < 1000 across forest trusts).
    #[serde(default)]
    pub sid_filtering: bool,
    /// Domain SID of the trusted partner, in canonical S-1-5-21-X-Y-Z form
    /// when the LDAP `securityIdentifier` attribute was captured by
    /// `enumerate_domain_trusts`. Carrying this on the trust object lets the
    /// orchestrator pre-populate `state.domain_sids` for the partner without
    /// a separate authenticated SAMR lookup against the foreign DC — that
    /// lookup gates child→parent forge dispatch on hardened (2019+) parent
    /// DCs where cross-realm NTLM is rejected and null-session lsaquery is
    /// disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_identifier: Option<String>,
}

impl TrustInfo {
    /// Is this a parent-child (intra-forest) trust?
    pub fn is_parent_child(&self) -> bool {
        self.trust_type == "parent_child"
    }

    /// Is this a cross-forest trust?
    pub fn is_cross_forest(&self) -> bool {
        self.trust_type == "forest" || self.trust_type == "external"
    }
}

/// Strength of evidence that a candidate string is a real AD domain.
///
/// Production AD discovery tools (BloodHound, NetExec, runZero) never trust a
/// hostname suffix alone — they require positive AD evidence (DC self-report,
/// authenticated bind, SRV record) before promoting a string to "authoritative
/// domain." This enum lets us tag the source of each candidate so the promotion
/// rules can stay consistent across discovery paths.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DomainEvidence {
    /// Configured in the operation target — authoritative starting point.
    TargetConfig,
    /// A DC self-reported the domain name (CLDAP NetLogon `DnsDomainName`,
    /// Kerberos AS-REP `crealm`, anonymous LDAP RootDSE `defaultNamingContext`).
    DcSelfReport,
    /// Captured from authenticated AD enumeration — successful LDAP bind,
    /// secretsdump, SMB session info from a verified auth.
    AuthenticatedAd,
    /// DNS SRV record `_ldap._tcp.dc._msdcs.<domain>` resolves.
    DnsSrv,
    /// Inferred from a host FQDN suffix (e.g. `srv01.contoso.local` →
    /// `contoso.local`). Lowest tier — must be corroborated before promotion.
    HostnameInference,
}

impl DomainEvidence {
    /// Whether this evidence is sufficient to promote a candidate to
    /// authoritative state without further corroboration.
    pub fn is_authoritative(self) -> bool {
        matches!(
            self,
            Self::TargetConfig | Self::DcSelfReport | Self::AuthenticatedAd | Self::DnsSrv
        )
    }
}

/// A domain name discovered during an operation, with provenance.
///
/// Held in `state.candidate_domains` until either (a) the evidence is
/// authoritative on its own, (b) a probe (DNS SRV / CLDAP) corroborates it,
/// or (c) it matches a domain already promoted via another path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateDomain {
    /// Lowercase FQDN.
    pub fqdn: String,
    pub evidence: DomainEvidence,
    /// IP of the host that produced this candidate (when applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_host_ip: Option<String>,
    pub discovered_at: DateTime<Utc>,
    /// Set once a probe has run. `confirmed = false` after probing means the
    /// probe rejected it; we keep the record so we don't re-probe.
    #[serde(default)]
    pub probed: bool,
    #[serde(default)]
    pub confirmed: bool,
    /// Timestamp of the most recent probe attempt. Used to retry transient
    /// probe failures without hammering DNS every loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probed_at: Option<DateTime<Utc>>,
    /// Count of transient probe attempts. Useful for visibility/backoff.
    #[serde(default)]
    pub probe_failures: u32,
}

impl CandidateDomain {
    pub fn new(fqdn: impl Into<String>, evidence: DomainEvidence) -> Self {
        Self {
            fqdn: fqdn.into().to_lowercase(),
            evidence,
            source_host_ip: None,
            discovered_at: Utc::now(),
            probed: false,
            confirmed: evidence.is_authoritative(),
            last_probed_at: None,
            probe_failures: 0,
        }
    }

    pub fn with_source(mut self, ip: impl Into<String>) -> Self {
        self.source_host_ip = Some(ip.into());
        self
    }
}

/// Discovered SMB share.
///
/// Redis serialization: `{"host","name","permissions","comment"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    pub host: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub permissions: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// Credential the enumerating tool authenticated as, formatted
    /// `"DOMAIN\\username"`. Lets the report show which key established
    /// READ/WRITE on the share so an operator can re-issue the same auth for
    /// follow-on file ops. `None` for share rows recovered from output that
    /// lost credential context (legacy serialized records, raw-text fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_as: Option<String>,
}

/// A forged Kerberos inter-realm ticket produced by `create_inter_realm_ticket`.
///
/// Stored in Redis (`ares:op:{id}:kerberos_tickets` HASH keyed by
/// `{source_domain}:{target_domain}:{username}`) so downstream tools can pick
/// up the ccache path when no NTLM bind works for the target forest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KerberosTicket {
    /// The domain whose krbtgt trust key was used to forge (source forest).
    pub source_domain: String,
    /// The foreign forest the ticket is valid for.
    pub target_domain: String,
    /// Username encoded in the ticket (typically `Administrator`).
    pub username: String,
    /// Absolute path to the `.ccache` file on the worker filesystem.
    pub ticket_path: String,
    /// When the ticket was forged (UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forged_at: Option<DateTime<Utc>>,
}

impl KerberosTicket {
    /// Redis HASH field key: `{source}:{target}:{username}`.
    pub fn dedup_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.source_domain.to_lowercase(),
            self.target_domain.to_lowercase(),
            self.username.to_lowercase()
        )
    }
}
