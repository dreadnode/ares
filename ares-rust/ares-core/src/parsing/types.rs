//! Data structures for parsed security tool outputs.

use std::fmt;
use std::str::FromStr;

/// A parsed NTLM hash entry from secretsdump or similar tool output.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHash {
    pub username: String,
    pub domain: String,
    pub rid: u32,
    pub lm_hash: String,
    pub nt_hash: String,
    /// Combined `LM:NT` hash value.
    pub hash_value: String,
    /// `true` when RID is 502 or username is `krbtgt` (case-insensitive).
    pub is_krbtgt: bool,
    /// `true` when RID is 500 or username is `administrator` (case-insensitive).
    pub is_administrator: bool,
    /// `true` when the username ends with `$`.
    pub is_machine_account: bool,
}

/// Type of Kerberos hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerberosHashType {
    /// TGS (`$krb5tgs$`) hash from Kerberoasting.
    TGS,
    /// AS-REP (`$krb5asrep$`) hash from AS-REP roasting.
    AsRep,
}

/// A parsed Kerberos hash entry.
#[derive(Debug, Clone, PartialEq)]
pub struct KerberosHash {
    pub username: String,
    pub domain: String,
    pub hash_value: String,
    pub hash_type: KerberosHashType,
}

/// A parsed host from netexec/crackmapexec SMB output.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHost {
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub domain: String,
}

/// Type of Kerberos delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationType {
    Unconstrained,
    Constrained,
    RBCD,
}

impl fmt::Display for DelegationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelegationType::Unconstrained => write!(f, "Unconstrained"),
            DelegationType::Constrained => write!(f, "Constrained"),
            DelegationType::RBCD => write!(f, "RBCD"),
        }
    }
}

/// Error returned when parsing a [`DelegationType`] from a string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDelegationTypeError(pub String);

impl fmt::Display for ParseDelegationTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown delegation type: {}", self.0)
    }
}

impl std::error::Error for ParseDelegationTypeError {}

impl FromStr for DelegationType {
    type Err = ParseDelegationTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        if lower.contains("unconstrained") && !lower.contains("resource") {
            Ok(DelegationType::Unconstrained)
        } else if lower.contains("resource") || lower.contains("rbcd") {
            Ok(DelegationType::RBCD)
        } else if lower.contains("constrained") {
            Ok(DelegationType::Constrained)
        } else {
            Err(ParseDelegationTypeError(s.to_string()))
        }
    }
}

/// A parsed delegation entry from impacket-findDelegation output.
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationEntry {
    pub account: String,
    pub account_type: String,
    pub delegation_type: DelegationType,
    pub target_spn: Option<String>,
}

/// A parsed SMB share.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedShare {
    pub host: String,
    pub name: String,
    pub permissions: String,
    pub comment: String,
}
