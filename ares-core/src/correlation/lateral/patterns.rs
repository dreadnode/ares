//! Lateral movement pattern detection using regex.

use regex::Regex;
use std::sync::LazyLock;

/// Regex for FQDN-like hostnames.
pub static HOSTNAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([a-zA-Z][a-zA-Z0-9-]*\.[a-zA-Z0-9.-]+)\b").unwrap());

/// Regex for bare IPv4 addresses.
pub static IP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());

/// Regex patterns for detecting lateral movement connection types.
pub struct LateralPatterns {
    pub patterns: Vec<(&'static str, Vec<Regex>)>,
}

impl Default for LateralPatterns {
    fn default() -> Self {
        Self::new()
    }
}

impl LateralPatterns {
    pub fn new() -> Self {
        let patterns = vec![
            (
                "smb",
                vec![
                    Regex::new(r"(?i)smb|445|admin\$|c\$|ipc\$").unwrap(),
                    Regex::new(r"(?i)tree.*connect|share.*access").unwrap(),
                    Regex::new(r"(?i)5140|5145").unwrap(),
                ],
            ),
            (
                "rdp",
                vec![
                    Regex::new(r"(?i)rdp|3389|remote.*desktop").unwrap(),
                    Regex::new(r"(?i)4624.*logon.*type.*10").unwrap(),
                    Regex::new(r"(?i)termsrv|mstsc").unwrap(),
                ],
            ),
            (
                "wmi",
                vec![
                    Regex::new(r"(?i)wmi|135|win32_process|root\\cimv2").unwrap(),
                    Regex::new(r"(?i)wmic|wmiprvse").unwrap(),
                ],
            ),
            (
                "psexec",
                vec![
                    Regex::new(r"(?i)psexec|7045|service.*install").unwrap(),
                    Regex::new(r"(?i)psexesvc|remcom").unwrap(),
                ],
            ),
            (
                "winrm",
                vec![
                    Regex::new(r"(?i)winrm|5985|5986|powershell.*session").unwrap(),
                    Regex::new(r"(?i)wsman|enter-pssession").unwrap(),
                ],
            ),
            (
                "ssh",
                vec![Regex::new(r"(?i)ssh|22/tcp|publickey|openssh").unwrap()],
            ),
            (
                "dcom",
                vec![
                    Regex::new(r"(?i)dcom|135/tcp|mmc20|shellwindows").unwrap(),
                    Regex::new(r"(?i)dcomexec|ole32").unwrap(),
                ],
            ),
            (
                "scheduled_task",
                vec![
                    Regex::new(r"(?i)4698|schtasks|taskscheduler").unwrap(),
                    Regex::new(r"(?i)at.*exec|scheduled.*task").unwrap(),
                ],
            ),
        ];
        Self { patterns }
    }

    pub fn detect(&self, text: &str) -> &'static str {
        for (conn_type, regexes) in &self.patterns {
            for re in regexes {
                if re.is_match(text) {
                    return conn_type;
                }
            }
        }
        "unknown"
    }
}
