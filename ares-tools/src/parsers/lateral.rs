use serde_json::{json, Value};

const HARD_FAILURE_MARKERS: &[&str] = &[
    "status_access_denied",
    "status_account_disabled",
    "status_account_locked_out",
    "status_account_restriction",
    "status_bad_network_name",
    "status_connection_refused",
    "status_connection_reset",
    "status_host_unreachable",
    "status_io_timeout",
    "status_logon_failure",
    "status_logon_type_not_granted",
    "status_no_logon_servers",
    "status_no_such_user",
    "status_password_expired",
    "status_password_must_change",
    "status_pipe_not_available",
    "status_wrong_password",
    "rpc_s_access_denied",
    "e_accessdenied",
    "0x80070005",
    "kdc_err_",
    "krb_ap_err_",
    "access denied",
    "access_denied",
    "authentication failed",
    "authentication failure",
    "login failed",
    "logon failure",
    "cannot connect",
    "could not connect",
    "unable to connect",
    "connection refused",
    "connection reset",
    "no route to host",
    "network is unreachable",
    "session setup failed",
    "session error",
    "sessionerror",
    "tree connect failed",
    "timed out",
    "errno 111",
    "errno 113",
    "traceback (most recent call last)",
];

const NOISE_MARKERS: &[&str] = &[
    "unable to initialize messaging context",
    "deprecated",
    "note: this is a debug build",
    "to get a list of possible commands",
    "warning:",
    "warnings.warn",
];

const EXEC_MARKERS: &[&str] = &[
    "creating service",
    "starting service",
    "found writable share",
    "launching semi-interactive shell",
    "press help for extra shell commands",
    "c:\\windows\\system32>",
];

const SMB_SESSION_MARKERS: &[&str] = &["dialect used"];

const MSSQL_SESSION_MARKERS: &[&str] =
    &["envchange(database)", "changed database context", "sql ("];

const SHARE_LISTING_MARKERS: &[&str] = &["blocks of size", "blocks available"];

const WMIS_CLASS_MARKERS: &[&str] = &["class: "];

const TICKET_SAVED_MARKERS: &[&str] = &["saving ticket in"];

fn contains_any(output: &str, markers: &[&str]) -> bool {
    let lowered = output.to_ascii_lowercase();
    markers.iter().any(|m| lowered.contains(m))
}

fn indicates_failure(output: &str) -> bool {
    contains_any(output, HARD_FAILURE_MARKERS)
        || output.lines().any(|l| l.trim_start().starts_with("[-]"))
}

fn has_remote_command_output(output: &str) -> bool {
    output.lines().map(str::trim).any(|line| {
        if line.is_empty()
            || line.starts_with('[')
            || line.starts_with("---")
            || line.starts_with('/')
            || line.starts_with("ERROR")
            || line.starts_with("Impacket v")
            || line.starts_with("Copyright")
        {
            return false;
        }
        !contains_any(line, NOISE_MARKERS)
    })
}

fn target_ip(params: &Value) -> String {
    ["target_ip", "target", "dc_ip", "host"]
        .iter()
        .filter_map(|k| params.get(*k).and_then(Value::as_str))
        .map(str::trim)
        .find(|v| super::looks_like_ip(v))
        .unwrap_or_default()
        .to_string()
}

fn target_hostname(params: &Value) -> String {
    ["target", "hostname"]
        .iter()
        .filter_map(|k| params.get(*k).and_then(Value::as_str))
        .map(str::trim)
        .find(|v| !v.is_empty() && !super::looks_like_ip(v))
        .unwrap_or_default()
        .to_lowercase()
}

fn host_record(params: &Value, roles: &[&str], services: &[&str], owned: bool) -> Vec<Value> {
    let ip = target_ip(params);
    let hostname = target_hostname(params);
    if ip.is_empty() && hostname.is_empty() {
        return Vec::new();
    }
    vec![json!({
        "ip": ip,
        "hostname": hostname,
        "os": "",
        "roles": roles,
        "services": services,
        "is_dc": false,
        "owned": owned,
    })]
}

pub fn parse_remote_exec(tool_name: &str, output: &str, params: &Value) -> Vec<Value> {
    if indicates_failure(output) {
        return Vec::new();
    }

    let impacket_exec = contains_any(output, EXEC_MARKERS)
        || contains_any(output, SMB_SESSION_MARKERS)
        || has_remote_command_output(output);

    let (roles, services, owned, succeeded) = match tool_name {
        "psexec" | "psexec_kerberos" | "smbexec" | "smbexec_kerberos" => {
            (&["smb"][..], &["445/tcp"][..], true, impacket_exec)
        }
        "wmiexec" | "wmiexec_kerberos" => (
            &["wmi"][..],
            &["135/tcp", "445/tcp"][..],
            true,
            impacket_exec,
        ),
        "pth_winexe" => (
            &["smb"][..],
            &["445/tcp"][..],
            true,
            has_remote_command_output(output),
        ),
        "pth_wmic" => (
            &["wmi"][..],
            &["135/tcp"][..],
            false,
            contains_any(output, WMIS_CLASS_MARKERS),
        ),
        "pth_rpcclient" => (
            &["smb"][..],
            &["445/tcp"][..],
            false,
            has_remote_command_output(output),
        ),
        _ => return Vec::new(),
    };

    if !succeeded {
        return Vec::new();
    }
    host_record(params, roles, services, owned)
}

pub fn parse_smb_share_access(output: &str, params: &Value) -> Vec<Value> {
    if indicates_failure(output) {
        return Vec::new();
    }
    if !contains_any(output, SHARE_LISTING_MARKERS) && !has_remote_command_output(output) {
        return Vec::new();
    }
    let host = params
        .get("target")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if host.is_empty() {
        return Vec::new();
    }
    let share = params
        .get("share")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("C$");
    vec![json!({
        "host": host,
        "name": share,
        "permissions": "READ",
        "comment": "",
    })]
}

pub fn parse_tgt_request(output: &str, params: &Value) -> Vec<Value> {
    if indicates_failure(output) || !contains_any(output, TICKET_SAVED_MARKERS) {
        return Vec::new();
    }
    let ip = params
        .get("dc_ip")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| super::looks_like_ip(v))
        .unwrap_or_default();
    if ip.is_empty() {
        return Vec::new();
    }
    vec![json!({
        "ip": ip,
        "hostname": "",
        "os": "",
        "roles": [],
        "services": ["88/tcp"],
        "is_dc": false,
        "owned": false,
    })]
}

pub fn parse_mssql_session(output: &str, params: &Value) -> Vec<Value> {
    if indicates_failure(output) || !contains_any(output, MSSQL_SESSION_MARKERS) {
        return Vec::new();
    }
    host_record(params, &["mssql"], &["1433/tcp (ms-sql-s)"], false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Value {
        json!({"target": "192.168.58.20", "username": "alice", "domain": "contoso.local"})
    }

    #[test]
    fn psexec_service_creation_marks_host_owned() {
        let output = "\
[*] Requesting shares on 192.168.58.20.....
[*] Found writable share ADMIN$
[*] Uploading file abcdefgh.exe
[*] Opening SVCManager on 192.168.58.20.....
[*] Creating service qWxZ on 192.168.58.20.....
[*] Starting service qWxZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.3.9600]
C:\\Windows\\system32>";
        let hosts = parse_remote_exec("psexec", output, &params());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.20");
        assert_eq!(hosts[0]["owned"], true);
        assert_eq!(hosts[0]["services"][0], "445/tcp");
    }

    #[test]
    fn psexec_kerberos_variant_shares_the_arm() {
        let output = "[*] Creating service qWxZ on dc01.contoso.local.....\n";
        let params = json!({"target": "dc01.contoso.local", "target_ip": "192.168.58.10"});
        let hosts = parse_remote_exec("psexec_kerberos", output, &params);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
        assert_eq!(hosts[0]["owned"], true);
    }

    #[test]
    fn psexec_admin_share_not_writable_is_not_credited() {
        let output = "\
[*] Requesting shares on 192.168.58.20.....
[-] share 'ADMIN$' is not writable.";
        assert!(parse_remote_exec("psexec", output, &params()).is_empty());
    }

    #[test]
    fn psexec_logon_failure_is_not_credited() {
        let output = "[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid.)";
        assert!(parse_remote_exec("psexec", output, &params()).is_empty());
    }

    #[test]
    fn psexec_access_denied_is_not_credited() {
        let output = "\
[*] Requesting shares on 192.168.58.20.....
STATUS_ACCESS_DENIED - {Access Denied}";
        assert!(parse_remote_exec("psexec", output, &params()).is_empty());
    }

    #[test]
    fn psexec_connection_refused_is_not_credited() {
        let output = "[-] [Errno 111] Connection refused";
        assert!(parse_remote_exec("psexec", output, &params()).is_empty());
    }

    #[test]
    fn psexec_banner_alone_is_not_credited() {
        let output = "Impacket v0.12.0 - Copyright Fortra, LLC\n\n";
        assert!(parse_remote_exec("psexec", output, &params()).is_empty());
    }

    #[test]
    fn wmiexec_command_output_marks_host_owned() {
        let output =
            "Impacket v0.12.0 - Copyright Fortra, LLC\n\n[*] SMBv3.0 dialect used\ncontoso\\alice\n";
        let hosts = parse_remote_exec("wmiexec", output, &params());
        assert_eq!(hosts[0]["owned"], true);
        assert_eq!(hosts[0]["services"][0], "135/tcp");
    }

    #[test]
    fn wmiexec_dcom_denied_is_not_credited() {
        let output = "[*] SMBv3.0 dialect used\n[-] rpc_s_access_denied\n";
        assert!(parse_remote_exec("wmiexec", output, &params()).is_empty());
    }

    #[test]
    fn wmiexec_python_warning_alone_is_not_credited() {
        let output = "/usr/lib/python3/dist-packages/impacket/foo.py:12: SyntaxWarning: bad escape\n  warnings.warn(msg)\n";
        assert!(parse_remote_exec("wmiexec", output, &params()).is_empty());
    }

    #[test]
    fn smbexec_semi_interactive_shell_marks_host_owned() {
        let output =
            "[!] Launching semi-interactive shell - Careful what you execute\nC:\\Windows\\system32>";
        let hosts = parse_remote_exec("smbexec_kerberos", output, &params());
        assert_eq!(hosts[0]["owned"], true);
    }

    #[test]
    fn pth_winexe_command_output_marks_host_owned() {
        let output = "contoso\\admin\n";
        let hosts = parse_remote_exec("pth_winexe", output, &params());
        assert_eq!(hosts[0]["owned"], true);
    }

    #[test]
    fn pth_winexe_error_line_is_not_credited() {
        let output = "ERROR: Failed to open connection - NT_STATUS_LOGON_FAILURE\n";
        assert!(parse_remote_exec("pth_winexe", output, &params()).is_empty());
    }

    #[test]
    fn pth_wmic_class_header_is_credited_without_ownership() {
        let output = "CLASS: Win32_OperatingSystem\nCaption|CSName\nWindows Server 2019|WS01\n";
        let hosts = parse_remote_exec("pth_wmic", output, &params());
        assert_eq!(hosts[0]["owned"], false);
        assert_eq!(hosts[0]["services"][0], "135/tcp");
    }

    #[test]
    fn pth_wmic_without_class_header_is_not_credited() {
        let output = "some unrelated chatter\n";
        assert!(parse_remote_exec("pth_wmic", output, &params()).is_empty());
    }

    #[test]
    fn pth_rpcclient_getusername_is_credited_without_ownership() {
        let output =
            "Unable to initialize messaging context\nAccount Name: alice, Authority Name: CONTOSO\n";
        let hosts = parse_remote_exec("pth_rpcclient", output, &params());
        assert_eq!(hosts[0]["owned"], false);
    }

    #[test]
    fn pth_rpcclient_samba_noise_alone_is_not_credited() {
        let output = "Unable to initialize messaging context\n";
        assert!(parse_remote_exec("pth_rpcclient", output, &params()).is_empty());
    }

    #[test]
    fn pth_rpcclient_nt_status_result_is_not_credited() {
        let output = "result was NT_STATUS_ACCESS_DENIED\n";
        assert!(parse_remote_exec("pth_rpcclient", output, &params()).is_empty());
    }

    #[test]
    fn unknown_tool_name_yields_nothing() {
        let output = "[*] Creating service qWxZ on 192.168.58.20.....\n";
        assert!(parse_remote_exec("nmap_scan", output, &params()).is_empty());
    }

    #[test]
    fn remote_exec_without_resolvable_target_yields_nothing() {
        let output = "[*] Starting service qWxZ.....\n";
        assert!(parse_remote_exec("psexec", output, &json!({})).is_empty());
    }

    #[test]
    fn smbclient_listing_yields_share() {
        let output = "\
  .                                   D        0  Mon Jul 28 11:02:14 2026
  ..                                  D        0  Mon Jul 28 11:02:14 2026
                9756244 blocks of size 4096. 5364823 blocks available";
        let params = json!({"target": "192.168.58.20", "share": "ADMIN$"});
        let shares = parse_smb_share_access(output, &params);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0]["host"], "192.168.58.20");
        assert_eq!(shares[0]["name"], "ADMIN$");
        assert_eq!(shares[0]["permissions"], "READ");
    }

    #[test]
    fn smbclient_defaults_to_c_dollar_share() {
        let output = "                9756244 blocks of size 4096. 5364823 blocks available";
        let shares = parse_smb_share_access(output, &json!({"target": "192.168.58.20"}));
        assert_eq!(shares[0]["name"], "C$");
    }

    #[test]
    fn smbclient_tree_connect_failure_yields_nothing() {
        let output = "tree connect failed: NT_STATUS_BAD_NETWORK_NAME\n";
        let params = json!({"target": "192.168.58.20", "share": "C$"});
        assert!(parse_smb_share_access(output, &params).is_empty());
    }

    #[test]
    fn smbclient_logon_failure_yields_nothing() {
        let output = "session setup failed: NT_STATUS_LOGON_FAILURE\n";
        let params = json!({"target": "192.168.58.20", "share": "C$"});
        assert!(parse_smb_share_access(output, &params).is_empty());
    }

    #[test]
    fn get_tgt_saved_ticket_yields_kdc_host() {
        let output = "[*] Saving ticket in alice.ccache\n";
        let params =
            json!({"domain": "contoso.local", "username": "alice", "dc_ip": "192.168.58.10"});
        let hosts = parse_tgt_request(output, &params);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["services"][0], "88/tcp");
        assert_eq!(hosts[0]["owned"], false);
    }

    #[test]
    fn get_tgt_preauth_failure_yields_nothing() {
        let output = "[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)";
        let params = json!({"dc_ip": "192.168.58.10"});
        assert!(parse_tgt_request(output, &params).is_empty());
    }

    #[test]
    fn get_tgt_without_dc_ip_yields_nothing() {
        let output = "[*] Saving ticket in alice.ccache\n";
        assert!(parse_tgt_request(output, &json!({"domain": "contoso.local"})).is_empty());
    }

    #[test]
    fn mssql_command_session_yields_sql_service() {
        let output = "\
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] INFO(SQL01): Line 1: Changed database context to 'master'.
SQL (CONTOSO\\alice  guest@master)> name
sql02";
        let params = json!({"target": "192.168.58.30", "username": "alice"});
        let hosts = parse_mssql_session(output, &params);
        assert_eq!(hosts[0]["ip"], "192.168.58.30");
        assert_eq!(hosts[0]["services"][0], "1433/tcp (ms-sql-s)");
        assert_eq!(hosts[0]["roles"][0], "mssql");
        assert_eq!(hosts[0]["owned"], false);
    }

    #[test]
    fn mssql_command_login_failure_yields_nothing() {
        let output = "[-] ERROR(SQL01): Line 1: Login failed for user 'CONTOSO\\alice'.";
        let params = json!({"target": "192.168.58.30"});
        assert!(parse_mssql_session(output, &params).is_empty());
    }

    #[test]
    fn mssql_command_without_session_marker_yields_nothing() {
        let output = "Impacket v0.12.0 - Copyright Fortra, LLC\n";
        let params = json!({"target": "192.168.58.30"});
        assert!(parse_mssql_session(output, &params).is_empty());
    }
}
