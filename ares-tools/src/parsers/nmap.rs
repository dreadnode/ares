//! Nmap output parser.

use serde_json::{json, Value};

/// Collapse adjacent duplicate labels in an FQDN (`host.host.suffix` →
/// `host.suffix`). Self-named-workgroup hosts (typical of stock Windows
/// installs that aren't domain-joined) report their reverse-DNS as
/// `name.name.workgroup`, which then propagates into recon output and host
/// records as a malformed FQDN. Real AD names don't repeat the leading label,
/// so collapsing is safe in practice.
fn dedup_adjacent_labels(fqdn: &str) -> String {
    let labels: Vec<&str> = fqdn.split('.').collect();
    if labels.len() < 3 {
        return fqdn.to_string();
    }
    let mut out: Vec<&str> = Vec::with_capacity(labels.len());
    for label in labels {
        if let Some(prev) = out.last() {
            if prev.eq_ignore_ascii_case(label) {
                continue;
            }
        }
        out.push(label);
    }
    out.join(".")
}

pub fn parse_nmap_output(output: &str, params: &Value) -> Vec<Value> {
    let target_ip = params
        .get("target")
        .or_else(|| params.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut hosts: Vec<Value> = Vec::new();
    let mut current_ip = String::new();
    let mut services: Vec<String> = Vec::new();
    let mut hostname = String::new();
    let mut os_info = String::new();
    let mut seen_report = false;

    for line in output.lines() {
        let line = line.trim();

        // "Nmap scan report for hostname (192.168.58.10)" or "Nmap scan report for 192.168.58.10"
        if line.starts_with("Nmap scan report for") {
            // Flush previous host (only if we already saw a report header)
            if seen_report && !current_ip.is_empty() {
                flush_nmap_host(&current_ip, &hostname, &os_info, &services, &mut hosts);
            }
            seen_report = true;
            services.clear();
            hostname.clear();
            os_info.clear();

            let rest = line.trim_start_matches("Nmap scan report for").trim();
            if let Some(paren_start) = rest.find('(') {
                hostname = dedup_adjacent_labels(rest[..paren_start].trim());
                current_ip = rest[paren_start + 1..]
                    .trim_end_matches(')')
                    .trim()
                    .to_string();
            } else {
                current_ip = rest.to_string();
            }

            // Discard cloud-provider reverse-DNS hostnames — they are
            // not useful for AD domain resolution and would prevent
            // FQDN extraction from script output later.
            if hostname.contains("compute.internal")
                || hostname.contains("amazonaws.com")
                || hostname.contains("compute.googleapis.com")
            {
                hostname.clear();
            }
        }

        // "445/tcp open  microsoft-ds"
        if line.contains("/tcp") && line.contains("open") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let port_proto = parts[0]; // "445/tcp"
                                           // Only capture the service name (column 3), not version/product info.
                                           // nmap -sV output: "389/tcp open ldap Microsoft Windows Active Directory LDAP ..."
                                           // We want just "ldap", not the full version string.
                let service = parts[2];
                services.push(format!("{} ({})", port_proto, service));
            }
        }

        // OS detection
        if line.starts_with("OS details:") || line.starts_with("Running:") {
            os_info = line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
        }

        // Extract FQDN from nmap script output when hostname is empty or a
        // short NetBIOS name (no dots).  Look for common patterns:
        //   smb-os-discovery:  |   FQDN: dc01.contoso.local
        //   rdp-ntlm-info:    |   DNS_Computer_Name: dc03.fabrikam.local
        //   ldap service:     |   dnsHostName: dc02.child.contoso.local
        //   ssl-cert:         | ssl-cert: Subject: commonName=dc01.contoso.local
        //   ssl-cert SAN:     | Subject Alternative Name: ..., DNS:dc01.contoso.local
        if !current_ip.is_empty() && !hostname.contains('.') {
            let trimmed = line.trim_start_matches('|').trim_start_matches('_').trim();

            // key: value patterns (smb-os-discovery, rdp-ntlm-info, ldap)
            for prefix in &["FQDN:", "DNS_Computer_Name:", "dnsHostName:"] {
                if let Some(rest) = trimmed.strip_prefix(prefix) {
                    let fqdn = rest.trim().to_lowercase();
                    if fqdn.contains('.') && !fqdn.contains(' ') {
                        hostname = dedup_adjacent_labels(&fqdn);
                        break;
                    }
                }
            }

            // ssl-cert commonName= pattern
            if !hostname.contains('.') {
                if let Some(cn_start) = trimmed.find("commonName=") {
                    let cn = &trimmed[cn_start + "commonName=".len()..];
                    let cn = cn
                        .split([',', '\n', '|'])
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();
                    if cn.contains('.') && !cn.contains(' ') {
                        hostname = dedup_adjacent_labels(&cn);
                    }
                }
            }

            // ssl-cert DNS: in Subject Alternative Name
            if !hostname.contains('.') {
                if let Some(dns_start) = trimmed.find("DNS:") {
                    let dns = &trimmed[dns_start + "DNS:".len()..];
                    let dns = dns
                        .split([',', '\n', '|', ' '])
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();
                    if dns.contains('.') && !dns.contains(' ') {
                        hostname = dedup_adjacent_labels(&dns);
                    }
                }
            }
        }
    }

    // Flush last host
    if seen_report && !current_ip.is_empty() {
        flush_nmap_host(&current_ip, &hostname, &os_info, &services, &mut hosts);
    }

    // If no hosts were found but we have a target_ip, create a minimal host entry
    // Skip CIDR notation (e.g. "192.168.58.0/24") — individual hosts will be discovered
    // by their own scan results; a subnet target should never become a host entry.
    if hosts.is_empty() && !target_ip.is_empty() && !target_ip.contains('/') {
        hosts.push(json!({
            "ip": target_ip,
            "hostname": "",
            "os": "",
            "roles": [],
            "services": [],
            "is_dc": false,
            "owned": false,
        }));
    }

    hosts
}

pub fn flush_nmap_host(
    ip: &str,
    hostname: &str,
    os: &str,
    services: &[String],
    hosts: &mut Vec<Value>,
) {
    if ip.is_empty() {
        return;
    }

    let mut roles = Vec::new();
    let is_dc = services
        .iter()
        .any(|s| s.contains("ldap") || s.contains("kerberos") || s.contains("88/tcp"))
        || hostname.to_lowercase().starts_with("dc");

    if is_dc {
        roles.push("domain_controller".to_string());
    }

    // Check for common services to assign roles
    if services.iter().any(|s| s.contains("1433")) {
        roles.push("mssql".to_string());
    }
    if services
        .iter()
        .any(|s| s.contains("5985") || s.contains("5986"))
    {
        roles.push("winrm".to_string());
    }

    hosts.push(json!({
        "ip": ip,
        "hostname": hostname,
        "os": os,
        "roles": roles,
        "services": services,
        "is_dc": is_dc,
        "owned": false,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_nmap_single_host_with_services() {
        let output = "\
Nmap scan report for dc01.contoso.local (192.168.58.10)
Host is up (0.0010s latency).
PORT     STATE SERVICE
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
5985/tcp open  wsman";
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
        let roles = hosts[0]["roles"].as_array().unwrap();
        let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
        assert!(role_strs.contains(&"domain_controller"));
        assert!(role_strs.contains(&"winrm"));
    }

    #[test]
    fn parse_nmap_ip_only_no_hostname() {
        let output = "\
Nmap scan report for 192.168.58.20
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s";
        let params = json!({"target": "192.168.58.20"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.20");
        assert_eq!(hosts[0]["hostname"], "");
        assert!(!hosts[0]["is_dc"].as_bool().unwrap());
        let roles = hosts[0]["roles"].as_array().unwrap();
        let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
        assert!(role_strs.contains(&"mssql"));
    }

    #[test]
    fn parse_nmap_multiple_hosts() {
        let output = "\
Nmap scan report for dc01.contoso.local (192.168.58.10)
PORT    STATE SERVICE
88/tcp  open  kerberos-sec
389/tcp open  ldap

Nmap scan report for srv01.contoso.local (192.168.58.20)
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s";
        let params = json!({"target": "192.168.58.0/24"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[1]["ip"], "192.168.58.20");
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
        assert!(!hosts[1]["is_dc"].as_bool().unwrap());
    }

    #[test]
    fn parse_nmap_os_detection() {
        let output = "\
Nmap scan report for 192.168.58.10
PORT    STATE SERVICE
445/tcp open  microsoft-ds
OS details: Microsoft Windows Server 2019";
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts[0]["os"], "Microsoft Windows Server 2019");
    }

    #[test]
    fn parse_nmap_empty_output_with_target() {
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output("Starting Nmap 7.94 ...\nNmap done: 0 hosts up", &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["hostname"], "");
    }

    #[test]
    fn parse_nmap_empty_output_no_target() {
        let hosts = parse_nmap_output("", &json!({}));
        assert!(hosts.is_empty());
    }

    #[test]
    fn parse_nmap_dc_hostname_detection() {
        let output = "Nmap scan report for DC02 (192.168.58.11)\nPORT    STATE SERVICE\n445/tcp open  microsoft-ds";
        let params = json!({"target": "192.168.58.11"});
        let hosts = parse_nmap_output(output, &params);
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
    }

    #[test]
    fn parse_nmap_fqdn_from_script_output() {
        let output = "\
Nmap scan report for 192.168.58.10
PORT    STATE SERVICE
88/tcp  open  kerberos-sec
389/tcp open  ldap
445/tcp open  microsoft-ds
| rdp-ntlm-info:
|   DNS_Domain_Name: contoso.local
|   DNS_Computer_Name: dc01.contoso.local
|   FQDN: dc01.contoso.local";
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
    }

    #[test]
    fn parse_nmap_fqdn_does_not_override_existing() {
        // When nmap header already has the FQDN, script output shouldn't override
        let output = "\
Nmap scan report for dc01.contoso.local (192.168.58.10)
PORT    STATE SERVICE
88/tcp  open  kerberos-sec
|   DNS_Computer_Name: dc01.contoso.local";
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
    }

    #[test]
    fn parse_nmap_fqdn_from_dns_host_name() {
        let output = "\
Nmap scan report for 192.168.58.11
PORT    STATE SERVICE
88/tcp  open  kerberos-sec
389/tcp open  ldap
|   dnsHostName: dc02.child.contoso.local";
        let params = json!({"target": "192.168.58.11"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts[0]["hostname"], "dc02.child.contoso.local");
    }

    #[test]
    fn parse_nmap_aws_internal_hostname_replaced_by_fqdn() {
        // AWS internal hostnames should be discarded, allowing FQDN extraction
        let output = "\
Nmap scan report for ip-192-168-58-10.us-west-2.compute.internal (192.168.58.10)
PORT    STATE SERVICE
88/tcp  open  kerberos-sec
389/tcp open  ldap
| ssl-cert: Subject: commonName=dc01.contoso.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.contoso.local";
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
    }

    #[test]
    fn parse_nmap_fqdn_from_ssl_cert_commonname() {
        let output = "\
Nmap scan report for 192.168.58.22
PORT    STATE SERVICE
389/tcp open  ldap
| ssl-cert: Subject: commonName=dc03.fabrikam.local
|_Not valid after:  2027-04-09T06:53:55";
        let params = json!({"target": "192.168.58.22"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts[0]["hostname"], "dc03.fabrikam.local");
    }

    #[test]
    fn parse_nmap_fqdn_from_ssl_cert_san_dns() {
        let output = "\
Nmap scan report for 192.168.58.23
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| Subject Alternative Name: DNS:srv01.child.contoso.local";
        let params = json!({"target": "192.168.58.23"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts[0]["hostname"], "srv01.child.contoso.local");
    }

    #[test]
    fn parse_nmap_version_info_stripped_from_services() {
        // nmap -sV output includes version/product info after the service name.
        // We should only capture the service name, not the version string.
        let output = "\
Nmap scan report for 192.168.58.11
PORT     STATE SERVICE       VERSION
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services";
        let params = json!({"target": "192.168.58.11"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts.len(), 1);
        let services = hosts[0]["services"].as_array().unwrap();
        let svc_strs: Vec<&str> = services.iter().filter_map(|v| v.as_str()).collect();
        // Should have clean service names without version info
        assert!(svc_strs.contains(&"88/tcp (kerberos-sec)"));
        assert!(svc_strs.contains(&"135/tcp (msrpc)"));
        assert!(svc_strs.contains(&"389/tcp (ldap)"));
        assert!(svc_strs.contains(&"445/tcp (microsoft-ds)"));
        assert!(svc_strs.contains(&"3389/tcp (ms-wbt-server)"));
        // Ensure version info is NOT included
        assert!(!svc_strs.iter().any(|s| s.contains("Microsoft Windows")));
    }

    #[test]
    fn flush_nmap_host_empty_ip() {
        let mut hosts = Vec::new();
        flush_nmap_host("", "host", "Windows", &[], &mut hosts);
        assert!(hosts.is_empty());
    }

    #[test]
    fn flush_nmap_host_winrm_role() {
        let mut hosts = Vec::new();
        let services = vec!["5985/tcp (wsman)".to_string()];
        flush_nmap_host("192.168.58.30", "", "", &services, &mut hosts);
        let roles = hosts[0]["roles"].as_array().unwrap();
        let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
        assert!(role_strs.contains(&"winrm"));
    }

    #[test]
    fn dedup_adjacent_labels_collapses_doubled_first_label() {
        // Self-named-workgroup hosts (stock Windows installs not domain-joined)
        // report reverse-DNS as `host.host.workgroup`. Collapse the doubled
        // label so the recorded FQDN is `host.workgroup`.
        assert_eq!(
            dedup_adjacent_labels("dc01.dc01.contoso.local"),
            "dc01.contoso.local"
        );
        assert_eq!(
            dedup_adjacent_labels("dc01.contoso.local"),
            "dc01.contoso.local"
        );
        assert_eq!(dedup_adjacent_labels("contoso.local"), "contoso.local");
        // Case-insensitive match — preserves the case of the first occurrence
        assert_eq!(
            dedup_adjacent_labels("DC01.dc01.contoso.local"),
            "DC01.contoso.local"
        );
    }

    #[test]
    fn parse_nmap_dedupes_doubled_reverse_dns() {
        // Reverse-DNS for a Win2003-style self-named workgroup host comes back
        // as `host.host.workgroup`. The recorded hostname must be collapsed.
        let output = "\
Nmap scan report for dc01.dc01.contoso.local (192.168.58.10)
445/tcp open microsoft-ds";
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output(output, &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["hostname"], "dc01.contoso.local");
    }
}
