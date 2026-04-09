//! Nmap output parser.

use serde_json::{json, Value};

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
                hostname = rest[..paren_start].trim().to_string();
                current_ip = rest[paren_start + 1..]
                    .trim_end_matches(')')
                    .trim()
                    .to_string();
            } else {
                current_ip = rest.to_string();
            }
        }

        // "445/tcp open  microsoft-ds"
        if line.contains("/tcp") && line.contains("open") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let port_proto = parts[0]; // "445/tcp"
                let service = if parts.len() >= 4 {
                    parts[2..].join(" ")
                } else {
                    parts[2].to_string()
                };
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
    }

    // Flush last host
    if seen_report && !current_ip.is_empty() {
        flush_nmap_host(&current_ip, &hostname, &os_info, &services, &mut hosts);
    }

    // If no hosts were found but we have a target_ip, create a minimal host entry
    if hosts.is_empty() && !target_ip.is_empty() {
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
    fn test_parse_nmap_single_host_with_services() {
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
    fn test_parse_nmap_ip_only_no_hostname() {
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
    fn test_parse_nmap_multiple_hosts() {
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
    fn test_parse_nmap_os_detection() {
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
    fn test_parse_nmap_empty_output_with_target() {
        let params = json!({"target": "192.168.58.10"});
        let hosts = parse_nmap_output("Starting Nmap 7.94 ...\nNmap done: 0 hosts up", &params);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[0]["hostname"], "");
    }

    #[test]
    fn test_parse_nmap_empty_output_no_target() {
        let hosts = parse_nmap_output("", &json!({}));
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_nmap_dc_hostname_detection() {
        let output = "Nmap scan report for DC02 (192.168.58.11)\nPORT    STATE SERVICE\n445/tcp open  microsoft-ds";
        let params = json!({"target": "192.168.58.11"});
        let hosts = parse_nmap_output(output, &params);
        assert!(hosts[0]["is_dc"].as_bool().unwrap());
    }

    #[test]
    fn test_flush_nmap_host_empty_ip() {
        let mut hosts = Vec::new();
        flush_nmap_host("", "host", "Windows", &[], &mut hosts);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_flush_nmap_host_winrm_role() {
        let mut hosts = Vec::new();
        let services = vec!["5985/tcp (wsman)".to_string()];
        flush_nmap_host("192.168.58.30", "", "", &services, &mut hosts);
        let roles = hosts[0]["roles"].as_array().unwrap();
        let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
        assert!(role_strs.contains(&"winrm"));
    }
}
