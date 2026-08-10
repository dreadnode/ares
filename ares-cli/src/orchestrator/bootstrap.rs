use std::sync::Arc;

use anyhow::Result;
use redis::AsyncCommands;
use tracing::{info, warn};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::task_queue::TaskQueue;

/// Probe ALL target IPs on ports 88 (Kerberos) and 389 (LDAP) to find every DC.
/// Returns all IPs that accept a TCP connection within 500ms on either port.
pub(crate) async fn probe_all_dcs(ips: &[String]) -> Vec<String> {
    let mut dc_ips = Vec::new();
    for ip in ips {
        for port in [88u16, 389] {
            let addr = format!("{ip}:{port}");
            if let Ok(Ok(_)) = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                info!(ip = %ip, port = port, "DC probe: port open");
                dc_ips.push(ip.clone());
                break; // Found open port, skip remaining ports for this IP
            }
        }
    }
    dc_ips
}

/// Query a DC's LDAP rootDSE to discover its domain name.
///
/// Sends a minimal anonymous LDAP SearchRequest for `defaultNamingContext`,
/// parses the DN response (e.g. `DC=child,DC=contoso,DC=local`), and
/// converts it to a domain name (`child.contoso.local`).
///
/// Returns `None` if the connection fails, the DC doesn't respond, or the
/// response doesn't contain a parseable `defaultNamingContext`.
pub(crate) async fn query_dc_domain(ip: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Pre-built LDAP SearchRequest:
    //   messageId=1, base="", scope=baseObject, filter=present(objectClass),
    //   attributes=[defaultNamingContext]
    #[rustfmt::skip]
    let ldap_request: &[u8] = &[
        0x30, 0x3b,                         // SEQUENCE, length 59
        0x02, 0x01, 0x01,                   // INTEGER messageId = 1
        0x63, 0x36,                         // APPLICATION[3] SearchRequest, length 54
        0x04, 0x00,                         //   baseObject = ""
        0x0a, 0x01, 0x00,                   //   scope = baseObject (0)
        0x0a, 0x01, 0x00,                   //   derefAliases = neverDeref (0)
        0x02, 0x01, 0x00,                   //   sizeLimit = 0
        0x02, 0x01, 0x05,                   //   timeLimit = 5
        0x01, 0x01, 0x00,                   //   typesOnly = false
        0x87, 0x0b,                         //   present filter, length 11
        b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
        0x30, 0x16,                         //   attributes SEQUENCE, length 22
        0x04, 0x14,                         //     OCTET STRING, length 20
        b'd', b'e', b'f', b'a', b'u', b'l', b't', b'N', b'a', b'm', b'i',
        b'n', b'g', b'C', b'o', b'n', b't', b'e', b'x', b't',
    ];

    let addr = format!("{ip}:389");
    let Ok(Ok(mut stream)) = tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    else {
        warn!(ip = %ip, "LDAP rootDSE: connection failed");
        return None;
    };

    if stream.write_all(ldap_request).await.is_err() {
        return None;
    }

    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(
        std::time::Duration::from_millis(2000),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };

    let domain = parse_dn_from_ldap_response(&buf[..n]);
    if let Some(ref d) = domain {
        info!(ip = %ip, domain = %d, "LDAP rootDSE: discovered DC domain");
    } else {
        warn!(ip = %ip, "LDAP rootDSE: could not parse defaultNamingContext");
    }
    domain
}

/// Parse `defaultNamingContext` DN from raw LDAP response bytes.
///
/// Locates the `defaultNamingContext` attribute name, then finds the subsequent
/// DN value containing `DC=` components and converts it to a domain name.
///
/// Uses the BER OCTET STRING length prefix immediately preceding the `DC=`
/// payload as the authoritative end-of-DN marker. Without this, a printable-byte
/// scan would happily consume the next BER tag (0x30 SEQUENCE = ASCII '0'),
/// producing phantom domains like `contoso.local0` that poison downstream state.
fn parse_dn_from_ldap_response(data: &[u8]) -> Option<String> {
    let attr_name = b"defaultNamingContext";
    let pos = data.windows(attr_name.len()).position(|w| w == attr_name)?;

    // After the attribute name, scan forward for "DC=" which starts the DN value
    let remaining = &data[pos + attr_name.len()..];
    let dc_pos = remaining
        .windows(3)
        .position(|w| w.eq_ignore_ascii_case(b"DC="))?;

    let dn_start = pos + attr_name.len() + dc_pos;

    // Prefer the BER OCTET STRING length prefix (the byte immediately before
    // `DC=`) for the DN length. Short-form only (high bit clear, non-zero).
    let mut dn_end = dn_start;
    if dc_pos > 0 {
        let length_byte = remaining[dc_pos - 1];
        if length_byte & 0x80 == 0 && length_byte > 0 {
            let length = length_byte as usize;
            if let Some(end) = dn_start.checked_add(length) {
                if end <= data.len() {
                    dn_end = end;
                }
            }
        }
    }

    // Fallback: walk only DN-legal characters (alphanumeric, `=`, `,`, `-`).
    // Stops before BER tag bytes (e.g. 0x30) that happen to be ASCII printable.
    if dn_end == dn_start {
        dn_end = dn_start;
        while dn_end < data.len() {
            let b = data[dn_end];
            let is_dn_char = b.is_ascii_alphanumeric() || matches!(b, b'=' | b',' | b'-' | b'.');
            if !is_dn_char {
                break;
            }
            dn_end += 1;
        }
    }

    let dn_str = std::str::from_utf8(&data[dn_start..dn_end]).ok()?;
    dn_to_domain(dn_str)
}

/// Convert an LDAP DN like `DC=child,DC=contoso,DC=local` to `child.contoso.local`.
fn dn_to_domain(dn: &str) -> Option<String> {
    let parts: Vec<&str> = dn
        .split(',')
        .filter_map(|component| {
            let component = component.trim();
            if component.len() > 3 && component[..3].eq_ignore_ascii_case("DC=") {
                Some(&component[3..])
            } else {
                None
            }
        })
        .collect();

    if parts.is_empty() {
        return None;
    }
    Some(parts.join(".").to_lowercase())
}

/// Discover all DCs and their domains from target IPs.
///
/// 1. Probes all IPs on ports 88/389 to find DCs
/// 2. Queries each DC's LDAP rootDSE to discover its actual domain
/// 3. Falls back to `fallback_domain` if LDAP query fails
///
/// Returns `Vec<(domain, ip)>` with one entry per unique domain.
pub(crate) async fn discover_dc_domains(
    ips: &[String],
    fallback_domain: &str,
) -> Vec<(String, String)> {
    let dc_ips = probe_all_dcs(ips).await;
    let mut results = Vec::new();
    let mut seen_domains = std::collections::HashSet::new();

    for ip in &dc_ips {
        let domain = query_dc_domain(ip)
            .await
            .unwrap_or_else(|| fallback_domain.to_lowercase());

        // First DC for each domain wins — skip duplicates (e.g. redundant DCs)
        if seen_domains.insert(domain.clone()) {
            results.push((domain, ip.clone()));
        }
    }

    results
}

/// Group target IPs by /24 prefix.
///
/// Returns one CIDR string (`"a.b.c.0/24"`) per /24 that contains at least 2
/// of the supplied IPv4 targets. Single-IP /24s are skipped — they don't
/// signal "lab subnet to discover", just isolated hosts the operator named
/// individually.
///
/// Non-IPv4 entries (CIDRs, hostnames) are ignored.
pub(crate) fn infer_target_subnets(ips: &[String]) -> Vec<String> {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    let mut counts: BTreeMap<[u8; 3], usize> = BTreeMap::new();
    for s in ips {
        let Ok(ip) = s.parse::<Ipv4Addr>() else {
            continue;
        };
        let oc = ip.octets();
        *counts.entry([oc[0], oc[1], oc[2]]).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .filter(|(_, n)| *n >= 2)
        .map(|(p, _)| format!("{}.{}.{}.0/24", p[0], p[1], p[2]))
        .collect()
}

/// Dispatch a /24-wide SMB sweep + ping sweep per inferred subnet.
///
/// Bootstrap recon only scans the IPs the operator named. In lab/CTF
/// environments those are typically just the DCs — but the same /24 will
/// hold the SQL/web/CA/workstation hosts that hold the real attack
/// surface (MSSQL pre-auth, web admin panels, ADCS web enrollment,
/// description-field creds, etc.). Sweeping the surrounding /24 surfaces
/// them so the credential-access and lateral pipelines have somewhere
/// to point.
///
/// Sweep targets pass as CIDRs (`a.b.c.0/24`), which short-circuit the
/// operation-scope IPv4 check — discovery is always allowed even on
/// hosts that aren't in the original target list. Single-target tools
/// run later still get gated by `OperationScope`, so the scope must be
/// expanded separately (see `OrchestratorConfig::expand_scope_to_subnets`)
/// to let agents pivot onto the discovered hosts.
pub(crate) async fn dispatch_subnet_sweep(
    dispatcher: &Arc<Dispatcher>,
    config: &OrchestratorConfig,
) -> usize {
    let subnets = infer_target_subnets(&config.target_ips);
    if subnets.is_empty() {
        return 0;
    }
    let domain = &config.target_domain;
    let mut count = 0;
    for cidr in &subnets {
        // smb_sweep over the /24 — netexec banner-grabs every live host
        let payload = serde_json::json!({
            "target_ip": cidr,
            "target": cidr,
            "domain": domain,
            "technique": "smb_sweep",
            "techniques": ["smb_sweep"],
            "instructions": format!(
                "Sweep the subnet {cidr} with netexec SMB to discover live hosts beyond                 the bootstrap target list. Call `smb_sweep` with `targets={cidr}`.                 Report every discovered host (IP + hostname + OS banner) in                 discovered_hosts so downstream recon/credential_access tasks can                 pivot onto non-DC hosts (SQL server, web server, workstation, ADCS box).",
            ),
        });
        match dispatcher
            .throttled_submit("recon", "recon", payload, 1)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, cidr = %cidr, "Dispatched subnet smb_sweep");
                count += 1;
            }
            Ok(None) => warn!(cidr = %cidr, "Subnet sweep throttled/deferred"),
            Err(e) => warn!(cidr = %cidr, err = %e, "Failed to dispatch subnet sweep"),
        }

        // nmap ping/SYN sweep over the /24 — catches hosts that don't respond
        // to SMB but do have TCP services exposed (web, MSSQL on non-1433, etc.)
        let nmap_payload = serde_json::json!({
            "target_ip": cidr,
            "target": cidr,
            "domain": domain,
            "technique": "network_scan",
            "techniques": ["network_scan"],
            "ports": "21,22,53,80,88,135,139,389,443,445,464,593,636,1433,3268,3269,3389,5432,5985,5986,8000,8080,8443,9389",
            "instructions": format!(
                "Discover live hosts in {cidr} via nmap. Call `nmap_scan` with                 `target={cidr}` and the supplied `ports` list (covers DC, MSSQL,                 ADCS web enrollment, RDP, WinRM, web admin panels). Report every                 IP that has at least one open port in discovered_hosts. This                 bootstraps non-DC attack surface (MSSQL on sql01, web admin on                 web01, ADCS web on ca01, etc.).",
            ),
        });
        match dispatcher
            .throttled_submit("recon", "recon", nmap_payload, 1)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, cidr = %cidr, "Dispatched subnet nmap_scan");
                count += 1;
            }
            Ok(None) => warn!(cidr = %cidr, "Subnet nmap throttled/deferred"),
            Err(e) => warn!(cidr = %cidr, err = %e, "Failed to dispatch subnet nmap"),
        }
    }
    info!(
        subnet_count = subnets.len(),
        tasks = count,
        "Subnet sweep dispatched"
    );
    count
}

/// Write initial operation metadata to Redis so workers can discover the operation.
pub(crate) async fn bootstrap_meta(queue: &TaskQueue, config: &OrchestratorConfig) -> Result<()> {
    use chrono::Utc;

    let mut conn = queue.connection();
    let meta_key = format!(
        "{}:{}:{}",
        ares_core::state::KEY_PREFIX,
        config.operation_id,
        "meta"
    );

    let now = Utc::now().to_rfc3339();

    // started_at must only be set once — use HSETNX so restarts/recoveries
    // don't overwrite the original start time (which would break runtime calc).
    let started_at_json = serde_json::to_string(&now).unwrap_or_default();
    let _: bool = conn
        .hset_nx(&meta_key, "started_at", &started_at_json)
        .await?;

    // Remaining fields are safe to overwrite on restart
    let fields: Vec<(&str, String)> = vec![
        ("initialized", "true".to_string()),
        (
            "target_domain",
            serde_json::to_string(&config.target_domain).unwrap_or_default(),
        ),
        (
            "target_ip",
            serde_json::to_string(config.target_ips.first().unwrap_or(&String::new()))
                .unwrap_or_default(),
        ),
        (
            "target_ips",
            serde_json::to_string(&config.target_ips.join(",")).unwrap_or_default(),
        ),
    ];

    for (field, value) in &fields {
        let _: () = conn.hset(&meta_key, *field, value).await?;
    }
    // 24h TTL
    let _: () = conn.expire(&meta_key, 86400).await?;

    // Set active operation pointer for worker discovery
    let _: () = conn.set("ares:op:active", &config.operation_id).await?;

    ares_core::state::set_operation_status(&mut conn, &config.operation_id, "running").await?;

    // Store the LLM model name for worker discovery and recovery
    let model_key = format!(
        "{}:{}:{}",
        ares_core::state::KEY_PREFIX,
        config.operation_id,
        ares_core::state::KEY_MODEL,
    );
    let model_name = std::env::var("ARES_LLM_MODEL").unwrap_or_default();
    if !model_name.is_empty() {
        let _: () = conn.set_ex(&model_key, &model_name, 86400u64).await?;
    }

    info!(
        operation_id = %config.operation_id,
        meta_key = %meta_key,
        "Operation metadata written to Redis"
    );
    Ok(())
}

/// Dispatch initial recon tasks for each target IP.
///
/// This seeds the reactive automation pipeline — without these initial tasks,
/// all automation tasks have nothing to work with on a fresh operation.
pub(crate) async fn dispatch_initial_recon(
    dispatcher: &Arc<Dispatcher>,
    config: &OrchestratorConfig,
) -> usize {
    let mut count = 0;
    let domain = &config.target_domain;

    // Order the entry targets. When randomize_entry_foothold is set, shuffle so
    // each run opens against a different target — the cheapest attack-path
    // diversity source, pushing run N off run N-1's opening move
    // (see docs/attack-path-diversity.md).
    let mut entry_ips: Vec<&String> = config.target_ips.iter().collect();
    if dispatcher.config.strategy.randomize_entry_foothold {
        use rand::seq::SliceRandom;
        entry_ips.shuffle(&mut rand::rng());
    }

    // Network scan + SMB sweep + SMB signing check per target IP.
    // smb_sweep (NetExec) is critical: it discovers hostnames, OS, and DCs
    // from SMB banners — data that nmap alone may miss.
    for ip in entry_ips {
        match dispatcher
            .request_recon(
                ip,
                domain,
                &["network_scan", "smb_sweep", "smb_signing_check"],
                None,
            )
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, ip = %ip, "Dispatched initial recon");
                count += 1;
            }
            Ok(None) => {
                warn!(ip = %ip, "Initial recon throttled/deferred");
            }
            Err(e) => {
                warn!(ip = %ip, err = %e, "Failed to dispatch initial recon");
            }
        }
    }

    // User enumeration against all target IPs — we don't know which are DCs yet,
    // and non-DC IPs may silently return no output. Null session for bootstrap.
    for ip in &config.target_ips {
        let payload = serde_json::json!({
            "target_ip": ip,
            "domain": domain,
            "technique": "user_enumeration",
            "techniques": ["user_enumeration"],
            "null_session": true,
            "instructions": concat!(
                "Enumerate domain users via UNAUTHENTICATED methods. This is a bootstrap task ",
                "— we have NO credentials yet. Try these techniques in order:\n\n",
                "1. Anonymous LDAP bind to enumerate users and their descriptions:\n",
                "   ldapsearch -x -H ldap://<target_ip> -b 'DC=<domain parts>' ",
                "'(objectClass=user)' sAMAccountName description userPrincipalName\n\n",
                "2. RPC null session user enumeration:\n",
                "   rpcclient -U '' -N <target_ip> -c 'enumdomusers'\n",
                "   Then for each user: rpcclient -U '' -N <target_ip> -c 'queryuser <rid>'\n\n",
                "3. Impacket lookupsid.py with anonymous:\n",
                "   lookupsid.py anonymous@<target_ip> -no-pass -domain-sids\n\n",
                "4. Impacket GetADUsers.py with anonymous:\n",
                "   GetADUsers.py -all -dc-ip <target_ip> <domain>/ 2>/dev/null\n\n",
                "5. enum4linux-ng for comprehensive SMB/RPC enumeration:\n",
                "   enum4linux-ng -A <target_ip>\n\n",
                "6. IF the target is NOT a DC (LDAP/Kerberos closed), probe non-DC services unauthenticated:\n",
                "   a. MSSQL pre-auth: impacket-mssqlclient 'sa:@<target_ip>' -no-pass (try empty / default `sa` pwd).\n",
                "      Also try: netexec mssql <target_ip> -u sa -p \"\" (sa with blank password is the classic GOAD/lab finding).\n",
                "   b. ADCS web enrollment / ESC8 surface: curl -sk -I https://<target_ip>/certsrv/ ; curl -sk -I http://<target_ip>/certsrv/.\n",
                "      If /certsrv/ responds 401 with WWW-Authenticate NTLM, this is an unauth ADCS web endpoint (HTTP-NTLM relay target).\n",
                "   c. IIS / web admin: curl -sk http://<target_ip>/ -I ; curl -sk https://<target_ip>/ -I ; check for /owa/, /ews/, /aspnet_client/, /Default.aspx.\n",
                "   d. WinRM open: nmap -p 5985,5986 <target_ip> --script http-title — banner often leaks hostname / IIS / .NET version.\n",
                "   e. RDP banner: nmap -p 3389 <target_ip> --script rdp-ntlm-info — leaks computer name, DNS name, target NetBIOS, and OS build (unauthenticated).\n",
                "      rdp-ntlm-info is the canonical non-DC username/hostname leak — ALWAYS try it.\n\n",
                "CRITICAL: Look for passwords in user DESCRIPTION fields! In many AD environments, ",
                "admins store passwords in the description attribute. For each user found, report ",
                "the description field content. If a description looks like a password (short string, ",
                "special chars, etc.), report it as a discovered credential:\n",
                "  {\"username\": \"samaccountname\", \"password\": \"<description>\", ",
                "\"domain\": \"<domain from the user's AD domain, NOT the local machine domain>\", \"source\": \"desc_enumeration\"}\n\n",
                "IMPORTANT: The 'domain' field for credentials and users MUST be the AD domain the user ",
                "belongs to (look at userPrincipalName suffix, or the domain reported by LDAP/RPC), NOT ",
                "the local machine name or workgroup. If the target is a DC for 'contoso.local', ",
                "users belong to 'contoso.local'. Use the 'domain' field from this task's payload ",
                "as the default domain unless evidence shows otherwise.\n\n",
                "Also report ALL discovered users in the discovered_users array:\n",
                "  {\"username\": \"samaccountname\", \"domain\": \"<AD domain>\", ",
                "\"source\": \"user_enumeration\"}\n\n",
                "If the target is not a DC (no LDAP/Kerberos), DO NOT give up — run step 6 against it (MSSQL/ADCS web/IIS/WinRM/RDP). Any banner, share name, or IIS path that leaks a hostname/username/version goes in discovered_hosts. A non-DC host with MSSQL open is a primary GOAD foothold path."
            ),
        });
        match dispatcher
            .throttled_submit("recon", "recon", payload, 1)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, ip = %ip, "Dispatched user enumeration");
                count += 1;
            }
            Ok(None) => warn!(ip = %ip, "User enumeration throttled/deferred"),
            Err(e) => warn!(ip = %ip, err = %e, "Failed to dispatch user enumeration"),
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_to_domain_child() {
        assert_eq!(
            dn_to_domain("DC=child,DC=contoso,DC=local"),
            Some("child.contoso.local".to_string())
        );
    }

    #[test]
    fn infer_target_subnets_clusters_by_24() {
        let ips = vec![
            "192.168.58.10".into(),
            "192.168.58.11".into(),
            "192.168.58.12".into(),
            "192.168.58.22".into(),
            "192.168.58.23".into(),
            // Isolated standalone — should NOT produce a sweep target.
            "192.168.60.50".into(),
        ];
        let subnets = super::infer_target_subnets(&ips);
        assert_eq!(subnets, vec!["192.168.58.0/24".to_string()]);
    }

    #[test]
    fn infer_target_subnets_skips_singleton_24() {
        // Only one IP in this /24 → not a cluster → no sweep.
        let ips = vec!["192.168.58.10".into()];
        assert!(super::infer_target_subnets(&ips).is_empty());
    }

    #[test]
    fn infer_target_subnets_two_clusters() {
        let ips = vec![
            "192.168.58.10".into(),
            "192.168.58.11".into(),
            "192.168.59.5".into(),
            "192.168.59.6".into(),
        ];
        let subnets = super::infer_target_subnets(&ips);
        assert_eq!(
            subnets,
            vec!["192.168.58.0/24".to_string(), "192.168.59.0/24".to_string()]
        );
    }

    #[test]
    fn infer_target_subnets_ignores_non_ipv4() {
        let ips = vec![
            "dc01.contoso.local".into(),
            "192.168.58.10".into(),
            "192.168.58.0/24".into(), // CIDR — ignored, not an IPv4
            "192.168.58.11".into(),
        ];
        assert_eq!(
            super::infer_target_subnets(&ips),
            vec!["192.168.58.0/24".to_string()]
        );
    }

    #[test]
    fn infer_target_subnets_empty_input() {
        let ips: Vec<String> = vec![];
        assert!(super::infer_target_subnets(&ips).is_empty());
    }

    #[test]
    fn dn_to_domain_root() {
        assert_eq!(
            dn_to_domain("DC=contoso,DC=local"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn dn_to_domain_single_component() {
        assert_eq!(dn_to_domain("DC=local"), Some("local".to_string()));
    }

    #[test]
    fn dn_to_domain_case_insensitive() {
        assert_eq!(
            dn_to_domain("dc=CONTOSO,dc=LOCAL"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn dn_to_domain_with_spaces() {
        assert_eq!(
            dn_to_domain("DC=child, DC=contoso, DC=local"),
            Some("child.contoso.local".to_string())
        );
    }

    #[test]
    fn dn_to_domain_mixed_components() {
        // DN with OU components should only extract DC parts
        assert_eq!(
            dn_to_domain("OU=Users,DC=contoso,DC=local"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn dn_to_domain_empty() {
        assert_eq!(dn_to_domain(""), None);
    }

    #[test]
    fn dn_to_domain_no_dc() {
        assert_eq!(dn_to_domain("OU=Users,CN=admin"), None);
    }

    #[test]
    fn parse_dn_from_ldap_response_realistic() {
        // Simulate a response containing the attribute name followed by a BER-encoded value
        let mut data = Vec::new();
        data.extend_from_slice(b"\x30\x50\x02\x01\x01\x64\x4b"); // LDAP envelope
        data.extend_from_slice(b"\x04\x00"); // objectName=""
        data.extend_from_slice(b"\x30\x45"); // attributes SEQUENCE
        data.extend_from_slice(b"\x30\x43"); // partial attribute SEQUENCE
        data.extend_from_slice(b"\x04\x14"); // type OCTET STRING, len 20
        data.extend_from_slice(b"defaultNamingContext");
        data.extend_from_slice(b"\x31\x29"); // vals SET, len 41
        data.extend_from_slice(b"\x04\x27"); // value OCTET STRING, len 39
        data.extend_from_slice(b"DC=child,DC=contoso,DC=local");
        data.push(0x00); // null terminator (end of printable range)

        assert_eq!(
            parse_dn_from_ldap_response(&data),
            Some("child.contoso.local".to_string())
        );
    }

    #[test]
    fn parse_dn_from_ldap_response_root_domain() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x30\x40\x02\x01\x01\x64\x3b");
        data.extend_from_slice(b"\x04\x00");
        data.extend_from_slice(b"\x30\x35\x30\x33");
        data.extend_from_slice(b"\x04\x14");
        data.extend_from_slice(b"defaultNamingContext");
        data.extend_from_slice(b"\x31\x19\x04\x17");
        data.extend_from_slice(b"DC=contoso,DC=local");
        data.push(0x00);

        assert_eq!(
            parse_dn_from_ldap_response(&data),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn parse_dn_from_ldap_response_no_attr() {
        let data = b"\x30\x10\x02\x01\x01\x04\x0bsomethingElse";
        assert_eq!(parse_dn_from_ldap_response(data), None);
    }

    #[test]
    fn parse_dn_from_ldap_response_no_dc() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x04\x14");
        data.extend_from_slice(b"defaultNamingContext");
        data.extend_from_slice(b"\x31\x0a\x04\x08");
        data.extend_from_slice(b"OU=Users"); // No DC= in value
        data.push(0x00);

        assert_eq!(parse_dn_from_ldap_response(&data), None);
    }

    /// Regression: the OCTET STRING value MUST be bounded by its BER length
    /// prefix. Without that bound, a printable-byte scan happily consumes the
    /// next BER SEQUENCE tag (0x30 = ASCII '0'), producing phantom domains
    /// like `contoso.local0` that poison the orchestrator's `domain_controllers`
    /// keys and make the completion loop's required-forest set unsatisfiable.
    #[test]
    fn parse_dn_from_ldap_response_does_not_bleed_into_next_ber_tag() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x04\x14");
        data.extend_from_slice(b"defaultNamingContext");
        data.extend_from_slice(b"\x31\x15\x04\x13"); // SET len 21, OCTET STRING len 19
        data.extend_from_slice(b"DC=contoso,DC=local"); // exactly 19 bytes
        data.extend_from_slice(b"\x30\x10"); // next SEQUENCE: tag 0x30 ('0'), len 0x10
        data.extend_from_slice(b"trailingjunk");

        assert_eq!(
            parse_dn_from_ldap_response(&data),
            Some("contoso.local".to_string())
        );
    }
}
