//! Static lookup tables for IOC and technique recommendations.

use crate::eval::ground_truth::{ExpectedIOC, ExpectedTechnique};

use super::types::DetectionRecommendation;

pub fn recommend_for_ioc(ioc: &ExpectedIOC) -> Option<DetectionRecommendation> {
    match ioc.ioc_type.as_str() {
        "ip" => Some(DetectionRecommendation {
            category: "query".to_string(),
            priority: if ioc.required { "high" } else { "medium" }.to_string(),
            title: format!("Add network IOC detection for {}", ioc.value),
            description: format!(
                "The IP address {} was involved in the attack but not \
                detected. Add network-based detection for this and similar IPs.",
                ioc.value,
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint: "Query firewall logs, netflow data, and DNS logs for this IP. \
                Consider adding threat intelligence feeds."
                .to_string(),
        }),

        "user" => Some(DetectionRecommendation {
            category: "query".to_string(),
            priority: if ioc.required { "critical" } else { "high" }.to_string(),
            title: format!("Monitor compromised account: {}", ioc.value),
            description: format!(
                "User account {} was compromised but not detected. \
                Add behavioral analysis for this account type.",
                ioc.value,
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint: "Query authentication logs (Windows Security, Kerberos). \
                Set up anomaly detection for account behavior."
                .to_string(),
        }),

        "hostname" | "domain" => Some(DetectionRecommendation {
            category: "query".to_string(),
            priority: if ioc.required { "high" } else { "medium" }.to_string(),
            title: format!("Add host/domain detection for {}", ioc.value),
            description: format!(
                "The host/domain {} was involved but not detected. \
                Ensure logs from this host are being collected.",
                ioc.value,
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint:
                "Verify log forwarding from this host. Add to asset inventory if missing."
                    .to_string(),
        }),

        "hash" => Some(DetectionRecommendation {
            category: "rule".to_string(),
            priority: "medium".to_string(),
            title: "Implement hash-based detection".to_string(),
            description: format!(
                "File hash {}... was not detected. \
                Consider adding hash-based IOC detection.",
                &ioc.value[..ioc.value.len().min(16)],
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint: "Integrate with threat intelligence for hash lookups. \
                Enable file integrity monitoring."
                .to_string(),
        }),

        _ => None,
    }
}

pub fn recommend_for_technique(tech: &ExpectedTechnique) -> Option<DetectionRecommendation> {
    struct TechRec {
        title: &'static str,
        description: &'static str,
        hint: &'static str,
    }

    let technique_recommendations: &[(&str, TechRec)] = &[
        (
            "T1003",
            TechRec {
                title: "Improve credential dumping detection",
                description: "OS Credential Dumping (T1003) was not detected. This is a \
                critical technique used in most advanced attacks.",
                hint: "Enable Sysmon Event ID 10 (process access), monitor LSASS access, \
                and alert on known credential dumping tools.",
            },
        ),
        (
            "T1003.006",
            TechRec {
                title: "Detect DCSync attacks",
                description: "DCSync (T1003.006) enables attackers to replicate AD credentials. \
                This is a high-priority detection gap.",
                hint: "Alert on Event ID 4662 with DS-Replication-Get-Changes rights \
                from non-DC sources. Monitor GetNCChanges RPC calls.",
            },
        ),
        (
            "T1078",
            TechRec {
                title: "Enhance valid account abuse detection",
                description: "Valid Accounts (T1078) abuse was not detected. Monitor for \
                unusual authentication patterns.",
                hint: "Implement impossible travel detection, monitor service account \
                usage, and alert on privilege escalation.",
            },
        ),
        (
            "T1558",
            TechRec {
                title: "Improve Kerberos attack detection",
                description: "Kerberos attacks (T1558) were not detected. These include \
                Golden/Silver ticket and Kerberoasting.",
                hint: "Monitor Event ID 4768/4769, detect TGT anomalies, and alert on \
                encryption downgrade attacks.",
            },
        ),
        (
            "T1558.003",
            TechRec {
                title: "Detect Kerberoasting attacks",
                description: "Kerberoasting (T1558.003) was not detected. Attackers request \
                TGS tickets for service accounts to crack offline.",
                hint: "Alert on Event ID 4769 with encryption type 0x17 (RC4). \
                Monitor unusual TGS requests for SPNs. Create Grafana alert: \
                |= \"4769\" |~ \"TicketEncryptionType.*0x17\"",
            },
        ),
        (
            "T1558.004",
            TechRec {
                title: "Detect AS-REP Roasting attacks",
                description: "AS-REP Roasting (T1558.004) was not detected. Targets accounts \
                with Kerberos pre-authentication disabled.",
                hint: "Alert on Event ID 4768 for accounts with pre-auth disabled. \
                Audit accounts with DONT_REQUIRE_PREAUTH flag. Create alert: \
                |= \"4768\" |~ \"PreAuthType.*0\"",
            },
        ),
        (
            "T1558.001",
            TechRec {
                title: "Detect Golden Ticket attacks",
                description: "Golden Ticket (T1558.001) was not detected. Attackers forge TGTs \
                using the krbtgt hash for persistent access.",
                hint: "Alert on TGS requests (4769) without corresponding TGT request (4768). \
                Monitor for TGTs with abnormal lifetimes or missing account correlation.",
            },
        ),
        (
            "T1550",
            TechRec {
                title: "Detect alternate authentication abuse",
                description: "Use Alternate Authentication Material (T1550) was not detected. \
                Includes Pass-the-Hash and Pass-the-Ticket.",
                hint: "Monitor for NTLM authentication from unusual sources. \
                Detect ticket reuse across different client IPs.",
            },
        ),
        (
            "T1550.003",
            TechRec {
                title: "Detect Constrained Delegation abuse",
                description:
                    "Pass the Ticket via Constrained Delegation (T1550.003) was not detected. \
                Attackers abuse S4U protocol to impersonate users.",
                hint: "Alert on Event ID 4769 with TransitedServices field populated. \
                Monitor S4U2Self/S4U2Proxy operations. Audit msDS-AllowedToDelegateTo \
                attribute changes.",
            },
        ),
        (
            "T1021",
            TechRec {
                title: "Detect lateral movement via remote services",
                description: "Remote Services (T1021) lateral movement was not detected. \
                Monitor for unusual remote connections.",
                hint: "Monitor Event ID 4624 Type 3/10, SMB/RDP connections, and \
                WinRM/PSRemoting activity.",
            },
        ),
        (
            "T1110",
            TechRec {
                title: "Improve brute force detection",
                description: "Brute Force (T1110) attacks were not detected. Implement \
                failed authentication monitoring.",
                hint: "Alert on multiple failed logins (Event ID 4625), implement \
                account lockout policies.",
            },
        ),
        (
            "T1649",
            TechRec {
                title: "Detect certificate-based attacks",
                description: "Certificate abuse (T1649) was not detected. ADCS attacks \
                are increasingly common.",
                hint: "Monitor certificate requests (Event ID 4886/4887), detect \
                ESC1-ESC8 vulnerabilities.",
            },
        ),
    ];

    // Check exact match first, then parent
    let tech_base = tech.technique_id.split('.').next().unwrap_or("");
    for key in &[tech.technique_id.as_str(), tech_base] {
        if let Some((_, rec_info)) = technique_recommendations.iter().find(|(k, _)| k == key) {
            return Some(DetectionRecommendation {
                category: "rule".to_string(),
                priority: if tech.required { "critical" } else { "high" }.to_string(),
                title: rec_info.title.to_string(),
                description: rec_info.description.to_string(),
                techniques: vec![tech.technique_id.clone()],
                implementation_hint: rec_info.hint.to_string(),
            });
        }
    }

    // Generic recommendation for unknown techniques
    Some(DetectionRecommendation {
        category: "rule".to_string(),
        priority: if tech.required { "high" } else { "medium" }.to_string(),
        title: format!("Add detection for {}", tech.technique_id),
        description: format!(
            "Technique {} ({}) was used but not detected. Research and implement detection.",
            tech.technique_id,
            if tech.technique_name.is_empty() {
                "Unknown"
            } else {
                &tech.technique_name
            },
        ),
        techniques: vec![tech.technique_id.clone()],
        implementation_hint: "Review MITRE ATT&CK documentation for detection guidance. \
            Consider Sigma rules from the community."
            .to_string(),
    })
}
