pub(crate) fn get_technique_name(id: &str) -> &'static str {
    match id {
        "T1046" => "Network Service Discovery",
        "T1003" => "OS Credential Dumping",
        "T1003.001" => "LSASS Memory",
        "T1003.006" => "DCSync",
        "T1078" => "Valid Accounts",
        "T1078.002" => "Domain Accounts",
        "T1110" => "Brute Force",
        "T1558" => "Steal or Forge Kerberos Tickets",
        "T1558.001" => "Golden Ticket",
        "T1558.003" => "Kerberoasting",
        "T1558.004" => "AS-REP Roasting",
        "T1021" => "Remote Services",
        "T1021.002" => "SMB/Windows Admin Shares",
        "T1649" => "ADCS Certificate Theft",
        "T1550" => "Use Alternate Authentication Material",
        "T1550.002" => "Pass the Hash",
        "T1484" => "Domain Policy Modification",
        "T1087" => "Account Discovery",
        _ => "",
    }
}

pub(crate) fn pyramid_level_name(level: u8) -> &'static str {
    match level {
        1 => "Hash Values (L1)",
        2 => "IP Addresses (L2)",
        3 => "Domain Names (L3)",
        4 => "Network/Host Artifacts (L4)",
        5 => "Tools (L5)",
        6 => "TTPs (L6)",
        _ => "Unknown",
    }
}
