//! Secretsdump, Kerberoast, and AS-REP roast output parsers.

use serde_json::{json, Value};

pub fn parse_secretsdump(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();
    let creds = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // NTLM hash format: "username:RID:LMhash:NThash:::"
        // or "DOMAIN\username:RID:LMhash:NThash:::"
        if line.contains(":::") && !line.starts_with('[') && !line.starts_with('#') {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let raw_user = parts[0];
                let (user_domain, username) = if raw_user.contains('\\') {
                    let split: Vec<&str> = raw_user.splitn(2, '\\').collect();
                    (split[0].to_string(), split[1].to_string())
                } else {
                    (domain.to_string(), raw_user.to_string())
                };

                let nt_hash = parts[3];
                if nt_hash.len() == 32 && nt_hash != "31d6cfe0d16ae931b73c59d7e0c089c0" {
                    // Skip empty/disabled hashes
                    let lm_hash = parts[2];
                    let hash_value = format!("{}:{}", lm_hash, nt_hash);

                    hashes.push(json!({
                        "username": username,
                        "domain": user_domain,
                        "hash_value": hash_value,
                        "hash_type": "ntlm",
                        "source": "secretsdump",
                    }));
                }
            }
        }

        // Cleartext passwords: "[*] Dumping DPAPI creds..." then "username:password"
        // or from LSA: "[*] DefaultPassword\n  username = ...\n  password = ..."
    }

    (hashes, creds)
}

pub fn parse_kerberoast(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        // "$krb5tgs$23$*username$DOMAIN$..." format
        if line.starts_with("$krb5tgs$") {
            // Extract username from the hash
            let parts: Vec<&str> = line.split('$').collect();
            let username = if parts.len() > 3 {
                parts[3].trim_start_matches('*').to_string()
            } else {
                "unknown".to_string()
            };

            hashes.push(json!({
                "username": username,
                "domain": domain,
                "hash_value": line,
                "hash_type": "kerberoast",
                "source": "kerberoast",
            }));
        }
    }

    hashes
}

pub fn parse_asrep_roast(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("$krb5asrep$") {
            let parts: Vec<&str> = line.split('$').collect();
            let username = if parts.len() > 3 {
                parts[3]
                    .trim_start_matches('*')
                    .split('@')
                    .next()
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "unknown".to_string()
            };

            hashes.push(json!({
                "username": username,
                "domain": domain,
                "hash_value": line,
                "hash_type": "asrep",
                "source": "asrep_roast",
            }));
        }
    }

    hashes
}
