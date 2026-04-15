use std::collections::{HashMap, HashSet};

use ares_core::models::{Credential, Hash, Host, User};

use super::strip_trailing_dot;

pub(super) const WELL_KNOWN_ACCOUNTS: &[&str] =
    &["krbtgt", "administrator", "guest", "defaultaccount"];

pub(crate) fn normalize_state_domains(
    users: &[User],
    credentials: &mut Vec<Credential>,
    hashes: &mut Vec<Hash>,
    domains: &mut Vec<String>,
    hosts: &[Host],
    target_domain: Option<&str>,
) {
    for d in domains.iter_mut() {
        *d = strip_trailing_dot(d.trim()).to_string();
    }
    for cred in credentials.iter_mut() {
        cred.domain = strip_trailing_dot(cred.domain.trim()).to_string();
    }
    for h in hashes.iter_mut() {
        h.domain = strip_trailing_dot(h.domain.trim()).to_string();
    }

    let mut user_domains: HashMap<String, HashSet<String>> = HashMap::new();
    for user in users {
        let username_lower = user.username.to_lowercase();
        let domain = strip_trailing_dot(user.domain.trim()).to_lowercase();
        if !domain.is_empty() {
            user_domains
                .entry(username_lower)
                .or_default()
                .insert(domain);
        }
    }

    {
        let mut cred_groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, cred) in credentials.iter().enumerate() {
            let key = format!("{}:{}", cred.username.to_lowercase(), cred.password);
            cred_groups.entry(key).or_default().push(i);
        }

        let mut keep = vec![false; credentials.len()];
        for indices in cred_groups.values() {
            let username_lower = credentials[indices[0]].username.to_lowercase();

            if WELL_KNOWN_ACCOUNTS.contains(&username_lower.as_str()) {
                for &i in indices {
                    keep[i] = true;
                }
                continue;
            }

            let domains_for_user = user_domains.get(&username_lower);

            if indices.len() == 1 {
                let i = indices[0];
                keep[i] = true;
                // Correct domain if user exists in exactly one domain
                if let Some(ds) = domains_for_user {
                    if ds.len() == 1 {
                        let correct = ds.iter().next().unwrap().clone();
                        if credentials[i].domain.to_lowercase() != correct {
                            credentials[i].domain = correct;
                        }
                    }
                }
            } else {
                match domains_for_user {
                    None => {
                        // Keep most specific (longest domain)
                        let best = *indices
                            .iter()
                            .max_by_key(|&&i| credentials[i].domain.len())
                            .unwrap();
                        keep[best] = true;
                    }
                    Some(ds) if ds.len() == 1 => {
                        let correct = ds.iter().next().unwrap();
                        // Keep only matching credential, or correct the best one
                        let matching = indices
                            .iter()
                            .find(|&&i| credentials[i].domain.to_lowercase() == *correct);
                        if let Some(&i) = matching {
                            keep[i] = true;
                        } else {
                            let best = *indices
                                .iter()
                                .max_by_key(|&&i| credentials[i].domain.len())
                                .unwrap();
                            credentials[best].domain = correct.clone();
                            keep[best] = true;
                        }
                    }
                    Some(ds) => {
                        // Keep only creds whose domain matches a known user domain
                        for &i in indices {
                            if ds.contains(&credentials[i].domain.to_lowercase()) {
                                keep[i] = true;
                            }
                        }
                    }
                }
            }
        }

        let mut j = 0;
        credentials.retain(|_| {
            let k = keep[j];
            j += 1;
            k
        });
    }

    {
        let mut known_domains: HashSet<String> = HashSet::new();
        for ds in user_domains.values() {
            known_domains.extend(ds.iter().cloned());
        }
        for host in hosts {
            if !host.hostname.is_empty() && host.hostname.contains('.') {
                let lower = host.hostname.to_lowercase();
                let parts: Vec<&str> = lower.split('.').collect();
                if parts.len() > 1 {
                    known_domains.insert(parts[1..].join("."));
                }
            }
        }
        if let Some(td) = target_domain {
            known_domains.insert(td.to_lowercase());
        }

        let mut seen: HashSet<String> = HashSet::new();
        let mut keep = vec![false; hashes.len()];

        for (i, h) in hashes.iter_mut().enumerate() {
            let username_lower = h.username.to_lowercase();
            let hash_domain = h.domain.to_lowercase();

            if WELL_KNOWN_ACCOUNTS.contains(&username_lower.as_str()) {
                let dedup_key = format!("{}:{}:{}", hash_domain, username_lower, h.hash_value);
                if seen.insert(dedup_key) {
                    keep[i] = true;
                }
                continue;
            }

            let domains_for_user = user_domains.get(&username_lower);
            if !known_domains.contains(&hash_domain) {
                if let Some(ds) = domains_for_user {
                    if ds.len() == 1 {
                        h.domain = ds.iter().next().unwrap().clone();
                    }
                }
            }

            let dedup_key = format!(
                "{}:{}:{}",
                h.domain.to_lowercase(),
                username_lower,
                h.hash_value
            );
            if seen.insert(dedup_key) {
                keep[i] = true;
            }
        }

        let mut j = 0;
        hashes.retain(|_| {
            let k = keep[j];
            j += 1;
            k
        });
    }

    {
        let mut valid_domains: HashSet<String> = HashSet::new();
        if let Some(td) = target_domain {
            valid_domains.insert(td.to_lowercase());
        }
        for host in hosts {
            if !host.hostname.is_empty() && host.hostname.contains('.') {
                let lower = host.hostname.to_lowercase();
                let parts: Vec<&str> = lower.split('.').collect();
                if parts.len() > 1 {
                    valid_domains.insert(parts[1..].join("."));
                }
            }
        }
        for user in users {
            if !user.domain.is_empty() {
                valid_domains.insert(user.domain.to_lowercase());
            }
        }

        domains.retain(|d| valid_domains.contains(&d.to_lowercase()));
    }
}
