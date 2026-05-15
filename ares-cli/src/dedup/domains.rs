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
        let mut host_fqdns: HashSet<String> = HashSet::new();
        if let Some(td) = target_domain {
            valid_domains.insert(td.to_lowercase());
        }
        for host in hosts {
            if !host.hostname.is_empty() && host.hostname.contains('.') {
                let lower = host.hostname.to_lowercase();
                host_fqdns.insert(lower.clone());
                let parts: Vec<&str> = lower.split('.').collect();
                if parts.len() > 1 {
                    valid_domains.insert(parts[1..].join("."));
                }
            }
        }
        for user in users {
            if !user.domain.is_empty() {
                let d = user.domain.to_lowercase();
                // Skip user.domain values that are actually a host FQDN —
                // some parsers misattribute and assign the DC's FQDN as the
                // user's AD domain, which would otherwise let the FQDN survive
                // the retain() filter below as a phantom "domain".
                if !host_fqdns.contains(&d) {
                    valid_domains.insert(d);
                }
            }
        }

        // Also keep child domains whose suffix parent is already valid.
        // e.g. north.sevenkingdoms.local survives when sevenkingdoms.local is valid,
        // even before any north users/hosts have been enumerated.
        let child_domains: Vec<String> = domains
            .iter()
            .filter_map(|d| {
                let lower = d.trim().to_lowercase();
                let parts: Vec<&str> = lower.split('.').collect();
                if parts.len() > 2 {
                    let parent = parts[1..].join(".");
                    if valid_domains.contains(&parent) {
                        return Some(lower);
                    }
                }
                None
            })
            .collect();
        valid_domains.extend(child_domains);

        // A string that appears as the suffix (parts[1..]) of any host FQDN is a real
        // domain, even if it also happens to appear as a host's own hostname field
        // (e.g. a DC recorded as hostname="north.sevenkingdoms.local" while
        // castelblack.north.sevenkingdoms.local is another host in the same op).
        let confirmed_domains: HashSet<String> = hosts
            .iter()
            .filter(|h| !h.hostname.is_empty() && h.hostname.contains('.'))
            .map(|h| {
                let lower = h.hostname.to_lowercase();
                let parts: Vec<&str> = lower.split('.').collect();
                parts[1..].join(".")
            })
            .collect();

        domains.retain(|d| {
            let lower = d.to_lowercase();
            valid_domains.contains(&lower)
                && (!host_fqdns.contains(&lower) || confirmed_domains.contains(&lower))
        });
    }
}
