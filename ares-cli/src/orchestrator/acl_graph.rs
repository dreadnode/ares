//! ACL attack graph over collected ACL edges.
//!
//! Nodes are AD principals, edges are the dangerous rights one principal holds
//! over another, plus group-membership edges so a right granted to a group
//! reaches its members. [`analyze`] scores every edge by its shortest hop
//! distance to a high-value terminal (Domain Admins and friends, the domain
//! object, or any principal we already hold DA-equivalent material for) and
//! materializes the ranked paths into `state.acl_chains` — the field
//! `auto_acl_chain_follow` reads and that nothing in the tree previously wrote.
//!
//! The ranking is also the dispatch gate: `auto_dacl_abuse` orders its work by
//! hop distance and takes a bounded slice per tick, so a 310-path enumeration
//! can't flood the shared `acl_chain_step` deferred bucket.

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{json, Value};

use super::state::StateInner;
use crate::worker::credential_resolver::is_authenticating_hash_type;

/// Maximum path length explored when scoring an edge. Beyond four hops a
/// "path to DA" is not a plan, and each extra hop multiplies the chance that
/// an intermediate step fails and strands the rest.
const MAX_HOPS: usize = 4;

/// Maximum chains written into `acl_chains`. Bounds both the memory the
/// orchestrator carries and the work `auto_acl_chain_follow` can enqueue.
const MAX_CHAINS: usize = 25;

/// Per-tick dispatch budget shared by the ACL drivers. Both submit under the
/// `acl_chain_step` task type, which has a 50-slot deferred cap.
pub(crate) const MAX_ACL_DISPATCH_PER_TICK: usize = 8;

/// Groups whose membership is domain compromise. Reaching any of them ends a
/// chain.
const HIGH_VALUE_GROUPS: &[&str] = &[
    "domain admins",
    "enterprise admins",
    "administrators",
    "schema admins",
    "account operators",
    "backup operators",
    "domain controllers",
    "enterprise domain controllers",
    "key admins",
    "enterprise key admins",
    "group policy creator owners",
    "krbtgt",
];

/// True when `vuln_type` names an ACL right the ACL drivers can act on.
pub(crate) fn is_acl_vuln_type(vuln_type: &str) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype.contains("forcechangepassword")
        || vtype.contains("genericwrite")
        || vtype.contains("writedacl")
        || vtype.contains("writeowner")
        || vtype.contains("genericall")
        || vtype.contains("self_membership")
        || vtype.contains("write_membership")
        || vtype.contains("writeproperty")
        || vtype.contains("allextendedrights")
        || vtype.contains("addmember")
        || vtype.contains("addself")
}

/// One dangerous right, source principal → target principal.
#[derive(Debug, Clone)]
pub(crate) struct AclEdge {
    pub vuln_id: String,
    pub right: String,
    pub source: String,
    pub source_domain: String,
    /// Principals that inherit this right through group membership, when the
    /// source is a group. Populated by the BloodHound collector parser.
    pub source_members: Vec<String>,
    pub target: String,
    pub target_type: String,
    pub domain: String,
}

/// Ranked view of the ACL graph.
pub(crate) struct AclAnalysis {
    /// `vuln_id` → hops from taking that edge to a high-value terminal. An
    /// edge landing directly on Domain Admins is 1.
    pub hops_to_terminal: HashMap<String, usize>,
    /// Ranked chains in `acl_chains` wire format: privileged-reaching first
    /// by hop count, then the rest.
    pub chains: Vec<Value>,
}

impl AclAnalysis {
    /// Sort key for an edge: hop distance ascending, unreachable last.
    ///
    /// Edges that reach nothing privileged are deprioritized, never dropped.
    pub fn rank_of(&self, vuln_id: &str) -> usize {
        self.hops_to_terminal
            .get(vuln_id)
            .copied()
            .unwrap_or(usize::MAX)
    }
}

fn detail_str(vuln: &ares_core::models::VulnerabilityInfo, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = vuln.details.get(*key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    String::new()
}

/// Lift the ACL-typed vulnerabilities in `state` into graph edges.
pub(crate) fn build_edges(state: &StateInner) -> Vec<AclEdge> {
    let mut edges: Vec<AclEdge> = state
        .discovered_vulnerabilities
        .values()
        .filter(|v| is_acl_vuln_type(&v.vuln_type))
        .filter(|v| !state.exploited_vulnerabilities.contains(&v.vuln_id))
        .filter_map(|v| {
            let source = detail_str(v, &["source", "source_user", "from"]);
            let target = detail_str(v, &["target", "target_user", "to"]);
            if source.is_empty() || target.is_empty() {
                return None;
            }
            let domain = detail_str(v, &["domain", "source_domain"]);
            let source_domain = detail_str(v, &["source_domain", "domain"]);
            let source_members = v
                .details
                .get("source_members")
                .and_then(|m| m.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m.as_str())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            Some(AclEdge {
                vuln_id: v.vuln_id.clone(),
                right: v.vuln_type.to_lowercase(),
                source,
                source_domain,
                source_members,
                target,
                target_type: detail_str(v, &["target_type"]),
                domain,
            })
        })
        .collect();
    edges.sort_by(|a, b| a.vuln_id.cmp(&b.vuln_id));
    edges
}

/// True when reaching `name` is domain compromise.
fn is_high_value_terminal(name: &str, target_type: &str, state: &StateInner) -> bool {
    if target_type.eq_ignore_ascii_case("domain") {
        return true;
    }
    let lower = name.to_lowercase();
    if HIGH_VALUE_GROUPS.contains(&lower.as_str()) {
        return true;
    }
    if state
        .admin_names
        .values()
        .any(|a| a.eq_ignore_ascii_case(name))
    {
        return true;
    }
    state
        .credentials
        .iter()
        .any(|c| c.is_admin && c.username.eq_ignore_ascii_case(name))
}

/// Principals that can exercise `edge` — its source, plus every member when
/// the source is a group.
fn edge_principals(edge: &AclEdge) -> Vec<String> {
    let mut principals = vec![edge.source.to_lowercase()];
    principals.extend(edge.source_members.iter().map(|m| m.to_lowercase()));
    principals
}

/// Shortest hop distance from each principal to a high-value terminal.
///
/// Multi-source BFS backwards from the terminals: if a node sits `d` hops out,
/// every principal holding a right over it sits `d + 1` hops out.
fn distances_to_terminal(edges: &[AclEdge], state: &StateInner) -> HashMap<String, usize> {
    let mut dist: HashMap<String, usize> = HashMap::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    for edge in edges {
        if is_high_value_terminal(&edge.target, &edge.target_type, state) {
            let key = edge.target.to_lowercase();
            if dist.insert(key.clone(), 0).is_none() {
                queue.push_back((key, 0));
            }
        }
    }

    let mut by_target: HashMap<String, Vec<&AclEdge>> = HashMap::new();
    for edge in edges {
        by_target
            .entry(edge.target.to_lowercase())
            .or_default()
            .push(edge);
    }

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= MAX_HOPS {
            continue;
        }
        let Some(incoming) = by_target.get(&node) else {
            continue;
        };
        for edge in incoming {
            for principal in edge_principals(edge) {
                if dist.contains_key(&principal) {
                    continue;
                }
                dist.insert(principal.clone(), depth + 1);
                queue.push_back((principal, depth + 1));
            }
        }
    }

    dist
}

/// True when `hash` is material an ACL tool can authenticate with.
///
/// Kerberoast / AS-REP ciphertext carries a non-empty `hash_value` but is
/// offline-crack material, not a login: `bloodyad_base` would be handed a
/// `$krb5tgs$` blob as `-p LM:NT`. The credential resolver already draws this
/// line with [`is_authenticating_hash_type`]; reuse it so the graph's notion of
/// "usable" matches what the worker will actually inject.
pub(crate) fn is_usable_hash(hash: &ares_core::models::Hash) -> bool {
    !hash.hash_value.is_empty() && is_authenticating_hash_type(&hash.hash_type)
}

/// Principals we hold usable auth material for, lowercased.
///
/// Any one of the three forms the ACL tools accept (precedence `ticket_path` >
/// `hash` > `password`, see [`crate::worker::credential_resolver`]) makes a
/// principal a viable chain start — the worker injects whichever it holds by
/// `(username, domain)` at dispatch time. Counting only password-bearing
/// credentials stranded every hash-only foothold, which is the shape a
/// shadow-credential takeover or an NTDS dump leaves behind: chains are only
/// ever walked from this set, so those principals started nothing.
fn owned_principals(state: &StateInner) -> HashSet<String> {
    let passwords = state
        .credentials
        .iter()
        .filter(|c| !c.password.is_empty())
        .map(|c| c.username.to_lowercase());
    let hashes = state
        .hashes
        .iter()
        .filter(|h| is_usable_hash(h))
        .map(|h| h.username.to_lowercase());
    let tickets = state
        .kerberos_tickets
        .iter()
        .filter(|t| !t.ticket_path.is_empty())
        .map(|t| t.username.to_lowercase());
    passwords.chain(hashes).chain(tickets).collect()
}

/// True for Kerberos roast material (TGS-REP / AS-REP), by hash value or type.
///
/// Deliberately disjoint from [`is_usable_hash`]: roast tickets are not an
/// authenticating hash type, so the worker cannot inject them, and a principal
/// known only by one is not "owned".
fn is_roastable_hash(hash: &ares_core::models::Hash) -> bool {
    let value = hash.hash_value.to_lowercase();
    if value.contains("$krb5tgs$") || value.contains("$krb5asrep$") {
        return true;
    }
    matches!(
        hash.hash_type.to_lowercase().as_str(),
        "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs" | "asrep" | "as-rep" | "krb5asrep"
    )
}

/// Principals holding uncracked roast material — one hashcat run from a
/// plaintext, lowercased.
///
/// These seed chain construction but never satisfy a dispatch. Seeding here is
/// what lets a chain exist *before* the DCSync that is otherwise the only source
/// of its root principal: empirically every ACL success in the corpus landed
/// after Domain Admin, because a chain rooted at a principal recoverable only
/// from NTDS cannot be built until NTDS has already been dumped.
///
/// Safe because `collect_acl_chain_work` resolves each step's principal and
/// abandons the chain when no usable material exists yet, so a chain rooted here
/// simply waits for the crack instead of dispatching a doomed step.
pub(crate) fn crackable_principals(state: &StateInner) -> HashSet<String> {
    state
        .hashes
        .iter()
        .filter(|h| is_roastable_hash(h))
        .filter(|h| h.cracked_password.is_none())
        .map(|h| h.username.to_lowercase())
        .collect()
}

fn chain_id(steps: &[Value]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    for step in steps {
        step.get("vuln_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .hash(&mut h);
        step.get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .hash(&mut h);
    }
    format!("{:x}", h.finish())
}

/// Render one edge as an `acl_chains` step.
///
/// `source_override` carries the group member actually exercising the right
/// when the graph edge is group-sourced — a group has no credential, so
/// without it the step is undispatchable.
fn build_step(edge: &AclEdge, source_override: Option<&str>, state: &StateInner) -> Value {
    let domain = if edge.domain.is_empty() {
        edge.source_domain.clone()
    } else {
        edge.domain.clone()
    };
    let target_ip = state.resolve_dc_ip(&domain).unwrap_or_default();
    let source = source_override.unwrap_or(&edge.source);
    let source_domain = if edge.source_domain.is_empty() {
        domain.clone()
    } else {
        edge.source_domain.clone()
    };
    let mut step = json!({
        "technique": "dacl_abuse",
        "vuln_id": edge.vuln_id,
        "acl_type": edge.right,
        "source": source,
        "source_domain": source_domain,
        "target": edge.target,
        "target_type": edge.target_type,
        "target_ip": target_ip,
        "domain": domain,
    });
    if let Some(via) = source_override {
        if !via.eq_ignore_ascii_case(&edge.source) {
            step["via_group"] = json!(edge.source);
        }
    }
    step
}

/// Walk the greedy shortest path from `start` to a terminal.
///
/// At each node take the outgoing edge whose target is closest to a terminal,
/// breaking ties on `vuln_id` so the chain set is stable across ticks.
fn walk_chain(
    start: &str,
    by_principal: &HashMap<String, Vec<&AclEdge>>,
    dist: &HashMap<String, usize>,
    state: &StateInner,
) -> Option<(Vec<Value>, String, usize)> {
    let mut node = start.to_string();
    let mut steps = Vec::new();
    let mut visited: HashSet<String> = HashSet::from([node.clone()]);

    for _ in 0..MAX_HOPS {
        let candidates = by_principal.get(&node)?;
        let best = candidates
            .iter()
            .filter(|e| !visited.contains(&e.target.to_lowercase()))
            .min_by(|a, b| {
                let da = dist
                    .get(&a.target.to_lowercase())
                    .copied()
                    .unwrap_or(usize::MAX);
                let db = dist
                    .get(&b.target.to_lowercase())
                    .copied()
                    .unwrap_or(usize::MAX);
                da.cmp(&db).then_with(|| a.vuln_id.cmp(&b.vuln_id))
            })?;

        let override_source = (!best.source.eq_ignore_ascii_case(&node)).then_some(node.as_str());
        steps.push(build_step(best, override_source, state));

        if is_high_value_terminal(&best.target, &best.target_type, state) {
            let hops = steps.len();
            return Some((steps, best.target.clone(), hops));
        }

        node = best.target.to_lowercase();
        if !visited.insert(node.clone()) {
            return None;
        }
    }

    None
}

/// Build the graph, score every edge, and render the ranked chains.
pub(crate) fn analyze(state: &StateInner) -> AclAnalysis {
    let edges = build_edges(state);
    if edges.is_empty() {
        return AclAnalysis {
            hops_to_terminal: HashMap::new(),
            chains: Vec::new(),
        };
    }

    let dist = distances_to_terminal(&edges, state);

    let mut hops_to_terminal = HashMap::new();
    for edge in &edges {
        let target_key = edge.target.to_lowercase();
        if let Some(d) = dist.get(&target_key) {
            hops_to_terminal.insert(edge.vuln_id.clone(), d + 1);
        }
    }

    let owned = owned_principals(state);
    let crackable = crackable_principals(state);
    let seeds: HashSet<String> = owned.union(&crackable).cloned().collect();
    let mut privileged: Vec<(usize, usize, String, Value)> = Vec::new();
    let mut unprivileged: Vec<(usize, String, Value)> = Vec::new();
    let mut seen_chains: HashSet<String> = HashSet::new();

    let mut by_principal: HashMap<String, Vec<&AclEdge>> = HashMap::new();
    for edge in &edges {
        for principal in edge_principals(edge) {
            by_principal.entry(principal).or_default().push(edge);
        }
    }

    let mut starts: Vec<&String> = seeds.iter().collect();
    starts.sort();

    for start in starts {
        if let Some((steps, terminal, hops)) = walk_chain(start, &by_principal, &dist, state) {
            let id = chain_id(&steps);
            if !seen_chains.insert(id.clone()) {
                continue;
            }
            let root_owned = owned.contains(start);
            privileged.push((
                usize::from(!root_owned),
                hops,
                id.clone(),
                json!({
                    "chain_id": id,
                    "reaches_privileged": true,
                    "root_owned": root_owned,
                    "hops": hops,
                    "terminal": terminal,
                    "steps": steps,
                }),
            ));
        }
    }

    for edge in &edges {
        if hops_to_terminal.contains_key(&edge.vuln_id) {
            continue;
        }
        let Some(principal) = edge_principals(edge)
            .into_iter()
            .find(|p| seeds.contains(p))
        else {
            continue;
        };
        let override_source =
            (!edge.source.eq_ignore_ascii_case(&principal)).then_some(principal.as_str());
        let steps = vec![build_step(edge, override_source, state)];
        let id = chain_id(&steps);
        if !seen_chains.insert(id.clone()) {
            continue;
        }
        let root_owned = owned.contains(&principal);
        unprivileged.push((
            usize::from(!root_owned),
            id.clone(),
            json!({
                "chain_id": id,
                "reaches_privileged": false,
                "root_owned": root_owned,
                "hops": 1,
                "terminal": Value::Null,
                "steps": steps,
            }),
        ));
    }

    privileged.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    unprivileged.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let chains: Vec<Value> = privileged
        .into_iter()
        .map(|(_, _, _, v)| v)
        .chain(unprivileged.into_iter().map(|(_, _, v)| v))
        .take(MAX_CHAINS)
        .collect();

    AclAnalysis {
        hops_to_terminal,
        chains,
    }
}

/// Recompute the graph and write the ranked chains into `state.acl_chains`.
///
/// Returns the number of chains materialized.
pub(crate) fn refresh_acl_chains(state: &mut StateInner) -> usize {
    let chains = analyze(state).chains;
    let count = chains.len();
    state.acl_chains = chains;
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, VulnerabilityInfo};

    fn cred(username: &str, domain: &str, is_admin: bool) -> Credential {
        Credential {
            id: format!("cred-{username}"),
            username: username.into(),
            password: "P@ssw0rd!".into(),
            domain: domain.into(),
            source: String::new(),
            discovered_at: None,
            is_admin,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn edge_vuln(vuln_id: &str, right: &str, source: &str, target: &str) -> VulnerabilityInfo {
        edge_vuln_typed(vuln_id, right, source, target, "User", &[])
    }

    fn edge_vuln_typed(
        vuln_id: &str,
        right: &str,
        source: &str,
        target: &str,
        target_type: &str,
        members: &[&str],
    ) -> VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("source".into(), json!(source));
        details.insert("target".into(), json!(target));
        details.insert("target_type".into(), json!(target_type));
        details.insert("domain".into(), json!("contoso.local"));
        details.insert("source_domain".into(), json!("contoso.local"));
        if !members.is_empty() {
            details.insert("source_members".into(), json!(members));
        }
        VulnerabilityInfo {
            vuln_id: vuln_id.into(),
            vuln_type: right.into(),
            target: "192.168.58.10".into(),
            discovered_by: "bloodhound".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn hash_for(username: &str, domain: &str, hash_type: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("hash-{username}"),
            username: username.into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            hash_type: hash_type.into(),
            domain: domain.into(),
            cracked_password: None,
            source: "secretsdump".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn state_with(vulns: Vec<VulnerabilityInfo>, creds: Vec<Credential>) -> StateInner {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for v in vulns {
            s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        }
        s.credentials = creds;
        s
    }

    #[test]
    fn empty_state_produces_no_chains() {
        let s = StateInner::new("op".into());
        let a = analyze(&s);
        assert!(a.chains.is_empty());
        assert!(a.hops_to_terminal.is_empty());
    }

    fn roast_hash(username: &str, ticket: &str) -> ares_core::models::Hash {
        let mut h = hash_for(username, "contoso.local", "kerberoast");
        h.hash_value = ticket.into();
        h
    }

    #[test]
    fn roastable_hash_is_not_owned_but_is_crackable() {
        let mut s = state_with(vec![], vec![]);
        s.hashes
            .push(roast_hash("bob", "$krb5tgs$23$*bob$CONTOSO.LOCAL*"));

        assert!(!owned_principals(&s).contains("bob"));
        assert!(crackable_principals(&s).contains("bob"));
    }

    #[test]
    fn asrep_and_type_keyed_roast_material_both_count() {
        let mut s = state_with(vec![], vec![]);
        s.hashes
            .push(roast_hash("bob", "$krb5asrep$23$bob@CONTOSO.LOCAL"));
        let mut typed = hash_for("carol", "contoso.local", "asrep");
        typed.hash_value = "opaque".into();
        s.hashes.push(typed);

        let crackable = crackable_principals(&s);
        assert!(crackable.contains("bob"));
        assert!(crackable.contains("carol"));
    }

    #[test]
    fn already_cracked_roast_material_is_not_a_speculative_seed() {
        let mut s = state_with(vec![], vec![]);
        let mut h = roast_hash("bob", "$krb5tgs$23$*bob$CONTOSO.LOCAL*");
        h.cracked_password = Some("P@ssw0rd!".into());
        s.hashes.push(h);

        assert!(!crackable_principals(&s).contains("bob"));
    }

    #[test]
    fn chain_is_built_from_an_uncracked_roast_principal() {
        let mut s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_bob_da",
                "genericall",
                "bob",
                "Domain Admins",
                "Group",
                &[],
            )],
            vec![],
        );
        s.hashes
            .push(roast_hash("bob", "$krb5tgs$23$*bob$CONTOSO.LOCAL*"));

        let a = analyze(&s);

        assert_eq!(a.chains.len(), 1, "chain should exist before the crack");
        assert_eq!(a.chains[0]["reaches_privileged"], true);
        assert_eq!(a.chains[0]["root_owned"], false);
    }

    #[test]
    fn owned_rooted_chains_outrank_speculative_ones() {
        let mut s = state_with(
            vec![
                edge_vuln_typed(
                    "acl_genericall_bob_da",
                    "genericall",
                    "bob",
                    "Domain Admins",
                    "Group",
                    &[],
                ),
                edge_vuln_typed(
                    "acl_genericall_alice_ea",
                    "genericall",
                    "alice",
                    "Enterprise Admins",
                    "Group",
                    &[],
                ),
            ],
            vec![cred("alice", "contoso.local", false)],
        );
        s.hashes
            .push(roast_hash("bob", "$krb5tgs$23$*bob$CONTOSO.LOCAL*"));

        let a = analyze(&s);

        assert_eq!(a.chains.len(), 2);
        assert_eq!(
            a.chains[0]["root_owned"], true,
            "an actionable chain must not be displaced by a speculative one"
        );
        assert_eq!(a.chains[1]["root_owned"], false);
    }

    #[test]
    fn direct_edge_onto_domain_admins_is_one_hop() {
        let s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_alice_da",
                "genericall",
                "alice",
                "Domain Admins",
                "Group",
                &[],
            )],
            vec![cred("alice", "contoso.local", false)],
        );
        let a = analyze(&s);
        assert_eq!(a.rank_of("acl_genericall_alice_da"), 1);
    }

    #[test]
    fn two_hop_chain_is_ordered_and_scored() {
        let s = state_with(
            vec![
                edge_vuln("acl_genericall_alice_bob", "genericall", "alice", "bob"),
                edge_vuln_typed(
                    "acl_addmember_bob_da",
                    "addmember",
                    "bob",
                    "Domain Admins",
                    "Group",
                    &[],
                ),
            ],
            vec![cred("alice", "contoso.local", false)],
        );
        let a = analyze(&s);
        assert_eq!(a.rank_of("acl_addmember_bob_da"), 1);
        assert_eq!(a.rank_of("acl_genericall_alice_bob"), 2);
        assert_eq!(a.chains.len(), 1);
        let chain = &a.chains[0];
        assert_eq!(chain["reaches_privileged"], true);
        assert_eq!(chain["hops"], 2);
        assert_eq!(chain["terminal"], "Domain Admins");
        let steps = chain["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["source"], "alice");
        assert_eq!(steps[0]["target"], "bob");
        assert_eq!(steps[1]["source"], "bob");
        assert_eq!(steps[1]["target"], "Domain Admins");
        assert_eq!(steps[0]["target_ip"], "192.168.58.10");
    }

    #[test]
    fn an_ntlm_hash_alone_owns_its_principal() {
        let mut s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_alice_da",
                "genericall",
                "alice",
                "Domain Admins",
                "Group",
                &[],
            )],
            Vec::new(),
        );
        s.hashes.push(hash_for("alice", "contoso.local", "ntlm"));
        let a = analyze(&s);
        assert_eq!(a.chains.len(), 1);
        assert_eq!(a.chains[0]["steps"][0]["source"], "alice");
    }

    #[test]
    fn roastable_ciphertext_does_not_own_its_principal() {
        let mut s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_alice_da",
                "genericall",
                "alice",
                "Domain Admins",
                "Group",
                &[],
            )],
            Vec::new(),
        );
        s.hashes
            .push(hash_for("alice", "contoso.local", "kerberoast"));
        s.hashes.push(hash_for("alice", "contoso.local", "AS-REP"));
        let a = analyze(&s);
        assert_eq!(a.rank_of("acl_genericall_alice_da"), 1);
        assert!(!owned_principals(&s).contains("alice"));
        assert!(a.chains.iter().all(|c| c["root_owned"] == false));
    }

    #[test]
    fn a_kerberos_ticket_owns_its_principal() {
        let mut s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_alice_da",
                "genericall",
                "alice",
                "Domain Admins",
                "Group",
                &[],
            )],
            Vec::new(),
        );
        s.kerberos_tickets.push(ares_core::models::KerberosTicket {
            source_domain: "contoso.local".into(),
            target_domain: "fabrikam.local".into(),
            username: "alice".into(),
            ticket_path: "/tmp/ares-tickets/alice.ccache".into(),
            forged_at: None,
        });
        let a = analyze(&s);
        assert_eq!(a.chains.len(), 1);
        assert_eq!(a.chains[0]["steps"][0]["source"], "alice");
    }

    #[test]
    fn edges_reaching_nothing_are_kept_but_ranked_last() {
        let s = state_with(
            vec![
                edge_vuln_typed(
                    "acl_genericall_alice_da",
                    "genericall",
                    "alice",
                    "Domain Admins",
                    "Group",
                    &[],
                ),
                edge_vuln("acl_writedacl_alice_carol", "writedacl", "alice", "carol"),
            ],
            vec![cred("alice", "contoso.local", false)],
        );
        let a = analyze(&s);
        assert_eq!(a.rank_of("acl_genericall_alice_da"), 1);
        assert_eq!(a.rank_of("acl_writedacl_alice_carol"), usize::MAX);
        assert_eq!(a.chains.len(), 2);
        assert_eq!(a.chains[0]["reaches_privileged"], true);
        assert_eq!(a.chains[1]["reaches_privileged"], false);
    }

    #[test]
    fn group_membership_lets_a_member_exercise_the_groups_right() {
        let s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_helpdesk_da",
                "genericall",
                "HELPDESK",
                "Domain Admins",
                "Group",
                &["alice", "bob"],
            )],
            vec![cred("alice", "contoso.local", false)],
        );
        let a = analyze(&s);
        assert_eq!(a.chains.len(), 1);
        let steps = a.chains[0]["steps"].as_array().unwrap();
        assert_eq!(steps[0]["source"], "alice");
        assert_eq!(steps[0]["via_group"], "HELPDESK");
    }

    #[test]
    fn group_sourced_edge_without_an_owned_member_yields_no_chain() {
        let s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_helpdesk_da",
                "genericall",
                "HELPDESK",
                "Domain Admins",
                "Group",
                &["carol"],
            )],
            vec![cred("alice", "contoso.local", false)],
        );
        let a = analyze(&s);
        assert_eq!(a.rank_of("acl_genericall_helpdesk_da"), 1);
        assert!(a.chains.is_empty());
    }

    #[test]
    fn domain_object_target_is_a_terminal() {
        let s = state_with(
            vec![edge_vuln_typed(
                "acl_writedacl_alice_contoso",
                "writedacl",
                "alice",
                "contoso.local",
                "Domain",
                &[],
            )],
            vec![cred("alice", "contoso.local", false)],
        );
        let a = analyze(&s);
        assert_eq!(a.rank_of("acl_writedacl_alice_contoso"), 1);
        assert_eq!(a.chains[0]["terminal"], "contoso.local");
    }

    #[test]
    fn a_principal_known_to_hold_da_is_a_terminal() {
        let s = state_with(
            vec![edge_vuln(
                "acl_genericall_alice_admin",
                "genericall",
                "alice",
                "admin",
            )],
            vec![
                cred("alice", "contoso.local", false),
                cred("admin", "contoso.local", true),
            ],
        );
        let a = analyze(&s);
        assert_eq!(a.rank_of("acl_genericall_alice_admin"), 1);
    }

    #[test]
    fn exploited_edges_leave_the_graph() {
        let mut s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_alice_da",
                "genericall",
                "alice",
                "Domain Admins",
                "Group",
                &[],
            )],
            vec![cred("alice", "contoso.local", false)],
        );
        s.exploited_vulnerabilities
            .insert("acl_genericall_alice_da".into());
        let a = analyze(&s);
        assert!(a.chains.is_empty());
        assert!(a.hops_to_terminal.is_empty());
    }

    #[test]
    fn cyclic_edges_terminate() {
        let s = state_with(
            vec![
                edge_vuln("acl_genericall_alice_bob", "genericall", "alice", "bob"),
                edge_vuln("acl_genericall_bob_alice", "genericall", "bob", "alice"),
            ],
            vec![cred("alice", "contoso.local", false)],
        );
        let a = analyze(&s);
        assert!(a.hops_to_terminal.is_empty());
        // Only the edge whose source we hold a credential for is emitted.
        assert_eq!(a.chains.len(), 1);
        assert_eq!(a.chains[0]["steps"][0]["source"], "alice");
    }

    #[test]
    fn chain_ids_are_stable_across_runs() {
        let s = state_with(
            vec![
                edge_vuln("acl_genericall_alice_bob", "genericall", "alice", "bob"),
                edge_vuln_typed(
                    "acl_addmember_bob_da",
                    "addmember",
                    "bob",
                    "Domain Admins",
                    "Group",
                    &[],
                ),
            ],
            vec![cred("alice", "contoso.local", false)],
        );
        let first = analyze(&s).chains;
        let second = analyze(&s).chains;
        assert_eq!(first[0]["chain_id"], second[0]["chain_id"]);
    }

    #[test]
    fn chain_count_is_capped() {
        let mut vulns = Vec::new();
        let mut creds = Vec::new();
        for i in 0..(MAX_CHAINS + 10) {
            let user = format!("svc_{i}");
            vulns.push(edge_vuln(
                &format!("acl_genericall_{user}_bob"),
                "genericall",
                &user,
                &format!("target{i}"),
            ));
            creds.push(cred(&user, "contoso.local", false));
        }
        let s = state_with(vulns, creds);
        assert_eq!(analyze(&s).chains.len(), MAX_CHAINS);
    }

    #[test]
    fn refresh_writes_chains_into_state() {
        let mut s = state_with(
            vec![edge_vuln_typed(
                "acl_genericall_alice_da",
                "genericall",
                "alice",
                "Domain Admins",
                "Group",
                &[],
            )],
            vec![cred("alice", "contoso.local", false)],
        );
        assert!(s.acl_chains.is_empty());
        let count = refresh_acl_chains(&mut s);
        assert_eq!(count, 1);
        assert_eq!(s.acl_chains.len(), 1);
        assert_eq!(s.acl_chains[0]["steps"][0]["source"], "alice");
    }

    #[test]
    fn non_acl_vulns_are_ignored() {
        let mut v = edge_vuln("smb-001", "smb_signing_disabled", "alice", "dc01");
        v.vuln_type = "smb_signing_disabled".into();
        let s = state_with(vec![v], vec![cred("alice", "contoso.local", false)]);
        assert!(build_edges(&s).is_empty());
    }

    #[test]
    fn acl_vuln_type_predicate_matches_the_driver_vocabulary() {
        for t in [
            "ForceChangePassword",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "GenericAll",
            "self_membership",
            "write_membership",
            "WriteProperty",
            "AllExtendedRights",
            "AddMember",
            "AddSelf",
        ] {
            assert!(is_acl_vuln_type(t), "{t} should be an ACL right");
        }
        for t in ["smb_signing_disabled", "esc1", "kerberoast", "zerologon"] {
            assert!(!is_acl_vuln_type(t), "{t} should not be an ACL right");
        }
    }
}
