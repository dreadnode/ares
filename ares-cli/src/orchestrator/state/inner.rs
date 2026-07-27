//! StateInner — the actual mutable state backing SharedState.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;

use chrono::{DateTime, Utc};

use ares_core::models::*;

use super::ALL_DEDUP_SETS;

/// Lockout quarantine duration: 5 minutes matches S4U cooldown and typical
/// AD lockout observation windows. Longer values block the critical path.
const QUARANTINE_DURATION_SECS: i64 = 300;

/// Fallback observation window for the spray-attempt accumulator when the
/// caller has not supplied the domain's real `lockoutObservationWindow`.
///
/// Deliberately longer than the 5-minute AD/GOAD default: the two failure
/// modes are not symmetric. Remembering attempts for too long only costs
/// spray throughput, while forgetting them too early locks the account and
/// costs the whole domain. Override per-op with `ARES_SPRAY_WINDOW_SECS`,
/// or pass `lockout_observation_window_mins` from `password_policy`.
const SPRAY_WINDOW_DEFAULT_SECS: i64 = 1800;

const CAPTURE_IN_FLIGHT_TTL_SECS: i64 = 180;

/// Maximum number of entries kept in `state.hashes`. ESC8 relay + coerce
/// floods can dump thousands of machine-account NTLMv2 rows into state
/// (WAYSFUCKED op-20260612 saw 11,977) which crowds out signal at every
/// read site. When ingestion hits this cap, `push_hash_capped` evicts the
/// oldest low-value entry to make room. High-value entries (krbtgt,
/// cracked, trust keys, AES256-bearing) are never evicted, so the cap is
/// soft — an all-high-value overflow logs a warn and still pushes.
const MAX_HASHES: usize = 500;

/// How long an LLM-marked "assist-abandoned" task pattern stays
/// dispatch-blocked before the orchestrator allows a single re-try.
///
/// The previous behavior (an entry in the generic dedup set with no TTL)
/// turned every `RequestAssistance` into a permanent op-wide drop. That is
/// the right call when the agent's complaint is structural — wrong
/// toolset, missing primitive — but it also fires when the complaint is
/// "no credentials in state yet": minutes later a parallel cred-harvest
/// can land the missing material and the pattern is still locked out.
///
/// 10 minutes is enough that a doomed pattern won't burn a re-dispatch
/// every 30s tick, and short enough that legitimately fixable patterns
/// get a second look within one LLM-budget worth of latency. Per-op,
/// in-memory only — operator-restart starts everyone fresh, by design.
pub(crate) const ASSIST_ABANDONED_TTL_SECS: i64 = 600;

#[derive(Debug)]
pub struct StateInner {
    pub operation_id: String,
    pub target: Option<Target>,
    pub target_ips: Vec<String>,

    // Collections (append-mostly)
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub shares: Vec<Share>,
    pub domains: Vec<String>,
    /// Domains discovered with evidence weaker than authoritative (typically
    /// inferred from a host FQDN). Held here until the probe confirms or a
    /// stronger source promotes them. Keyed by lowercase FQDN.
    pub candidate_domains: HashMap<String, CandidateDomain>,

    // Vulnerability tracking
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: HashSet<String>,

    // Per-vuln consecutive exploit-failure counts. Drives `is_exploit_abandoned`
    // — once a vuln crosses MAX_EXPLOIT_FAILURES, the exploitation workflow
    // skips it permanently for this op. Prevents 2-hour LLM stuck-loops on
    // exploits whose preconditions (creds, reachable target, working tool)
    // can never be satisfied. Operation-scoped, in-memory only.
    pub exploit_failure_counts: HashMap<String, u32>,

    // Maps
    pub domain_controllers: HashMap<String, String>,
    pub netbios_to_fqdn: HashMap<String, String>,
    pub domain_sids: HashMap<String, String>,
    /// RID-500 account name per domain (may differ from "Administrator" if renamed).
    pub admin_names: HashMap<String, String>,

    // Trust relationships (domain FQDN → trust metadata)
    pub trusted_domains: HashMap<String, TrustInfo>,

    // Per-domain DA tracking: domains where krbtgt NTLM has been obtained
    pub dominated_domains: HashSet<String>,

    // Per-domain timestamp set when an automation dispatches a credential-
    // capture primitive (secretsdump/DCSync). Read by destructive ACL gates
    // to defer ForceChangePassword while DCSync is still in flight. TTL'd —
    // no explicit clear hook; once the dump succeeds the domain enters
    // `dominated_domains`, and the TTL is the safety valve for silent fails.
    pub credential_capture_in_flight: HashMap<String, DateTime<Utc>>,

    /// Patterns the LLM ended a task on with `RequestAssistance`, with the
    /// timestamp the abandonment was recorded. Read by
    /// `throttled_submit_outcome` to drop re-dispatches of doomed patterns
    /// until `ASSIST_ABANDONED_TTL_SECS` elapses, at which point a single
    /// re-try is allowed in case state has shifted (new cred, new vuln).
    /// In-memory only — see the const comment for why this isn't
    /// persisted.
    pub assist_abandoned_at: HashMap<String, DateTime<Utc>>,

    // Flags
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,

    // Dedup sets (persisted to Redis)
    pub dedup: HashMap<String, HashSet<String>>,

    // MSSQL enum tracking (persisted to Redis SET)
    pub mssql_enum_dispatched: HashSet<String>,

    // ACL chain data (from BloodHound, stored in Redis LIST)
    pub acl_chains: Vec<serde_json::Value>,

    // ACL step dedup (tracks which chain steps have been dispatched)
    pub dispatched_acl_steps: HashSet<String>,

    // Pending/completed tasks (in-memory only)
    pub pending_tasks: HashMap<String, TaskInfo>,
    pub completed_tasks: HashMap<String, ares_core::models::TaskResult>,

    // Principal lockout quarantine: `user@domain` → expiry time.
    // Populated by two write paths that converge on the same semantics:
    //   - auth attempts that returned STATUS_ACCOUNT_LOCKED_OUT or
    //     KDC_ERR_CLIENT_REVOKED for a known cleartext credential
    //   - enumeration paths (username_as_password, password_spray) that
    //     observed the principal locked even though we don't hold a
    //     cleartext for them
    // Both cases carry the same operational meaning at every read site —
    // "don't authenticate as this principal right now" — so they share one
    // map. Used by the LLM snapshot filter, automation paths that consume
    // credential/hash lists, and the spray-injection path that builds
    // excluded_users.
    pub quarantined_principals: HashMap<String, DateTime<Utc>>,

    // Per-domain spray budget accumulator: `domain` → (attempts already
    // spent against each account, window expiry).
    //
    // Keyed by domain rather than principal because a spray tries the same
    // password list against every account in the userlist, so the attempts
    // burned *per account* are uniform across the domain.
    //
    // This exists because `attempts_used_per_account` is a tool argument:
    // left to the LLM it is re-reported as 0 on every call, so N sprays in
    // one observation window each stay under the per-call cap and still
    // sum past the lockout threshold. Quarantine is the reactive half
    // (stop hitting an account already locked); this is the proactive half.
    pub spray_attempts: HashMap<String, (i64, DateTime<Utc>)>,

    // Per-trust counter: how many times the cross-forest forge dispatch
    // has been deferred waiting for the AES256 trust key to upsert.
    // secretsdump runs twice (NTLM-only first, then AES-equipped) and
    // Win2016+ targets reject RC4-only inter-realm tickets. Bound this
    // so we don't defer indefinitely if AES never arrives.
    pub forge_aes_defers: HashMap<String, u32>,

    // Per-trust counter: how many times the cross-forest forge has fired
    // NTLM-only (the AES256 trust key never upserted within the defer window)
    // and come back with zero hashes. AES-only target forests reject an RC4
    // inter-realm ticket with KDC_ERR_ETYPE_NOSUPP, so a zero-hash result there
    // is the etype rejection — not SID filtering. We clear dedup and re-wait
    // for AES up to this bound so a late trust-key extraction can drive a
    // successful AES forge; past the bound we lock so a genuinely-unreachable
    // target can't hot-loop.
    pub forge_ntlm_fallback_attempts: HashMap<String, u32>,

    // Per-(trust_follow dedup key) timestamp recording when the
    // cross-forest forge dispatch was marked-processed. `auto_trust_follow`
    // marks dedup *before* spawning the dispatch so the next 30s tick
    // doesn't double-fire, but if the spawn never actually runs the tool
    // (tracing event drop, runtime cancellation, panic between mark and
    // spawn body) the dedup persists and the cross-forest pivot is
    // permanently lost for this op. This map lets the planner detect
    // stale marks and unmark them after `FORGE_STALENESS_LIMIT`, so a
    // later tick re-dispatches. In-memory only — restart resilience
    // isn't required because the persistence layer reclears
    // `trust_follow` on op load anyway.
    pub forge_in_flight: HashMap<String, Instant>,

    // Per-(linked_server vuln) failed-attempt counter for
    // `auto_mssql_link_pivot`. Bounded retries before we mark the
    // pivot dedup'd — keeps a flaky link from looping forever while
    // still tolerating transient auth races.
    pub mssql_link_pivot_attempts: HashMap<String, u32>,

    // Per-`user@domain` count of weak credential-reject observations seen by
    // the containment classifier. A generic `STATUS_LOGON_FAILURE` /
    // `invalidCredentials` only revokes the principal once it recurs
    // `CREDENTIAL_REVOKE_MIN_OBSERVATIONS` times, so one benign auth miss can't
    // starve the LLM's view of a still-valid credential. In-memory only — a
    // restart resets the budget, which re-tries rather than over-revokes.
    pub containment_reject_counts: HashMap<String, u32>,

    // Per-(dc, domain, principal) consecutive-`Transient` counter for
    // `auto_krbtgt_extraction`, keyed by `krbtgt_principal_attempt_key`. A
    // `Transient` outcome intentionally leaves state clean so genuine network
    // blips retry, but a principal that keeps returning non-logon-failure
    // output that never advances (e.g. a full-dump retry that still can't
    // parse krbtgt) would otherwise be re-picked every tick forever. After
    // `KRBTGT_MAX_TRANSIENT` consecutive Transients we mark the principal dedup
    // so the loop rotates to the next candidate. In-memory only — restart just
    // resets the budget, which is the safe direction (re-try, don't over-skip).
    pub krbtgt_transient_counts: HashMap<String, u32>,

    // Per-hash crack attempt counter, keyed by `crack_dedup_key`. Lets a
    // failed crack (wrong wordlist, password not in list, hashcat transient)
    // be retried up to `MAX_CRACK_ATTEMPTS` before the dispatcher marks
    // `DEDUP_CRACK_REQUESTS` and gives up permanently. The previous behavior
    // wrote dedup on dispatch success, so a single hashcat exit ≠ 0 left
    // the hash stuck uncracked forever. Restart resilience: the counter is
    // in-memory only; dedup (the cap marker) is persisted to Redis, so
    // post-restart capped hashes stay capped while uncapped ones get a
    // fresh budget (acceptable mild leak).
    pub crack_attempts: HashMap<String, u32>,

    // Forged inter-realm Kerberos tickets (source→target forest, cached path)
    pub kerberos_tickets: Vec<ares_core::models::KerberosTicket>,

    // Completion flag (set externally to signal operation should wrap up)
    pub completed: bool,

    /// Timestamp when all forests were first detected as dominated.
    /// Used by the completion monitor to enforce a post-exploitation grace period.
    pub all_forests_dominated_at: Option<tokio::time::Instant>,

    /// Per-DC coercion phase state — Bug F. Tracks which coercion techniques
    /// have already been attempted, the attempt count, the last observed error
    /// signal, and any active cooldown. The previous boolean dedup
    /// (`DEDUP_COERCED_DCS`) accepted one attempt per DC and never cycled
    /// techniques, so one `RPC_S_ACCESS_DENIED` on PetitPotam locked the DC
    /// out of every other coercion forever. The cycling logic in
    /// `auto_coercion` reads this map to pick the next un-tried technique
    /// (unauth ladder → authenticated retry when a same-forest cred lands).
    pub coercion_phase_state:
        HashMap<String, crate::orchestrator::automation::coercion::CoercionPhaseState>,

    /// Blue-side containment observations — a credential we hold started
    /// consistently returning `STATUS_LOGON_FAILURE` or LDAP
    /// `INVALID_CREDENTIALS`. Keyed by `user@domain` (lowercase). Read by
    /// the exploitation queue to drop attempts that depend on the principal
    /// and by the LLM prompt formatter to signal "this cred is dead".
    /// Semantically distinct from [`Self::quarantined_principals`], which
    /// carries the short 5-min lockout signal — a revocation persists for
    /// the remainder of the op unless an operator rolls it back.
    pub revoked_principals: HashMap<String, DateTime<Utc>>,

    /// Hosts blue firewalled off. Keyed by IP string. Populated when SMB,
    /// WinRM and LDAP to a previously-reachable host all start returning
    /// network-unreachable inside a short window. Consumers skip vulns
    /// and lateral targets pointing at these IPs.
    pub isolated_hosts: HashMap<String, DateTime<Utc>>,

    /// Domains where blue rotated krbtgt. Keyed by lowercase realm.
    /// Populated on forest-wide `KRB_AP_ERR_MODIFIED`. Consumers drop
    /// cached TGTs and forged tickets for the realm.
    pub krbtgt_rotated_at: HashMap<String, DateTime<Utc>>,

    /// Certificates blue revoked. Keyed by serial (hex, lowercase).
    /// Populated on PKINIT `KDC_ERR_CLIENT_REVOKED`. Consumers drop
    /// ADCS-based exploit paths pinned to the revoked serial.
    pub revoked_certificates: HashMap<String, DateTime<Utc>>,

    /// IPv4 addresses bound to the orchestrator's own network interfaces.
    /// Populated once at orchestrator startup via `SharedState::initialize_self_ips`
    /// from `local_ip_address::list_afinet_netifas`. `publish_host` skips any
    /// host whose IP is in this set so the attacker pivot box doesn't get
    /// counted as a discovered target when an SMB sweep hits its own NIC.
    /// Empty by default — tests using `StateInner::new` get deterministic
    /// no-op filtering without needing to mock interface enumeration.
    pub self_ips: HashSet<IpAddr>,
}

impl StateInner {
    pub(crate) fn new(operation_id: String) -> Self {
        let mut dedup = HashMap::new();
        for name in ALL_DEDUP_SETS {
            dedup.insert(name.to_string(), HashSet::new());
        }

        Self {
            operation_id,
            target: None,
            target_ips: Vec::new(),
            credentials: Vec::new(),
            hashes: Vec::new(),
            hosts: Vec::new(),
            users: Vec::new(),
            shares: Vec::new(),
            domains: Vec::new(),
            candidate_domains: HashMap::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            exploit_failure_counts: HashMap::new(),
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
            domain_sids: HashMap::new(),
            admin_names: HashMap::new(),
            trusted_domains: HashMap::new(),
            dominated_domains: HashSet::new(),
            credential_capture_in_flight: HashMap::new(),
            assist_abandoned_at: HashMap::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            dedup,
            mssql_enum_dispatched: HashSet::new(),
            acl_chains: Vec::new(),
            dispatched_acl_steps: HashSet::new(),
            pending_tasks: HashMap::new(),
            completed_tasks: HashMap::new(),
            quarantined_principals: HashMap::new(),
            spray_attempts: HashMap::new(),
            forge_aes_defers: HashMap::new(),
            forge_ntlm_fallback_attempts: HashMap::new(),
            forge_in_flight: HashMap::new(),
            mssql_link_pivot_attempts: HashMap::new(),
            containment_reject_counts: HashMap::new(),
            krbtgt_transient_counts: HashMap::new(),
            crack_attempts: HashMap::new(),
            kerberos_tickets: Vec::new(),
            completed: false,
            all_forests_dominated_at: None,
            coercion_phase_state: HashMap::new(),
            revoked_principals: HashMap::new(),
            isolated_hosts: HashMap::new(),
            krbtgt_rotated_at: HashMap::new(),
            revoked_certificates: HashMap::new(),
            self_ips: HashSet::new(),
        }
    }

    /// Whether blue has revoked a credential for the given principal.
    /// Comparison is case-insensitive on both fields.
    pub fn is_credential_revoked(&self, username: &str, domain: &str) -> bool {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        self.revoked_principals.contains_key(&key)
    }

    /// Whether blue has firewalled off the given IP.
    pub fn is_host_isolated(&self, ip: &str) -> bool {
        self.isolated_hosts.contains_key(ip)
    }

    /// Whether blue has rotated krbtgt in the given realm (case-insensitive).
    pub fn is_krbtgt_rotated(&self, domain: &str) -> bool {
        self.krbtgt_rotated_at.contains_key(&domain.to_lowercase())
    }

    /// Whether blue has revoked the certificate with the given serial.
    /// Comparison is case-insensitive on the serial (hex).
    pub fn is_certificate_revoked(&self, serial: &str) -> bool {
        self.revoked_certificates
            .contains_key(&serial.to_lowercase())
    }

    /// Check if a username is the delegating account for a constrained
    /// delegation or RBCD vulnerability.  These accounts must be reserved
    /// for S4U exploitation — spraying or secretsdump with their creds
    /// causes lockout before S4U can use them.
    pub fn is_delegation_account(&self, username: &str) -> bool {
        let u = username.to_lowercase();
        self.discovered_vulnerabilities.values().any(|vuln| {
            let vtype = vuln.vuln_type.to_lowercase();
            if vtype != "constrained_delegation" && vtype != "rbcd" {
                return false;
            }
            vuln.details
                .get("account_name")
                .or_else(|| vuln.details.get("AccountName"))
                .and_then(|v| v.as_str())
                .map(|a| a.to_lowercase() == u)
                .unwrap_or(false)
        })
    }

    /// Check if a principal (`user@domain`) is quarantined due to lockout —
    /// either a known cleartext that returned STATUS_ACCOUNT_LOCKED_OUT /
    /// KDC_ERR_CLIENT_REVOKED, or a principal observed locked during
    /// enumeration (`username_as_password`, `password_spray`). Expired
    /// quarantines are ignored (lazy cleanup).
    pub fn is_principal_quarantined(&self, username: &str, domain: &str) -> bool {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        self.quarantined_principals
            .get(&key)
            .map(|expiry| Utc::now() < *expiry)
            .unwrap_or(false)
    }

    /// Quarantine a principal for `QUARANTINE_DURATION_SECS` after a lockout
    /// signal. See [`is_principal_quarantined`] for which signals feed in.
    pub fn quarantine_principal(&mut self, username: &str, domain: &str) {
        self.quarantine_principal_for(username, domain, QUARANTINE_DURATION_SECS);
    }

    /// Attempts already spent against each account in `domain` during the
    /// current observation window. Returns 0 once the window has lapsed, at
    /// which point AD has reset `badPwdCount` and the budget is whole again.
    pub fn spray_attempts_used(&self, domain: &str) -> i64 {
        self.spray_attempts
            .get(&domain.to_lowercase())
            .filter(|(_, expiry)| Utc::now() < *expiry)
            .map(|(used, _)| *used)
            .unwrap_or(0)
    }

    /// Debit `attempts` from `domain`'s lockout budget for `window_secs`.
    ///
    /// Accumulates within a live window and restarts the count once the
    /// previous window lapsed. The expiry is refreshed on every debit
    /// because AD's observation window runs from the most recent bad
    /// password, not from the first one in the burst.
    pub fn record_spray_attempts(&mut self, domain: &str, attempts: i64, window_secs: i64) {
        if attempts <= 0 {
            return;
        }
        let key = domain.to_lowercase();
        let now = Utc::now();
        let carried = self
            .spray_attempts
            .get(&key)
            .filter(|(_, expiry)| now < *expiry)
            .map(|(used, _)| *used)
            .unwrap_or(0);
        let window = if window_secs > 0 {
            window_secs
        } else {
            SPRAY_WINDOW_DEFAULT_SECS
        };
        self.spray_attempts.insert(
            key,
            (carried + attempts, now + chrono::Duration::seconds(window)),
        );
    }

    /// Quarantine a principal for `duration_secs`. Caller chooses the window:
    /// the default 5-min `QUARANTINE_DURATION_SECS` is appropriate for ordinary
    /// auth-attempt lockouts where the next 5-min window probably clears the
    /// AD lockout policy; a SPN-bearing service account observed locked from
    /// password_spray should use the AD default (~30 min) instead so the
    /// spray loop doesn't keep re-hammering the same locked principal across
    /// neighbouring domains. Picks the longer of the existing and new expiry
    /// so a 30-min extension never accidentally shortens an in-flight cooldown.
    pub fn quarantine_principal_for(&mut self, username: &str, domain: &str, duration_secs: i64) {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        let new_expiry = Utc::now() + chrono::Duration::seconds(duration_secs);
        let final_expiry = match self.quarantined_principals.get(&key) {
            Some(existing) if *existing > new_expiry => *existing,
            _ => new_expiry,
        };
        self.quarantined_principals.insert(key, final_expiry);
    }

    pub fn mark_credential_capture_in_flight(&mut self, domain: &str) {
        if domain.is_empty() {
            return;
        }
        self.credential_capture_in_flight
            .insert(domain.to_lowercase(), Utc::now());
    }

    pub fn credential_capture_in_flight_for(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        let Some(ts) = self.credential_capture_in_flight.get(&d) else {
            return false;
        };
        Utc::now().signed_duration_since(*ts).num_seconds() < CAPTURE_IN_FLIGHT_TTL_SECS
    }

    /// Push a hash onto `state.hashes`, evicting the oldest low-value entry
    /// when the vector is at or above `MAX_HASHES`. "Low-value" here means:
    /// not `krbtgt`, not cracked, no trust-key flag, no AES256 key. If every
    /// entry is high-value the push still lands (warn logged); the cap is
    /// deliberately soft so we never drop a hash the attack chain actually
    /// needs.
    pub fn push_hash_capped(&mut self, hash: Hash) {
        if self.hashes.len() >= MAX_HASHES {
            let evict = self.hashes.iter().position(|h| {
                h.username.to_lowercase() != "krbtgt"
                    && h.cracked_password.is_none()
                    && !h.is_trust_key
                    && h.aes_key.is_none()
            });
            if let Some(idx) = evict {
                let dropped = self.hashes.remove(idx);
                tracing::debug!(
                    username = %dropped.username,
                    domain = %dropped.domain,
                    hash_type = %dropped.hash_type,
                    len_after = self.hashes.len(),
                    cap = MAX_HASHES,
                    "state.hashes evicted low-value entry at cap"
                );
            } else {
                tracing::warn!(
                    len = self.hashes.len(),
                    cap = MAX_HASHES,
                    "state.hashes at cap but every entry is high-value — allowing overflow"
                );
            }
        }
        self.hashes.push(hash);
    }

    /// Return a deduplicated list of currently-quarantined usernames in
    /// `domain` (case-insensitive). Used to populate `excluded_users` on
    /// outbound spray dispatches so the worker can drop them before auth.
    pub fn quarantined_principals_in_domain(&self, domain: &str) -> Vec<String> {
        let domain_l = domain.to_lowercase();
        let now = Utc::now();
        let mut out: Vec<String> = self
            .quarantined_principals
            .iter()
            .filter(|(_, expiry)| now < **expiry)
            .filter_map(|(key, _)| {
                let (user, dom) = key.split_once('@')?;
                if dom == domain_l {
                    Some(user.to_string())
                } else {
                    None
                }
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Resolve the DC IP for a domain.
    ///
    /// Checks `domain_controllers` first, then falls back to scanning the hosts
    /// list for a DC whose FQDN suffix matches the domain. This is more robust
    /// than relying solely on `domain_controllers`, which can have stale or
    /// missing entries due to startup seed timing issues in multi-domain
    /// environments.
    pub fn resolve_dc_ip(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();
        if let Some(ip) = self.domain_controllers.get(&domain_lower).or_else(|| {
            self.domain_controllers
                .iter()
                .find(|(k, _)| k.to_lowercase() == domain_lower)
                .map(|(_, v)| v)
        }) {
            return Some(ip.clone());
        }
        for host in &self.hosts {
            if !(host.is_dc || host.detect_dc()) || host.hostname.is_empty() {
                continue;
            }
            if host
                .hostname
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&domain_lower)
            {
                return Some(host.ip.clone());
            }
        }
        for host in &self.hosts {
            if !(host.is_dc || host.detect_dc()) || host.hostname.is_empty() {
                continue;
            }
            let hostname_lower = host.hostname.trim_end_matches('.').to_lowercase();
            if self
                .domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&hostname_lower))
            {
                continue;
            }
            let parts: Vec<&str> = hostname_lower.split('.').collect();
            if parts.len() >= 3 && parts[1..].join(".") == domain_lower {
                return Some(host.ip.clone());
            }
        }
        None
    }

    /// Return all unique domains that have a resolvable DC.
    ///
    /// Merges domains from `domain_controllers`, `domains`, and `trusted_domains`
    /// then filters to those where `resolve_dc_ip()` succeeds. Returns
    /// `(domain, dc_ip)` pairs.
    pub fn all_domains_with_dcs(&self) -> Vec<(String, String)> {
        let mut seen = std::collections::HashSet::new();
        self.domain_controllers
            .keys()
            .chain(&self.domains)
            .chain(self.trusted_domains.keys())
            .map(|d| d.to_lowercase())
            .filter(|d| seen.insert(d.clone()))
            .filter_map(|d| self.resolve_dc_ip(&d).map(|ip| (d, ip)))
            .collect()
    }

    /// Find a cleartext credential from a trusted domain that can authenticate
    /// to `target_domain` via AD trust (child→parent or cross-forest).
    ///
    /// Used as a fallback when no same-domain cleartext credential exists.
    /// Child-domain creds authenticate to parent DCs via the parent-child trust;
    /// cross-forest creds authenticate via bidirectional forest trusts.
    pub fn find_trust_credential(
        &self,
        target_domain: &str,
    ) -> Option<ares_core::models::Credential> {
        let target = target_domain.to_lowercase();

        // Priority 1: child-domain cred → parent-domain (most reliable)
        if let Some(c) = self.credentials.iter().find(|c| {
            !c.password.is_empty()
                && !self.is_principal_quarantined(&c.username, &c.domain)
                && c.domain.to_lowercase().ends_with(&format!(".{target}"))
        }) {
            return Some(c.clone());
        }

        // Priority 2: cross-forest trusted domain cred (bidirectional trust)
        // Check if any credential's domain has a trust with the target domain.
        // Also falls back to discovered-domain heuristic: if both domains have
        // known DCs in the same operation, they are likely in a trust relationship.
        // LDAP bind will simply fail if there is no actual trust.
        for cred in &self.credentials {
            if cred.password.is_empty()
                || self.is_principal_quarantined(&cred.username, &cred.domain)
            {
                continue;
            }
            let cred_dom = cred.domain.to_lowercase();
            if cred_dom == target {
                continue; // same domain, not a trust fallback
            }
            let cred_forest = self.forest_root_of(&cred_dom);
            let target_forest = self.forest_root_of(&target);
            if cred_forest != target_forest {
                // Explicit trust relationship known
                if self.trusted_domains.contains_key(&target_forest)
                    || self.trusted_domains.contains_key(&cred_forest)
                {
                    return Some(cred.clone());
                }
                // Heuristic: both forests have DCs in this engagement — likely
                // trust-related. LDAP bind will fail harmlessly if not.
                let target_has_dc = self.domain_controllers.keys().any(|d| {
                    let d = d.to_lowercase();
                    d == target_forest || self.forest_root_of(&d) == target_forest
                });
                let cred_has_dc = self.domain_controllers.keys().any(|d| {
                    let d = d.to_lowercase();
                    d == cred_forest || self.forest_root_of(&d) == cred_forest
                });
                if target_has_dc && cred_has_dc {
                    return Some(cred.clone());
                }
            }
        }

        None
    }

    /// Find a credential for the SOURCE user (the principal performing the
    /// action), regardless of which TARGET domain the action is aimed at.
    ///
    /// Cross-forest ACL/MSSQL/ADCS exploitation has the source user living in
    /// their own domain (e.g. `testuser@contoso.local`) while a vuln's
    /// `domain` field points at the target (e.g. `fabrikam.local`).
    /// Same-domain matching against the target therefore drops legitimate
    /// cross-forest work.
    ///
    /// Selection priority:
    ///   1. Cred whose domain matches the explicit `@domain` suffix of
    ///      `source_user`, if present.
    ///   2. Cred whose domain == `target_domain` (same-domain case).
    ///   3. Cred from a domain in a trust relationship with `target_domain`
    ///      (forest sibling, child↔parent, or trusted_domains entry).
    ///   4. Any non-empty, non-quarantined cred with matching username.
    pub fn find_source_credential(
        &self,
        source_user: &str,
        target_domain: &str,
    ) -> Option<ares_core::models::Credential> {
        let (name, explicit_dom) = parse_principal(source_user);
        let name_l = name.to_lowercase();
        let target_l = target_domain.to_lowercase();
        let target_forest = self.forest_root_of(&target_l);

        let usable = |c: &ares_core::models::Credential| -> bool {
            !c.password.is_empty()
                && !self.is_principal_quarantined(&c.username, &c.domain)
                && c.username.to_lowercase() == name_l
        };

        if let Some(ref d) = explicit_dom {
            if let Some(c) = self
                .credentials
                .iter()
                .find(|c| usable(c) && c.domain.to_lowercase() == *d)
            {
                return Some(c.clone());
            }
        }

        if let Some(c) = self
            .credentials
            .iter()
            .find(|c| usable(c) && c.domain.to_lowercase() == target_l)
        {
            return Some(c.clone());
        }

        if let Some(c) = self.credentials.iter().find(|c| {
            if !usable(c) {
                return false;
            }
            let dom = c.domain.to_lowercase();
            if dom == target_l {
                return false;
            }
            let cred_forest = self.forest_root_of(&dom);
            cred_forest == target_forest
                || self.trusted_domains.contains_key(&target_forest)
                || self.trusted_domains.contains_key(&cred_forest)
        }) {
            return Some(c.clone());
        }

        self.credentials.iter().find(|c| usable(c)).cloned()
    }

    /// NTLM-hash variant of [`find_source_credential`] with the same priority
    /// order. Restricts to NTLM hashes (the only type usable for PTH).
    pub fn find_source_hash(
        &self,
        source_user: &str,
        target_domain: &str,
    ) -> Option<ares_core::models::Hash> {
        let (name, explicit_dom) = parse_principal(source_user);
        let name_l = name.to_lowercase();
        let target_l = target_domain.to_lowercase();
        let target_forest = self.forest_root_of(&target_l);

        let usable = |h: &ares_core::models::Hash| -> bool {
            !h.hash_value.is_empty()
                && h.hash_type.eq_ignore_ascii_case("NTLM")
                && !self.is_principal_quarantined(&h.username, &h.domain)
                && h.username.to_lowercase() == name_l
        };

        if let Some(ref d) = explicit_dom {
            if let Some(h) = self
                .hashes
                .iter()
                .find(|h| usable(h) && h.domain.to_lowercase() == *d)
            {
                return Some(h.clone());
            }
        }

        if let Some(h) = self
            .hashes
            .iter()
            .find(|h| usable(h) && h.domain.to_lowercase() == target_l)
        {
            return Some(h.clone());
        }

        if let Some(h) = self.hashes.iter().find(|h| {
            if !usable(h) {
                return false;
            }
            let dom = h.domain.to_lowercase();
            if dom == target_l {
                return false;
            }
            let cred_forest = self.forest_root_of(&dom);
            cred_forest == target_forest
                || self.trusted_domains.contains_key(&target_forest)
                || self.trusted_domains.contains_key(&cred_forest)
        }) {
            return Some(h.clone());
        }

        self.hashes.iter().find(|h| usable(h)).cloned()
    }

    /// Get the forest root for a domain.
    /// If the domain is a child (e.g. `child.contoso.local`), the forest
    /// root is the parent (e.g. `contoso.local`). Otherwise returns self.
    pub fn forest_root_of(&self, domain: &str) -> String {
        let d = domain.to_lowercase();
        // Check if this domain is a child of any known domain
        for known in self.domains.iter() {
            let k = known.to_lowercase();
            if d != k && d.ends_with(&format!(".{k}")) {
                return k;
            }
        }
        for known in self.domain_controllers.keys() {
            let k = known.to_lowercase();
            if d != k && d.ends_with(&format!(".{k}")) {
                return k;
            }
        }
        d
    }

    /// Return true when this exact domain is already dominated.
    ///
    /// This intentionally avoids forest-root inference: a child-domain krbtgt
    /// should not suppress work in an undominated parent domain. NetBIOS names
    /// are resolved through `netbios_to_fqdn` when available.
    pub fn is_domain_dominated(&self, domain: &str) -> bool {
        let raw = domain.to_lowercase();
        if raw.is_empty() {
            return false;
        }
        let normalized = if raw.contains('.') {
            raw
        } else {
            self.netbios_to_fqdn
                .get(&raw)
                .or_else(|| self.netbios_to_fqdn.get(&domain.to_uppercase()))
                .map(|fqdn| fqdn.to_lowercase())
                .unwrap_or(raw)
        };
        self.dominated_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&normalized))
    }

    /// Check if a dedup key exists in the named set.
    pub fn is_processed(&self, set_name: &str, key: &str) -> bool {
        self.dedup
            .get(set_name)
            .map(|s| s.contains(key))
            .unwrap_or(false)
    }

    /// Check if any key in the named dedup set starts with `prefix`.
    pub fn has_processed_prefix(&self, set_name: &str, prefix: &str) -> bool {
        self.dedup
            .get(set_name)
            .map(|s| s.iter().any(|k| k.starts_with(prefix)))
            .unwrap_or(false)
    }

    /// Mark a key as processed in the named set.
    pub fn mark_processed(&mut self, set_name: &str, key: String) {
        self.dedup
            .entry(set_name.to_string())
            .or_default()
            .insert(key);
    }

    /// Remove a key from the named dedup set so it can be retried.
    pub fn unmark_processed(&mut self, set_name: &str, key: &str) {
        if let Some(s) = self.dedup.get_mut(set_name) {
            s.remove(key);
        }
    }

    /// Record an LLM-marked "assist-abandoned" pattern at `now`.
    /// Time is injectable so the TTL behavior is unit-testable without
    /// real-time clocks.
    pub fn mark_assist_abandoned_at(&mut self, key: String, now: DateTime<Utc>) {
        self.assist_abandoned_at.insert(key, now);
    }

    /// Convenience wrapper around `mark_assist_abandoned_at` that uses
    /// the current UTC time. Call sites in production code use this.
    pub fn mark_assist_abandoned(&mut self, key: String) {
        self.mark_assist_abandoned_at(key, Utc::now());
    }

    /// Return true when `key` is currently within the assist-abandoned
    /// window (i.e. `now - abandoned_at < ASSIST_ABANDONED_TTL_SECS`).
    /// An expired entry returns false without being cleaned up — the
    /// bounded per-op pattern space makes lazy GC fine; the next
    /// `mark_assist_abandoned` for the same key overwrites the stale
    /// entry.
    pub fn is_assist_abandoned_at(&self, key: &str, now: DateTime<Utc>) -> bool {
        let Some(at) = self.assist_abandoned_at.get(key) else {
            return false;
        };
        now.signed_duration_since(*at).num_seconds() < ASSIST_ABANDONED_TTL_SECS
    }

    /// Convenience wrapper around `is_assist_abandoned_at` for production
    /// call sites.
    pub fn is_assist_abandoned(&self, key: &str) -> bool {
        self.is_assist_abandoned_at(key, Utc::now())
    }

    /// Remove every key in `set_name` that starts with `prefix`. Returns the
    /// removed keys so the caller can also drop them from the persisted store.
    /// Used by trust automation to wake cross-forest fallback automations
    /// (FSP/ACL/group enum) for a target domain when their dedup format is
    /// `{kind}:{domain}[:tail]` — clearing all entries for a target without
    /// knowing the full key.
    pub fn unmark_processed_by_prefix(&mut self, set_name: &str, prefix: &str) -> Vec<String> {
        let Some(s) = self.dedup.get_mut(set_name) else {
            return Vec::new();
        };
        let to_remove: Vec<String> = s
            .iter()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        for k in &to_remove {
            s.remove(k);
        }
        to_remove
    }

    /// Check if all discovered forests have been dominated (krbtgt obtained).
    ///
    /// Returns `true` when `compute_undominated_forests()` returns an empty list,
    /// meaning every forest root (initial target, trusted domains, and DCs) has
    /// a corresponding entry in `dominated_domains`.
    ///
    /// Automations should check `has_domain_admin && all_forests_dominated()`
    /// before going idle — DA in one forest doesn't mean we're done if cross-forest
    /// targets remain.
    pub fn all_forests_dominated(&self) -> bool {
        crate::orchestrator::completion::compute_undominated_forests(
            self.target.as_ref().map(|t| t.domain.as_str()),
            self.domains.first().map(|d| d.as_str()),
            &self.trusted_domains,
            &self.dominated_domains,
            &self.domain_controllers,
        )
        .is_empty()
    }
}

/// Parse a principal string of form `name` or `name@domain.fqdn`.
/// Returns `(name, Some(domain_lower))` for the @-form, `(name, None)` for bare names.
fn parse_principal(s: &str) -> (&str, Option<String>) {
    if let Some((name, dom)) = s.split_once('@') {
        (name, Some(dom.to_lowercase()))
    } else {
        (s, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::*;

    #[test]
    fn state_inner_new_initializes_all_dedup_sets() {
        let state = StateInner::new("op-test".into());
        assert_eq!(state.operation_id, "op-test");
        assert!(!state.has_domain_admin);
        assert!(!state.has_golden_ticket);
        assert!(!state.completed);

        // All 19 dedup sets should be initialized
        for name in ALL_DEDUP_SETS {
            assert!(state.dedup.contains_key(*name), "Missing dedup set: {name}");
            assert!(state.dedup[*name].is_empty());
        }
        assert_eq!(state.dedup.len(), ALL_DEDUP_SETS.len());
    }

    #[test]
    fn is_processed_returns_false_for_unknown_set() {
        let state = StateInner::new("op-1".into());
        assert!(!state.is_processed("nonexistent_set", "key1"));
    }

    #[test]
    fn mark_processed_and_is_processed() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));

        state.mark_processed(DEDUP_CRACK_REQUESTS, "hash1".into());
        assert!(state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "hash2"));
    }

    #[test]
    fn mark_processed_creates_new_set_if_needed() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed("custom_set", "key1".into());
        assert!(state.is_processed("custom_set", "key1"));
    }

    #[test]
    fn mark_processed_idempotent() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());
        assert_eq!(state.dedup[DEDUP_SECRETSDUMP].len(), 1);
    }

    #[test]
    fn unmark_processed_by_prefix_removes_matching() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "xforest:fabrikam.local:dc01".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "xforest:fabrikam.local:dc02".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "xforest:contoso.local:dc01".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "unrelated:key".into());
        let removed =
            state.unmark_processed_by_prefix(DEDUP_SECRETSDUMP, "xforest:fabrikam.local:");
        assert_eq!(removed.len(), 2);
        assert!(removed
            .iter()
            .all(|k| k.starts_with("xforest:fabrikam.local:")));
        assert_eq!(state.dedup[DEDUP_SECRETSDUMP].len(), 2);
    }

    #[test]
    fn unmark_processed_by_prefix_unknown_set_returns_empty() {
        let mut state = StateInner::new("op-1".into());
        let removed = state.unmark_processed_by_prefix("does_not_exist", "x:");
        assert!(removed.is_empty());
    }

    // --- assist-abandoned TTL ----------------------------------------

    #[test]
    fn assist_abandoned_starts_false() {
        let state = StateInner::new("op-1".into());
        assert!(!state.is_assist_abandoned("any:key"));
    }

    #[test]
    fn assist_abandoned_marked_now_is_blocked() {
        let mut state = StateInner::new("op-1".into());
        state.mark_assist_abandoned("credential_access|192.168.58.10|alice|contoso.local".into());
        assert!(state.is_assist_abandoned("credential_access|192.168.58.10|alice|contoso.local"));
    }

    #[test]
    fn assist_abandoned_expires_after_ttl() {
        let mut state = StateInner::new("op-1".into());
        let key = "credential_access|192.168.58.10|alice|contoso.local".to_string();
        let old = Utc::now() - chrono::Duration::seconds(ASSIST_ABANDONED_TTL_SECS + 1);
        state.mark_assist_abandoned_at(key.clone(), old);
        // Within window: still blocked relative to `old + 1s`.
        assert!(state.is_assist_abandoned_at(&key, old + chrono::Duration::seconds(1)));
        // Past the TTL: re-dispatch allowed.
        assert!(!state.is_assist_abandoned_at(
            &key,
            old + chrono::Duration::seconds(ASSIST_ABANDONED_TTL_SECS + 2),
        ));
        // And the production helper, which uses `Utc::now()`, also reports false
        // because `old` was placed past the TTL.
        assert!(!state.is_assist_abandoned(&key));
    }

    #[test]
    fn assist_abandoned_remark_extends_window() {
        // A repeat RequestAssistance after the TTL elapses should re-arm
        // the block (orchestrator marks again on every failure).
        let mut state = StateInner::new("op-1".into());
        let key = "k".to_string();
        let old = Utc::now() - chrono::Duration::seconds(ASSIST_ABANDONED_TTL_SECS + 100);
        state.mark_assist_abandoned_at(key.clone(), old);
        assert!(!state.is_assist_abandoned(&key));
        state.mark_assist_abandoned(key.clone());
        assert!(state.is_assist_abandoned(&key));
    }

    #[test]
    fn assist_abandoned_keys_independent() {
        let mut state = StateInner::new("op-1".into());
        state.mark_assist_abandoned("pattern_a".into());
        assert!(state.is_assist_abandoned("pattern_a"));
        assert!(!state.is_assist_abandoned("pattern_b"));
    }

    #[test]
    fn credential_capture_in_flight_initially_empty() {
        let state = StateInner::new("op-1".into());
        assert!(!state.credential_capture_in_flight_for("contoso.local"));
    }

    #[test]
    fn credential_capture_in_flight_after_mark() {
        let mut state = StateInner::new("op-1".into());
        state.mark_credential_capture_in_flight("Contoso.Local");
        // Stored lowercased; lookup is case-insensitive.
        assert!(state.credential_capture_in_flight_for("contoso.local"));
        assert!(state.credential_capture_in_flight_for("CONTOSO.LOCAL"));
        // Unrelated domain stays clear.
        assert!(!state.credential_capture_in_flight_for("fabrikam.local"));
    }

    #[test]
    fn credential_capture_in_flight_expires_after_ttl() {
        let mut state = StateInner::new("op-1".into());
        // Backdate the marker past the TTL by writing directly.
        state.credential_capture_in_flight.insert(
            "contoso.local".to_string(),
            Utc::now() - chrono::Duration::seconds(CAPTURE_IN_FLIGHT_TTL_SECS + 1),
        );
        assert!(!state.credential_capture_in_flight_for("contoso.local"));
    }

    #[test]
    fn credential_capture_in_flight_empty_domain_noop() {
        let mut state = StateInner::new("op-1".into());
        state.mark_credential_capture_in_flight("");
        assert!(state.credential_capture_in_flight.is_empty());
    }

    #[test]
    fn dedup_sets_are_independent() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_CRACK_REQUESTS, "hash1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());

        assert!(state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "192.168.58.10"));
        assert!(state.is_processed(DEDUP_SECRETSDUMP, "192.168.58.10"));
        assert!(!state.is_processed(DEDUP_SECRETSDUMP, "hash1"));
    }

    #[test]
    fn exploited_vulnerabilities_tracking() {
        let mut state = StateInner::new("op-1".into());
        assert!(state.exploited_vulnerabilities.is_empty());

        state
            .exploited_vulnerabilities
            .insert("vuln-001".to_string());
        assert!(state.exploited_vulnerabilities.contains("vuln-001"));
        assert!(!state.exploited_vulnerabilities.contains("vuln-002"));
    }

    #[test]
    fn mssql_enum_dispatched_tracking() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.mssql_enum_dispatched.contains("192.168.58.20"));

        state
            .mssql_enum_dispatched
            .insert("192.168.58.20".to_string());
        assert!(state.mssql_enum_dispatched.contains("192.168.58.20"));
    }

    #[test]
    fn domain_controller_map() {
        let mut state = StateInner::new("op-1".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());

        assert_eq!(
            state.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.10".to_string())
        );
        assert_eq!(
            state.domain_controllers.get("fabrikam.local"),
            Some(&"192.168.58.20".to_string())
        );
        assert_eq!(state.domain_controllers.get("unknown.local"), None);
    }

    #[test]
    fn all_known_dedup_set_constants() {
        // Verify constants are accessible and match expected names
        let expected = vec![
            DEDUP_CRACK_REQUESTS,
            DEDUP_SECRETSDUMP,
            DEDUP_DELEGATION_CREDS,
            DEDUP_ADCS_SERVERS,
            DEDUP_BLOODHOUND_DOMAINS,
            DEDUP_SPIDERED_SHARES,
            DEDUP_EXPANSION_CREDS,
            DEDUP_ASREP_DOMAINS,
            DEDUP_USERNAME_SPRAY,
            DEDUP_PASSWORD_SPRAY,
            DEDUP_ESC8_SERVERS,
            DEDUP_COERCED_DCS,
            DEDUP_WRITABLE_SHARES,
            DEDUP_HASH_LATERAL,
            DEDUP_SCANNED_TARGETS,
            DEDUP_ACL_STEPS,
            DEDUP_TRUST_FOLLOW,
            DEDUP_S4U_EXPLOITS,
            DEDUP_GMSA_ACCOUNTS,
            DEDUP_LOW_HANGING,
            DEDUP_CRED_SECRETSDUMP,
            DEDUP_SHARE_ENUM,
            DEDUP_ADCS_EXPLOIT,
            DEDUP_GPO_ABUSE,
            DEDUP_LAPS,
            DEDUP_NTLM_RELAY,
            DEDUP_NOPAC,
            DEDUP_ZEROLOGON,
            DEDUP_PRINTNIGHTMARE,
            DEDUP_MSSQL_COERCION,
            DEDUP_PASSWORD_POLICY,
            DEDUP_GPP_SYSVOL,
            DEDUP_NTLMV1_DOWNGRADE,
            DEDUP_LDAP_SIGNING,
            DEDUP_WEBDAV_DETECTION,
            DEDUP_SPOOLER_CHECK,
            DEDUP_MACHINE_ACCOUNT_QUOTA,
            DEDUP_DFS_COERCION,
            DEDUP_PETITPOTAM_UNAUTH,
            DEDUP_WINRM_LATERAL,
            DEDUP_GROUP_ENUMERATION,
            DEDUP_KRBRELAYUP,
            DEDUP_SEARCHCONNECTOR,
            DEDUP_LSASSY_DUMP,
            DEDUP_RDP_LATERAL,
            DEDUP_FOREIGN_GROUP_ENUM,
            DEDUP_CERTIPY_AUTH,
            DEDUP_SID_ENUMERATION,
            DEDUP_DNS_ENUM,
            DEDUP_DOMAIN_USER_ENUM,
            DEDUP_PTH_SPRAY,
            DEDUP_CERTIFRIED,
            DEDUP_DACL_ABUSE,
            DEDUP_SMBCLIENT_ENUM,
            DEDUP_ACL_DISCOVERY,
            DEDUP_CROSS_FOREST_ENUM,
            DEDUP_CROSS_REALM_LATERAL,
            DEDUP_GOLDEN_CERT,
            DEDUP_MSSQL_RETRY,
            DEDUP_MSSQL_LINK_PIVOT,
            DEDUP_MSSQL_IMPERSONATION,
            DEDUP_MSSQL_FAR_HOST_DUMP,
            DEDUP_SID_HISTORY,
            DEDUP_STALL_COLD_START,
        ];
        assert_eq!(expected.len(), ALL_DEDUP_SETS.len());
        for name in expected {
            assert!(
                ALL_DEDUP_SETS.contains(&name),
                "Missing from ALL_DEDUP_SETS: {name}"
            );
        }
    }

    #[test]
    fn checks_delegation_account() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.is_delegation_account("john.smith"));

        // Add a constrained delegation vuln for john.smith
        let mut details = std::collections::HashMap::new();
        details.insert("account_name".to_string(), serde_json::json!("john.smith"));
        state.discovered_vulnerabilities.insert(
            "constrained_delegation_john.smith".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "constrained_delegation_john.smith".into(),
                vuln_type: "constrained_delegation".into(),
                target: "".into(),
                discovered_by: "".into(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: "".into(),
                priority: 8,
            },
        );

        assert!(state.is_delegation_account("john.smith"));
        assert!(state.is_delegation_account("John.Smith")); // case insensitive
        assert!(!state.is_delegation_account("sam.wilson"));
    }

    #[test]
    fn credential_quarantine() {
        let mut state = StateInner::new("op-1".into());

        // Not quarantined initially
        assert!(!state.is_principal_quarantined("jdoe", "child.contoso.local"));

        // Quarantine a credential
        state.quarantine_principal("jdoe", "child.contoso.local");
        assert!(state.is_principal_quarantined("jdoe", "child.contoso.local"));
        assert!(state.is_principal_quarantined("JDOE", "CHILD.CONTOSO.LOCAL")); // case insensitive

        // Different credential not affected
        assert!(!state.is_principal_quarantined("john.smith", "child.contoso.local"));
    }

    #[test]
    fn all_forests_dominated_no_forests() {
        let state = StateInner::new("op-1".into());
        // No domains, no DCs, no trusts → vacuously true
        assert!(state.all_forests_dominated());
    }

    #[test]
    fn all_forests_dominated_single_forest() {
        let mut state = StateInner::new("op-1".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Not dominated yet
        assert!(!state.all_forests_dominated());

        // Dominate it
        state.dominated_domains.insert("contoso.local".into());
        assert!(state.all_forests_dominated());
    }

    #[test]
    fn all_forests_dominated_multi_forest() {
        let mut state = StateInner::new("op-1".into());
        state
            .domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.23".into());

        // Dominate only the contoso forest
        state.dominated_domains.insert("child.contoso.local".into());
        state.dominated_domains.insert("contoso.local".into());

        // fabrikam.local is still undominated
        assert!(!state.all_forests_dominated());

        // Dominate fabrikam too
        state.dominated_domains.insert("fabrikam.local".into());
        assert!(state.all_forests_dominated());
    }

    #[test]
    fn is_domain_dominated_exact_and_netbios_only() {
        let mut state = StateInner::new("op-1".into());
        state
            .netbios_to_fqdn
            .insert("child".into(), "child.contoso.local".into());
        state.dominated_domains.insert("child.contoso.local".into());

        assert!(state.is_domain_dominated("child.contoso.local"));
        assert!(state.is_domain_dominated("CHILD"));
        assert!(!state.is_domain_dominated("contoso.local"));
        assert!(!state.is_domain_dominated(""));
    }

    #[test]
    fn user_quarantine_basic() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.is_principal_quarantined("testuser1", "contoso.local"));

        state.quarantine_principal("testuser1", "contoso.local");
        assert!(state.is_principal_quarantined("testuser1", "contoso.local"));
        assert!(state.is_principal_quarantined("TESTUSER1", "CONTOSO.LOCAL")); // case insensitive

        // Different user not affected
        assert!(!state.is_principal_quarantined("testuser2", "contoso.local"));
        // Same user, different domain not affected
        assert!(!state.is_principal_quarantined("testuser1", "fabrikam.local"));
    }

    #[test]
    fn spray_attempts_accumulate_within_the_window() {
        let mut state = StateInner::new("op-1".into());
        assert_eq!(state.spray_attempts_used("essos.local"), 0);

        state.record_spray_attempts("essos.local", 3, 300);
        assert_eq!(state.spray_attempts_used("essos.local"), 3);

        state.record_spray_attempts("essos.local", 2, 300);
        assert_eq!(
            state.spray_attempts_used("essos.local"),
            5,
            "a second spray in the same window must add to the tally, not replace it"
        );
    }

    #[test]
    fn spray_attempts_are_scoped_per_domain_and_case_insensitive() {
        let mut state = StateInner::new("op-1".into());
        state.record_spray_attempts("ESSOS.local", 4, 300);
        assert_eq!(state.spray_attempts_used("essos.LOCAL"), 4);
        assert_eq!(state.spray_attempts_used("north.sevenkingdoms.local"), 0);
    }

    #[test]
    fn spray_attempts_lapse_with_the_observation_window() {
        let mut state = StateInner::new("op-1".into());
        // A window that has already closed — AD has reset badPwdCount, so the
        // budget is whole again.
        state.spray_attempts.insert(
            "essos.local".into(),
            (4, Utc::now() - chrono::Duration::seconds(1)),
        );
        assert_eq!(state.spray_attempts_used("essos.local"), 0);

        // ...and a fresh debit starts the count over rather than carrying the
        // lapsed 4 forward.
        state.record_spray_attempts("essos.local", 2, 300);
        assert_eq!(state.spray_attempts_used("essos.local"), 2);
    }

    #[test]
    fn spray_attempts_ignores_a_zero_cost_call() {
        let mut state = StateInner::new("op-1".into());
        state.record_spray_attempts("essos.local", 0, 300);
        assert!(state.spray_attempts.is_empty());
    }

    #[test]
    fn repeated_sprays_never_exceed_the_lockout_threshold() {
        // The essos regression, end to end. Policy is threshold 5 / 5-min
        // observation window. Before the tally existed, every call re-reported
        // attempts_used_per_account=0, so each one spent its full per-call cap
        // and the second spray locked every account in the domain.
        let mut state = StateInner::new("op-1".into());
        let args = serde_json::json!({
            "domain": "essos.local",
            "lockout_threshold": 5,
            "use_common_passwords": true,
        });

        let mut spent = 0i64;
        for _ in 0..5 {
            let used = state.spray_attempts_used("essos.local");
            let cost = ares_tools::credential_access::spray_attempt_cost(&args, used) as i64;
            state.record_spray_attempts("essos.local", cost, 300);
            spent += cost;
        }

        assert_eq!(
            spent, 4,
            "five sprays in one window must spend the budget once (threshold 5 \
             minus the 1-attempt safety buffer), then refuse"
        );
        assert!(spent < 5, "must stay under the lockout threshold");
    }

    #[test]
    fn repeated_blind_start_sprays_never_exceed_the_lockout_threshold() {
        // op-20260727-230409, reproduced. A blind start has no credential, so
        // `password_policy` never runs and the agent falls back to
        // `acknowledge_no_policy=true` — the DEFAULT path under testes.sh, and
        // the one the first fix left unguarded. Eight sprays each took a fresh
        // 2-password allowance and locked sql_svc and Administrator twice in
        // twelve minutes against a threshold of 5.
        let mut state = StateInner::new("op-1".into());
        let args = serde_json::json!({
            "domain": "essos.local",
            "use_common_passwords": true,
            "acknowledge_no_policy": true,
        });

        let mut spent = 0i64;
        for _ in 0..8 {
            let used = state.spray_attempts_used("essos.local");
            let cost = ares_tools::credential_access::spray_attempt_cost(&args, used) as i64;
            state.record_spray_attempts("essos.local", cost, 300);
            spent += cost;
        }

        assert_eq!(
            spent, 2,
            "the no-policy allowance is a per-window total: the first spray \
             spends it and the rest must refuse (pre-fix this was 16)"
        );
        assert!(
            spent < 5,
            "must stay under a default 5-attempt AD lockout threshold"
        );
    }

    #[test]
    fn quarantined_principals_in_domain_filters() {
        let mut state = StateInner::new("op-1".into());
        state.quarantine_principal("testuser1", "contoso.local");
        state.quarantine_principal("testuser2", "contoso.local");
        state.quarantine_principal("testuser3", "fabrikam.local");

        let mut contoso = state.quarantined_principals_in_domain("contoso.local");
        contoso.sort();
        assert_eq!(
            contoso,
            vec!["testuser1".to_string(), "testuser2".to_string()]
        );

        let fabrikam = state.quarantined_principals_in_domain("fabrikam.local");
        assert_eq!(fabrikam, vec!["testuser3".to_string()]);

        let unknown = state.quarantined_principals_in_domain("unknown.local");
        assert!(unknown.is_empty());
    }

    #[test]
    fn quarantined_principals_in_domain_skips_expired() {
        let mut state = StateInner::new("op-1".into());
        state.quarantined_principals.insert(
            "expired@contoso.local".into(),
            Utc::now() - chrono::Duration::seconds(1),
        );
        state.quarantine_principal("fresh", "contoso.local");

        let users = state.quarantined_principals_in_domain("contoso.local");
        assert_eq!(users, vec!["fresh".to_string()]);
    }

    #[test]
    fn credential_quarantine_expired() {
        let mut state = StateInner::new("op-1".into());

        // Insert with an already-expired time
        let key = "jdoe@child.contoso.local".to_string();
        state
            .quarantined_principals
            .insert(key, Utc::now() - chrono::Duration::seconds(1));

        // Should not be quarantined (expired)
        assert!(!state.is_principal_quarantined("jdoe", "child.contoso.local"));
    }

    // --- push_hash_capped ---------------------------------------------------

    fn make_test_hash(username: &str, hash_value: &str) -> Hash {
        Hash {
            id: format!("h-{username}-{hash_value}"),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "test".to_string(),
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

    #[test]
    fn push_hash_capped_under_cap_just_appends() {
        let mut state = StateInner::new("op-1".into());
        for i in 0..10 {
            state.push_hash_capped(make_test_hash(&format!("user{i}"), &format!("{i:032x}")));
        }
        assert_eq!(state.hashes.len(), 10);
    }

    #[test]
    fn push_hash_capped_evicts_oldest_low_value_at_cap() {
        let mut state = StateInner::new("op-1".into());
        // Fill to cap with uncracked, non-krbtgt, non-trust-key, no-AES entries.
        for i in 0..MAX_HASHES {
            state.push_hash_capped(make_test_hash(&format!("user{i}"), &format!("{i:032x}")));
        }
        assert_eq!(state.hashes.len(), MAX_HASHES);
        let first_before = state.hashes[0].username.clone();
        // Push one more — oldest low-value entry (index 0) should be evicted.
        state.push_hash_capped(make_test_hash("newcomer", "deadbeef"));
        assert_eq!(state.hashes.len(), MAX_HASHES);
        assert_ne!(state.hashes[0].username, first_before);
        assert_eq!(state.hashes.last().unwrap().username, "newcomer");
    }

    #[test]
    fn push_hash_capped_never_evicts_krbtgt() {
        let mut state = StateInner::new("op-1".into());
        // krbtgt at index 0, then fill with low-value entries.
        let mut krb = make_test_hash("krbtgt", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        krb.hash_type = "NTLM".into();
        state.push_hash_capped(krb);
        for i in 0..MAX_HASHES {
            state.push_hash_capped(make_test_hash(&format!("user{i}"), &format!("{i:032x}")));
        }
        // krbtgt must still be present.
        assert!(state
            .hashes
            .iter()
            .any(|h| h.username.eq_ignore_ascii_case("krbtgt")));
        assert_eq!(state.hashes.len(), MAX_HASHES);
    }

    #[test]
    fn push_hash_capped_never_evicts_cracked() {
        let mut state = StateInner::new("op-1".into());
        let mut cracked = make_test_hash("victim", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        cracked.cracked_password = Some("P@ssw0rd!".into());
        state.push_hash_capped(cracked);
        for i in 0..MAX_HASHES {
            state.push_hash_capped(make_test_hash(&format!("user{i}"), &format!("{i:032x}")));
        }
        assert!(state
            .hashes
            .iter()
            .any(|h| h.username == "victim" && h.cracked_password.is_some()));
    }

    #[test]
    fn push_hash_capped_never_evicts_trust_key_or_aes() {
        let mut state = StateInner::new("op-1".into());
        let mut trust = make_test_hash("CONTOSO$", "cccccccccccccccccccccccccccccccc");
        trust.is_trust_key = true;
        state.push_hash_capped(trust);
        let mut aes = make_test_hash("svc_aes", "dddddddddddddddddddddddddddddddd");
        aes.aes_key = Some("a".repeat(64));
        state.push_hash_capped(aes);
        for i in 0..MAX_HASHES {
            state.push_hash_capped(make_test_hash(&format!("user{i}"), &format!("{i:032x}")));
        }
        assert!(state.hashes.iter().any(|h| h.is_trust_key));
        assert!(state.hashes.iter().any(|h| h.aes_key.is_some()));
    }

    #[test]
    fn push_hash_capped_all_high_value_overflows() {
        let mut state = StateInner::new("op-1".into());
        // Fill entirely with cracked entries (all high-value).
        for i in 0..MAX_HASHES {
            let mut h = make_test_hash(&format!("user{i}"), &format!("{i:032x}"));
            h.cracked_password = Some("pw".into());
            state.push_hash_capped(h);
        }
        // Add one more — cap is soft, all entries are protected, so we overflow.
        let mut extra = make_test_hash("extra", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        extra.cracked_password = Some("pw".into());
        state.push_hash_capped(extra);
        assert_eq!(state.hashes.len(), MAX_HASHES + 1);
    }

    fn make_dc_host(ip: &str, hostname: &str) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: vec!["domain_controller".to_string()],
            services: vec![],
            is_dc: true,
            owned: false,
        }
    }

    #[test]
    fn resolve_dc_ip_zone_apex_does_not_transpose_parent_and_child() {
        let mut state = StateInner::new("op-1".into());
        state.domains.push("contoso.local".into());
        state.domains.push("north.contoso.local".into());
        state
            .hosts
            .push(make_dc_host("192.168.58.240", "north.contoso.local"));
        state
            .hosts
            .push(make_dc_host("192.168.58.243", "contoso.local"));

        assert_eq!(
            state.resolve_dc_ip("contoso.local"),
            Some("192.168.58.243".to_string()),
            "parent domain must resolve to the parent DC, not the child"
        );
        assert_eq!(
            state.resolve_dc_ip("north.contoso.local"),
            Some("192.168.58.240".to_string()),
            "child domain must resolve to the child DC"
        );
    }

    #[test]
    fn resolve_dc_ip_normal_fqdn_still_strips_machine_label() {
        let mut state = StateInner::new("op-1".into());
        state.domains.push("contoso.local".into());
        state
            .hosts
            .push(make_dc_host("192.168.58.10", "dc01.contoso.local"));

        assert_eq!(
            state.resolve_dc_ip("contoso.local"),
            Some("192.168.58.10".to_string())
        );
    }
}
