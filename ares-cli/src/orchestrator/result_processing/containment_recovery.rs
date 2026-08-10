//! Classify red-tool failures that suggest blue has taken a containment
//! action (account disabled, host firewalled, krbtgt rotated, certificate
//! revoked). Each signal maps 1:1 to a `SharedState::publish_*` method on
//! the containment publisher; the driver in `process_completed_task`
//! iterates the returned list and dispatches.
//!
//! The classifier is intentionally conservative: it only fires on
//! well-known error strings and only when there's enough context on the
//! task to make the observation actionable (a `cred_key` for revocation,
//! a `task_target_ip` for isolation, a Kerberos-hitting technique for
//! krbtgt rotation, a certificate-based technique for cert revocation).
//!
//! False positives are cheaper than false negatives for the host, realm and
//! certificate signals because
//! [`SharedState::publish_credential_revoked`] / `_host_isolated` /
//! `_krbtgt_rotated` / `_certificate_revoked` are idempotent per identity
//! key — a duplicate emit is a no-op — and the downstream queue filter
//! treats an observation as advisory (skip the affected work-item, don't
//! crash the op). Under-firing means the demo never adapts to blue.
//!
//! Credential revocation is the exception: it hides the credential from the
//! LLM for the rest of the operation with no operator rollback, so a false
//! positive costs red an access it still holds. The weak-marker path is
//! therefore gated to reject-strings whose provenance actually implicates
//! the principal — see `is_attributable_reject_technique` and
//! `reject_is_same_realm`.

use serde_json::Value;

use super::collect_result_text_parts;

/// A single containment observation extracted from a task result.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ContainmentSignal {
    CredentialRevoked {
        username: String,
        domain: String,
        source: String,
    },
    HostIsolated {
        ip: String,
        hostname: String,
        source: String,
    },
    KrbtgtRotated {
        domain: String,
        source: String,
    },
    CertificateRevoked {
        serial: String,
        ca: String,
        source: String,
    },
}

/// Case-insensitive substring match against any tool-output text on the
/// result payload.
fn any_text_contains(result: &Option<Value>, needle: &str) -> bool {
    let Some(payload) = result else {
        return false;
    };
    let needle_lower = needle.to_lowercase();
    collect_result_text_parts(payload)
        .iter()
        .any(|t| t.to_lowercase().contains(&needle_lower))
}

/// True when any tool-output text contains at least one of `needles`.
fn any_text_contains_any(result: &Option<Value>, needles: &[&str]) -> bool {
    needles.iter().any(|n| any_text_contains(result, n))
}

/// Techniques that authenticate with a certificate. On
/// `KDC_ERR_CLIENT_REVOKED` inside one of these, the classifier attributes
/// the failure to certificate revocation rather than account disablement.
fn is_certificate_backed_technique(technique: &str) -> bool {
    let t = technique.to_lowercase();
    matches!(
        t.as_str(),
        "certipy_auth" | "certipy_req" | "certipy_shadow" | "pkinit"
    ) || t.contains("certipy")
        || t.contains("esc1")
        || t.contains("esc4")
        || t.contains("esc8")
        || t.contains("adcs")
        || t.contains("pkinit")
}

/// Tools that talk to a specific host over SMB / WinRM / LDAP / WMI. If
/// they hit network-unreachable errors, the target is a plausible
/// candidate for `HostIsolated`. Filters out HTTP recon and general
/// scanning where unreachable can mean "closed port on a live host".
fn is_host_pivot_technique(technique: &str) -> bool {
    let t = technique.to_lowercase();
    t.contains("smb")
        || t.contains("winrm")
        || t.contains("ldap")
        || t.contains("wmi")
        || t.contains("nxc")
        || t.contains("netexec")
        || t.contains("secretsdump")
        || t.contains("dcsync")
        || t.contains("psexec")
        || t.contains("evil_winrm")
}

/// Well-known network-unreachable substrings that show up in the various
/// Python / Rust tool stacks red currently drives.
const NETWORK_UNREACHABLE_MARKERS: &[&str] = &[
    "STATUS_HOST_UNREACHABLE",
    "STATUS_NETWORK_UNREACHABLE",
    "STATUS_IO_TIMEOUT",
    "No route to host",
    "Network is unreachable",
    "Connection timed out",
    "connect: timed out",
    "Errno 110",
    "Errno 113",
    "ETIMEDOUT",
];

/// Well-known "credential rejected" substrings that indicate the *acting*
/// credential was refused. `KDC_ERR_C_PRINCIPAL_UNKNOWN` is deliberately NOT
/// here: it means the KDC couldn't find the *queried* principal (a missing SPN
/// or a non-existent user), which is a routine side-effect of kerberoast/AS-REP
/// SPN enumeration — not evidence the acting account was disabled. Treating it
/// as a revocation string revoked the op's own principal on benign recon.
const CREDENTIAL_REJECT_MARKERS: &[&str] = &[
    "STATUS_LOGON_FAILURE",
    "INVALID_CREDENTIALS",
    "invalidCredentials",
    "The user name or password is incorrect",
];

/// The KDC's explicit "this client principal is revoked" (account disabled,
/// locked, or expired) status. Unlike the generic reject strings this is
/// unambiguous — no benign enumeration path produces it — so a single
/// observation under a password-backed technique is trusted immediately.
pub(crate) const KDC_CLIENT_REVOKED_MARKER: &str = "KDC_ERR_CLIENT_REVOKED";

/// Minimum number of weak credential-reject observations for the same principal
/// before the driver believes blue revoked it. A lone `STATUS_LOGON_FAILURE` is
/// far more often a stale hash or an LLM password guess than an account disable;
/// requiring corroboration keeps benign auth noise from starving the LLM's view
/// of a still-valid credential. The unambiguous [`KDC_CLIENT_REVOKED_MARKER`]
/// bypasses this and revokes on first sight.
pub(crate) const CREDENTIAL_REVOKE_MIN_OBSERVATIONS: u32 = 2;

/// Minimum number of `KRB_AP_ERR_MODIFIED` observations for the same realm
/// before the driver believes that realm's krbtgt actually rotated.
///
/// A rotation observation is realm-wide, not work-item-wide: it skips *every*
/// Kerberos-shaped `credential_access` task in the realm for the rest of the
/// operation. One flaky ticket exchange therefore costs red the realm's entire
/// roasting surface, which is how an operation loses a domain it can otherwise
/// reach. Corroboration keeps a single mismatch from spending that much.
pub(crate) const KRBTGT_ROTATION_MIN_OBSERVATIONS: u32 = 2;

/// Whether a `KRB_AP_ERR_MODIFIED` under this technique says anything about the
/// realm's krbtgt.
///
/// It usually does not. The KDC returns it whenever a ticket cannot be
/// decrypted by the service it was presented to, so red produces it itself in
/// two routine ways. Certificate-backed enrollment is the load-bearing case:
/// `certipy auth` PKINIT intermittently fails the AS exchange with this exact
/// string (~50% per attempt on some AES-only KDCs — see the retry loop in
/// `ares_tools::privesc::adcs`), so an ESC chain that ultimately *succeeds*
/// still leaves the marker in its output. Forging with a stale or wrong trust
/// key is the other: an inter-realm TGT that the target KDC cannot decrypt is
/// indistinguishable, on this string alone, from one whose key was rotated.
///
/// Unknown provenance fails closed, matching
/// [`is_attributable_reject_technique`]: no technique, no inference.
fn is_attributable_key_mismatch_technique(technique: &str) -> bool {
    let t = technique.to_lowercase();
    !t.trim().is_empty()
        && !is_certificate_backed_technique(&t)
        && !t.contains("ticketer")
        && !t.contains("trust")
        && !t.contains("forge")
        && !t.contains("inter_realm")
        && !t.contains("interrealm")
}

/// Techniques that emit credential-reject strings as a normal part of their
/// operation rather than as evidence the acting account was disabled.
/// `password_spray` logs `STATUS_LOGON_FAILURE` on every wrong guess by design,
/// and brute-force variants do the same. A rejection under one of these is
/// noise, so the weak-marker path never revokes for them.
fn is_benign_reject_technique(technique: &str) -> bool {
    let t = technique.to_lowercase();
    t.contains("spray") || t.contains("brute")
}

/// Whether the technique behind a weak credential-reject is known well enough
/// to attribute the rejection to the acting principal.
///
/// An unnamed technique cannot clear [`is_benign_reject_technique`] — the empty
/// string contains neither `spray` nor `brute` — so an unpopulated `technique`
/// param used to sail through the benign-technique exemption and let ordinary
/// spray misses revoke a working credential. Unknown provenance now fails
/// closed: no technique, no inference.
fn is_attributable_reject_technique(technique: &str) -> bool {
    !technique.trim().is_empty() && !is_benign_reject_technique(technique)
}

/// Whether a credential-reject observed on this task can be blamed on the
/// credential rather than on the realm boundary it was fired across.
///
/// Recon fans authenticated enumeration across every discovered host with
/// whatever principal it holds, so a credential from one realm routinely gets
/// pointed at hosts in another. The rejection that comes back is the expected
/// answer for a foreign principal, not evidence the account died in its own
/// realm. Only a same-realm rejection carries that meaning.
///
/// Returns `true` when the target realm is unknown: absence of a realm is not
/// evidence of a mismatch, and [`is_attributable_reject_technique`] still has
/// to pass before anything is inferred.
fn reject_is_same_realm(cred_key: &str, task_domain: Option<&str>) -> bool {
    let Some(target) = task_domain.map(str::trim).filter(|d| !d.is_empty()) else {
        return true;
    };
    cred_key
        .split_once('@')
        .is_none_or(|(_, cred_domain)| cred_domain.trim().eq_ignore_ascii_case(target))
}

/// Inspect a completed task and return any containment signals it surfaces.
///
/// - `cred_key`: `user@domain` for the credential the task was dispatched
///   with (already extracted by the caller from `pending_tasks`).
/// - `task_domain`: realm the task was targeting, if known.
/// - `task_target_ip`: canonical target address the task was pointed at.
///
/// Empty result = no signals; the caller should still run its existing
/// lockout / retry logic.
pub(crate) fn classify_containment_signals(
    result: &Option<Value>,
    technique: Option<&str>,
    cred_key: Option<&str>,
    task_domain: Option<&str>,
    task_target_ip: Option<&str>,
) -> Vec<ContainmentSignal> {
    let mut signals = Vec::new();
    let tech = technique.unwrap_or("");

    // 1. KDC_ERR_CLIENT_REVOKED under a cert-backed technique → certificate revoked.
    //    Under a password-backed technique → treat as credential revoked.
    let client_revoked = any_text_contains(result, "KDC_ERR_CLIENT_REVOKED");

    if client_revoked && is_certificate_backed_technique(tech) {
        signals.push(ContainmentSignal::CertificateRevoked {
            serial: String::new(), // Extraction from the raw PKINIT reject line is deferred.
            ca: String::new(),
            source: format!("KDC_ERR_CLIENT_REVOKED via {tech}"),
        });
    }

    // 2. STATUS_LOGON_FAILURE / INVALID_CREDENTIALS on a task using a stored cred
    //    → credential revoked. Only fires when we know which principal was used
    //    (cred_key set) — otherwise we don't have a target for the observation.
    //
    //    Two paths with different confidence. `strong_revoked` is the KDC
    //    explicitly declaring the client principal revoked under a
    //    password-backed technique — unambiguous, published on first sight,
    //    and true about the principal regardless of what it was aimed at.
    //    `weak_revoked` is a generic auth-reject string, which only means the
    //    account died when the technique is known and auth-*using*
    //    (`is_attributable_reject_technique`) and the target sits in the
    //    credential's own realm (`reject_is_same_realm`). The caller then
    //    additionally requires corroboration (see
    //    CREDENTIAL_REVOKE_MIN_OBSERVATIONS) before acting.
    if let Some(key) = cred_key {
        let strong_revoked = client_revoked && !is_certificate_backed_technique(tech);
        let weak_revoked = is_attributable_reject_technique(tech)
            && reject_is_same_realm(key, task_domain)
            && any_text_contains_any(result, CREDENTIAL_REJECT_MARKERS);
        if strong_revoked || weak_revoked {
            if let Some((username, domain)) = key.split_once('@') {
                let marker =
                    credential_reject_marker_text(result).unwrap_or("STATUS_LOGON_FAILURE");
                signals.push(ContainmentSignal::CredentialRevoked {
                    username: username.to_string(),
                    domain: domain.to_string(),
                    source: format!("{marker} via {tech}"),
                });
            }
        }
    }

    // 3. KRB_AP_ERR_MODIFIED → krbtgt possibly rotated. Fires on the realm the
    //    task was targeting, or on the cred's realm when task_domain is empty.
    //
    //    Gated the same way the weak credential-reject path is, and for the same
    //    reason: the marker is only evidence when red did not manufacture it.
    //    `is_attributable_key_mismatch_technique` drops the self-inflicted
    //    sources, `reject_is_same_realm` drops tickets fired across a realm
    //    boundary (where a mismatch is the expected answer, not a rotation), and
    //    the caller requires KRBTGT_ROTATION_MIN_OBSERVATIONS corroboration
    //    before acting.
    if any_text_contains(result, "KRB_AP_ERR_MODIFIED")
        && is_attributable_key_mismatch_technique(tech)
        && cred_key.is_none_or(|k| reject_is_same_realm(k, task_domain))
    {
        let realm = task_domain
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .or_else(|| {
                cred_key
                    .and_then(|k| k.split_once('@'))
                    .map(|(_, d)| d.to_string())
            })
            .unwrap_or_default();
        if !realm.is_empty() {
            signals.push(ContainmentSignal::KrbtgtRotated {
                domain: realm,
                source: format!("KRB_AP_ERR_MODIFIED via {tech}"),
            });
        }
    }

    // 4. Network unreachable + host-pivot technique + known target IP → host isolated.
    if let Some(ip) = task_target_ip {
        if is_host_pivot_technique(tech)
            && any_text_contains_any(result, NETWORK_UNREACHABLE_MARKERS)
        {
            let marker = network_unreachable_marker_text(result).unwrap_or("network unreachable");
            signals.push(ContainmentSignal::HostIsolated {
                ip: ip.to_string(),
                hostname: String::new(),
                source: format!("{marker} via {tech}"),
            });
        }
    }

    signals
}

fn credential_reject_marker_text(result: &Option<Value>) -> Option<&'static str> {
    for m in CREDENTIAL_REJECT_MARKERS {
        if any_text_contains(result, m) {
            return Some(*m);
        }
    }
    if any_text_contains(result, KDC_CLIENT_REVOKED_MARKER) {
        return Some(KDC_CLIENT_REVOKED_MARKER);
    }
    None
}

fn network_unreachable_marker_text(result: &Option<Value>) -> Option<&'static str> {
    for m in NETWORK_UNREACHABLE_MARKERS {
        if any_text_contains(result, m) {
            return Some(*m);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn out(text: &str) -> Option<Value> {
        Some(json!({ "tool_outputs": [text] }))
    }

    #[test]
    fn credential_revoked_on_status_logon_failure_with_cred_key() {
        let result = out("[-] contoso.local\\svc_mssql:P@ss STATUS_LOGON_FAILURE");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("svc_mssql@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s.iter().any(
            |sig| matches!(sig, ContainmentSignal::CredentialRevoked { username, domain, .. }
                if username == "svc_mssql" && domain == "contoso.local")
        ));
    }

    #[test]
    fn credential_revoked_needs_cred_key() {
        let result = out("STATUS_LOGON_FAILURE somewhere");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            None, // no cred_key => can't attribute
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
    }

    #[test]
    fn certificate_revoked_on_kdc_client_revoked_under_certipy() {
        let result = out("KDC_ERR_CLIENT_REVOKED");
        let s = classify_containment_signals(
            &result,
            Some("certipy_auth"),
            None,
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CertificateRevoked { .. })));
    }

    #[test]
    fn kdc_client_revoked_under_password_flow_is_credential_revoked() {
        let result = out("KDC_ERR_CLIENT_REVOKED on the wire");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CertificateRevoked { .. })));
    }

    #[test]
    fn password_spray_logon_failure_does_not_revoke() {
        // password_spray emits STATUS_LOGON_FAILURE on every wrong guess by
        // design; the acting principal is fine. A benign technique must never
        // produce a revocation signal even with a cred_key set.
        let result = out("contoso.local\\alice:P@ssw0rd! STATUS_LOGON_FAILURE");
        let s = classify_containment_signals(
            &result,
            Some("password_spray"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
    }

    #[test]
    fn cross_realm_logon_failure_does_not_revoke() {
        let result = out("[-] contoso.local\\alice:P@ssw0rd! STATUS_LOGON_FAILURE");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("alice@contoso.local"),
            Some("fabrikam.local"),
            Some("192.168.58.20"),
        );
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
    }

    #[test]
    fn child_realm_logon_failure_does_not_revoke_parent_credential() {
        let result = out("STATUS_LOGON_FAILURE");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("alice@child.contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.240"),
        );
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
    }

    #[test]
    fn unknown_technique_logon_failure_does_not_revoke() {
        for tech in [None, Some(""), Some("   ")] {
            let s = classify_containment_signals(
                &out("STATUS_LOGON_FAILURE"),
                tech,
                Some("alice@contoso.local"),
                Some("contoso.local"),
                Some("192.168.58.10"),
            );
            assert!(
                !s.iter()
                    .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })),
                "technique {tech:?} must not produce a weak revocation"
            );
        }
    }

    #[test]
    fn kdc_client_revoked_survives_both_new_gates() {
        let s = classify_containment_signals(
            &out("KDC_ERR_CLIENT_REVOKED"),
            None,
            Some("alice@contoso.local"),
            Some("fabrikam.local"),
            Some("192.168.58.20"),
        );
        assert!(s.iter().any(
            |sig| matches!(sig, ContainmentSignal::CredentialRevoked { username, domain, .. }
                if username == "alice" && domain == "contoso.local")
        ));
    }

    #[test]
    fn same_realm_logon_failure_still_revokes() {
        let s = classify_containment_signals(
            &out("STATUS_LOGON_FAILURE"),
            Some("nxc_smb"),
            Some("alice@CONTOSO.LOCAL"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
    }

    #[test]
    fn unknown_target_realm_still_revokes_under_known_technique() {
        for domain in [None, Some("")] {
            let s = classify_containment_signals(
                &out("STATUS_LOGON_FAILURE"),
                Some("nxc_smb"),
                Some("alice@contoso.local"),
                domain,
                Some("192.168.58.10"),
            );
            assert!(
                s.iter()
                    .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })),
                "target realm {domain:?} is unknown, not mismatched"
            );
        }
    }

    #[test]
    fn kdc_principal_unknown_is_not_credential_revoked() {
        // KDC_ERR_C_PRINCIPAL_UNKNOWN is a routine kerberoast/SPN-enumeration
        // side-effect (the *queried* SPN doesn't exist), not evidence the
        // acting credential was revoked. It must not be a reject marker.
        let result = out("KDC_ERR_C_PRINCIPAL_UNKNOWN for MSSQLSvc/absent.contoso.local");
        let s = classify_containment_signals(
            &result,
            Some("kerberoast"),
            Some("svc_sql@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
    }

    #[test]
    fn weak_revoke_source_is_distinguishable_from_kdc_client_revoked() {
        // The caller thresholds weak markers and publishes KDC-declared
        // revocations immediately, keyed off the source string. A weak signal's
        // source must NOT carry the strong marker; a strong one must.
        let weak = classify_containment_signals(
            &out("STATUS_LOGON_FAILURE"),
            Some("nxc_smb"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        let weak_src = weak
            .iter()
            .find_map(|sig| match sig {
                ContainmentSignal::CredentialRevoked { source, .. } => Some(source.clone()),
                _ => None,
            })
            .expect("weak revocation signal");
        assert!(!weak_src.contains(KDC_CLIENT_REVOKED_MARKER));

        let strong = classify_containment_signals(
            &out("KDC_ERR_CLIENT_REVOKED"),
            Some("nxc_smb"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        let strong_src = strong
            .iter()
            .find_map(|sig| match sig {
                ContainmentSignal::CredentialRevoked { source, .. } => Some(source.clone()),
                _ => None,
            })
            .expect("strong revocation signal");
        assert!(strong_src.contains(KDC_CLIENT_REVOKED_MARKER));
    }

    #[test]
    fn krbtgt_rotated_on_krb_ap_err_modified() {
        let result = out("KRB_AP_ERR_MODIFIED — decrypt integrity check failed");
        let s = classify_containment_signals(
            &result,
            Some("secretsdump"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.240"),
        );
        assert!(s.iter().any(
            |sig| matches!(sig, ContainmentSignal::KrbtgtRotated { domain, .. }
                if domain == "contoso.local")
        ));
    }

    fn rotates(technique: &str, cred: Option<&str>, task_domain: Option<&str>) -> bool {
        classify_containment_signals(
            &out("KRB_AP_ERR_MODIFIED — decrypt integrity check failed"),
            Some(technique),
            cred,
            task_domain,
            Some("192.168.58.240"),
        )
        .iter()
        .any(|sig| matches!(sig, ContainmentSignal::KrbtgtRotated { .. }))
    }

    #[test]
    fn certipy_pkinit_flake_does_not_rotate_the_realm() {
        for tech in [
            "certipy_auth",
            "certipy_esc1_full_chain",
            "adcs_esc1",
            "pkinit",
        ] {
            assert!(
                !rotates(tech, Some("alice@contoso.local"), Some("contoso.local")),
                "{tech}: certipy PKINIT emits KRB_AP_ERR_MODIFIED as a ~50% transient \
                 flake and retries it internally — it is not evidence of a rotation"
            );
        }
    }

    #[test]
    fn wrong_trust_key_forge_does_not_rotate_the_realm() {
        for tech in ["ticketer", "trust_ticket_forge", "inter_realm_forge"] {
            assert!(
                !rotates(tech, Some("alice@contoso.local"), Some("fabrikam.local")),
                "{tech}: a forged inter-realm TGT the target KDC cannot decrypt is \
                 indistinguishable from a rotated key on this string alone"
            );
        }
    }

    #[test]
    fn cross_realm_key_mismatch_does_not_rotate_the_target_realm() {
        assert!(
            !rotates(
                "secretsdump",
                Some("alice@contoso.local"),
                Some("fabrikam.local")
            ),
            "a ticket fired across a realm boundary is expected to fail to decrypt"
        );
        assert!(rotates(
            "secretsdump",
            Some("alice@contoso.local"),
            Some("contoso.local")
        ));
    }

    #[test]
    fn unknown_technique_does_not_rotate_the_realm() {
        assert!(!rotates(
            "",
            Some("alice@contoso.local"),
            Some("contoso.local")
        ));
        assert!(!rotates("   ", None, Some("contoso.local")));
    }

    #[test]
    fn host_isolated_requires_host_pivot_technique() {
        let result = out("STATUS_HOST_UNREACHABLE");
        let s_smb = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            None,
            None,
            Some("192.168.58.20"),
        );
        assert!(s_smb.iter().any(
            |sig| matches!(sig, ContainmentSignal::HostIsolated { ip, .. }
                if ip == "192.168.58.20")
        ));

        // Same failure text on an HTTP recon tool must NOT flip host-isolated,
        // because HTTP timeouts are noisy and mean many things.
        let s_http = classify_containment_signals(
            &result,
            Some("http_probe"),
            None,
            None,
            Some("192.168.58.20"),
        );
        assert!(!s_http
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::HostIsolated { .. })));
    }

    #[test]
    fn host_isolated_needs_target_ip() {
        let result = out("STATUS_HOST_UNREACHABLE");
        let s = classify_containment_signals(&result, Some("nxc_smb"), None, None, None);
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::HostIsolated { .. })));
    }

    #[test]
    fn empty_result_yields_no_signals() {
        assert!(classify_containment_signals(&None, Some("nxc_smb"), None, None, None).is_empty());
    }

    #[test]
    fn benign_output_yields_no_signals() {
        let result = out("[+] contoso.local\\alice:P@ss (Pwn3d!)");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s.is_empty());
    }
}
