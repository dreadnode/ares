//! DNS SRV-based domain prober.
//!
//! Real AD domains publish `_ldap._tcp.dc._msdcs.<domain>` SRV records. This
//! is the same lookup that NetExec, runZero, and BloodHound use to discover
//! domain controllers, and it serves equally well as a binary "is this a real
//! AD domain?" probe.
//!
//! Resolver behavior:
//! - We construct a `TokioResolver` from the system resolv.conf so we
//!   pick up whatever recursive resolver the operator has configured (often
//!   the same DNS server an attacker would query during real-world recon).
//! - NXDOMAIN / NoRecordsFound → `Rejected` (the suffix is definitely not AD).
//! - Successful answer with at least one SRV record → `Confirmed`.
//! - I/O / timeout / refused → `Indeterminate` (we'll retry next tick).

use async_trait::async_trait;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::TokioResolver;

use super::{DomainProber, ProbeOutcome};

/// Real DNS prober. Wraps a hickory `TokioResolver`.
pub struct DnsSrvProber {
    resolver: TokioResolver,
}

impl DnsSrvProber {
    /// Construct using the system resolver (resolv.conf on Unix).
    /// Falls back to a Cloudflare/Google config if system config is unreadable
    /// — we still need *something* to query in container environments where
    /// /etc/resolv.conf may be missing.
    pub fn from_system() -> Self {
        let resolver = TokioResolver::builder_tokio()
            .and_then(|b| b.build())
            .unwrap_or_else(|e| {
                tracing::warn!(err = %e, "DNS SRV prober: system resolver unreadable, falling back to defaults");
                TokioResolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioRuntimeProvider::default(),
                )
                .build()
                .expect("default ResolverConfig should always build")
            });
        Self { resolver }
    }
}

#[async_trait]
impl DomainProber for DnsSrvProber {
    async fn probe(&self, fqdn: &str) -> ProbeOutcome {
        let query = format!("_ldap._tcp.dc._msdcs.{}.", fqdn.trim_end_matches('.'));
        match self.resolver.srv_lookup(&query).await {
            Ok(answer) => {
                if !answer.answers().is_empty() {
                    ProbeOutcome::Confirmed
                } else {
                    ProbeOutcome::Rejected("no SRV records")
                }
            }
            Err(e) => match &e {
                NetError::Dns(DnsError::NoRecordsFound(_)) => {
                    ProbeOutcome::Rejected("NXDOMAIN / no _ldap._tcp.dc._msdcs SRV")
                }
                _ => {
                    tracing::debug!(fqdn = %fqdn, err = %e, "DNS SRV probe transient error");
                    ProbeOutcome::Indeterminate
                }
            },
        }
    }
}
