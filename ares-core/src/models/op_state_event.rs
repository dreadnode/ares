//! Operation state event envelope for the JetStream `ARES_OPSTATE` log.
//!
//! Every mutation to live operation state (credentials, hosts, users,
//! vulnerabilities, timeline) is appended to JetStream as an `OpStateEvent`.
//! The stream is the durable source of truth — Redis becomes a read cache and
//! Postgres becomes a projection that the projector consumer keeps current.
//!
//! Subject layout (granular per entity-action; see [`OpStateEventPayload::subject_suffix`]):
//!
//! - `ares.ops.{op_id}.cred.captured`
//! - `ares.ops.{op_id}.hash.captured`
//! - `ares.ops.{op_id}.host.discovered`
//! - `ares.ops.{op_id}.host.owned`
//! - `ares.ops.{op_id}.user.discovered`
//! - `ares.ops.{op_id}.vuln.discovered`
//! - `ares.ops.{op_id}.vuln.exploited`
//! - `ares.ops.{op_id}.timeline`
//!
//! `event_id` is sent as the `Nats-Msg-Id` header so JetStream dedups
//! at-least-once retries. Per-subject optimistic concurrency uses
//! `Nats-Expected-Last-Subject-Sequence`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::core::{Credential, Hash, Host, User};
use super::task::VulnerabilityInfo;
use super::util::new_uuid;

/// Envelope for a single mutation to operation state.
///
/// Serialized as JSON onto the `ARES_OPSTATE` stream. The `event_id` doubles
/// as the JetStream dedup key (`Nats-Msg-Id` header) so a publisher retrying
/// after a transient error never produces a duplicate event in the log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpStateEvent {
    /// Stable identifier for this event. Used as the JetStream dedup key.
    #[serde(default = "new_uuid")]
    pub event_id: String,
    /// Operation that produced the event.
    pub op_id: String,
    /// Wall-clock time the event was recorded at the publisher.
    #[serde(default = "Utc::now")]
    pub recorded_at: DateTime<Utc>,
    /// Typed payload — discriminated by `kind` in the JSON form.
    #[serde(flatten)]
    pub payload: OpStateEventPayload,
}

impl OpStateEvent {
    /// Build a new event with a freshly generated id and current timestamp.
    pub fn new(op_id: impl Into<String>, payload: OpStateEventPayload) -> Self {
        Self {
            event_id: new_uuid(),
            op_id: op_id.into(),
            recorded_at: Utc::now(),
            payload,
        }
    }

    /// Subject suffix for this event (e.g. `cred.captured`).
    pub fn subject_suffix(&self) -> &'static str {
        self.payload.subject_suffix()
    }
}

/// Typed payload for [`OpStateEvent`].
///
/// Serializes with an internal `kind` tag matching the subject suffix so a
/// consumer can route purely on subject filter or fall back to payload kind
/// when subscribed to the wildcard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OpStateEventPayload {
    CredentialCaptured {
        credential: Credential,
    },
    HashCaptured {
        hash: Hash,
    },
    HostDiscovered {
        host: Host,
    },
    HostOwned {
        ip: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        hostname: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        owned_by: String,
    },
    UserDiscovered {
        user: User,
    },
    VulnDiscovered {
        vuln: VulnerabilityInfo,
    },
    VulnExploited {
        vuln_id: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        exploited_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<serde_json::Value>,
    },
    TimelineEvent {
        event: serde_json::Value,
    },
}

impl OpStateEventPayload {
    /// Subject suffix that identifies this entity-action pair. Stable —
    /// changing values here is a wire-format break and requires migration.
    pub fn subject_suffix(&self) -> &'static str {
        match self {
            Self::CredentialCaptured { .. } => "cred.captured",
            Self::HashCaptured { .. } => "hash.captured",
            Self::HostDiscovered { .. } => "host.discovered",
            Self::HostOwned { .. } => "host.owned",
            Self::UserDiscovered { .. } => "user.discovered",
            Self::VulnDiscovered { .. } => "vuln.discovered",
            Self::VulnExploited { .. } => "vuln.exploited",
            Self::TimelineEvent { .. } => "timeline",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::core::Host;

    fn sample_credential() -> Credential {
        Credential {
            id: "cred-1".into(),
            username: "alice".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "secretsdump".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn sample_host() -> Host {
        Host {
            ip: "192.168.58.10".into(),
            hostname: "dc01.contoso.local".into(),
            os: "Windows Server 2019".into(),
            roles: vec!["Domain Controller".into()],
            services: vec!["88/tcp kerberos".into()],
            is_dc: true,
            owned: false,
        }
    }

    #[test]
    fn event_new_assigns_id_and_timestamp() {
        let ev = OpStateEvent::new(
            "op-1",
            OpStateEventPayload::CredentialCaptured {
                credential: sample_credential(),
            },
        );
        assert_eq!(ev.op_id, "op-1");
        assert_eq!(ev.event_id.len(), 36); // UUIDv4
        assert!(ev.recorded_at <= Utc::now());
    }

    #[test]
    fn distinct_events_get_distinct_ids() {
        let p = OpStateEventPayload::UserDiscovered {
            user: User {
                username: "bob".into(),
                domain: "contoso.local".into(),
                description: String::new(),
                is_admin: false,
                source: "ldap".into(),
            },
        };
        let a = OpStateEvent::new("op-1", p.clone());
        let b = OpStateEvent::new("op-1", p);
        assert_ne!(a.event_id, b.event_id);
    }

    #[test]
    fn subject_suffix_matches_each_variant() {
        let cases: &[(OpStateEventPayload, &str)] = &[
            (
                OpStateEventPayload::CredentialCaptured {
                    credential: sample_credential(),
                },
                "cred.captured",
            ),
            (
                OpStateEventPayload::HashCaptured {
                    hash: Hash {
                        id: "h1".into(),
                        username: "krbtgt".into(),
                        hash_value: "aaaa".into(),
                        hash_type: "NTLM".into(),
                        domain: "contoso.local".into(),
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
                    },
                },
                "hash.captured",
            ),
            (
                OpStateEventPayload::HostDiscovered {
                    host: sample_host(),
                },
                "host.discovered",
            ),
            (
                OpStateEventPayload::HostOwned {
                    ip: "192.168.58.10".into(),
                    hostname: "dc01.contoso.local".into(),
                    owned_by: "lateral".into(),
                },
                "host.owned",
            ),
            (
                OpStateEventPayload::UserDiscovered {
                    user: User {
                        username: "carol".into(),
                        domain: "contoso.local".into(),
                        description: String::new(),
                        is_admin: false,
                        source: "ldap".into(),
                    },
                },
                "user.discovered",
            ),
            (
                OpStateEventPayload::VulnDiscovered {
                    vuln: VulnerabilityInfo {
                        vuln_id: "v1".into(),
                        vuln_type: "ADCS_ESC1".into(),
                        target: "192.168.58.10".into(),
                        discovered_by: "recon".into(),
                        discovered_at: Utc::now(),
                        details: Default::default(),
                        recommended_agent: "privesc".into(),
                        priority: 1,
                    },
                },
                "vuln.discovered",
            ),
            (
                OpStateEventPayload::VulnExploited {
                    vuln_id: "v1".into(),
                    exploited_by: "privesc".into(),
                    result: None,
                },
                "vuln.exploited",
            ),
            (
                OpStateEventPayload::TimelineEvent {
                    event: serde_json::json!({"description": "captured DA"}),
                },
                "timeline",
            ),
        ];

        for (payload, expected) in cases {
            let ev = OpStateEvent::new("op-x", payload.clone());
            assert_eq!(ev.subject_suffix(), *expected);
        }
    }

    #[test]
    fn json_roundtrip_credential_captured() {
        let ev = OpStateEvent::new(
            "op-42",
            OpStateEventPayload::CredentialCaptured {
                credential: sample_credential(),
            },
        );
        let j = serde_json::to_string(&ev).unwrap();
        let back: OpStateEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn json_tag_uses_snake_case_kind() {
        let ev = OpStateEvent::new(
            "op-1",
            OpStateEventPayload::HostOwned {
                ip: "192.168.58.10".into(),
                hostname: String::new(),
                owned_by: String::new(),
            },
        );
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v.get("kind").and_then(|s| s.as_str()), Some("host_owned"));
        assert_eq!(v.get("op_id").and_then(|s| s.as_str()), Some("op-1"));
    }

    #[test]
    fn json_roundtrip_timeline_event_carries_arbitrary_payload() {
        let ev = OpStateEvent::new(
            "op-1",
            OpStateEventPayload::TimelineEvent {
                event: serde_json::json!({
                    "description": "Captured Domain Admin",
                    "mitre": ["T1003"],
                }),
            },
        );
        let j = serde_json::to_string(&ev).unwrap();
        let back: OpStateEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(ev, back);
    }
}
