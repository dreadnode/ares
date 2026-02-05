"""Tests for JSON serialization of SharedRedTeamState.

Verifies that SharedRedTeamState round-trips through JSON correctly,
preserving all field types (sets, datetimes, enums, Pydantic models,
nested dataclasses).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from ares.core.models import (
    AgentInfo,
    AgentRole,
    Credential,
    Hash,
    Host,
    Share,
    SharedRedTeamState,
    Target,
    TaskInfo,
    TaskResult,
    TaskStatus,
    TimelineEvent,
    User,
    VulnerabilityInfo,
)


class TestEmptyStateRoundTrip:
    """Test that a minimal state serializes and deserializes."""

    def test_empty_state_round_trip(self) -> None:
        """Minimal SharedRedTeamState survives JSON round-trip."""
        original = SharedRedTeamState(operation_id="op-empty")

        data = original.to_bytes()
        restored = SharedRedTeamState.from_bytes(data)

        assert restored.operation_id == "op-empty"
        assert restored.target is None
        assert restored.all_credentials == []
        assert restored.all_hashes == []
        assert restored.all_hosts == []
        assert restored.all_users == []
        assert restored.all_shares == []
        assert restored.all_weaknesses == []
        assert restored.discovered_vulnerabilities == {}
        assert restored.exploited_vulnerabilities == set()
        assert restored.pending_tasks == {}
        assert restored.completed_tasks == {}
        assert restored.has_domain_admin is False
        assert restored.has_golden_ticket is False
        assert restored.completed is False
        assert restored.identified_techniques == set()
        assert restored.pending_credential_findings == set()
        assert restored.scanned_targets == set()
        assert restored.downloaded_artifacts == {}
        assert restored.registered_agents == {}
        assert restored.operation_timeline == []


class TestFullStateRoundTrip:
    """Test a fully-populated state round-trips correctly."""

    def _make_full_state(self) -> SharedRedTeamState:
        """Build a state with all field types populated."""
        state = SharedRedTeamState(
            operation_id="op-full-001",
            target=Target(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                domain="contoso.local",
            ),
            started_at=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
        )

        # Credentials
        state.all_credentials = [
            Credential(
                username="admin",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoast",
                is_admin=True,
            ),
            Credential(
                username="svc_backup",
                password="Backup2024!",  # pragma: allowlist secret
                domain="contoso.local",
                source="secretsdump",
            ),
        ]

        # Hashes
        state.all_hashes = [
            Hash(
                username="krbtgt",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="NTLM",
                domain="contoso.local",
                source="secretsdump",
                discovered_at=datetime(2025, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
            ),
        ]

        # Hosts
        state.all_hosts = [
            Host(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                os="Windows Server 2022",
                roles=["Domain Controller"],
                services=["88/tcp kerberos", "389/tcp ldap", "445/tcp smb"],
                is_dc=True,
            ),
            Host(
                ip="192.168.58.20",
                hostname="sql01.contoso.local",
                os="Windows Server 2019",
                services=["1433/tcp mssql"],
            ),
        ]

        # Users
        state.all_users = [
            User(username="admin", domain="contoso.local", is_admin=True),
            User(username="svc_backup", domain="contoso.local"),
        ]

        # Shares
        state.all_shares = [
            Share(host="192.168.58.10", name="SYSVOL", permissions="READ"),
            Share(host="192.168.58.10", name="NETLOGON", permissions="READ"),
        ]

        # Weaknesses
        state.all_weaknesses = ["SMB signing disabled on sql01"]

        # Domains
        state.all_domains = ["contoso.local"]
        state.netbios_to_fqdn = {"contoso": "contoso.local"}

        # Vulnerabilities
        state.discovered_vulnerabilities = {
            "vuln-001": VulnerabilityInfo(
                vuln_id="vuln-001",
                vuln_type="ADCS_ESC1",
                target="dc01.contoso.local",
                discovered_by="acl",
                discovered_at=datetime(2025, 6, 15, 11, 30, 0, tzinfo=timezone.utc),
                details={"template": "UserCert", "ca": "contoso-CA"},
                recommended_agent="privesc",
                priority=1,
            ),
        }
        state.exploited_vulnerabilities = {"vuln-old-001"}

        # Tasks
        state.pending_tasks = {
            "task-001": TaskInfo(
                task_id="task-001",
                task_type="crack",
                assigned_agent="cracker",
                status=TaskStatus.IN_PROGRESS,
                created_at=datetime(2025, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
                params={"hash_value": "abc123", "wordlist": "rockyou"},
                result="cracked: P@ssw0rd",
                retry_count=1,
                max_retries=3,
            ),
        }
        state.completed_tasks = {
            "task-000": TaskResult(
                task_id="task-000",
                success=True,
                result="scan complete",
                completed_at=datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc),
            ),
        }

        # Flags
        state.has_domain_admin = True
        state.has_golden_ticket = False
        state.completed = False
        state.domain_admin_path = "secretsdump -> krbtgt NTLM hash"

        # Agents
        state.registered_agents = {
            "cracker-pod-1": AgentInfo(
                name="cracker-pod-1",
                pod_name="ares-cracker-abc123",
                role=AgentRole.CRACKER,
                capabilities={"hashcat", "john"},
                status="busy",
                current_task="task-001",
                registered_at=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
                last_heartbeat=datetime(2025, 6, 15, 11, 45, 0, tzinfo=timezone.utc),
            ),
        }

        # Timeline
        state.operation_timeline = [
            TimelineEvent(
                id="evt-001",
                timestamp=datetime(2025, 6, 15, 10, 5, 0, tzinfo=timezone.utc),
                description="Initial enumeration started",
                confidence=0.9,
            ),
        ]

        # Sets
        state.identified_techniques = {"T1558.003", "T1003.006"}
        state.pending_credential_findings = {"contoso.local:svc_sql"}
        state.scanned_targets = {"192.168.58.0/24", "192.168.58.10"}

        # Artifacts
        state.downloaded_artifacts = {
            "sysvol/login.bat": "QmF0Y2ggZmlsZSBjb250ZW50",
        }

        return state

    def test_full_state_round_trip(self) -> None:
        """Fully-populated state survives JSON round-trip."""
        original = self._make_full_state()
        data = original.to_bytes()
        restored = SharedRedTeamState.from_bytes(data)

        assert restored.operation_id == "op-full-001"

        # Target
        assert restored.target is not None
        assert restored.target.ip == "192.168.58.10"
        assert restored.target.hostname == "dc01.contoso.local"
        assert restored.target.domain == "contoso.local"

        # Credentials
        assert len(restored.all_credentials) == 2
        assert restored.all_credentials[0].username == "admin"
        assert restored.all_credentials[0].is_admin is True
        assert restored.all_credentials[1].username == "svc_backup"

        # Hashes
        assert len(restored.all_hashes) == 1
        assert restored.all_hashes[0].username == "krbtgt"
        assert restored.all_hashes[0].hash_type == "NTLM"

        # Hosts
        assert len(restored.all_hosts) == 2
        assert restored.all_hosts[0].is_dc is True
        assert restored.all_hosts[0].services == [
            "88/tcp kerberos",
            "389/tcp ldap",
            "445/tcp smb",
        ]

        # Users
        assert len(restored.all_users) == 2
        assert restored.all_users[0].is_admin is True

        # Shares
        assert len(restored.all_shares) == 2
        assert restored.all_shares[0].name == "SYSVOL"

        # Weaknesses
        assert restored.all_weaknesses == ["SMB signing disabled on sql01"]

        # Domains
        assert restored.all_domains == ["contoso.local"]
        assert restored.netbios_to_fqdn == {"contoso": "contoso.local"}

        # Vulnerabilities
        assert "vuln-001" in restored.discovered_vulnerabilities
        vuln = restored.discovered_vulnerabilities["vuln-001"]
        assert vuln.vuln_type == "ADCS_ESC1"
        assert vuln.details == {"template": "UserCert", "ca": "contoso-CA"}
        assert vuln.priority == 1
        assert restored.exploited_vulnerabilities == {"vuln-old-001"}

        # Tasks
        assert "task-001" in restored.pending_tasks
        task = restored.pending_tasks["task-001"]
        assert task.status == TaskStatus.IN_PROGRESS
        assert task.params == {"hash_value": "abc123", "wordlist": "rockyou"}
        assert task.result == "cracked: P@ssw0rd"
        assert task.retry_count == 1

        assert "task-000" in restored.completed_tasks
        result = restored.completed_tasks["task-000"]
        assert result.success is True
        assert result.result == "scan complete"

        # Flags
        assert restored.has_domain_admin is True
        assert restored.has_golden_ticket is False
        assert restored.domain_admin_path == "secretsdump -> krbtgt NTLM hash"

        # Agents
        assert "cracker-pod-1" in restored.registered_agents
        agent = restored.registered_agents["cracker-pod-1"]
        assert agent.role == AgentRole.CRACKER
        assert agent.capabilities == {"hashcat", "john"}
        assert agent.status == "busy"

        # Timeline
        assert len(restored.operation_timeline) == 1
        assert restored.operation_timeline[0].description == "Initial enumeration started"

        # Sets
        assert restored.identified_techniques == {"T1558.003", "T1003.006"}
        assert restored.pending_credential_findings == {"contoso.local:svc_sql"}
        assert restored.scanned_targets == {"192.168.58.0/24", "192.168.58.10"}

        # Artifacts
        assert restored.downloaded_artifacts == {
            "sysvol/login.bat": "QmF0Y2ggZmlsZSBjb250ZW50",
        }


class TestSetPreservation:
    """Test that set fields survive round-trip as sets."""

    def test_sets_round_trip_as_sets(self) -> None:
        """All set-typed fields are restored as set instances."""
        state = SharedRedTeamState(operation_id="op-sets")
        state.exploited_vulnerabilities = {"v1", "v2", "v3"}
        state.identified_techniques = {"T1001", "T1002"}
        state.scanned_targets = {"192.168.58.0/24"}
        state.pending_credential_findings = {"contoso.local:admin"}

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert isinstance(restored.exploited_vulnerabilities, set)
        assert restored.exploited_vulnerabilities == {"v1", "v2", "v3"}

        assert isinstance(restored.identified_techniques, set)
        assert restored.identified_techniques == {"T1001", "T1002"}

        assert isinstance(restored.scanned_targets, set)
        assert restored.scanned_targets == {"192.168.58.0/24"}

        assert isinstance(restored.pending_credential_findings, set)
        assert restored.pending_credential_findings == {"contoso.local:admin"}

    def test_empty_sets_preserved(self) -> None:
        """Empty sets survive round-trip."""
        state = SharedRedTeamState(operation_id="op-empty-sets")

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert isinstance(restored.exploited_vulnerabilities, set)
        assert restored.exploited_vulnerabilities == set()
        assert isinstance(restored.identified_techniques, set)
        assert restored.identified_techniques == set()


class TestDatetimePreservation:
    """Test that datetime fields survive round-trip."""

    def test_started_at_preserved(self) -> None:
        """started_at datetime survives round-trip."""
        ts = datetime(2025, 3, 15, 14, 30, 0, tzinfo=timezone.utc)
        state = SharedRedTeamState(operation_id="op-dt", started_at=ts)

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert isinstance(restored.started_at, datetime)
        assert restored.started_at == ts

    def test_task_datetimes_preserved(self) -> None:
        """TaskInfo datetime fields survive round-trip."""
        created = datetime(2025, 3, 15, 14, 0, 0, tzinfo=timezone.utc)
        started = datetime(2025, 3, 15, 14, 5, 0, tzinfo=timezone.utc)
        completed = datetime(2025, 3, 15, 14, 10, 0, tzinfo=timezone.utc)

        state = SharedRedTeamState(operation_id="op-task-dt")
        state.pending_tasks["t1"] = TaskInfo(
            task_id="t1",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.COMPLETED,
            created_at=created,
            started_at=started,
            completed_at=completed,
        )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        task = restored.pending_tasks["t1"]
        assert isinstance(task.created_at, datetime)
        assert task.created_at == created
        assert isinstance(task.started_at, datetime)
        assert task.started_at == started
        assert isinstance(task.completed_at, datetime)
        assert task.completed_at == completed

    def test_none_datetimes_preserved(self) -> None:
        """None datetime fields survive round-trip."""
        state = SharedRedTeamState(operation_id="op-none-dt")
        state.pending_tasks["t1"] = TaskInfo(
            task_id="t1",
            task_type="crack",
            assigned_agent="cracker",
            created_at=datetime(2025, 3, 15, 14, 0, 0, tzinfo=timezone.utc),
            started_at=None,
            completed_at=None,
        )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        task = restored.pending_tasks["t1"]
        assert task.started_at is None
        assert task.completed_at is None

    def test_agent_datetimes_preserved(self) -> None:
        """AgentInfo datetime fields survive round-trip."""
        reg_time = datetime(2025, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        hb_time = datetime(2025, 3, 15, 14, 30, 0, tzinfo=timezone.utc)

        state = SharedRedTeamState(operation_id="op-agent-dt")
        state.registered_agents["a1"] = AgentInfo(
            name="a1",
            pod_name="pod-a1",
            role=AgentRole.CRACKER,
            registered_at=reg_time,
            last_heartbeat=hb_time,
        )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        agent = restored.registered_agents["a1"]
        assert isinstance(agent.registered_at, datetime)
        assert agent.registered_at == reg_time
        assert isinstance(agent.last_heartbeat, datetime)
        assert agent.last_heartbeat == hb_time

    def test_hash_discovered_at_preserved(self) -> None:
        """Hash.discovered_at datetime survives round-trip."""
        disc_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        state = SharedRedTeamState(operation_id="op-hash-dt")
        state.all_hashes = [
            Hash(
                username="test",
                hash_value="abc123",
                discovered_at=disc_time,
            ),
        ]

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert isinstance(restored.all_hashes[0].discovered_at, datetime)
        assert restored.all_hashes[0].discovered_at == disc_time


class TestEnumPreservation:
    """Test that enum fields survive round-trip."""

    def test_task_status_preserved(self) -> None:
        """TaskStatus enum values survive round-trip."""
        state = SharedRedTeamState(operation_id="op-enum")

        for status in TaskStatus:
            state.pending_tasks[f"t-{status.value}"] = TaskInfo(
                task_id=f"t-{status.value}",
                task_type="test",
                assigned_agent="test",
                status=status,
                created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        for status in TaskStatus:
            task = restored.pending_tasks[f"t-{status.value}"]
            assert isinstance(task.status, TaskStatus)
            assert task.status == status

    def test_agent_role_preserved(self) -> None:
        """AgentRole enum values survive round-trip."""
        state = SharedRedTeamState(operation_id="op-role")

        for role in AgentRole:
            state.registered_agents[f"a-{role.value}"] = AgentInfo(
                name=f"a-{role.value}",
                pod_name=f"pod-{role.value}",
                role=role,
                registered_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
                last_heartbeat=datetime(2025, 1, 1, tzinfo=timezone.utc),
            )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        for role in AgentRole:
            agent = restored.registered_agents[f"a-{role.value}"]
            assert isinstance(agent.role, AgentRole)
            assert agent.role == role


class TestPydanticModelPreservation:
    """Test that Pydantic model fields survive round-trip."""

    def test_target_preserved(self) -> None:
        """Target Pydantic model survives round-trip."""
        state = SharedRedTeamState(
            operation_id="op-pydantic",
            target=Target(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                domain="contoso.local",
            ),
        )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert isinstance(restored.target, Target)
        assert restored.target.ip == "192.168.58.10"
        assert restored.target.hostname == "dc01.contoso.local"
        assert restored.target.domain == "contoso.local"

    def test_credential_fields_intact(self) -> None:
        """Credential Pydantic model fields survive round-trip."""
        state = SharedRedTeamState(operation_id="op-cred")
        state.all_credentials = [
            Credential(
                username="admin",
                password="P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoast",
                is_admin=True,
            ),
        ]

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        cred = restored.all_credentials[0]
        assert isinstance(cred, Credential)
        assert cred.username == "admin"
        assert cred.password == "P@ssw0rd!"  # pragma: allowlist secret
        assert cred.domain == "contoso.local"
        assert cred.source == "kerberoast"
        assert cred.is_admin is True

    def test_host_fields_intact(self) -> None:
        """Host Pydantic model with lists survives round-trip."""
        state = SharedRedTeamState(operation_id="op-host")
        state.all_hosts = [
            Host(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                os="Windows Server 2022",
                roles=["Domain Controller", "DNS"],
                services=["88/tcp kerberos", "389/tcp ldap"],
                is_dc=True,
            ),
        ]

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        host = restored.all_hosts[0]
        assert isinstance(host, Host)
        assert host.ip == "192.168.58.10"
        assert host.os == "Windows Server 2022"
        assert host.roles == ["Domain Controller", "DNS"]
        assert host.services == ["88/tcp kerberos", "389/tcp ldap"]
        assert host.is_dc is True

    def test_hash_fields_intact(self) -> None:
        """Hash Pydantic model survives round-trip."""
        state = SharedRedTeamState(operation_id="op-hash")
        state.all_hashes = [
            Hash(
                username="svc_sql",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0",
                hash_type="NTLM",
                domain="contoso.local",
                cracked_password="Summer2024!",  # pragma: allowlist secret
                source="secretsdump",
            ),
        ]

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        h = restored.all_hashes[0]
        assert isinstance(h, Hash)
        assert h.username == "svc_sql"
        assert h.hash_type == "NTLM"
        assert h.cracked_password == "Summer2024!"  # pragma: allowlist secret
        assert h.source == "secretsdump"

    def test_timeline_event_preserved(self) -> None:
        """TimelineEvent Pydantic model survives round-trip."""
        state = SharedRedTeamState(operation_id="op-timeline")
        state.operation_timeline = [
            TimelineEvent(
                id="evt-001",
                timestamp=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
                description="Recon started",
                evidence_ids=["ev-001", "ev-002"],
                mitre_techniques=["T1046"],
                confidence=0.95,
                source="recon",
            ),
        ]

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        evt = restored.operation_timeline[0]
        assert isinstance(evt, TimelineEvent)
        assert evt.id == "evt-001"
        assert evt.description == "Recon started"
        assert evt.evidence_ids == ["ev-001", "ev-002"]
        assert evt.mitre_techniques == ["T1046"]
        assert evt.confidence == 0.95

    def test_user_fields_intact(self) -> None:
        """User Pydantic model survives round-trip."""
        state = SharedRedTeamState(operation_id="op-user")
        state.all_users = [
            User(
                username="jsmith",
                domain="contoso.local",
                description="Service Account",
                is_admin=True,
            ),
        ]

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        user = restored.all_users[0]
        assert isinstance(user, User)
        assert user.username == "jsmith"
        assert user.domain == "contoso.local"
        assert user.description == "Service Account"
        assert user.is_admin is True

    def test_share_fields_intact(self) -> None:
        """Share Pydantic model survives round-trip."""
        state = SharedRedTeamState(operation_id="op-share")
        state.all_shares = [
            Share(
                host="192.168.58.10",
                name="ADMIN$",
                permissions="READ/WRITE",
                comment="Remote Admin",
            ),
        ]

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        share = restored.all_shares[0]
        assert isinstance(share, Share)
        assert share.host == "192.168.58.10"
        assert share.name == "ADMIN$"
        assert share.permissions == "READ/WRITE"
        assert share.comment == "Remote Admin"


class TestNestedDataclassPreservation:
    """Test that nested dataclass fields survive round-trip."""

    def test_vulnerability_info_in_dict(self) -> None:
        """VulnerabilityInfo inside discovered_vulnerabilities dict survives."""
        state = SharedRedTeamState(operation_id="op-vuln")
        state.discovered_vulnerabilities = {
            "v1": VulnerabilityInfo(
                vuln_id="v1",
                vuln_type="ADCS_ESC1",
                target="dc01",
                discovered_by="acl",
                discovered_at=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
                details={"template": "UserCert", "ca_name": "contoso-CA"},
                recommended_agent="privesc",
                priority=1,
            ),
            "v2": VulnerabilityInfo(
                vuln_id="v2",
                vuln_type="UNCONSTRAINED_DELEGATION",
                target="sql01",
                discovered_by="recon",
                details={"spn": "MSSQLSvc/sql01:1433"},
                priority=3,
            ),
        }

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert len(restored.discovered_vulnerabilities) == 2
        v1 = restored.discovered_vulnerabilities["v1"]
        assert isinstance(v1, VulnerabilityInfo)
        assert v1.vuln_type == "ADCS_ESC1"
        assert v1.details == {"template": "UserCert", "ca_name": "contoso-CA"}
        assert v1.priority == 1
        assert isinstance(v1.discovered_at, datetime)

        v2 = restored.discovered_vulnerabilities["v2"]
        assert isinstance(v2, VulnerabilityInfo)
        assert v2.vuln_type == "UNCONSTRAINED_DELEGATION"

    def test_task_info_in_dict(self) -> None:
        """TaskInfo inside pending_tasks dict survives."""
        state = SharedRedTeamState(operation_id="op-task")
        state.pending_tasks = {
            "t1": TaskInfo(
                task_id="t1",
                task_type="crack",
                assigned_agent="cracker",
                status=TaskStatus.RETRYING,
                created_at=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
                params={"hash_value": "abc123"},
                result="partial",
                error="pod restart",
                retry_count=2,
                max_retries=3,
            ),
        }

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        t1 = restored.pending_tasks["t1"]
        assert isinstance(t1, TaskInfo)
        assert t1.status == TaskStatus.RETRYING
        assert t1.params == {"hash_value": "abc123"}
        assert t1.result == "partial"
        assert t1.error == "pod restart"
        assert t1.retry_count == 2
        assert t1.max_retries == 3

    def test_task_result_in_dict(self) -> None:
        """TaskResult inside completed_tasks dict survives."""
        state = SharedRedTeamState(operation_id="op-result")
        state.completed_tasks = {
            "t0": TaskResult(
                task_id="t0",
                success=True,
                result="scan complete",
                error=None,
                completed_at=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
            ),
            "t1": TaskResult(
                task_id="t1",
                success=False,
                result=None,
                error="timeout",
                completed_at=datetime(2025, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
            ),
        }

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert len(restored.completed_tasks) == 2
        t0 = restored.completed_tasks["t0"]
        assert isinstance(t0, TaskResult)
        assert t0.success is True
        assert t0.result == "scan complete"
        assert t0.error is None

        t1 = restored.completed_tasks["t1"]
        assert t1.success is False
        assert t1.result is None
        assert t1.error == "timeout"

    def test_agent_info_with_set_capabilities(self) -> None:
        """AgentInfo with set[str] capabilities survives round-trip."""
        state = SharedRedTeamState(operation_id="op-agent")
        state.registered_agents = {
            "enum-pod": AgentInfo(
                name="enum-pod",
                pod_name="ares-enum-xyz",
                role=AgentRole.RECON,
                capabilities={"nmap", "bloodhound", "ldapsearch"},
                status="idle",
                current_task=None,
                registered_at=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
                last_heartbeat=datetime(2025, 6, 15, 14, 0, 0, tzinfo=timezone.utc),
            ),
        }

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        agent = restored.registered_agents["enum-pod"]
        assert isinstance(agent, AgentInfo)
        assert isinstance(agent.capabilities, set)
        assert agent.capabilities == {"nmap", "bloodhound", "ldapsearch"}
        assert agent.current_task is None


class TestDispatcherExcluded:
    """Test that _dispatcher is excluded from JSON."""

    def test_dispatcher_not_in_json(self) -> None:
        """JSON output does not contain _dispatcher."""
        state = SharedRedTeamState(operation_id="op-dispatcher")
        # Simulate setting a dispatcher
        state.set_dispatcher(object())

        data = state.to_bytes()
        parsed = json.loads(data)

        assert "_dispatcher" not in parsed

    def test_dispatcher_none_after_restore(self) -> None:
        """_dispatcher is None after deserialization."""
        state = SharedRedTeamState(operation_id="op-dispatcher")
        state.set_dispatcher(object())

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert restored._dispatcher is None


class TestAnyFieldHandling:
    """Test that Any-typed fields round-trip correctly."""

    def test_task_result_string(self) -> None:
        """TaskInfo.result as string survives round-trip."""
        state = SharedRedTeamState(operation_id="op-any")
        state.pending_tasks["t1"] = TaskInfo(
            task_id="t1",
            task_type="crack",
            assigned_agent="cracker",
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            result="cracked password: Summer2024!",
        )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert restored.pending_tasks["t1"].result == "cracked password: Summer2024!"

    def test_task_params_dict(self) -> None:
        """TaskInfo.params as dict survives round-trip."""
        state = SharedRedTeamState(operation_id="op-params")
        state.pending_tasks["t1"] = TaskInfo(
            task_id="t1",
            task_type="lateral",
            assigned_agent="lateral",
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            params={"target_host": "192.168.58.20", "method": "psexec", "port": 445},
        )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        params = restored.pending_tasks["t1"].params
        assert params["target_host"] == "192.168.58.20"
        assert params["method"] == "psexec"
        assert params["port"] == 445

    def test_vuln_details_dict(self) -> None:
        """VulnerabilityInfo.details dict survives round-trip."""
        state = SharedRedTeamState(operation_id="op-vuln-details")
        state.discovered_vulnerabilities["v1"] = VulnerabilityInfo(
            vuln_id="v1",
            vuln_type="constrained_delegation",
            target="dc01",
            discovered_by="recon",
            details={
                "spn": "cifs/dc01.contoso.local",
                "account": "svc_web",
                "delegatable": "true",
            },
        )

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        details = restored.discovered_vulnerabilities["v1"].details
        assert details["spn"] == "cifs/dc01.contoso.local"
        assert details["account"] == "svc_web"


class TestLargeArtifacts:
    """Test that downloaded_artifacts with base64 content survive."""

    def test_large_artifact_round_trip(self) -> None:
        """Large base64-encoded artifacts survive round-trip."""
        import base64

        state = SharedRedTeamState(operation_id="op-artifacts")
        # Simulate a 100KB artifact
        content = b"A" * 100_000
        encoded = base64.b64encode(content).decode("ascii")
        state.downloaded_artifacts = {
            "loot/ntds.dit": encoded,
            "sysvol/logon.bat": base64.b64encode(b"echo hello").decode("ascii"),
        }

        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        assert len(restored.downloaded_artifacts) == 2
        assert restored.downloaded_artifacts["loot/ntds.dit"] == encoded
        decoded = base64.b64decode(restored.downloaded_artifacts["loot/ntds.dit"])
        assert decoded == content


class TestJsonFormatMarker:
    """Test that the JSON format includes a version marker."""

    def test_version_marker_present(self) -> None:
        """JSON output contains _v key."""
        state = SharedRedTeamState(operation_id="op-version")
        data = state.to_bytes()
        parsed = json.loads(data)

        assert "_v" in parsed
        assert parsed["_v"] == 1

    def test_version_marker_stripped_on_load(self) -> None:
        """_v key is stripped during deserialization."""
        state = SharedRedTeamState(operation_id="op-version")
        restored = SharedRedTeamState.from_bytes(state.to_bytes())

        # _v should not appear as an attribute on the restored state
        assert not hasattr(restored, "_v")

    def test_json_format_detected(self) -> None:
        """JSON is detected by first byte being '{'."""
        state = SharedRedTeamState(operation_id="op-detect")
        data = state.to_bytes()

        assert data[0:1] == b"{"


class TestExistingTestsStillPass:
    """Verify recovery tests work with JSON serialization."""

    def test_recovery_round_trip(self) -> None:
        """State with in-progress tasks used by recovery tests survives JSON."""
        state = SharedRedTeamState(
            operation_id="test-op-002",
            target=Target(ip="192.168.58.100", hostname="dc01"),
        )

        state.pending_tasks["task_001"] = TaskInfo(
            task_id="task_001",
            task_type="crack",
            assigned_agent="cracker",
            status=TaskStatus.IN_PROGRESS,
            created_at=datetime.now(timezone.utc),
            params={"hash_value": "abc123"},
            retry_count=0,
            max_retries=3,
        )

        data = state.to_bytes()
        restored = SharedRedTeamState.from_bytes(data)

        assert restored.operation_id == "test-op-002"
        task = restored.pending_tasks["task_001"]
        assert task.status == TaskStatus.IN_PROGRESS
        assert task.params == {"hash_value": "abc123"}
        assert task.retry_count == 0
        assert task.max_retries == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
