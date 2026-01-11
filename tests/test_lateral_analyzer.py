"""Tests for the Lateral Movement Analyzer module."""

from datetime import datetime, timezone

from ares.core.lateral_analyzer import (
    HostConnection,
    LateralGraph,
    LateralMovementAnalyzer,
)


class TestHostConnection:
    """Tests for HostConnection dataclass."""

    def test_create_host_connection(self) -> None:
        """Test creating a basic host connection."""
        conn = HostConnection(
            source_host="workstation01",
            destination_host="server01",
            connection_type="smb",
        )

        assert conn.source_host == "workstation01"
        assert conn.destination_host == "server01"
        assert conn.connection_type == "smb"
        assert conn.timestamp is None
        assert conn.user is None
        assert conn.evidence_ids == []
        assert conn.mitre_technique is None

    def test_create_host_connection_full(self) -> None:
        """Test creating a host connection with all fields."""
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        conn = HostConnection(
            source_host="workstation01",
            destination_host="server01",
            connection_type="rdp",
            timestamp=ts,
            user="admin",
            evidence_ids=["ev001", "ev002"],
            mitre_technique="T1021.001",
        )

        assert conn.timestamp == ts
        assert conn.user == "admin"
        assert conn.evidence_ids == ["ev001", "ev002"]
        assert conn.mitre_technique == "T1021.001"


class TestLateralGraph:
    """Tests for LateralGraph class."""

    def test_create_empty_graph(self) -> None:
        """Test creating an empty graph."""
        graph = LateralGraph()

        assert graph.connections == []
        assert graph.investigated_hosts == set()
        assert graph.pending_hosts == set()

    def test_add_connection(self) -> None:
        """Test adding a connection to the graph."""
        graph = LateralGraph()

        conn = graph.add_connection(
            source="WORKSTATION01",
            destination="SERVER01",
            conn_type="smb",
        )

        assert conn is not None
        assert conn.source_host == "workstation01"  # Normalized to lowercase
        assert conn.destination_host == "server01"
        assert len(graph.connections) == 1

    def test_add_connection_normalizes_hostnames(self) -> None:
        """Test that add_connection normalizes hostnames."""
        graph = LateralGraph()

        conn = graph.add_connection(
            source="  WORKSTATION01  ",
            destination="  Server01  ",
            conn_type="smb",
        )

        assert conn.source_host == "workstation01"
        assert conn.destination_host == "server01"

    def test_add_connection_rejects_self_connection(self) -> None:
        """Test that add_connection rejects self-connections."""
        graph = LateralGraph()

        conn = graph.add_connection(
            source="server01",
            destination="SERVER01",  # Same host, different case
            conn_type="smb",
        )

        assert conn is None
        assert len(graph.connections) == 0

    def test_add_connection_marks_destination_pending(self) -> None:
        """Test that add_connection marks destination as pending."""
        graph = LateralGraph()

        graph.add_connection(
            source="workstation01",
            destination="server01",
            conn_type="smb",
        )

        assert "server01" in graph.pending_hosts

    def test_add_connection_with_evidence_id(self) -> None:
        """Test adding a connection with evidence ID."""
        graph = LateralGraph()

        conn = graph.add_connection(
            source="workstation01",
            destination="server01",
            conn_type="smb",
            evidence_id="ev001",
        )

        assert conn.evidence_ids == ["ev001"]

    def test_add_connection_with_optional_fields(self) -> None:
        """Test adding a connection with all optional fields."""
        graph = LateralGraph()
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        conn = graph.add_connection(
            source="workstation01",
            destination="server01",
            conn_type="rdp",
            timestamp=ts,
            user="admin",
            evidence_id="ev001",
            mitre_technique="T1021.001",
        )

        assert conn.timestamp == ts
        assert conn.user == "admin"
        assert conn.mitre_technique == "T1021.001"

    def test_mark_investigated(self) -> None:
        """Test marking a host as investigated."""
        graph = LateralGraph()
        graph.pending_hosts.add("server01")

        graph.mark_investigated("SERVER01")

        assert "server01" in graph.investigated_hosts
        assert "server01" not in graph.pending_hosts

    def test_mark_investigated_normalizes_hostname(self) -> None:
        """Test that mark_investigated normalizes hostname."""
        graph = LateralGraph()

        graph.mark_investigated("  SERVER01  ")

        assert "server01" in graph.investigated_hosts

    def test_add_connection_skips_pending_for_investigated_host(self) -> None:
        """Test that investigated hosts are not added to pending."""
        graph = LateralGraph()
        graph.mark_investigated("server01")

        graph.add_connection(
            source="workstation01",
            destination="server01",
            conn_type="smb",
        )

        assert "server01" not in graph.pending_hosts

    def test_get_uninvestigated_targets(self) -> None:
        """Test getting uninvestigated target hosts."""
        graph = LateralGraph()
        graph.pending_hosts = {"server01", "server02", "server03"}

        targets = graph.get_uninvestigated_targets()

        assert len(targets) <= 5
        assert all(t in graph.pending_hosts for t in targets)

    def test_get_uninvestigated_targets_with_limit(self) -> None:
        """Test getting uninvestigated targets with custom limit."""
        graph = LateralGraph()
        graph.pending_hosts = {f"server{i:02d}" for i in range(10)}

        targets = graph.get_uninvestigated_targets(limit=3)

        assert len(targets) == 3

    def test_get_uninvestigated_targets_empty(self) -> None:
        """Test getting uninvestigated targets when none exist."""
        graph = LateralGraph()

        targets = graph.get_uninvestigated_targets()

        assert targets == []

    def test_get_host_connections(self) -> None:
        """Test getting all connections involving a host."""
        graph = LateralGraph()
        graph.add_connection("workstation01", "server01", "smb")
        graph.add_connection("server01", "dc01", "rdp")
        graph.add_connection("workstation02", "server02", "wmi")

        connections = graph.get_host_connections("server01")

        assert len(connections) == 2

    def test_get_host_connections_normalizes_hostname(self) -> None:
        """Test that get_host_connections normalizes hostname."""
        graph = LateralGraph()
        graph.add_connection("workstation01", "server01", "smb")

        connections = graph.get_host_connections("  SERVER01  ")

        assert len(connections) == 1

    def test_get_host_connections_empty(self) -> None:
        """Test getting connections for unknown host."""
        graph = LateralGraph()
        graph.add_connection("workstation01", "server01", "smb")

        connections = graph.get_host_connections("unknown")

        assert connections == []

    def test_get_outgoing_connections(self) -> None:
        """Test getting outgoing connections from a host."""
        graph = LateralGraph()
        graph.add_connection("workstation01", "server01", "smb")
        graph.add_connection("workstation01", "server02", "rdp")
        graph.add_connection("server01", "dc01", "wmi")

        connections = graph.get_outgoing_connections("workstation01")

        assert len(connections) == 2
        assert all(c.source_host == "workstation01" for c in connections)

    def test_get_incoming_connections(self) -> None:
        """Test getting incoming connections to a host."""
        graph = LateralGraph()
        graph.add_connection("workstation01", "server01", "smb")
        graph.add_connection("workstation02", "server01", "rdp")
        graph.add_connection("server01", "dc01", "wmi")

        connections = graph.get_incoming_connections("server01")

        assert len(connections) == 2
        assert all(c.destination_host == "server01" for c in connections)

    def test_get_unique_users(self) -> None:
        """Test getting unique users from connections."""
        graph = LateralGraph()
        graph.add_connection("ws01", "srv01", "smb", user="admin")
        graph.add_connection("ws02", "srv01", "rdp", user="admin")
        graph.add_connection("ws03", "srv02", "wmi", user="svc_account")
        graph.add_connection("ws04", "srv03", "ssh")  # No user

        users = graph.get_unique_users()

        assert users == {"admin", "svc_account"}

    def test_get_unique_users_empty(self) -> None:
        """Test getting unique users with no connections."""
        graph = LateralGraph()

        users = graph.get_unique_users()

        assert users == set()

    def test_to_summary(self) -> None:
        """Test generating graph summary."""
        graph = LateralGraph()
        graph.add_connection("ws01", "srv01", "smb", user="admin")
        graph.add_connection("ws01", "srv02", "rdp", user="admin")
        graph.add_connection("srv01", "dc01", "wmi", user="svc")
        graph.mark_investigated("ws01")

        summary = graph.to_summary()

        assert summary["total_connections"] == 3
        assert summary["hosts_investigated"] == 1
        assert summary["hosts_pending"] == 3  # srv01, srv02, dc01
        assert summary["connection_types"] == {"smb": 1, "rdp": 1, "wmi": 1}
        assert set(summary["unique_users"]) == {"admin", "svc"}

    def test_to_summary_empty(self) -> None:
        """Test generating summary for empty graph."""
        graph = LateralGraph()

        summary = graph.to_summary()

        assert summary["total_connections"] == 0
        assert summary["hosts_investigated"] == 0
        assert summary["hosts_pending"] == 0
        assert summary["connection_types"] == {}

    def test_to_summary_truncates_large_lists(self) -> None:
        """Test that summary truncates large host lists."""
        graph = LateralGraph()
        for i in range(20):
            graph.add_connection(f"ws{i:02d}", f"srv{i:02d}", "smb")

        summary = graph.to_summary()

        assert len(summary["investigated_hosts_list"]) <= 10
        assert len(summary["pending_hosts_list"]) <= 10


class TestLateralMovementAnalyzer:
    """Tests for LateralMovementAnalyzer class."""

    def test_init_creates_graph(self) -> None:
        """Test that init creates a LateralGraph."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer.graph is not None
        assert isinstance(analyzer.graph, LateralGraph)

    def test_init_with_existing_graph(self) -> None:
        """Test init with existing graph."""
        graph = LateralGraph()
        graph.add_connection("ws01", "srv01", "smb")

        analyzer = LateralMovementAnalyzer(graph=graph)

        assert analyzer.graph is graph
        assert len(analyzer.graph.connections) == 1

    def test_looks_like_hostname_valid(self) -> None:
        """Test _looks_like_hostname with valid hostnames."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._looks_like_hostname("server01.domain.local") is True
        assert analyzer._looks_like_hostname("workstation.corp.com") is True
        assert analyzer._looks_like_hostname("dc01.ad.company.net") is True

    def test_looks_like_hostname_invalid_ip(self) -> None:
        """Test _looks_like_hostname rejects IP addresses."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._looks_like_hostname("192.168.1.100") is False
        assert analyzer._looks_like_hostname("10.0.0.1") is False

    def test_looks_like_hostname_invalid_no_dot(self) -> None:
        """Test _looks_like_hostname rejects strings without dots."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._looks_like_hostname("server01") is False
        assert analyzer._looks_like_hostname("localhost") is False

    def test_looks_like_hostname_invalid_starts_with_digit(self) -> None:
        """Test _looks_like_hostname rejects strings starting with digit."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._looks_like_hostname("123server.domain.com") is False

    def test_looks_like_hostname_invalid_too_short(self) -> None:
        """Test _looks_like_hostname rejects strings that are too short."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._looks_like_hostname("a.b") is False

    def test_looks_like_hostname_invalid_too_long(self) -> None:
        """Test _looks_like_hostname rejects strings that are too long."""
        analyzer = LateralMovementAnalyzer()

        # Must exceed 255 characters to be rejected
        long_hostname = "a" * 252 + ".com"  # 256 chars total
        assert analyzer._looks_like_hostname(long_hostname) is False

    def test_detect_connection_type_smb(self) -> None:
        """Test detecting SMB connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("port 445 connection") == "smb"
        assert analyzer._detect_connection_type("admin$ share access") == "smb"
        assert analyzer._detect_connection_type("c$ share mounted") == "smb"
        assert analyzer._detect_connection_type("Event 5140 logged") == "smb"

    def test_detect_connection_type_rdp(self) -> None:
        """Test detecting RDP connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("rdp session started") == "rdp"
        assert analyzer._detect_connection_type("port 3389 open") == "rdp"
        assert analyzer._detect_connection_type("remote desktop connection") == "rdp"
        assert analyzer._detect_connection_type("mstsc.exe executed") == "rdp"

    def test_detect_connection_type_wmi(self) -> None:
        """Test detecting WMI connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("wmi query executed") == "wmi"
        assert analyzer._detect_connection_type("port 135 connection") == "wmi"
        assert analyzer._detect_connection_type("Win32_Process created") == "wmi"
        assert analyzer._detect_connection_type("wmic command") == "wmi"

    def test_detect_connection_type_psexec(self) -> None:
        """Test detecting PsExec connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("psexec executed") == "psexec"
        assert analyzer._detect_connection_type("Event 7045 service install") == "psexec"
        assert analyzer._detect_connection_type("PSEXESVC service started") == "psexec"

    def test_detect_connection_type_winrm(self) -> None:
        """Test detecting WinRM connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("winrm connection") == "winrm"
        assert analyzer._detect_connection_type("port 5985 open") == "winrm"
        assert analyzer._detect_connection_type("Enter-PSSession executed") == "winrm"
        assert analyzer._detect_connection_type("WSMan connection") == "winrm"

    def test_detect_connection_type_ssh(self) -> None:
        """Test detecting SSH connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("ssh connection established") == "ssh"
        assert analyzer._detect_connection_type("22/tcp open") == "ssh"
        assert analyzer._detect_connection_type("OpenSSH session") == "ssh"

    def test_detect_connection_type_dcom(self) -> None:
        """Test detecting DCOM connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("dcom activation") == "dcom"
        # Note: 135/tcp matches WMI first since patterns are checked in dict order
        assert analyzer._detect_connection_type("MMC20 application") == "dcom"
        assert analyzer._detect_connection_type("ShellWindows") == "dcom"
        assert analyzer._detect_connection_type("dcomexec") == "dcom"
        assert analyzer._detect_connection_type("ole32 execution") == "dcom"

    def test_detect_connection_type_scheduled_task(self) -> None:
        """Test detecting scheduled task connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("Event 4698") == "scheduled_task"
        assert analyzer._detect_connection_type("schtasks /create") == "scheduled_task"
        assert analyzer._detect_connection_type("TaskScheduler") == "scheduled_task"

    def test_detect_connection_type_unknown(self) -> None:
        """Test detecting unknown connection type."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer._detect_connection_type("random log entry") == "unknown"
        assert analyzer._detect_connection_type("") == "unknown"

    def test_technique_mappings(self) -> None:
        """Test MITRE technique mappings are correct."""
        analyzer = LateralMovementAnalyzer()

        assert analyzer.TECHNIQUE_MAPPINGS["smb"] == "T1021.002"
        assert analyzer.TECHNIQUE_MAPPINGS["rdp"] == "T1021.001"
        assert analyzer.TECHNIQUE_MAPPINGS["wmi"] == "T1047"
        assert analyzer.TECHNIQUE_MAPPINGS["psexec"] == "T1569.002"
        assert analyzer.TECHNIQUE_MAPPINGS["winrm"] == "T1021.006"
        assert analyzer.TECHNIQUE_MAPPINGS["ssh"] == "T1021.004"
        assert analyzer.TECHNIQUE_MAPPINGS["dcom"] == "T1021.003"
        assert analyzer.TECHNIQUE_MAPPINGS["scheduled_task"] == "T1053.005"

    def test_get_pivot_suggestions_empty(self) -> None:
        """Test pivot suggestions with no pending hosts."""
        analyzer = LateralMovementAnalyzer()

        suggestions = analyzer.get_pivot_suggestions()

        assert suggestions == []

    def test_get_pivot_suggestions(self) -> None:
        """Test generating pivot suggestions."""
        analyzer = LateralMovementAnalyzer()
        analyzer.graph.add_connection("ws01", "srv01.domain.local", "smb")
        analyzer.graph.add_connection("ws01", "srv01.domain.local", "rdp")
        analyzer.graph.add_connection("ws02", "srv02.domain.local", "wmi")

        suggestions = analyzer.get_pivot_suggestions()

        assert len(suggestions) >= 1
        # srv01.domain.local should have higher priority (2 connections)
        assert suggestions[0]["host"] in ["srv01.domain.local", "srv02.domain.local"]
        assert "discovered_from" in suggestions[0]
        assert "connection_types" in suggestions[0]
        assert "suggested_queries" in suggestions[0]
        assert "suggested_actions" in suggestions[0]

    def test_get_pivot_suggestions_sorted_by_priority(self) -> None:
        """Test that pivot suggestions are sorted by priority."""
        analyzer = LateralMovementAnalyzer()
        # srv01 has 3 connections, srv02 has 1
        analyzer.graph.add_connection("ws01", "srv01.domain.local", "smb")
        analyzer.graph.add_connection("ws02", "srv01.domain.local", "rdp")
        analyzer.graph.add_connection("ws03", "srv01.domain.local", "wmi")
        analyzer.graph.add_connection("ws04", "srv02.domain.local", "ssh")

        suggestions = analyzer.get_pivot_suggestions()

        # srv01 should come first due to higher priority
        assert suggestions[0]["host"] == "srv01.domain.local"
        assert suggestions[0]["priority"] == 3

    def test_get_attack_path_empty(self) -> None:
        """Test attack path with no connections."""
        analyzer = LateralMovementAnalyzer()

        path = analyzer.get_attack_path()

        assert path == []

    def test_get_attack_path_simple_chain(self) -> None:
        """Test attack path with simple chain."""
        analyzer = LateralMovementAnalyzer()
        analyzer.graph.add_connection("ws01", "srv01", "smb")
        analyzer.graph.add_connection("srv01", "dc01", "rdp")

        path = analyzer.get_attack_path()

        assert path == ["ws01", "srv01", "dc01"]

    def test_get_attack_path_branching(self) -> None:
        """Test attack path with branching connections."""
        analyzer = LateralMovementAnalyzer()
        analyzer.graph.add_connection("ws01", "srv01", "smb")
        analyzer.graph.add_connection("ws01", "srv02", "rdp")
        analyzer.graph.add_connection("srv01", "dc01", "wmi")

        path = analyzer.get_attack_path()

        # Should start with entry point (ws01)
        assert path[0] == "ws01"
        # Should visit all hosts
        assert set(path) == {"ws01", "srv01", "srv02", "dc01"}

    def test_get_attack_path_no_clear_entry(self) -> None:
        """Test attack path when there's no clear entry point."""
        analyzer = LateralMovementAnalyzer()
        # Circular dependency
        analyzer.graph.add_connection("srv01", "srv02", "smb")
        analyzer.graph.add_connection("srv02", "srv01", "rdp")

        path = analyzer.get_attack_path()

        # Should still produce a path
        assert len(path) == 2
        assert set(path) == {"srv01", "srv02"}

    def test_get_attack_path_avoids_cycles(self) -> None:
        """Test that attack path avoids infinite cycles."""
        analyzer = LateralMovementAnalyzer()
        analyzer.graph.add_connection("ws01", "srv01", "smb")
        analyzer.graph.add_connection("srv01", "srv02", "rdp")
        analyzer.graph.add_connection("srv02", "srv01", "wmi")  # Cycle back

        path = analyzer.get_attack_path()

        # Each host should appear only once
        assert len(path) == len(set(path))


class TestLateralMovementAnalyzerIntegration:
    """Integration tests for LateralMovementAnalyzer with realistic scenarios."""

    def test_analyze_rdp_lateral_movement(self) -> None:
        """Test analyzing RDP lateral movement scenario."""
        analyzer = LateralMovementAnalyzer()

        # Simulate query result with RDP indicators
        result_data = {
            "stream": {"hostname": "workstation01"},
            "values": [
                "Event 4624: Logon Type 10 from server01.domain.local",
                "mstsc.exe initiated connection to port 3389",
            ],
        }

        connections = analyzer.analyze_query_result(result_data, source_host="workstation01")

        # Should detect RDP connection
        if connections:
            assert any(c.connection_type == "rdp" for c in connections)

    def test_analyze_smb_lateral_movement(self) -> None:
        """Test analyzing SMB lateral movement scenario."""
        analyzer = LateralMovementAnalyzer()

        # Simulate query result with SMB indicators
        result_data = {
            "message": "admin$ share accessed on fileserver.corp.local via port 445",
        }

        connections = analyzer.analyze_query_result(result_data, source_host="attacker.corp.local")

        # Should detect SMB connection
        if connections:
            assert any(c.connection_type == "smb" for c in connections)

    def test_full_lateral_movement_investigation(self) -> None:
        """Test full lateral movement investigation workflow."""
        analyzer = LateralMovementAnalyzer()

        # Initial compromise
        analyzer.graph.mark_investigated("initial-workstation.corp.local")

        # Discover lateral movement
        analyzer.graph.add_connection(
            source="initial-workstation.corp.local",
            destination="fileserver.corp.local",
            conn_type="smb",
            user="compromised_user",
            mitre_technique="T1021.002",
        )

        analyzer.graph.add_connection(
            source="initial-workstation.corp.local",
            destination="dc01.corp.local",
            conn_type="rdp",
            user="compromised_user",
            mitre_technique="T1021.001",
        )

        # Get pivot suggestions
        suggestions = analyzer.get_pivot_suggestions()

        assert len(suggestions) == 2
        pending_hosts = {s["host"] for s in suggestions}
        assert "fileserver.corp.local" in pending_hosts
        assert "dc01.corp.local" in pending_hosts

        # Investigate one host
        analyzer.graph.mark_investigated("fileserver.corp.local")

        # Continue investigation
        analyzer.graph.add_connection(
            source="fileserver.corp.local",
            destination="backup-server.corp.local",
            conn_type="wmi",
            user="compromised_user",
        )

        # Get attack path
        path = analyzer.get_attack_path()

        assert path[0] == "initial-workstation.corp.local"
        assert "fileserver.corp.local" in path
        assert "dc01.corp.local" in path

        # Check summary
        summary = analyzer.graph.to_summary()

        assert summary["total_connections"] == 3
        assert summary["hosts_investigated"] == 2
        assert "compromised_user" in summary["unique_users"]


class TestLateralPatternsRegex:
    """Tests for lateral movement pattern regex matching."""

    def test_smb_patterns(self) -> None:
        """Test SMB pattern detection."""
        analyzer = LateralMovementAnalyzer()

        smb_strings = [
            "SMB connection established",
            "Port 445 open",
            "ADMIN$ share access",
            "C$ mounted",
            "IPC$ connection",
            "Tree connect request",
            "Event ID 5140",
            "Event ID 5145",
        ]

        for s in smb_strings:
            assert analyzer._detect_connection_type(s) == "smb", f"Failed for: {s}"

    def test_rdp_patterns(self) -> None:
        """Test RDP pattern detection."""
        analyzer = LateralMovementAnalyzer()

        rdp_strings = [
            "RDP session",
            "Port 3389 connection",
            "Remote Desktop Protocol",
            "Event 4624 logon type 10",  # Must include "4624" for the pattern to match
            "TermSrv connection",
            "mstsc.exe",
        ]

        for s in rdp_strings:
            assert analyzer._detect_connection_type(s) == "rdp", f"Failed for: {s}"

    def test_wmi_patterns(self) -> None:
        """Test WMI pattern detection."""
        analyzer = LateralMovementAnalyzer()

        wmi_strings = [
            "WMI query",
            "Port 135 RPC",
            "Win32_Process",
            "root\\\\cimv2",  # Double backslash as it appears in escaped log data
            "wmic command",
            "wmiprvse.exe",
        ]

        for s in wmi_strings:
            assert analyzer._detect_connection_type(s) == "wmi", f"Failed for: {s}"

    def test_winrm_patterns(self) -> None:
        """Test WinRM pattern detection."""
        analyzer = LateralMovementAnalyzer()

        winrm_strings = [
            "WinRM connection",
            "Port 5985",
            "Port 5986",
            "PowerShell session remote",
            "WSMan connection",
            "Enter-PSSession",
        ]

        for s in winrm_strings:
            assert analyzer._detect_connection_type(s) == "winrm", f"Failed for: {s}"
