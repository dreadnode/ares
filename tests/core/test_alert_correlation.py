"""Tests for the Alert Correlation module."""

from datetime import datetime, timezone

import pytest

from ares.core.alert_correlation import AlertCluster, AlertCorrelator


class TestAlertCluster:
    """Tests for AlertCluster dataclass."""

    def test_create_empty_cluster(self) -> None:
        """Test creating an empty cluster."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        assert cluster.cluster_id == "cluster-0001"
        assert cluster.alerts == []
        assert cluster.common_hosts == set()
        assert cluster.common_users == set()
        assert cluster.common_ips == set()
        assert cluster.techniques == set()
        assert cluster.time_range is None

    def test_add_alert_extracts_hostname_from_labels(self) -> None:
        """Test that add_alert extracts hostname from various label keys."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"hostname": "WORKSTATION01"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "workstation01" in cluster.common_hosts
        assert len(cluster.alerts) == 1

    def test_add_alert_extracts_host_from_labels(self) -> None:
        """Test that add_alert extracts host from 'host' label key."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"host": "SERVER01"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "server01" in cluster.common_hosts

    def test_add_alert_extracts_computer_from_labels(self) -> None:
        """Test that add_alert extracts host from 'computer' label key."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"computer": "DC01"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "dc01" in cluster.common_hosts

    def test_add_alert_extracts_host_from_instance(self) -> None:
        """Test that add_alert extracts host from instance label."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"instance": "webserver01:9090"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "webserver01" in cluster.common_hosts

    def test_add_alert_skips_ip_in_instance(self) -> None:
        """Test that add_alert skips IP addresses in instance label."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"instance": "192.168.58.100:9090"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        # Should not add IP as hostname
        assert "192.168.58.100" not in cluster.common_hosts

    def test_add_alert_extracts_users_from_labels(self) -> None:
        """Test that add_alert extracts users from various label keys."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"user": "Admin"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "admin" in cluster.common_users

    def test_add_alert_extracts_users_from_annotations(self) -> None:
        """Test that add_alert extracts users from annotations."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {},
            "annotations": {"TargetUserName": "ServiceAccount"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "serviceaccount" in cluster.common_users

    def test_add_alert_extracts_multiple_user_keys(self) -> None:
        """Test that add_alert extracts users from multiple keys."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {
                "user": "User1",
                "username": "User2",
                "account": "User3",
            },
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "user1" in cluster.common_users
        assert "user2" in cluster.common_users
        assert "user3" in cluster.common_users

    def test_add_alert_extracts_ips(self) -> None:
        """Test that add_alert extracts IP addresses."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {
                "ip": "192.168.58.100",
                "source_ip": "192.168.58.50",
            },
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "192.168.58.100" in cluster.common_ips
        assert "192.168.58.50" in cluster.common_ips

    def test_add_alert_extracts_techniques_string(self) -> None:
        """Test that add_alert extracts MITRE techniques as string."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"mitre_technique": "T1059.001"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "T1059.001" in cluster.techniques

    def test_add_alert_extracts_techniques_list(self) -> None:
        """Test that add_alert extracts MITRE techniques as list."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"mitre_technique": ["T1059.001", "T1078"]},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert "T1059.001" in cluster.techniques
        assert "T1078" in cluster.techniques

    def test_add_alert_updates_time_range_initial(self) -> None:
        """Test that add_alert sets initial time range."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {},
            "startsAt": "2024-01-15T10:00:00Z",
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert cluster.time_range is not None
        assert cluster.time_range[0] == cluster.time_range[1]

    def test_add_alert_expands_time_range(self) -> None:
        """Test that add_alert expands time range with new alerts."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert1 = {
            "labels": {},
            "startsAt": "2024-01-15T10:00:00Z",
            "fingerprint": "abc123",
        }
        alert2 = {
            "labels": {},
            "startsAt": "2024-01-15T12:00:00Z",
            "fingerprint": "def456",
        }
        cluster.add_alert(alert1)
        cluster.add_alert(alert2)

        assert cluster.time_range is not None
        assert cluster.time_range[0] < cluster.time_range[1]

    def test_add_alert_handles_invalid_timestamp(self) -> None:
        """Test that add_alert handles invalid timestamps gracefully."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {},
            "startsAt": "invalid-timestamp",
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        # Should not crash, time_range remains None
        assert cluster.time_range is None

    def test_add_alert_handles_missing_labels(self) -> None:
        """Test that add_alert handles alerts without labels."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {"fingerprint": "abc123"}
        cluster.add_alert(alert)

        assert len(cluster.alerts) == 1
        assert cluster.common_hosts == set()

    def test_similarity_score_host_match(self) -> None:
        """Test similarity score with matching host."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_hosts.add("server01")

        alert = {"labels": {"hostname": "SERVER01"}}
        score = cluster.similarity_score(alert)

        assert score >= 0.4  # Host match gives 0.4

    def test_similarity_score_user_match(self) -> None:
        """Test similarity score with matching user."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_users.add("admin")

        alert = {"labels": {"user": "Admin"}}
        score = cluster.similarity_score(alert)

        assert score >= 0.3  # User match gives 0.3

    def test_similarity_score_ip_match(self) -> None:
        """Test similarity score with matching IP."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_ips.add("192.168.58.100")

        alert = {"labels": {"ip": "192.168.58.100"}}
        score = cluster.similarity_score(alert)

        assert score >= 0.2  # IP match gives 0.2

    def test_similarity_score_technique_match_string(self) -> None:
        """Test similarity score with matching technique (string)."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.techniques.add("T1059.001")

        alert = {"labels": {"mitre_technique": "T1059.001"}}
        score = cluster.similarity_score(alert)

        assert score >= 0.2  # Technique match gives 0.2

    def test_similarity_score_technique_match_list(self) -> None:
        """Test similarity score with matching technique (list)."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.techniques.add("T1059.001")

        alert = {"labels": {"mitre_technique": ["T1078", "T1059.001"]}}
        score = cluster.similarity_score(alert)

        assert score >= 0.2  # Technique match gives 0.2

    def test_similarity_score_time_proximity(self) -> None:
        """Test similarity score with time proximity bonus."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_hosts.add("server01")
        cluster.time_range = (
            datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
        )

        alert = {
            "labels": {"hostname": "server01"},
            "startsAt": "2024-01-15T10:30:00Z",
        }
        score = cluster.similarity_score(alert)

        # Should get host match + time proximity bonus
        assert score >= 0.5

    def test_similarity_score_multiple_matches(self) -> None:
        """Test similarity score with multiple matches."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_hosts.add("server01")
        cluster.common_users.add("admin")
        cluster.common_ips.add("192.168.58.100")

        alert = {
            "labels": {
                "hostname": "server01",
                "user": "admin",
                "ip": "192.168.58.100",
            }
        }
        score = cluster.similarity_score(alert)

        # Should get host (0.4) + user (0.3) + IP (0.2) = 0.9
        # Use pytest.approx for floating point comparison
        assert score == pytest.approx(0.9, abs=0.01)

    def test_similarity_score_capped_at_one(self) -> None:
        """Test that similarity score is capped at 1.0."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_hosts.add("server01")
        cluster.common_users.add("admin")
        cluster.common_ips.add("192.168.58.100")
        cluster.techniques.add("T1059.001")
        cluster.time_range = (
            datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
        )

        alert = {
            "labels": {
                "hostname": "server01",
                "user": "admin",
                "ip": "192.168.58.100",
                "mitre_technique": "T1059.001",
            },
            "startsAt": "2024-01-15T10:30:00Z",
        }
        score = cluster.similarity_score(alert)

        assert score == 1.0

    def test_similarity_score_no_match(self) -> None:
        """Test similarity score with no matches."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_hosts.add("server01")

        alert = {"labels": {"hostname": "server02"}}
        score = cluster.similarity_score(alert)

        assert score == 0.0

    def test_similarity_score_instance_host_match(self) -> None:
        """Test similarity score with instance-based host match."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_hosts.add("webserver01")

        alert = {"labels": {"instance": "webserver01:9090"}}
        score = cluster.similarity_score(alert)

        assert score >= 0.3  # Instance host match gives 0.3

    def test_add_alert_extracts_operation_id(self) -> None:
        """Test that add_alert extracts operation_id from operation_context."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        alert = {
            "labels": {"hostname": "server01"},
            "operation_context": {"operation_id": "op-20260303-123456"},
            "fingerprint": "abc123",
        }
        cluster.add_alert(alert)

        assert cluster.operation_id == "op-20260303-123456"

    def test_similarity_score_operation_id_match(self) -> None:
        """Test that matching operation_id gives small bonus (not auto-cluster)."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.operation_id = "op-20260303-123456"

        # Alert with same operation_id but different host/domain
        alert = {
            "labels": {"hostname": "different-host"},
            "operation_context": {"operation_id": "op-20260303-123456"},
        }
        score = cluster.similarity_score(alert)

        # Same operation_id gives 0.1 bonus - NOT enough to auto-cluster (threshold 0.3)
        # This prevents all alerts from same operation being forced into one cluster
        assert score == pytest.approx(0.1, abs=0.01)

    def test_similarity_score_operation_id_mismatch(self) -> None:
        """Test that different operation_ids don't boost score."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.operation_id = "op-20260303-111111"

        alert = {
            "labels": {"hostname": "server01"},
            "operation_context": {"operation_id": "op-20260303-222222"},
        }
        score = cluster.similarity_score(alert)

        # No operation_id boost, no host match either
        assert score == 0.0

    def test_similarity_score_operation_id_only_in_alert(self) -> None:
        """Test scoring when cluster has no operation_id but alert does."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        # cluster.operation_id is None

        alert = {
            "labels": {"hostname": "server01"},
            "operation_context": {"operation_id": "op-20260303-123456"},
        }
        score = cluster.similarity_score(alert)

        # No operation_id match (cluster has none), no host match
        assert score == 0.0

    def test_to_summary(self) -> None:
        """Test cluster summary generation."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.alerts = [{"id": 1}, {"id": 2}]
        cluster.common_hosts = {"server01", "server02"}
        cluster.common_users = {"admin"}
        cluster.common_ips = {"192.168.58.100"}
        cluster.techniques = {"T1059.001"}
        cluster.operation_id = "op-20260303-123456"
        cluster.time_range = (
            datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        )

        summary = cluster.to_summary()

        assert summary["cluster_id"] == "cluster-0001"
        assert summary["alert_count"] == 2
        assert summary["operation_id"] == "op-20260303-123456"
        assert len(summary["common_hosts"]) == 2
        assert len(summary["common_users"]) == 1
        assert summary["time_range"]["start"] is not None
        assert summary["time_range"]["end"] is not None

    def test_to_summary_no_time_range(self) -> None:
        """Test cluster summary when time_range is None."""
        cluster = AlertCluster(cluster_id="cluster-0001")

        summary = cluster.to_summary()

        assert summary["time_range"]["start"] is None
        assert summary["time_range"]["end"] is None

    def test_to_summary_truncates_large_lists(self) -> None:
        """Test that summary truncates large lists to 10 items."""
        cluster = AlertCluster(cluster_id="cluster-0001")
        cluster.common_hosts = {f"host{i}" for i in range(20)}

        summary = cluster.to_summary()

        assert len(summary["common_hosts"]) == 10


class TestAlertCorrelator:
    """Tests for AlertCorrelator class."""

    def test_init(self) -> None:
        """Test correlator initialization."""
        correlator = AlertCorrelator()

        assert correlator.clusters == []
        assert correlator._cluster_counter == 0
        assert correlator._alert_to_cluster == {}
        assert correlator.CLUSTER_THRESHOLD == 0.3

    def test_add_alert_creates_new_cluster(self) -> None:
        """Test that add_alert creates a new cluster for first alert."""
        correlator = AlertCorrelator()

        alert = {
            "labels": {"hostname": "server01"},
            "fingerprint": "abc123",
        }
        cluster = correlator.add_alert(alert)

        assert cluster is not None
        assert cluster.cluster_id == "cluster-0001"
        assert len(correlator.clusters) == 1
        assert "abc123" in correlator._alert_to_cluster

    def test_add_alert_joins_existing_cluster(self) -> None:
        """Test that add_alert joins existing cluster on high similarity."""
        correlator = AlertCorrelator()

        alert1 = {
            "labels": {"hostname": "server01", "user": "admin"},
            "fingerprint": "abc123",
        }
        alert2 = {
            "labels": {"hostname": "server01", "user": "admin"},
            "fingerprint": "def456",
        }

        cluster1 = correlator.add_alert(alert1)
        cluster2 = correlator.add_alert(alert2)

        assert cluster1 is cluster2
        assert len(correlator.clusters) == 1
        assert len(cluster1.alerts) == 2

    def test_add_alert_creates_separate_cluster_on_low_similarity(self) -> None:
        """Test that add_alert creates new cluster on low similarity."""
        correlator = AlertCorrelator()

        alert1 = {
            "labels": {"hostname": "server01"},
            "fingerprint": "abc123",
        }
        alert2 = {
            "labels": {"hostname": "different-server"},
            "fingerprint": "def456",
        }

        cluster1 = correlator.add_alert(alert1)
        cluster2 = correlator.add_alert(alert2)

        assert cluster1 is not cluster2
        assert len(correlator.clusters) == 2

    def test_add_alert_uses_id_as_fingerprint_fallback(self) -> None:
        """Test that add_alert uses id() as fingerprint when not provided."""
        correlator = AlertCorrelator()

        alert = {"labels": {"hostname": "server01"}}
        correlator.add_alert(alert)

        # Should not crash, and alert should be tracked
        assert len(correlator.clusters) == 1

    def test_add_alert_threshold_boundary(self) -> None:
        """Test add_alert behavior at threshold boundary."""
        correlator = AlertCorrelator()

        # First alert
        alert1 = {
            "labels": {"hostname": "server01"},
            "fingerprint": "abc123",
        }
        correlator.add_alert(alert1)

        # Alert with exactly 0.3 similarity (IP match = 0.2, below threshold)
        alert2 = {
            "labels": {"ip": "192.168.58.100"},
            "fingerprint": "def456",
        }
        # This has different host, only IP would match (0.2 < 0.3 threshold)
        # So it should create a new cluster

        # But first, add an IP to make it matchable
        correlator.clusters[0].common_ips.add("192.168.58.100")

        correlator.add_alert(alert2)

        # IP match only gives 0.2, which is below 0.3 threshold
        # So should create new cluster
        assert len(correlator.clusters) == 2

    def test_get_cluster_context_for_clustered_alert(self) -> None:
        """Test get_cluster_context for alert in a cluster."""
        correlator = AlertCorrelator()

        alert1 = {
            "labels": {"hostname": "server01", "user": "admin"},
            "fingerprint": "abc123",
        }
        alert2 = {
            "labels": {"hostname": "server01", "user": "admin"},
            "fingerprint": "def456",
        }
        correlator.add_alert(alert1)
        correlator.add_alert(alert2)

        context = correlator.get_cluster_context(alert1)

        assert context["cluster_id"] == "cluster-0001"
        assert context["related_alerts"] == 1  # Excludes current alert
        assert "server01" in context["common_hosts"]
        assert "admin" in context["common_users"]

    def test_get_cluster_context_for_unclustered_alert(self) -> None:
        """Test get_cluster_context for alert not in any cluster."""
        correlator = AlertCorrelator()

        alert = {"labels": {}, "fingerprint": "abc123"}
        context = correlator.get_cluster_context(alert)

        assert context["cluster_id"] is None
        assert "message" in context

    def test_get_cluster_for_alert(self) -> None:
        """Test get_cluster_for_alert returns correct cluster."""
        correlator = AlertCorrelator()

        alert = {
            "labels": {"hostname": "server01"},
            "fingerprint": "abc123",
        }
        added_cluster = correlator.add_alert(alert)
        retrieved_cluster = correlator.get_cluster_for_alert(alert)

        assert retrieved_cluster is added_cluster

    def test_get_cluster_for_alert_not_found(self) -> None:
        """Test get_cluster_for_alert returns None for unknown alert."""
        correlator = AlertCorrelator()

        alert = {"labels": {}, "fingerprint": "unknown"}
        cluster = correlator.get_cluster_for_alert(alert)

        assert cluster is None

    def test_get_all_clusters_summary(self) -> None:
        """Test get_all_clusters_summary returns summaries for all clusters."""
        correlator = AlertCorrelator()

        alert1 = {
            "labels": {"hostname": "server01"},
            "fingerprint": "abc123",
        }
        alert2 = {
            "labels": {"hostname": "server02"},
            "fingerprint": "def456",
        }
        correlator.add_alert(alert1)
        correlator.add_alert(alert2)

        summaries = correlator.get_all_clusters_summary()

        assert len(summaries) == 2
        assert all("cluster_id" in s for s in summaries)

    def test_get_related_alerts(self) -> None:
        """Test get_related_alerts returns other alerts in cluster."""
        correlator = AlertCorrelator()

        alert1 = {
            "labels": {"hostname": "server01", "user": "admin"},
            "fingerprint": "abc123",
        }
        alert2 = {
            "labels": {"hostname": "server01", "user": "admin"},
            "fingerprint": "def456",
        }
        alert3 = {
            "labels": {"hostname": "server01", "user": "admin"},
            "fingerprint": "ghi789",
        }
        correlator.add_alert(alert1)
        correlator.add_alert(alert2)
        correlator.add_alert(alert3)

        related = correlator.get_related_alerts(alert1)

        assert len(related) == 2
        fingerprints = [a.get("fingerprint") for a in related]
        assert "def456" in fingerprints
        assert "ghi789" in fingerprints
        assert "abc123" not in fingerprints  # Excludes the queried alert

    def test_get_related_alerts_not_found(self) -> None:
        """Test get_related_alerts returns empty for unknown alert."""
        correlator = AlertCorrelator()

        alert = {"labels": {}, "fingerprint": "unknown"}
        related = correlator.get_related_alerts(alert)

        assert related == []

    def test_reset(self) -> None:
        """Test reset clears all state."""
        correlator = AlertCorrelator()

        alert = {
            "labels": {"hostname": "server01"},
            "fingerprint": "abc123",
        }
        correlator.add_alert(alert)
        correlator.reset()

        assert correlator.clusters == []
        assert correlator._cluster_counter == 0
        assert correlator._alert_to_cluster == {}

    def test_cluster_id_incrementing(self) -> None:
        """Test that cluster IDs increment correctly."""
        correlator = AlertCorrelator()

        alerts = [
            {"labels": {"hostname": f"server{i:02d}"}, "fingerprint": f"fp{i}"} for i in range(5)
        ]
        clusters = [correlator.add_alert(a) for a in alerts]

        cluster_ids = [c.cluster_id for c in clusters]
        assert cluster_ids == [
            "cluster-0001",
            "cluster-0002",
            "cluster-0003",
            "cluster-0004",
            "cluster-0005",
        ]


class TestAlertCorrelatorIntegration:
    """Integration tests for AlertCorrelator with realistic scenarios."""

    def test_correlate_authentication_attack(self) -> None:
        """Test correlating multiple alerts from an authentication attack."""
        correlator = AlertCorrelator()

        # Simulated authentication attack alerts
        alerts = [
            {
                "labels": {
                    "hostname": "DC01",
                    "user": "admin",
                    "mitre_technique": "T1078",
                },
                "startsAt": "2024-01-15T10:00:00Z",
                "fingerprint": "auth1",
            },
            {
                "labels": {
                    "hostname": "DC01",
                    "user": "admin",
                    "mitre_technique": "T1110",
                },
                "startsAt": "2024-01-15T10:05:00Z",
                "fingerprint": "auth2",
            },
            {
                "labels": {
                    "hostname": "DC01",
                    "user": "admin",
                    "source_ip": "192.168.58.100",
                },
                "startsAt": "2024-01-15T10:10:00Z",
                "fingerprint": "auth3",
            },
        ]

        for alert in alerts:
            correlator.add_alert(alert)

        # All should be in the same cluster (same host + user)
        assert len(correlator.clusters) == 1
        assert len(correlator.clusters[0].alerts) == 3

    def test_correlate_separate_incidents(self) -> None:
        """Test that unrelated alerts create separate clusters."""
        correlator = AlertCorrelator()

        # Two separate incidents
        incident1_alerts = [
            {
                "labels": {"hostname": "WORKSTATION01", "user": "user1"},
                "fingerprint": "inc1_alert1",
            },
            {
                "labels": {"hostname": "WORKSTATION01", "user": "user1"},
                "fingerprint": "inc1_alert2",
            },
        ]
        incident2_alerts = [
            {
                "labels": {"hostname": "SERVER99", "user": "svc-sql"},
                "fingerprint": "inc2_alert1",
            },
            {
                "labels": {"hostname": "SERVER99", "user": "svc-sql"},
                "fingerprint": "inc2_alert2",
            },
        ]

        for alert in incident1_alerts + incident2_alerts:
            correlator.add_alert(alert)

        assert len(correlator.clusters) == 2
        assert all(len(c.alerts) == 2 for c in correlator.clusters)

    def test_correlate_lateral_movement_chain(self) -> None:
        """Test correlating alerts from lateral movement across hosts."""
        correlator = AlertCorrelator()

        # Lateral movement: same user across multiple hosts
        alerts = [
            {
                "labels": {
                    "hostname": "WORKSTATION01",
                    "user": "danj",
                    "source_ip": "192.168.58.10",
                },
                "fingerprint": "lat1",
            },
            {
                "labels": {
                    "hostname": "SERVER01",
                    "user": "danj",
                    "source_ip": "192.168.58.10",
                },
                "fingerprint": "lat2",
            },
            {
                "labels": {
                    "hostname": "DC01",
                    "user": "danj",
                    "source_ip": "192.168.58.10",
                },
                "fingerprint": "lat3",
            },
        ]

        for alert in alerts:
            correlator.add_alert(alert)

        # Should be correlated by user + source_ip
        assert len(correlator.clusters) <= 2  # Might create 1-2 clusters depending on ordering

    def test_correlate_cross_domain_attack_separate_clusters(self) -> None:
        """Test that cross-domain alerts with only operation_id match create separate clusters.

        Previously operation_id match auto-clustered ALL alerts into one cluster (return 1.0).
        This was a bug - it prevented parallel investigations of different incidents.
        Now operation_id only gives a 0.1 bonus, so alerts with different hosts/users/IPs
        will correctly create separate clusters for parallel investigation.
        """
        correlator = AlertCorrelator()

        # Cross-domain attack - different hosts, users, and domains
        operation_id = "op-20260303-123456"
        alerts = [
            {
                "labels": {
                    "hostname": "dc01.contoso.local",
                    "user": "admin",
                    "mitre_technique": "T1003",
                },
                "operation_context": {"operation_id": operation_id},
                "fingerprint": "cross1",
            },
            {
                "labels": {
                    "hostname": "dc01.fabrikam.local",  # Different domain
                    "user": "svc_sql",  # Different user
                    "mitre_technique": "T1558",
                },
                "operation_context": {"operation_id": operation_id},
                "fingerprint": "cross2",
            },
            {
                "labels": {
                    "hostname": "web01.child.contoso.local",  # Child domain
                    "user": "krbtgt",  # Different user
                    "mitre_technique": "T1558.003",
                },
                "operation_context": {"operation_id": operation_id},
                "fingerprint": "cross3",
            },
        ]

        for alert in alerts:
            correlator.add_alert(alert)

        # Alerts should create SEPARATE clusters since they have different hosts/users
        # operation_id only adds 0.1 bonus, not enough to auto-cluster (threshold 0.3)
        assert len(correlator.clusters) == 3
        # Each cluster should have operation_id set
        for cluster in correlator.clusters:
            assert cluster.operation_id == operation_id

    def test_alerts_cluster_by_host_not_operation_id(self) -> None:
        """Test that alerts cluster by host/user/IP, NOT by operation_id.

        Operation ID only provides a small bonus (0.1) - not enough to cluster
        alerts that would otherwise be unrelated. This enables parallel
        investigation of different incidents within the same operation.
        """
        correlator = AlertCorrelator()

        # Same operation but different hosts - should create separate clusters
        alerts = [
            {
                "labels": {"hostname": "dc01.contoso.local", "user": "admin"},
                "operation_context": {"operation_id": "op-111111-111111"},
                "fingerprint": "op1_alert1",
            },
            {
                # Same host + user = should cluster with previous
                "labels": {"hostname": "dc01.contoso.local", "user": "admin"},
                "operation_context": {"operation_id": "op-111111-111111"},
                "fingerprint": "op1_alert2",
            },
            {
                # Different host = should NOT cluster (operation_id only adds 0.1)
                "labels": {"hostname": "dc01.fabrikam.local", "user": "svc_sql"},
                "operation_context": {"operation_id": "op-111111-111111"},
                "fingerprint": "op1_alert3",
            },
        ]

        for alert in alerts:
            correlator.add_alert(alert)

        # Should create 2 clusters - grouped by host/user, not by operation
        assert len(correlator.clusters) == 2
        # First cluster has 2 alerts (same host+user)
        assert len(correlator.clusters[0].alerts) == 2
        # Second cluster has 1 alert (different host)
        assert len(correlator.clusters[1].alerts) == 1
