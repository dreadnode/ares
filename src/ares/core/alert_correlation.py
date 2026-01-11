"""Alert correlation engine for grouping related alerts.

This module provides:
1. Alert clustering based on shared characteristics (hosts, users, IPs, techniques)
2. Similarity scoring between alerts
3. Correlation context for investigations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from loguru import logger


@dataclass
class AlertCluster:
    """A cluster of related alerts."""

    cluster_id: str
    alerts: list[dict] = field(default_factory=list)
    common_hosts: set[str] = field(default_factory=set)
    common_users: set[str] = field(default_factory=set)
    common_ips: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    time_range: tuple[datetime, datetime] | None = None

    def add_alert(self, alert: dict) -> None:  # noqa: PLR0912
        """Add an alert to the cluster.

        Args:
            alert: Alert dictionary from Grafana
        """
        self.alerts.append(alert)

        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        # Extract hosts
        for key in ["hostname", "host", "computer"]:
            if key in labels:
                self.common_hosts.add(labels[key].lower())
        # Instance often contains host:port
        if "instance" in labels:
            host = labels["instance"].split(":")[0]
            if host and not host[0].isdigit():  # Skip if IP
                self.common_hosts.add(host.lower())

        # Extract users
        for key in ["user", "username", "account", "TargetUserName", "SubjectUserName"]:
            if key in labels:
                self.common_users.add(labels[key].lower())
            if key in annotations:
                self.common_users.add(annotations[key].lower())

        # Extract IPs
        for key in ["ip", "source_ip", "src_ip", "IpAddress", "ClientAddress"]:
            if key in labels:
                self.common_ips.add(labels[key])

        # Extract techniques
        for key in ["mitre_technique", "technique", "technique_id"]:
            if key in labels:
                tech = labels[key]
                if isinstance(tech, list):
                    self.techniques.update(tech)
                else:
                    self.techniques.add(tech)

        # Update time range
        starts_at = alert.get("startsAt")
        if starts_at:
            try:
                ts = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                if self.time_range is None:
                    self.time_range = (ts, ts)
                else:
                    self.time_range = (
                        min(self.time_range[0], ts),
                        max(self.time_range[1], ts),
                    )
            except ValueError:
                pass

    def similarity_score(self, alert: dict) -> float:  # noqa: PLR0912
        """Calculate similarity score between this cluster and an alert.

        Args:
            alert: Alert dictionary to compare

        Returns:
            Similarity score between 0.0 and 1.0
        """
        score = 0.0
        labels = alert.get("labels", {})

        # Host match: high weight
        for key in ["hostname", "host", "computer"]:
            if key in labels and labels[key].lower() in self.common_hosts:
                score += 0.4
                break
        # Instance host check
        if "instance" in labels:
            host = labels["instance"].split(":")[0].lower()
            if host in self.common_hosts:
                score += 0.3

        # User match: high weight
        for key in ["user", "username", "account"]:
            if key in labels and labels[key].lower() in self.common_users:
                score += 0.3
                break

        # IP match: medium weight
        for key in ["ip", "source_ip", "src_ip", "IpAddress"]:
            if key in labels and labels[key] in self.common_ips:
                score += 0.2
                break

        # Technique match: medium weight
        for key in ["mitre_technique", "technique"]:
            if key in labels:
                tech = labels[key]
                if isinstance(tech, list):
                    if any(t in self.techniques for t in tech):
                        score += 0.2
                        break
                elif tech in self.techniques:
                    score += 0.2
                    break

        # Time proximity: bonus for recent alerts
        starts_at = alert.get("startsAt")
        if starts_at and self.time_range:
            try:
                ts = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                window_start = self.time_range[0] - timedelta(hours=1)
                window_end = self.time_range[1] + timedelta(hours=1)
                if window_start <= ts <= window_end:
                    score += 0.1
            except ValueError:
                pass

        return min(score, 1.0)

    def to_summary(self) -> dict[str, Any]:
        """Generate summary for the cluster.

        Returns:
            Summary dict with cluster information
        """
        return {
            "cluster_id": self.cluster_id,
            "alert_count": len(self.alerts),
            "common_hosts": list(self.common_hosts)[:10],
            "common_users": list(self.common_users)[:10],
            "common_ips": list(self.common_ips)[:10],
            "techniques": list(self.techniques),
            "time_range": {
                "start": self.time_range[0].isoformat() if self.time_range else None,
                "end": self.time_range[1].isoformat() if self.time_range else None,
            },
        }


class AlertCorrelator:
    """Correlates alerts into clusters for unified investigation.

    Groups related alerts based on shared hosts, users, IPs, techniques,
    and time proximity.
    """

    CLUSTER_THRESHOLD = 0.3  # Minimum similarity to join a cluster

    def __init__(self):
        """Initialize the correlator."""
        self.clusters: list[AlertCluster] = []
        self._cluster_counter = 0
        self._alert_to_cluster: dict[str, str] = {}  # fingerprint -> cluster_id

    def add_alert(self, alert: dict) -> AlertCluster:
        """Add an alert, either to existing cluster or new one.

        Args:
            alert: Alert dictionary from Grafana

        Returns:
            The cluster this alert was added to
        """
        # Find best matching cluster
        best_cluster = None
        best_score = 0.0

        for cluster in self.clusters:
            score = cluster.similarity_score(alert)
            if score > best_score:
                best_score = score
                best_cluster = cluster

        fingerprint = alert.get("fingerprint", str(id(alert)))

        if best_cluster and best_score >= self.CLUSTER_THRESHOLD:
            best_cluster.add_alert(alert)
            self._alert_to_cluster[fingerprint] = best_cluster.cluster_id
            logger.info(
                f"Alert {fingerprint[:8]} added to cluster {best_cluster.cluster_id} "
                f"(similarity: {best_score:.2f})"
            )
            return best_cluster
        # Create new cluster
        self._cluster_counter += 1
        new_cluster = AlertCluster(cluster_id=f"cluster-{self._cluster_counter:04d}")
        new_cluster.add_alert(alert)
        self.clusters.append(new_cluster)
        self._alert_to_cluster[fingerprint] = new_cluster.cluster_id
        logger.info(f"Created new cluster {new_cluster.cluster_id} for alert {fingerprint[:8]}")
        return new_cluster

    def get_cluster_context(self, alert: dict) -> dict[str, Any]:
        """Get correlation context for an alert.

        Args:
            alert: Alert dictionary to get context for

        Returns:
            Correlation context with related alerts and common IOCs
        """
        fingerprint = alert.get("fingerprint", str(id(alert)))
        cluster_id = self._alert_to_cluster.get(fingerprint)

        if not cluster_id:
            return {"cluster_id": None, "message": "Alert not in any cluster"}

        # Find the cluster
        for cluster in self.clusters:
            if cluster.cluster_id == cluster_id:
                return {
                    "cluster_id": cluster_id,
                    "related_alerts": len(cluster.alerts) - 1,  # Exclude this alert
                    "common_hosts": list(cluster.common_hosts)[:10],
                    "common_users": list(cluster.common_users)[:10],
                    "common_ips": list(cluster.common_ips)[:10],
                    "techniques_in_cluster": list(cluster.techniques),
                    "time_range": {
                        "start": cluster.time_range[0].isoformat() if cluster.time_range else None,
                        "end": cluster.time_range[1].isoformat() if cluster.time_range else None,
                    },
                }

        return {"cluster_id": cluster_id, "message": "Cluster not found"}

    def get_cluster_for_alert(self, alert: dict) -> AlertCluster | None:
        """Get the cluster for a specific alert.

        Args:
            alert: Alert dictionary

        Returns:
            The cluster containing this alert, or None
        """
        fingerprint = alert.get("fingerprint", str(id(alert)))
        cluster_id = self._alert_to_cluster.get(fingerprint)

        if not cluster_id:
            return None

        for cluster in self.clusters:
            if cluster.cluster_id == cluster_id:
                return cluster

        return None

    def get_all_clusters_summary(self) -> list[dict[str, Any]]:
        """Get summary of all clusters.

        Returns:
            List of cluster summaries
        """
        return [cluster.to_summary() for cluster in self.clusters]

    def get_related_alerts(self, alert: dict) -> list[dict]:
        """Get alerts related to this one.

        Args:
            alert: Alert to find related alerts for

        Returns:
            List of related alert dictionaries
        """
        cluster = self.get_cluster_for_alert(alert)
        if not cluster:
            return []

        fingerprint = alert.get("fingerprint", str(id(alert)))
        return [a for a in cluster.alerts if a.get("fingerprint", str(id(a))) != fingerprint]

    def reset(self) -> None:
        """Reset the correlator state."""
        self.clusters = []
        self._cluster_counter = 0
        self._alert_to_cluster = {}
