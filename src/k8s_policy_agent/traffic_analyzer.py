"""Traffic analyzer for Kubernetes clusters."""

from __future__ import annotations

from typing import Any

import structlog

from k8s_policy_agent.models import (
    PolicyConfig,
    Protocol,
    TrafficDirection,
    TrafficObservation,
    TrafficRule,
)

logger = structlog.get_logger()


class TrafficAnalyzer:
    """Analyzes network traffic in Kubernetes clusters."""

    def __init__(self, config: PolicyConfig) -> None:
        """Initialize the traffic analyzer.

        Args:
            config: Policy configuration
        """
        self.config = config
        self._observations: list[TrafficObservation] = []
        self._mock_observations: list[dict[str, Any]] = []

    def set_mock_observations(self, observations: list[dict[str, Any]]) -> None:
        """Set mock observations for testing.

        Args:
            observations: List of mock observation dictionaries
        """
        self._mock_observations = observations

    async def analyze_namespace(self, namespace: str) -> list[TrafficObservation]:
        """Analyze traffic in a namespace.

        Args:
            namespace: Namespace to analyze

        Returns:
            List of traffic observations
        """
        if self.config.mock_mode:
            return self._get_mock_observations(namespace)

        return await self._query_cni_logs(namespace)

    async def analyze_pod(
        self, namespace: str, pod_labels: dict[str, str]
    ) -> list[TrafficObservation]:
        """Analyze traffic for specific pods.

        Args:
            namespace: Pod namespace
            pod_labels: Pod label selectors

        Returns:
            List of traffic observations
        """
        if self.config.mock_mode:
            return self._get_mock_observations(namespace)

        return await self._query_pod_traffic(namespace, pod_labels)

    async def get_traffic_map(self, namespace: str) -> dict[str, list[TrafficObservation]]:
        """Get a map of traffic flows by source pod.

        Args:
            namespace: Namespace to analyze

        Returns:
            Dictionary mapping source pods to their traffic
        """
        observations = await self.analyze_namespace(namespace)

        traffic_map: dict[str, list[TrafficObservation]] = {}

        for obs in observations:
            key = f"{obs.source_namespace}/{obs.source_pod}"
            if key not in traffic_map:
                traffic_map[key] = []
            traffic_map[key].append(obs)

        return traffic_map

    def observations_to_rules(self, observations: list[TrafficObservation]) -> list[TrafficRule]:
        """Convert observations to traffic rules.

        Args:
            observations: Traffic observations

        Returns:
            List of traffic rules
        """
        rules = []

        for obs in observations:
            rule = TrafficRule(
                direction=TrafficDirection.EGRESS,
                source_namespace=obs.source_namespace,
                source_pod=obs.source_pod,
                source_labels=obs.source_labels,
                dest_namespace=obs.dest_namespace,
                dest_pod=obs.dest_pod,
                dest_labels=obs.dest_labels,
                port=obs.dest_port,
                protocol=obs.protocol,
                count=obs.count,
                last_seen=obs.last_seen,
            )
            rules.append(rule)

        return rules

    async def _query_cni_logs(self, namespace: str) -> list[TrafficObservation]:
        """Query CNI (Cilium/Calico) logs for traffic.

        Args:
            namespace: Namespace to query

        Returns:
            List of observations from CNI logs
        """
        logger.info("querying_cni_logs", namespace=namespace)

        # In production, this would query Cilium Hubble or Calico logs
        # For now, return empty list
        return []

    async def _query_pod_traffic(
        self, namespace: str, pod_labels: dict[str, str]
    ) -> list[TrafficObservation]:
        """Query traffic for specific pods.

        Args:
            namespace: Pod namespace
            pod_labels: Pod labels

        Returns:
            List of observations
        """
        logger.info("querying_pod_traffic", namespace=namespace, labels=pod_labels)
        return []

    def _get_mock_observations(self, namespace: str) -> list[TrafficObservation]:
        """Get mock observations for testing.

        Args:
            namespace: Target namespace

        Returns:
            Mock observations
        """
        if self._mock_observations:
            return [
                TrafficObservation(
                    source_namespace=obs.get("source_namespace", namespace),
                    source_pod=obs.get("source_pod", "frontend"),
                    source_labels=obs.get("source_labels", {"app": "frontend"}),
                    dest_namespace=obs.get("dest_namespace", namespace),
                    dest_pod=obs.get("dest_pod", "backend"),
                    dest_labels=obs.get("dest_labels", {"app": "backend"}),
                    dest_port=obs.get("dest_port", 8080),
                    protocol=Protocol(obs.get("protocol", "TCP")),
                    count=obs.get("count", 100),
                )
                for obs in self._mock_observations
            ]

        # Default mock observations
        return [
            TrafficObservation(
                source_namespace=namespace,
                source_pod="frontend-abc123",
                source_labels={"app": "frontend", "tier": "web"},
                dest_namespace=namespace,
                dest_pod="backend-def456",
                dest_labels={"app": "backend", "tier": "api"},
                dest_port=8080,
                protocol=Protocol.TCP,
                count=1500,
            ),
            TrafficObservation(
                source_namespace=namespace,
                source_pod="backend-def456",
                source_labels={"app": "backend", "tier": "api"},
                dest_namespace=namespace,
                dest_pod="database-ghi789",
                dest_labels={"app": "postgres", "tier": "data"},
                dest_port=5432,
                protocol=Protocol.TCP,
                count=3000,
            ),
            TrafficObservation(
                source_namespace=namespace,
                source_pod="backend-def456",
                source_labels={"app": "backend", "tier": "api"},
                dest_namespace="kube-system",
                dest_pod="coredns-xxx",
                dest_labels={"k8s-app": "kube-dns"},
                dest_port=53,
                protocol=Protocol.UDP,
                count=5000,
            ),
            TrafficObservation(
                source_namespace=namespace,
                source_pod="frontend-abc123",
                source_labels={"app": "frontend", "tier": "web"},
                dest_namespace="",
                dest_pod="external",
                dest_labels={},
                dest_port=443,
                protocol=Protocol.TCP,
                count=200,
            ),
        ]

    def aggregate_observations(
        self, observations: list[TrafficObservation]
    ) -> list[TrafficObservation]:
        """Aggregate similar observations.

        Args:
            observations: Raw observations

        Returns:
            Aggregated observations
        """
        aggregated: dict[str, TrafficObservation] = {}

        for obs in observations:
            key = (
                f"{obs.source_namespace}:{obs.source_labels}:"
                f"{obs.dest_namespace}:{obs.dest_labels}:{obs.dest_port}"
            )

            if key in aggregated:
                existing = aggregated[key]
                aggregated[key] = TrafficObservation(
                    source_namespace=existing.source_namespace,
                    source_pod=existing.source_pod,
                    source_labels=existing.source_labels,
                    dest_namespace=existing.dest_namespace,
                    dest_pod=existing.dest_pod,
                    dest_labels=existing.dest_labels,
                    dest_port=existing.dest_port,
                    protocol=existing.protocol,
                    count=existing.count + obs.count,
                    first_seen=min(existing.first_seen, obs.first_seen),
                    last_seen=max(existing.last_seen, obs.last_seen),
                )
            else:
                aggregated[key] = obs

        return list(aggregated.values())

    def get_stats(self) -> dict[str, Any]:
        """Get analyzer statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "total_observations": len(self._observations),
            "namespaces_analyzed": len({o.source_namespace for o in self._observations}),
        }


def create_traffic_analyzer(config: PolicyConfig | None = None) -> TrafficAnalyzer:
    """Factory function to create TrafficAnalyzer.

    Args:
        config: Optional policy configuration

    Returns:
        Configured TrafficAnalyzer instance
    """
    if config is None:
        config = PolicyConfig()

    return TrafficAnalyzer(config)
