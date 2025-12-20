"""Tests for traffic analyzer."""

import pytest
from typing import Any

from k8s_policy_agent.models import PolicyConfig, Protocol, TrafficObservation
from k8s_policy_agent.traffic_analyzer import TrafficAnalyzer, create_traffic_analyzer


class TestTrafficAnalyzerInit:
    """Tests for TrafficAnalyzer initialization."""

    def test_create_with_config(self, mock_config: PolicyConfig) -> None:
        """Test creating analyzer with config."""
        analyzer = TrafficAnalyzer(mock_config)
        assert analyzer.config == mock_config

    def test_factory_function(self, mock_config: PolicyConfig) -> None:
        """Test factory function."""
        analyzer = create_traffic_analyzer(mock_config)
        assert analyzer is not None

    def test_factory_without_config(self) -> None:
        """Test factory function without config."""
        analyzer = create_traffic_analyzer()
        assert analyzer.config is not None


class TestAnalyzeNamespace:
    """Tests for namespace analysis."""

    @pytest.mark.asyncio
    async def test_analyze_namespace_mock_mode(self, mock_config: PolicyConfig) -> None:
        """Test analyzing namespace in mock mode."""
        analyzer = TrafficAnalyzer(mock_config)
        observations = await analyzer.analyze_namespace("default")

        assert len(observations) > 0
        assert all(isinstance(obs, TrafficObservation) for obs in observations)

    @pytest.mark.asyncio
    async def test_analyze_namespace_returns_expected_traffic(
        self, mock_config: PolicyConfig
    ) -> None:
        """Test mock observations contain expected traffic patterns."""
        analyzer = TrafficAnalyzer(mock_config)
        observations = await analyzer.analyze_namespace("default")

        # Check for frontend -> backend traffic
        frontend_traffic = [obs for obs in observations if "frontend" in obs.source_pod]
        assert len(frontend_traffic) > 0

    @pytest.mark.asyncio
    async def test_analyze_namespace_includes_dns(self, mock_config: PolicyConfig) -> None:
        """Test mock observations include DNS traffic."""
        analyzer = TrafficAnalyzer(mock_config)
        observations = await analyzer.analyze_namespace("default")

        dns_traffic = [obs for obs in observations if obs.dest_port == 53]
        assert len(dns_traffic) > 0

    @pytest.mark.asyncio
    async def test_analyze_namespace_non_mock(self, mock_config: PolicyConfig) -> None:
        """Test analyzing namespace in non-mock mode returns empty."""
        mock_config = PolicyConfig(mock_mode=False)
        analyzer = TrafficAnalyzer(mock_config)
        observations = await analyzer.analyze_namespace("default")

        # Without actual k8s connection, should return empty
        assert observations == []


class TestAnalyzePod:
    """Tests for pod analysis."""

    @pytest.mark.asyncio
    async def test_analyze_pod_mock_mode(self, mock_config: PolicyConfig) -> None:
        """Test analyzing specific pod in mock mode."""
        analyzer = TrafficAnalyzer(mock_config)
        observations = await analyzer.analyze_pod("default", {"app": "backend"})

        assert len(observations) > 0

    @pytest.mark.asyncio
    async def test_analyze_pod_returns_observations(self, mock_config: PolicyConfig) -> None:
        """Test pod analysis returns traffic observations."""
        analyzer = TrafficAnalyzer(mock_config)
        observations = await analyzer.analyze_pod("test-ns", {"app": "frontend"})

        assert all(isinstance(obs, TrafficObservation) for obs in observations)


class TestSetMockObservations:
    """Tests for setting custom mock observations."""

    @pytest.mark.asyncio
    async def test_set_mock_observations(
        self,
        mock_config: PolicyConfig,
        sample_mock_observations: list[dict[str, Any]],
    ) -> None:
        """Test setting custom mock observations."""
        analyzer = TrafficAnalyzer(mock_config)
        analyzer.set_mock_observations(sample_mock_observations)

        observations = await analyzer.analyze_namespace("default")

        assert len(observations) == 2
        assert observations[0].source_pod == "web-server"
        assert observations[1].dest_port == 6379

    @pytest.mark.asyncio
    async def test_mock_observations_override_defaults(
        self,
        mock_config: PolicyConfig,
        sample_mock_observations: list[dict[str, Any]],
    ) -> None:
        """Test custom observations override defaults."""
        analyzer = TrafficAnalyzer(mock_config)

        # First get default observations
        default_obs = await analyzer.analyze_namespace("default")
        default_count = len(default_obs)

        # Set custom and verify they're used
        analyzer.set_mock_observations(sample_mock_observations)
        custom_obs = await analyzer.analyze_namespace("default")

        assert len(custom_obs) == 2
        assert len(custom_obs) != default_count


class TestGetTrafficMap:
    """Tests for traffic mapping."""

    @pytest.mark.asyncio
    async def test_get_traffic_map(self, mock_config: PolicyConfig) -> None:
        """Test getting traffic map by source pod."""
        analyzer = TrafficAnalyzer(mock_config)
        traffic_map = await analyzer.get_traffic_map("default")

        assert isinstance(traffic_map, dict)
        assert len(traffic_map) > 0

    @pytest.mark.asyncio
    async def test_traffic_map_keys_format(self, mock_config: PolicyConfig) -> None:
        """Test traffic map keys are namespace/pod format."""
        analyzer = TrafficAnalyzer(mock_config)
        traffic_map = await analyzer.get_traffic_map("default")

        for key in traffic_map:
            assert "/" in key
            parts = key.split("/")
            assert len(parts) == 2


class TestObservationsToRules:
    """Tests for converting observations to rules."""

    def test_observations_to_rules(
        self,
        mock_config: PolicyConfig,
        sample_traffic_observations: list[TrafficObservation],
    ) -> None:
        """Test converting observations to traffic rules."""
        analyzer = TrafficAnalyzer(mock_config)
        rules = analyzer.observations_to_rules(sample_traffic_observations)

        assert len(rules) == len(sample_traffic_observations)

    def test_rule_properties(
        self,
        mock_config: PolicyConfig,
        sample_traffic_observation: TrafficObservation,
    ) -> None:
        """Test rule properties match observation."""
        analyzer = TrafficAnalyzer(mock_config)
        rules = analyzer.observations_to_rules([sample_traffic_observation])

        rule = rules[0]
        assert rule.source_namespace == sample_traffic_observation.source_namespace
        assert rule.port == sample_traffic_observation.dest_port
        assert rule.protocol == sample_traffic_observation.protocol


class TestAggregateObservations:
    """Tests for observation aggregation."""

    def test_aggregate_similar_observations(self, mock_config: PolicyConfig) -> None:
        """Test aggregating similar observations."""
        analyzer = TrafficAnalyzer(mock_config)

        observations = [
            TrafficObservation(
                source_namespace="default",
                source_pod="frontend-1",
                source_labels={"app": "frontend"},
                dest_namespace="default",
                dest_pod="backend-1",
                dest_labels={"app": "backend"},
                dest_port=8080,
                count=100,
            ),
            TrafficObservation(
                source_namespace="default",
                source_pod="frontend-2",
                source_labels={"app": "frontend"},
                dest_namespace="default",
                dest_pod="backend-2",
                dest_labels={"app": "backend"},
                dest_port=8080,
                count=200,
            ),
        ]

        aggregated = analyzer.aggregate_observations(observations)

        # Should be aggregated into one observation
        assert len(aggregated) == 1
        assert aggregated[0].count == 300

    def test_aggregate_different_observations(self, mock_config: PolicyConfig) -> None:
        """Test different observations are not aggregated."""
        analyzer = TrafficAnalyzer(mock_config)

        observations = [
            TrafficObservation(
                source_namespace="default",
                source_pod="frontend",
                source_labels={"app": "frontend"},
                dest_namespace="default",
                dest_pod="backend",
                dest_labels={"app": "backend"},
                dest_port=8080,
                count=100,
            ),
            TrafficObservation(
                source_namespace="default",
                source_pod="frontend",
                source_labels={"app": "frontend"},
                dest_namespace="default",
                dest_pod="database",
                dest_labels={"app": "postgres"},
                dest_port=5432,
                count=200,
            ),
        ]

        aggregated = analyzer.aggregate_observations(observations)

        # Should remain separate
        assert len(aggregated) == 2


class TestGetStats:
    """Tests for analyzer statistics."""

    def test_get_stats_initial(self, mock_config: PolicyConfig) -> None:
        """Test initial statistics."""
        analyzer = TrafficAnalyzer(mock_config)
        stats = analyzer.get_stats()

        assert "total_observations" in stats
        assert "namespaces_analyzed" in stats
        assert stats["total_observations"] == 0

    @pytest.mark.asyncio
    async def test_stats_after_analysis(self, mock_config: PolicyConfig) -> None:
        """Test stats are still accurate (observations stored internally)."""
        analyzer = TrafficAnalyzer(mock_config)
        await analyzer.analyze_namespace("default")

        stats = analyzer.get_stats()
        # Internal observations may not be stored depending on implementation
        assert "total_observations" in stats
