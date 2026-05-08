"""Tests for policy generator."""

import pytest

from k8s_policy_agent.models import (
    NetworkPolicySpec,
    PolicyConfig,
    PolicyGenerationRequest,
    PolicyGenerationSource,
    TrafficObservation,
)
from k8s_policy_agent.policy_generator import PolicyGenerator, create_policy_generator


class TestPolicyGeneratorInit:
    """Tests for PolicyGenerator initialization."""

    def test_create_with_config(self, mock_config: PolicyConfig) -> None:
        """Test creating generator with config."""
        generator = PolicyGenerator(mock_config)
        assert generator.config == mock_config

    def test_factory_function(self, mock_config: PolicyConfig) -> None:
        """Test factory function."""
        generator = create_policy_generator(mock_config)
        assert generator is not None

    def test_factory_without_config(self) -> None:
        """Test factory function without config."""
        generator = create_policy_generator()
        assert generator.config is not None

    def test_mock_mode_no_model_init(self, mock_config: PolicyConfig) -> None:
        """Test AI model not initialized in mock mode."""
        generator = PolicyGenerator(mock_config)
        assert generator._model is None


class TestGenerate:
    """Tests for policy generation."""

    @pytest.mark.asyncio
    async def test_generate_from_request(
        self,
        mock_config: PolicyConfig,
        sample_policy_generation_request: PolicyGenerationRequest,
    ) -> None:
        """Test generating policy from request."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate(sample_policy_generation_request)

        assert isinstance(policy, NetworkPolicySpec)
        assert policy.namespace == "default"
        assert policy.generation.source == PolicyGenerationSource.MOCK
        assert policy.generation.degraded is False

    @pytest.mark.asyncio
    async def test_generate_without_gemini_model_marks_degraded(
        self,
        sample_policy_generation_request: PolicyGenerationRequest,
    ) -> None:
        """Test missing Gemini configuration falls back with explicit metadata."""
        config = PolicyConfig(mock_mode=False, gemini_api_key="")
        generator = PolicyGenerator(config)

        policy = await generator.generate(sample_policy_generation_request)

        assert policy.generation.source == PolicyGenerationSource.FALLBACK
        assert policy.generation.degraded is True
        assert policy.generation.model == "gemini-2.0-flash"
        assert "Gemini model unavailable" in policy.generation.error

    @pytest.mark.asyncio
    async def test_gemini_generation_error_marks_degraded(
        self,
        sample_policy_generation_request: PolicyGenerationRequest,
    ) -> None:
        """Test Gemini failures fall back with visible error metadata."""

        class FailingModel:
            def generate_content(self, prompt: str) -> None:
                raise RuntimeError("network unavailable")

        config = PolicyConfig(mock_mode=False, gemini_api_key="test-key")
        generator = PolicyGenerator(config)
        generator._model = FailingModel()

        policy = await generator.generate(sample_policy_generation_request)

        assert policy.generation.source == PolicyGenerationSource.FALLBACK
        assert policy.generation.degraded is True
        assert policy.generation.error == "network unavailable"

    @pytest.mark.asyncio
    async def test_generate_includes_dns_egress(
        self,
        mock_config: PolicyConfig,
        sample_policy_generation_request: PolicyGenerationRequest,
    ) -> None:
        """Test generated policy includes DNS egress."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate(sample_policy_generation_request)

        dns_rules = [
            rule for rule in policy.egress_rules if any(port.port == 53 for port in rule.ports)
        ]
        assert len(dns_rules) > 0

    @pytest.mark.asyncio
    async def test_generate_has_policy_types(
        self,
        mock_config: PolicyConfig,
        sample_policy_generation_request: PolicyGenerationRequest,
    ) -> None:
        """Test generated policy has policy types."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate(sample_policy_generation_request)

        assert "Ingress" in policy.policy_types
        assert "Egress" in policy.policy_types


class TestGenerateFromObservations:
    """Tests for generating from traffic observations."""

    @pytest.mark.asyncio
    async def test_generate_from_observations(
        self,
        mock_config: PolicyConfig,
        sample_traffic_observations: list[TrafficObservation],
    ) -> None:
        """Test generating policy from observations."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate_from_observations(
            namespace="default",
            pod_labels={"app": "backend"},
            observations=sample_traffic_observations,
        )

        assert isinstance(policy, NetworkPolicySpec)
        assert policy.namespace == "default"

    @pytest.mark.asyncio
    async def test_generate_from_observations_pod_selector(
        self,
        mock_config: PolicyConfig,
        sample_traffic_observations: list[TrafficObservation],
    ) -> None:
        """Test generated policy has correct pod selector."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate_from_observations(
            namespace="default",
            pod_labels={"app": "backend", "tier": "api"},
            observations=sample_traffic_observations,
        )

        assert policy.pod_selector.match_labels == {"app": "backend", "tier": "api"}


class TestGenerateDefaultDeny:
    """Tests for default deny policy generation."""

    @pytest.mark.asyncio
    async def test_generate_default_deny(self, mock_config: PolicyConfig) -> None:
        """Test generating default deny policy."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate_default_deny("production")

        assert policy.name == "default-deny-production"
        assert policy.namespace == "production"

    @pytest.mark.asyncio
    async def test_default_deny_empty_ingress(self, mock_config: PolicyConfig) -> None:
        """Test default deny has no ingress rules."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate_default_deny("test")

        assert policy.ingress_rules == []

    @pytest.mark.asyncio
    async def test_default_deny_allows_dns(self, mock_config: PolicyConfig) -> None:
        """Test default deny allows DNS egress."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate_default_deny("test")

        dns_rules = [
            rule for rule in policy.egress_rules if any(port.port == 53 for port in rule.ports)
        ]
        assert len(dns_rules) == 1

    @pytest.mark.asyncio
    async def test_default_deny_has_description(self, mock_config: PolicyConfig) -> None:
        """Test default deny has description."""
        generator = PolicyGenerator(mock_config)
        policy = await generator.generate_default_deny("test")

        assert "default deny" in policy.description.lower()


class TestPolicyToYaml:
    """Tests for YAML conversion."""

    def test_policy_to_yaml(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test converting policy to YAML."""
        generator = PolicyGenerator(mock_config)
        yaml_content = generator.policy_to_yaml(sample_network_policy)

        assert isinstance(yaml_content, str)
        assert "apiVersion: networking.k8s.io/v1" in yaml_content
        assert "kind: NetworkPolicy" in yaml_content

    def test_yaml_contains_metadata(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test YAML contains metadata."""
        generator = PolicyGenerator(mock_config)
        yaml_content = generator.policy_to_yaml(sample_network_policy)

        assert "name: allow-backend" in yaml_content
        assert "namespace: default" in yaml_content
        assert "generation-source: manual" in yaml_content

    def test_yaml_contains_spec(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test YAML contains spec."""
        generator = PolicyGenerator(mock_config)
        yaml_content = generator.policy_to_yaml(sample_network_policy)

        assert "podSelector:" in yaml_content
        assert "policyTypes:" in yaml_content


class TestFormatTrafficPatterns:
    """Tests for traffic pattern formatting."""

    def test_format_traffic_patterns(
        self,
        mock_config: PolicyConfig,
        sample_traffic_observations: list[TrafficObservation],
    ) -> None:
        """Test formatting traffic patterns for prompt."""
        generator = PolicyGenerator(mock_config)
        formatted = generator._format_traffic_patterns(sample_traffic_observations)

        assert isinstance(formatted, str)
        assert "default" in formatted
        assert "8080" in formatted

    def test_format_empty_observations(self, mock_config: PolicyConfig) -> None:
        """Test formatting empty observations."""
        generator = PolicyGenerator(mock_config)
        formatted = generator._format_traffic_patterns([])

        assert formatted == "No traffic observed"


class TestExtractJson:
    """Tests for JSON extraction from AI response."""

    def test_extract_json_code_block(self, mock_config: PolicyConfig) -> None:
        """Test extracting JSON from code block."""
        generator = PolicyGenerator(mock_config)
        text = '```json\n{"name": "test"}\n```'
        result = generator._extract_json(text)

        assert result == {"name": "test"}

    def test_extract_json_plain(self, mock_config: PolicyConfig) -> None:
        """Test extracting plain JSON."""
        generator = PolicyGenerator(mock_config)
        text = '{"name": "test"}'
        result = generator._extract_json(text)

        assert result == {"name": "test"}

    def test_extract_json_invalid(self, mock_config: PolicyConfig) -> None:
        """Test extracting invalid JSON returns empty dict."""
        generator = PolicyGenerator(mock_config)
        text = "not valid json"
        result = generator._extract_json(text)

        assert result == {}


class TestMockPolicyGeneration:
    """Tests for mock policy generation logic."""

    @pytest.mark.asyncio
    async def test_mock_generates_ingress_rules(
        self,
        mock_config: PolicyConfig,
    ) -> None:
        """Test mock generation creates ingress rules from observations."""
        observations = [
            TrafficObservation(
                source_namespace="default",
                source_pod="frontend",
                source_labels={"app": "frontend"},
                dest_namespace="default",
                dest_pod="backend",
                dest_labels={"app": "backend"},  # Target
                dest_port=8080,
            ),
        ]

        generator = PolicyGenerator(mock_config)
        request = PolicyGenerationRequest(
            target_namespace="default",
            target_pod_labels={"app": "backend"},
            traffic_observations=observations,
        )

        policy = await generator.generate(request)

        # Should create ingress rule since dest matches target
        assert len(policy.ingress_rules) > 0

    @pytest.mark.asyncio
    async def test_mock_generates_egress_rules(
        self,
        mock_config: PolicyConfig,
    ) -> None:
        """Test mock generation creates egress rules from observations."""
        observations = [
            TrafficObservation(
                source_namespace="default",
                source_pod="backend",
                source_labels={"app": "backend"},  # Source matches target
                dest_namespace="default",
                dest_pod="database",
                dest_labels={"app": "postgres"},
                dest_port=5432,
            ),
        ]

        generator = PolicyGenerator(mock_config)
        request = PolicyGenerationRequest(
            target_namespace="default",
            target_pod_labels={"app": "backend"},
            traffic_observations=observations,
        )

        policy = await generator.generate(request)

        # Should create egress rule (plus DNS)
        assert len(policy.egress_rules) >= 1

    @pytest.mark.asyncio
    async def test_policy_name_generation(self, mock_config: PolicyConfig) -> None:
        """Test policy name is generated from labels."""
        request = PolicyGenerationRequest(
            target_namespace="default",
            target_pod_labels={"app": "web"},
            traffic_observations=[],
        )

        generator = PolicyGenerator(mock_config)
        policy = await generator.generate(request)

        assert "web" in policy.name.lower() or "allow" in policy.name.lower()
