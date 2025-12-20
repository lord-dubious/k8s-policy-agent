"""Tests for policy agent orchestrator."""

import pytest
from typing import Any

from k8s_policy_agent.models import (
    PolicyConfig,
    NetworkPolicySpec,
    TrafficObservation,
    PolicyValidationResult,
    PolicyEvaluation,
    AgentStats,
    Protocol,
)
from k8s_policy_agent.agent import PolicyAgent, create_policy_agent


class TestPolicyAgentInit:
    """Tests for PolicyAgent initialization."""

    def test_create_with_config(self, mock_config: PolicyConfig) -> None:
        """Test creating agent with config."""
        agent = PolicyAgent(mock_config)
        assert agent.config == mock_config

    def test_factory_function(self, mock_config: PolicyConfig) -> None:
        """Test factory function."""
        agent = create_policy_agent(mock_config)
        assert agent is not None

    def test_factory_without_config(self) -> None:
        """Test factory function without config."""
        agent = create_policy_agent()
        assert agent.config is not None

    def test_agent_components_initialized(self, mock_config: PolicyConfig) -> None:
        """Test agent components are initialized."""
        agent = PolicyAgent(mock_config)

        assert agent.traffic_analyzer is not None
        assert agent.policy_generator is not None
        assert agent.policy_validator is not None
        assert agent.gitops_manager is not None


class TestAnalyzeAndGenerate:
    """Tests for analyze and generate workflow."""

    @pytest.mark.asyncio
    async def test_analyze_and_generate(self, mock_config: PolicyConfig) -> None:
        """Test basic analyze and generate."""
        agent = PolicyAgent(mock_config)
        policy = await agent.analyze_and_generate("default")

        assert isinstance(policy, NetworkPolicySpec)
        assert policy.namespace == "default"

    @pytest.mark.asyncio
    async def test_analyze_and_generate_with_labels(self, mock_config: PolicyConfig) -> None:
        """Test analyze and generate with pod labels."""
        agent = PolicyAgent(mock_config)
        policy = await agent.analyze_and_generate(
            "default",
            pod_labels={"app": "backend"},
        )

        assert policy.pod_selector.match_labels == {"app": "backend"}

    @pytest.mark.asyncio
    async def test_analyze_and_generate_updates_stats(self, mock_config: PolicyConfig) -> None:
        """Test analyze and generate updates statistics."""
        agent = PolicyAgent(mock_config)
        await agent.analyze_and_generate("default")

        stats = agent.get_stats()
        assert stats.policies_generated >= 1

    @pytest.mark.asyncio
    async def test_analyze_and_generate_caches_policy(self, mock_config: PolicyConfig) -> None:
        """Test generated policy is cached."""
        agent = PolicyAgent(mock_config)
        policy = await agent.analyze_and_generate("default")

        cached = agent.get_cached_policy("default", policy.name)
        assert cached is not None


class TestGenerateFromObservations:
    """Tests for generating from observations."""

    @pytest.mark.asyncio
    async def test_generate_from_observations(
        self,
        mock_config: PolicyConfig,
        sample_traffic_observations: list[TrafficObservation],
    ) -> None:
        """Test generating from provided observations."""
        agent = PolicyAgent(mock_config)
        policy = await agent.generate_from_observations(
            namespace="default",
            pod_labels={"app": "backend"},
            observations=sample_traffic_observations,
        )

        assert isinstance(policy, NetworkPolicySpec)
        assert policy.namespace == "default"


class TestGenerateDefaultDeny:
    """Tests for default deny generation."""

    @pytest.mark.asyncio
    async def test_generate_default_deny(self, mock_config: PolicyConfig) -> None:
        """Test generating default deny policy."""
        agent = PolicyAgent(mock_config)
        policy = await agent.generate_default_deny("production")

        assert policy.name.startswith("default-deny")
        assert policy.namespace == "production"


class TestValidate:
    """Tests for validation."""

    def test_validate_policy(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test validating a policy."""
        agent = PolicyAgent(mock_config)
        result = agent.validate(sample_network_policy)

        assert isinstance(result, PolicyValidationResult)
        assert result.is_valid is True

    def test_validate_updates_stats(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test validation updates statistics."""
        agent = PolicyAgent(mock_config)
        agent.validate(sample_network_policy)

        stats = agent.get_stats()
        assert stats.policies_validated >= 1

    def test_validate_invalid_policy_updates_errors(
        self,
        mock_config: PolicyConfig,
    ) -> None:
        """Test validation of invalid policy updates error count."""
        from k8s_policy_agent.models import PodSelector

        policy = NetworkPolicySpec(
            name="",  # Invalid - no name
            namespace="default",
            pod_selector=PodSelector(match_labels={"app": "test"}),
            policy_types=["Ingress"],
        )

        agent = PolicyAgent(mock_config)
        agent.validate(policy)

        stats = agent.get_stats()
        assert stats.validation_errors >= 1


class TestValidateYaml:
    """Tests for YAML validation."""

    def test_validate_yaml(
        self,
        mock_config: PolicyConfig,
        valid_policy_yaml: str,
    ) -> None:
        """Test validating YAML string."""
        agent = PolicyAgent(mock_config)
        result = agent.validate_yaml(valid_policy_yaml)

        assert isinstance(result, PolicyValidationResult)
        assert result.is_valid is True


class TestEvaluate:
    """Tests for policy evaluation."""

    def test_evaluate_policy(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test evaluating a policy."""
        agent = PolicyAgent(mock_config)
        evaluation = agent.evaluate(sample_network_policy)

        assert isinstance(evaluation, PolicyEvaluation)
        assert 0 <= evaluation.score <= 1


class TestApplyPolicy:
    """Tests for applying policies via GitOps."""

    @pytest.mark.asyncio
    async def test_apply_policy(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test applying a policy."""
        agent = PolicyAgent(mock_config)
        commit = await agent.apply_policy(sample_network_policy)

        assert commit is not None
        assert commit.commit_hash is not None

        await agent.cleanup()

    @pytest.mark.asyncio
    async def test_apply_policy_validates_first(self, mock_config: PolicyConfig) -> None:
        """Test apply validates policy first."""
        from k8s_policy_agent.models import PodSelector

        policy = NetworkPolicySpec(
            name="",  # Invalid
            namespace="default",
            pod_selector=PodSelector(match_labels={"app": "test"}),
            policy_types=["Ingress"],
        )

        agent = PolicyAgent(mock_config)

        with pytest.raises(ValueError, match="validation failed"):
            await agent.apply_policy(policy)

        await agent.cleanup()

    @pytest.mark.asyncio
    async def test_apply_policy_custom_message(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test apply with custom commit message."""
        agent = PolicyAgent(mock_config)
        commit = await agent.apply_policy(
            sample_network_policy,
            commit_message="Deploy backend policy",
        )

        assert commit.message == "Deploy backend policy"

        await agent.cleanup()

    @pytest.mark.asyncio
    async def test_apply_policy_updates_stats(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test apply updates statistics."""
        agent = PolicyAgent(mock_config)
        await agent.apply_policy(sample_network_policy)

        stats = agent.get_stats()
        assert stats.policies_applied >= 1
        assert stats.gitops_commits >= 1

        await agent.cleanup()


class TestApplyPolicies:
    """Tests for applying multiple policies."""

    @pytest.mark.asyncio
    async def test_apply_multiple_policies(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
        default_deny_policy: NetworkPolicySpec,
    ) -> None:
        """Test applying multiple policies."""
        agent = PolicyAgent(mock_config)
        commit = await agent.apply_policies(
            [sample_network_policy, default_deny_policy],
        )

        assert len(commit.policy_names) == 2

        await agent.cleanup()


class TestFullPipeline:
    """Tests for full pipeline execution."""

    @pytest.mark.asyncio
    async def test_full_pipeline(self, mock_config: PolicyConfig) -> None:
        """Test running full pipeline."""
        agent = PolicyAgent(mock_config)
        result = await agent.full_pipeline("default")

        assert "policy" in result
        assert "policy_yaml" in result
        assert "validation" in result
        assert "evaluation" in result
        assert result["applied"] is False  # auto_apply=False by default

        await agent.cleanup()

    @pytest.mark.asyncio
    async def test_full_pipeline_with_labels(self, mock_config: PolicyConfig) -> None:
        """Test full pipeline with pod labels."""
        agent = PolicyAgent(mock_config)
        result = await agent.full_pipeline(
            "default",
            pod_labels={"app": "backend"},
        )

        policy = result["policy"]
        assert policy.pod_selector.match_labels == {"app": "backend"}

        await agent.cleanup()

    @pytest.mark.asyncio
    async def test_full_pipeline_auto_apply(self, mock_config: PolicyConfig) -> None:
        """Test full pipeline with auto apply."""
        agent = PolicyAgent(mock_config)
        result = await agent.full_pipeline(
            "default",
            pod_labels={"app": "backend"},
            auto_apply=True,
        )

        assert result["applied"] is True
        assert result["commit"] is not None

        await agent.cleanup()


class TestCache:
    """Tests for policy caching."""

    @pytest.mark.asyncio
    async def test_get_cached_policy(self, mock_config: PolicyConfig) -> None:
        """Test getting cached policy."""
        agent = PolicyAgent(mock_config)
        policy = await agent.analyze_and_generate("default")

        cached = agent.get_cached_policy("default", policy.name)
        assert cached == policy

    def test_get_cached_policy_not_found(self, mock_config: PolicyConfig) -> None:
        """Test getting non-existent cached policy."""
        agent = PolicyAgent(mock_config)
        cached = agent.get_cached_policy("default", "nonexistent")
        assert cached is None

    @pytest.mark.asyncio
    async def test_clear_cache(self, mock_config: PolicyConfig) -> None:
        """Test clearing cache."""
        agent = PolicyAgent(mock_config)
        await agent.analyze_and_generate("default")

        agent.clear_cache()

        # Cache should be empty now
        full_stats = agent.get_full_stats()
        assert full_stats["cached_policies"] == 0


class TestStatistics:
    """Tests for statistics tracking."""

    def test_initial_stats(self, mock_config: PolicyConfig) -> None:
        """Test initial statistics."""
        agent = PolicyAgent(mock_config)
        stats = agent.get_stats()

        assert isinstance(stats, AgentStats)
        assert stats.policies_generated == 0
        assert stats.policies_validated == 0

    def test_get_full_stats(self, mock_config: PolicyConfig) -> None:
        """Test full statistics."""
        agent = PolicyAgent(mock_config)
        stats = agent.get_full_stats()

        assert "agent" in stats
        assert "traffic_analyzer" in stats
        assert "gitops" in stats
        assert "cached_policies" in stats


class TestCleanup:
    """Tests for cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup(self, mock_config: PolicyConfig) -> None:
        """Test cleanup releases resources."""
        agent = PolicyAgent(mock_config)
        await agent.analyze_and_generate("default")
        await agent.cleanup()

        # Should not raise
