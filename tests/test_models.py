"""Tests for data models."""

import pytest

from k8s_policy_agent.models import (
    AgentStats,
    EgressRule,
    GitOpsCommit,
    IngressRule,
    IPBlock,
    NamespaceSelector,
    NetworkPeer,
    NetworkPolicySpec,
    PodSelector,
    PolicyAction,
    PolicyConfig,
    PolicyEvaluation,
    PolicyGenerationMetadata,
    PolicyGenerationRequest,
    PolicyGenerationSource,
    PolicyValidationResult,
    PortSpec,
    Protocol,
    TrafficDirection,
    TrafficObservation,
    TrafficRule,
    create_config,
)


class TestEnums:
    """Tests for enum types."""

    def test_traffic_direction_values(self) -> None:
        """Test TrafficDirection enum values."""
        assert TrafficDirection.INGRESS.value == "ingress"
        assert TrafficDirection.EGRESS.value == "egress"
        assert TrafficDirection.BOTH.value == "both"

    def test_policy_action_values(self) -> None:
        """Test PolicyAction enum values."""
        assert PolicyAction.ALLOW.value == "allow"
        assert PolicyAction.DENY.value == "deny"

    def test_protocol_values(self) -> None:
        """Test Protocol enum values."""
        assert Protocol.TCP.value == "TCP"
        assert Protocol.UDP.value == "UDP"
        assert Protocol.SCTP.value == "SCTP"


class TestPolicyConfig:
    """Tests for PolicyConfig."""

    def test_default_config(self, mock_config: PolicyConfig) -> None:
        """Test default configuration values."""
        assert mock_config.mock_mode is True
        assert mock_config.dry_run is True
        assert mock_config.namespace == "default"

    def test_create_config_factory(self) -> None:
        """Test create_config factory function."""
        config = create_config(mock_mode=True, namespace="test")
        assert config.mock_mode is True
        assert config.namespace == "test"

    def test_config_env_prefix(self) -> None:
        """Test environment variable prefix."""
        assert PolicyConfig.model_config.get("env_prefix") == "K8S_POLICY_"

    def test_config_default_values(self) -> None:
        """Test default config values."""
        config = PolicyConfig()
        assert config.gemini_model == "gemini-2.0-flash"
        assert config.git_branch == "main"
        assert config.git_policies_path == "policies/"


class TestPortSpec:
    """Tests for PortSpec."""

    def test_port_spec_creation(self, sample_port_spec: PortSpec) -> None:
        """Test PortSpec creation."""
        assert sample_port_spec.port == 8080
        assert sample_port_spec.protocol == Protocol.TCP

    def test_port_spec_with_range(self) -> None:
        """Test PortSpec with port range."""
        port_range = PortSpec(port=8000, end_port=8100, protocol=Protocol.TCP)
        assert port_range.end_port == 8100

    def test_port_spec_frozen(self, sample_port_spec: PortSpec) -> None:
        """Test PortSpec is frozen."""
        frozen_field = "port"
        with pytest.raises(ValueError):
            setattr(sample_port_spec, frozen_field, 9090)


class TestPodSelector:
    """Tests for PodSelector."""

    def test_pod_selector_creation(self, sample_pod_selector: PodSelector) -> None:
        """Test PodSelector creation."""
        assert sample_pod_selector.match_labels == {"app": "backend", "tier": "api"}

    def test_empty_pod_selector(self) -> None:
        """Test empty PodSelector."""
        empty = PodSelector()
        assert empty.match_labels == {}

    def test_pod_selector_with_expressions(self) -> None:
        """Test PodSelector with expressions."""
        selector = PodSelector(
            match_expressions=[{"key": "app", "operator": "In", "values": ["web", "api"]}]
        )
        assert len(selector.match_expressions) == 1


class TestNamespaceSelector:
    """Tests for NamespaceSelector."""

    def test_namespace_selector_creation(
        self, sample_namespace_selector: NamespaceSelector
    ) -> None:
        """Test NamespaceSelector creation."""
        assert "kubernetes.io/metadata.name" in sample_namespace_selector.match_labels


class TestIPBlock:
    """Tests for IPBlock."""

    def test_ip_block_creation(self) -> None:
        """Test IPBlock creation."""
        ip_block = IPBlock(cidr="10.0.0.0/8")
        assert ip_block.cidr == "10.0.0.0/8"
        assert ip_block.except_cidrs == []

    def test_ip_block_with_exceptions(self) -> None:
        """Test IPBlock with exceptions."""
        ip_block = IPBlock(
            cidr="10.0.0.0/8",
            except_cidrs=["10.1.0.0/16", "10.2.0.0/16"],
        )
        assert len(ip_block.except_cidrs) == 2


class TestNetworkPeer:
    """Tests for NetworkPeer."""

    def test_network_peer_with_pod_selector(self, sample_network_peer: NetworkPeer) -> None:
        """Test NetworkPeer with pod selector."""
        assert sample_network_peer.pod_selector is not None
        assert sample_network_peer.namespace_selector is not None

    def test_network_peer_with_ip_block(self) -> None:
        """Test NetworkPeer with IP block."""
        peer = NetworkPeer(ip_block=IPBlock(cidr="0.0.0.0/0"))
        assert peer.ip_block is not None
        assert peer.pod_selector is None


class TestTrafficRule:
    """Tests for TrafficRule."""

    def test_traffic_rule_creation(self, sample_traffic_rule: TrafficRule) -> None:
        """Test TrafficRule creation."""
        assert sample_traffic_rule.direction == TrafficDirection.EGRESS
        assert sample_traffic_rule.port == 8080
        assert sample_traffic_rule.protocol == Protocol.TCP

    def test_traffic_rule_defaults(self) -> None:
        """Test TrafficRule default values."""
        rule = TrafficRule(direction=TrafficDirection.INGRESS)
        assert rule.count == 1
        assert rule.source_namespace == ""


class TestIngressRule:
    """Tests for IngressRule."""

    def test_ingress_rule_creation(self, sample_ingress_rule: IngressRule) -> None:
        """Test IngressRule creation."""
        assert len(sample_ingress_rule.from_peers) == 1
        assert len(sample_ingress_rule.ports) == 1

    def test_empty_ingress_rule(self) -> None:
        """Test empty IngressRule (allow all)."""
        rule = IngressRule()
        assert rule.from_peers == []
        assert rule.ports == []


class TestEgressRule:
    """Tests for EgressRule."""

    def test_egress_rule_creation(self, sample_egress_rule: EgressRule) -> None:
        """Test EgressRule creation."""
        assert len(sample_egress_rule.to_peers) == 1
        assert len(sample_egress_rule.ports) == 1

    def test_dns_egress_rule(self, dns_egress_rule: EgressRule) -> None:
        """Test DNS egress rule."""
        assert dns_egress_rule.ports[0].port == 53
        assert dns_egress_rule.ports[0].protocol == Protocol.UDP


class TestNetworkPolicySpec:
    """Tests for NetworkPolicySpec."""

    def test_policy_creation(self, sample_network_policy: NetworkPolicySpec) -> None:
        """Test NetworkPolicySpec creation."""
        assert sample_network_policy.name == "allow-backend"
        assert sample_network_policy.namespace == "default"
        assert "Ingress" in sample_network_policy.policy_types
        assert "Egress" in sample_network_policy.policy_types

    def test_policy_to_k8s_manifest(self, sample_network_policy: NetworkPolicySpec) -> None:
        """Test conversion to Kubernetes manifest."""
        manifest = sample_network_policy.to_k8s_manifest()

        assert manifest["apiVersion"] == "networking.k8s.io/v1"
        assert manifest["kind"] == "NetworkPolicy"
        assert manifest["metadata"]["name"] == "allow-backend"
        assert manifest["metadata"]["namespace"] == "default"
        assert manifest["metadata"]["annotations"]["generation-source"] == "manual"
        assert manifest["metadata"]["annotations"]["generation-degraded"] == "false"
        assert "podSelector" in manifest["spec"]
        assert "policyTypes" in manifest["spec"]

    def test_policy_manifest_includes_generation_failure_metadata(self) -> None:
        """Test degraded generation metadata is visible in manifests."""
        policy = NetworkPolicySpec(
            name="fallback-policy",
            generation=PolicyGenerationMetadata(
                source=PolicyGenerationSource.FALLBACK,
                degraded=True,
                model="gemini-2.0-flash",
                error="Gemini unavailable",
            ),
        )

        annotations = policy.to_k8s_manifest()["metadata"]["annotations"]

        assert annotations["generation-source"] == "fallback"
        assert annotations["generation-degraded"] == "true"
        assert annotations["generation-model"] == "gemini-2.0-flash"
        assert annotations["generation-error"] == "Gemini unavailable"

    def test_policy_manifest_ingress(self, sample_network_policy: NetworkPolicySpec) -> None:
        """Test manifest ingress rules."""
        manifest = sample_network_policy.to_k8s_manifest()
        assert "ingress" in manifest["spec"]
        assert len(manifest["spec"]["ingress"]) > 0

    def test_policy_manifest_egress(self, sample_network_policy: NetworkPolicySpec) -> None:
        """Test manifest egress rules."""
        manifest = sample_network_policy.to_k8s_manifest()
        assert "egress" in manifest["spec"]
        assert len(manifest["spec"]["egress"]) > 0

    def test_policy_compute_hash(self, sample_network_policy: NetworkPolicySpec) -> None:
        """Test policy hash computation."""
        hash1 = sample_network_policy.compute_hash()
        assert len(hash1) == 12
        assert hash1.isalnum()

    def test_default_deny_policy(self, default_deny_policy: NetworkPolicySpec) -> None:
        """Test default deny policy structure."""
        assert default_deny_policy.ingress_rules == []
        assert len(default_deny_policy.egress_rules) == 1  # DNS only
        manifest = default_deny_policy.to_k8s_manifest()
        assert manifest["spec"]["podSelector"]["matchLabels"] == {}


class TestPolicyValidationResult:
    """Tests for PolicyValidationResult."""

    def test_validation_result_valid(self) -> None:
        """Test valid validation result."""
        result = PolicyValidationResult(
            policy_name="test-policy",
            is_valid=True,
            allows_dns=True,
        )
        assert result.is_valid is True
        assert result.errors == []

    def test_validation_result_invalid(self) -> None:
        """Test invalid validation result."""
        result = PolicyValidationResult(
            policy_name="test-policy",
            is_valid=False,
            errors=["Missing namespace"],
        )
        assert result.is_valid is False
        assert len(result.errors) == 1


class TestPolicyEvaluation:
    """Tests for PolicyEvaluation."""

    def test_evaluation_creation(self) -> None:
        """Test PolicyEvaluation creation."""
        evaluation = PolicyEvaluation(
            policy_name="test-policy",
            score=0.85,
            security_score=0.9,
            completeness_score=0.8,
            least_privilege_score=0.85,
            tests_passed=4,
            tests_failed=1,
        )
        assert evaluation.score == 0.85
        assert evaluation.tests_passed == 4

    def test_evaluation_defaults(self) -> None:
        """Test PolicyEvaluation default values."""
        evaluation = PolicyEvaluation(policy_name="test", score=0.5)
        assert evaluation.test_details == []
        assert evaluation.tests_passed == 0


class TestTrafficObservation:
    """Tests for TrafficObservation."""

    def test_observation_creation(self, sample_traffic_observation: TrafficObservation) -> None:
        """Test TrafficObservation creation."""
        assert sample_traffic_observation.source_namespace == "default"
        assert sample_traffic_observation.dest_port == 8080
        assert sample_traffic_observation.count == 1500

    def test_observation_defaults(self) -> None:
        """Test TrafficObservation defaults."""
        obs = TrafficObservation(
            source_namespace="default",
            source_pod="test",
            dest_namespace="default",
            dest_pod="target",
            dest_port=80,
        )
        assert obs.count == 1


class TestPolicyGenerationRequest:
    """Tests for PolicyGenerationRequest."""

    def test_request_creation(
        self, sample_policy_generation_request: PolicyGenerationRequest
    ) -> None:
        """Test PolicyGenerationRequest creation."""
        assert sample_policy_generation_request.target_namespace == "default"
        assert sample_policy_generation_request.target_pod_labels == {"app": "backend"}
        assert len(sample_policy_generation_request.traffic_observations) == 3

    def test_request_defaults(self) -> None:
        """Test PolicyGenerationRequest defaults."""
        request = PolicyGenerationRequest(target_namespace="test")
        assert request.target_pod_labels == {}
        assert request.traffic_observations == []


class TestGitOpsCommit:
    """Tests for GitOpsCommit."""

    def test_commit_creation(self) -> None:
        """Test GitOpsCommit creation."""
        commit = GitOpsCommit(
            commit_hash="abc123def456",
            message="Add policy",
            author="k8s-policy-agent",
            files_changed=["policies/test.yaml"],
            policy_names=["test-policy"],
        )
        assert commit.commit_hash == "abc123def456"
        assert len(commit.files_changed) == 1
        assert commit.operation_mode == "real"
        assert commit.failure_reason == ""


class TestAgentStats:
    """Tests for AgentStats."""

    def test_stats_creation(self) -> None:
        """Test AgentStats creation."""
        stats = AgentStats(
            policies_generated=10,
            policies_validated=15,
            policies_applied=5,
        )
        assert stats.policies_generated == 10

    def test_stats_defaults(self) -> None:
        """Test AgentStats default values."""
        stats = AgentStats()
        assert stats.policies_generated == 0
        assert stats.validation_errors == 0
