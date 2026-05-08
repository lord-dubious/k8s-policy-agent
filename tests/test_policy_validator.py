"""Tests for policy validator."""

from k8s_policy_agent.models import (
    EgressRule,
    NamespaceSelector,
    NetworkPeer,
    NetworkPolicySpec,
    PodSelector,
    PolicyConfig,
    PolicyEvaluation,
    PolicyValidationResult,
    PortSpec,
    Protocol,
)
from k8s_policy_agent.policy_validator import (
    SECURITY_RULES,
    PolicyValidator,
    create_policy_validator,
)


class TestPolicyValidatorInit:
    """Tests for PolicyValidator initialization."""

    def test_create_with_config(self, mock_config: PolicyConfig) -> None:
        """Test creating validator with config."""
        validator = PolicyValidator(mock_config)
        assert validator.config == mock_config

    def test_factory_function(self, mock_config: PolicyConfig) -> None:
        """Test factory function."""
        validator = create_policy_validator(mock_config)
        assert validator is not None

    def test_factory_without_config(self) -> None:
        """Test factory function without config."""
        validator = create_policy_validator()
        assert validator.config is not None


class TestSecurityRules:
    """Tests for security rules configuration."""

    def test_security_rules_defined(self) -> None:
        """Test security rules are defined."""
        assert len(SECURITY_RULES) > 0

    def test_required_rules(self) -> None:
        """Test required security rules."""
        assert "dns_egress" in SECURITY_RULES
        assert "no_allow_all_ingress" in SECURITY_RULES
        assert "no_allow_all_egress" in SECURITY_RULES
        assert "has_pod_selector" in SECURITY_RULES
        assert "has_policy_types" in SECURITY_RULES


class TestValidate:
    """Tests for policy validation."""

    def test_validate_valid_policy(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test validating a valid policy."""
        validator = PolicyValidator(mock_config)
        result = validator.validate(sample_network_policy)

        assert isinstance(result, PolicyValidationResult)
        assert result.is_valid is True
        assert result.policy_name == "allow-backend"

    def test_validate_policy_without_name(self, mock_config: PolicyConfig) -> None:
        """Test validating policy without name."""
        policy = NetworkPolicySpec(
            name="",
            namespace="default",
            pod_selector=PodSelector(match_labels={"app": "test"}),
            policy_types=["Ingress"],
        )

        validator = PolicyValidator(mock_config)
        result = validator.validate(policy)

        assert result.is_valid is False
        assert any("name" in error.lower() for error in result.errors)

    def test_validate_policy_without_namespace(self, mock_config: PolicyConfig) -> None:
        """Test validating policy without namespace."""
        policy = NetworkPolicySpec(
            name="test",
            namespace="",
            pod_selector=PodSelector(match_labels={"app": "test"}),
            policy_types=["Ingress"],
        )

        validator = PolicyValidator(mock_config)
        result = validator.validate(policy)

        assert result.is_valid is False
        assert any("namespace" in error.lower() for error in result.errors)

    def test_validate_policy_without_policy_types(self, mock_config: PolicyConfig) -> None:
        """Test validating policy without policy types."""
        policy = NetworkPolicySpec(
            name="test",
            namespace="default",
            pod_selector=PodSelector(match_labels={"app": "test"}),
            policy_types=[],
        )

        validator = PolicyValidator(mock_config)
        result = validator.validate(policy)

        assert result.is_valid is False


class TestValidateOverlyPermissive:
    """Tests for detecting overly permissive policies."""

    def test_warn_allow_all_ingress(
        self,
        mock_config: PolicyConfig,
        overly_permissive_policy: NetworkPolicySpec,
    ) -> None:
        """Test warning for allow-all ingress."""
        validator = PolicyValidator(mock_config)
        result = validator.validate(overly_permissive_policy)

        assert any("ingress" in w.lower() for w in result.warnings)

    def test_warn_allow_all_egress(
        self,
        mock_config: PolicyConfig,
        overly_permissive_policy: NetworkPolicySpec,
    ) -> None:
        """Test warning for allow-all egress."""
        validator = PolicyValidator(mock_config)
        result = validator.validate(overly_permissive_policy)

        assert any("egress" in w.lower() for w in result.warnings)


class TestDnsCheck:
    """Tests for DNS egress checking."""

    def test_allows_dns_true(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test policy allows DNS."""
        validator = PolicyValidator(mock_config)
        result = validator.validate(sample_network_policy)

        assert result.allows_dns is True

    def test_allows_dns_false(
        self,
        mock_config: PolicyConfig,
        policy_without_dns: NetworkPolicySpec,
    ) -> None:
        """Test policy blocks DNS."""
        validator = PolicyValidator(mock_config)
        result = validator.validate(policy_without_dns)

        assert result.allows_dns is False

    def test_dns_warning_when_blocked(
        self,
        mock_config: PolicyConfig,
        policy_without_dns: NetworkPolicySpec,
    ) -> None:
        """Test warning when DNS is blocked."""
        validator = PolicyValidator(mock_config)
        result = validator.validate(policy_without_dns)

        assert any("dns" in w.lower() for w in result.warnings)


class TestValidateYaml:
    """Tests for YAML validation."""

    def test_validate_valid_yaml(
        self,
        mock_config: PolicyConfig,
        valid_policy_yaml: str,
    ) -> None:
        """Test validating valid YAML."""
        validator = PolicyValidator(mock_config)
        result = validator.validate_yaml(valid_policy_yaml)

        assert result.is_valid is True

    def test_validate_invalid_kind(
        self,
        mock_config: PolicyConfig,
        invalid_policy_yaml: str,
    ) -> None:
        """Test validating YAML with wrong kind."""
        validator = PolicyValidator(mock_config)
        result = validator.validate_yaml(invalid_policy_yaml)

        assert result.is_valid is False
        assert any("NetworkPolicy" in error for error in result.errors)

    def test_validate_invalid_yaml_syntax(self, mock_config: PolicyConfig) -> None:
        """Test validating invalid YAML syntax."""
        validator = PolicyValidator(mock_config)
        result = validator.validate_yaml("not: valid: yaml: :")

        assert result.is_valid is False
        assert any("YAML" in error for error in result.errors)


class TestEvaluate:
    """Tests for policy evaluation."""

    def test_evaluate_returns_evaluation(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test evaluate returns PolicyEvaluation."""
        validator = PolicyValidator(mock_config)
        evaluation = validator.evaluate(sample_network_policy)

        assert isinstance(evaluation, PolicyEvaluation)
        assert evaluation.policy_name == "allow-backend"

    def test_evaluate_scores(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test evaluation scores are calculated."""
        validator = PolicyValidator(mock_config)
        evaluation = validator.evaluate(sample_network_policy)

        assert 0 <= evaluation.security_score <= 1
        assert 0 <= evaluation.completeness_score <= 1
        assert 0 <= evaluation.least_privilege_score <= 1
        assert 0 <= evaluation.score <= 1

    def test_evaluate_test_counts(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test evaluation includes test counts."""
        validator = PolicyValidator(mock_config)
        evaluation = validator.evaluate(sample_network_policy)

        total = evaluation.tests_passed + evaluation.tests_failed
        assert total == len(SECURITY_RULES)

    def test_evaluate_test_details(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test evaluation includes test details."""
        validator = PolicyValidator(mock_config)
        evaluation = validator.evaluate(sample_network_policy)

        assert len(evaluation.test_details) == len(SECURITY_RULES)
        for detail in evaluation.test_details:
            assert "test" in detail
            assert "passed" in detail
            assert "description" in detail


class TestSecurityTests:
    """Tests for individual security tests."""

    def test_dns_egress_test_passes(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test DNS egress test passes."""
        validator = PolicyValidator(mock_config)
        result = validator._run_security_test(sample_network_policy, "dns_egress")
        assert result is True

    def test_dns_egress_test_fails(
        self,
        mock_config: PolicyConfig,
        policy_without_dns: NetworkPolicySpec,
    ) -> None:
        """Test DNS egress test fails."""
        validator = PolicyValidator(mock_config)
        result = validator._run_security_test(policy_without_dns, "dns_egress")
        assert result is False

    def test_no_allow_all_ingress_passes(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test no-allow-all-ingress test passes."""
        validator = PolicyValidator(mock_config)
        result = validator._run_security_test(sample_network_policy, "no_allow_all_ingress")
        assert result is True

    def test_no_allow_all_ingress_fails(
        self,
        mock_config: PolicyConfig,
        overly_permissive_policy: NetworkPolicySpec,
    ) -> None:
        """Test no-allow-all-ingress test fails."""
        validator = PolicyValidator(mock_config)
        result = validator._run_security_test(overly_permissive_policy, "no_allow_all_ingress")
        assert result is False

    def test_has_pod_selector_passes(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test has-pod-selector test passes."""
        validator = PolicyValidator(mock_config)
        result = validator._run_security_test(sample_network_policy, "has_pod_selector")
        assert result is True

    def test_has_pod_selector_fails(
        self,
        mock_config: PolicyConfig,
        policy_with_no_pod_selector: NetworkPolicySpec,
    ) -> None:
        """Test has-pod-selector test fails."""
        validator = PolicyValidator(mock_config)
        result = validator._run_security_test(policy_with_no_pod_selector, "has_pod_selector")
        assert result is False


class TestCompletenessScore:
    """Tests for completeness score calculation."""

    def test_complete_policy_high_score(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test complete policy gets high score."""
        validator = PolicyValidator(mock_config)
        score = validator._calculate_completeness(sample_network_policy)

        assert score >= 0.8

    def test_minimal_policy_low_score(self, mock_config: PolicyConfig) -> None:
        """Test minimal policy gets lower score."""
        policy = NetworkPolicySpec(
            name="",  # No name
            namespace="",  # No namespace
            pod_selector=PodSelector(),
            policy_types=[],
        )

        validator = PolicyValidator(mock_config)
        score = validator._calculate_completeness(policy)

        assert score < 0.5


class TestLeastPrivilegeScore:
    """Tests for least privilege score calculation."""

    def test_restrictive_policy_high_score(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test restrictive policy gets high score."""
        validator = PolicyValidator(mock_config)
        score = validator._calculate_least_privilege(sample_network_policy)

        assert score > 0.5

    def test_permissive_policy_low_score(
        self,
        mock_config: PolicyConfig,
        overly_permissive_policy: NetworkPolicySpec,
    ) -> None:
        """Test permissive policy gets low score."""
        validator = PolicyValidator(mock_config)
        score = validator._calculate_least_privilege(overly_permissive_policy)

        assert score < 0.5


class TestRecommendations:
    """Tests for validation recommendations."""

    def test_recommendations_for_empty_ingress(self, mock_config: PolicyConfig) -> None:
        """Test recommendations for empty ingress rules."""
        policy = NetworkPolicySpec(
            name="test",
            namespace="default",
            pod_selector=PodSelector(match_labels={"app": "test"}),
            policy_types=["Ingress", "Egress"],
            ingress_rules=[],
            egress_rules=[
                EgressRule(
                    to_peers=[
                        NetworkPeer(
                            namespace_selector=NamespaceSelector(
                                match_labels={"kubernetes.io/metadata.name": "kube-system"}
                            ),
                            pod_selector=PodSelector(match_labels={"k8s-app": "kube-dns"}),
                        )
                    ],
                    ports=[PortSpec(port=53, protocol=Protocol.UDP)],
                )
            ],
        )

        validator = PolicyValidator(mock_config)
        result = validator.validate(policy)

        assert any("ingress" in r.lower() for r in result.recommendations)
