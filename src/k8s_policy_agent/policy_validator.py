"""Policy validator using DeepEval."""

from __future__ import annotations

from typing import Any

import structlog
import yaml

from k8s_policy_agent.models import (
    NetworkPolicySpec,
    PolicyConfig,
    PolicyEvaluation,
    PolicyValidationResult,
)

logger = structlog.get_logger()


# Golden rules for security validation
SECURITY_RULES = {
    "dns_egress": {
        "description": "Policy should allow DNS egress to kube-system",
        "required": True,
    },
    "no_allow_all_ingress": {
        "description": "Policy should not allow all ingress",
        "required": True,
    },
    "no_allow_all_egress": {
        "description": "Policy should not allow all egress",
        "required": True,
    },
    "has_pod_selector": {
        "description": "Policy should target specific pods",
        "required": True,
    },
    "has_policy_types": {
        "description": "Policy should specify policy types",
        "required": True,
    },
}


class PolicyValidator:
    """Validates NetworkPolicy specifications."""

    def __init__(self, config: PolicyConfig) -> None:
        """Initialize the policy validator.

        Args:
            config: Policy configuration
        """
        self.config = config

    def validate(self, policy: NetworkPolicySpec) -> PolicyValidationResult:
        """Validate a NetworkPolicy specification.

        Args:
            policy: Policy to validate

        Returns:
            Validation result
        """
        errors: list[str] = []
        warnings: list[str] = []
        recommendations: list[str] = []

        # Basic validation
        if not policy.name:
            errors.append("Policy must have a name")

        if not policy.namespace:
            errors.append("Policy must have a namespace")

        # Check policy types
        if not policy.policy_types:
            errors.append("Policy must specify policy types (Ingress/Egress)")

        # Check for overly permissive rules
        allows_all_ingress = self._allows_all_traffic(policy.ingress_rules, "ingress")
        allows_all_egress = self._allows_all_traffic(policy.egress_rules, "egress")

        if allows_all_ingress:
            warnings.append("Policy allows all ingress traffic - consider restricting")

        if allows_all_egress:
            warnings.append("Policy allows all egress traffic - consider restricting")

        # Check DNS egress
        allows_dns = self._check_dns_egress(policy)
        if not allows_dns and "Egress" in policy.policy_types:
            warnings.append("Policy may block DNS - ensure DNS egress is allowed")

        # Check API server access
        allows_api = self._check_api_server_access(policy)

        # Check external traffic blocking
        blocks_external = self._check_blocks_external(policy)

        # Generate recommendations
        if not policy.ingress_rules and "Ingress" in policy.policy_types:
            recommendations.append("No ingress rules defined - all ingress will be blocked")

        if len(policy.egress_rules) < 2 and "Egress" in policy.policy_types:
            recommendations.append("Consider adding more specific egress rules for better security")

        is_valid = len(errors) == 0

        return PolicyValidationResult(
            policy_name=policy.name,
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            allows_dns=allows_dns,
            allows_api_server=allows_api,
            blocks_external=blocks_external,
            recommendations=recommendations,
        )

    def validate_yaml(self, yaml_content: str) -> PolicyValidationResult:
        """Validate a policy from YAML string.

        Args:
            yaml_content: YAML policy content

        Returns:
            Validation result
        """
        try:
            data = yaml.safe_load(yaml_content)

            if data.get("kind") != "NetworkPolicy":
                return PolicyValidationResult(
                    policy_name="unknown",
                    is_valid=False,
                    errors=["Not a NetworkPolicy resource"],
                )

            # Extract policy spec from manifest
            metadata = data.get("metadata", {})
            spec = data.get("spec", {})

            policy = self._manifest_to_spec(metadata, spec)
            return self.validate(policy)

        except yaml.YAMLError as e:
            return PolicyValidationResult(
                policy_name="unknown",
                is_valid=False,
                errors=[f"Invalid YAML: {e}"],
            )

    def evaluate(self, policy: NetworkPolicySpec) -> PolicyEvaluation:
        """Evaluate a policy using DeepEval-style metrics.

        Args:
            policy: Policy to evaluate

        Returns:
            Policy evaluation result
        """
        tests_passed = 0
        tests_failed = 0
        test_details: list[dict[str, Any]] = []

        # Run security tests
        for rule_name, rule_config in SECURITY_RULES.items():
            passed = self._run_security_test(policy, rule_name)

            if passed:
                tests_passed += 1
            else:
                tests_failed += 1

            test_details.append(
                {
                    "test": rule_name,
                    "description": rule_config["description"],
                    "passed": passed,
                    "required": rule_config["required"],
                }
            )

        # Calculate scores
        total_tests = tests_passed + tests_failed
        security_score = tests_passed / total_tests if total_tests > 0 else 0.0

        # Completeness score based on rule coverage
        completeness_score = self._calculate_completeness(policy)

        # Least privilege score
        least_privilege_score = self._calculate_least_privilege(policy)

        # Overall score
        overall_score = (
            security_score * 0.4 + completeness_score * 0.3 + least_privilege_score * 0.3
        )

        return PolicyEvaluation(
            policy_name=policy.name,
            score=overall_score,
            security_score=security_score,
            completeness_score=completeness_score,
            least_privilege_score=least_privilege_score,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            test_details=test_details,
        )

    def _allows_all_traffic(self, rules: list[Any], direction: str) -> bool:
        """Check if rules allow all traffic.

        Args:
            rules: Ingress or egress rules
            direction: Traffic direction

        Returns:
            True if allows all traffic
        """
        if not rules:
            return False

        for rule in rules:
            peers = rule.from_peers if direction == "ingress" else rule.to_peers
            if not peers:
                return True  # Empty peers = allow all

            for peer in peers:
                if not peer.pod_selector and not peer.namespace_selector and not peer.ip_block:
                    return True

        return False

    def _check_dns_egress(self, policy: NetworkPolicySpec) -> bool:
        """Check if policy allows DNS egress.

        Args:
            policy: Policy to check

        Returns:
            True if DNS is allowed
        """
        if "Egress" not in policy.policy_types:
            return True  # No egress restriction

        for rule in policy.egress_rules:
            for port in rule.ports:
                if port.port == 53:
                    return True

        return False

    def _check_api_server_access(self, policy: NetworkPolicySpec) -> bool:
        """Check if policy allows API server access.

        Args:
            policy: Policy to check

        Returns:
            True if API server access is allowed
        """
        if "Egress" not in policy.policy_types:
            return True

        for rule in policy.egress_rules:
            for port in rule.ports:
                if port.port == 443 or port.port == 6443:
                    return True

        return False

    def _check_blocks_external(self, policy: NetworkPolicySpec) -> bool:
        """Check if policy blocks external traffic.

        Args:
            policy: Policy to check

        Returns:
            True if external traffic is blocked
        """
        if "Egress" not in policy.policy_types:
            return False

        # If there are egress rules but none allow external IPs, it blocks external
        for rule in policy.egress_rules:
            for peer in rule.to_peers:
                if peer.ip_block and "0.0.0.0/0" in peer.ip_block.cidr:
                    return False

        return len(policy.egress_rules) > 0

    def _run_security_test(self, policy: NetworkPolicySpec, test_name: str) -> bool:
        """Run a specific security test.

        Args:
            policy: Policy to test
            test_name: Test name

        Returns:
            True if test passes
        """
        if test_name == "dns_egress":
            return self._check_dns_egress(policy)

        if test_name == "no_allow_all_ingress":
            return not self._allows_all_traffic(policy.ingress_rules, "ingress")

        if test_name == "no_allow_all_egress":
            return not self._allows_all_traffic(policy.egress_rules, "egress")

        if test_name == "has_pod_selector":
            return bool(policy.pod_selector.match_labels)

        if test_name == "has_policy_types":
            return bool(policy.policy_types)

        return True

    def _calculate_completeness(self, policy: NetworkPolicySpec) -> float:
        """Calculate policy completeness score.

        Args:
            policy: Policy to evaluate

        Returns:
            Completeness score (0-1)
        """
        score = 0.0

        # Has name
        if policy.name:
            score += 0.1

        # Has namespace
        if policy.namespace:
            score += 0.1

        # Has pod selector
        if policy.pod_selector.match_labels:
            score += 0.2

        # Has policy types
        if policy.policy_types:
            score += 0.1

        # Has ingress rules if Ingress type
        if (
            "Ingress" in policy.policy_types
            and policy.ingress_rules
            or "Ingress" not in policy.policy_types
        ):
            score += 0.2

        # Has egress rules if Egress type
        if (
            "Egress" in policy.policy_types
            and policy.egress_rules
            or "Egress" not in policy.policy_types
        ):
            score += 0.2

        # Has description
        if policy.description:
            score += 0.1

        return min(score, 1.0)

    def _calculate_least_privilege(self, policy: NetworkPolicySpec) -> float:
        """Calculate least privilege score.

        Args:
            policy: Policy to evaluate

        Returns:
            Least privilege score (0-1)
        """
        score = 1.0

        # Penalize allow-all rules
        if self._allows_all_traffic(policy.ingress_rules, "ingress"):
            score -= 0.3

        if self._allows_all_traffic(policy.egress_rules, "egress"):
            score -= 0.3

        # Reward specific pod selectors
        if policy.pod_selector.match_labels:
            score += 0.1

        # Reward specific peer selectors in rules
        specific_peers = 0
        total_peers = 0

        for ingress_rule in policy.ingress_rules:
            for peer in ingress_rule.from_peers:
                total_peers += 1
                if peer.pod_selector and peer.pod_selector.match_labels:
                    specific_peers += 1

        for egress_rule in policy.egress_rules:
            for peer in egress_rule.to_peers:
                total_peers += 1
                if peer.pod_selector and peer.pod_selector.match_labels:
                    specific_peers += 1

        if total_peers > 0:
            score += (specific_peers / total_peers) * 0.2

        return max(min(score, 1.0), 0.0)

    def _manifest_to_spec(
        self, metadata: dict[str, Any], spec: dict[str, Any]
    ) -> NetworkPolicySpec:
        """Convert K8s manifest to NetworkPolicySpec.

        Args:
            metadata: Manifest metadata
            spec: Manifest spec

        Returns:
            NetworkPolicySpec
        """
        from k8s_policy_agent.models import PodSelector

        pod_selector_data = spec.get("podSelector", {})
        pod_selector = PodSelector(match_labels=pod_selector_data.get("matchLabels", {}))

        return NetworkPolicySpec(
            name=metadata.get("name", "unknown"),
            namespace=metadata.get("namespace", "default"),
            pod_selector=pod_selector,
            policy_types=spec.get("policyTypes", []),
            description=metadata.get("annotations", {}).get("description", ""),
        )


def create_policy_validator(config: PolicyConfig | None = None) -> PolicyValidator:
    """Factory function to create PolicyValidator.

    Args:
        config: Optional policy configuration

    Returns:
        Configured PolicyValidator instance
    """
    if config is None:
        config = PolicyConfig()

    return PolicyValidator(config)
