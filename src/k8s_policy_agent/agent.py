"""Main orchestrator agent for Kubernetes policy management."""

from __future__ import annotations

from typing import Any

import structlog

from k8s_policy_agent.gitops import GitOpsManager
from k8s_policy_agent.models import (
    AgentStats,
    GitOpsCommit,
    NetworkPolicySpec,
    PolicyConfig,
    PolicyEvaluation,
    PolicyGenerationRequest,
    PolicyValidationResult,
    TrafficObservation,
)
from k8s_policy_agent.policy_generator import PolicyGenerator
from k8s_policy_agent.policy_validator import PolicyValidator
from k8s_policy_agent.traffic_analyzer import TrafficAnalyzer

logger = structlog.get_logger()


class PolicyAgent:
    """Orchestrates the full policy lifecycle: analyze -> generate -> validate -> apply."""

    def __init__(self, config: PolicyConfig) -> None:
        """Initialize the policy agent.

        Args:
            config: Policy configuration
        """
        self.config = config
        self.traffic_analyzer = TrafficAnalyzer(config)
        self.policy_generator = PolicyGenerator(config)
        self.policy_validator = PolicyValidator(config)
        self.gitops_manager = GitOpsManager(config)

        # Statistics
        self._stats = AgentStats()
        self._policies_cache: dict[str, NetworkPolicySpec] = {}

    async def analyze_and_generate(
        self,
        namespace: str,
        pod_labels: dict[str, str] | None = None,
    ) -> NetworkPolicySpec:
        """Analyze traffic and generate a NetworkPolicy.

        Args:
            namespace: Target namespace
            pod_labels: Optional pod label selectors

        Returns:
            Generated NetworkPolicy
        """
        logger.info("starting_analysis", namespace=namespace, pod_labels=pod_labels)

        # Analyze traffic
        if pod_labels:
            observations = await self.traffic_analyzer.analyze_pod(namespace, pod_labels)
        else:
            observations = await self.traffic_analyzer.analyze_namespace(namespace)

        logger.info("traffic_analyzed", observations_count=len(observations))

        # Aggregate observations
        aggregated = self.traffic_analyzer.aggregate_observations(observations)

        # Generate policy
        request = PolicyGenerationRequest(
            target_namespace=namespace,
            target_pod_labels=pod_labels or {},
            traffic_observations=aggregated,
        )

        policy = await self.policy_generator.generate(request)

        # Update stats
        self._update_stats(policies_generated=1, traffic_rules_observed=len(observations))

        # Cache policy
        cache_key = f"{namespace}/{policy.name}"
        self._policies_cache[cache_key] = policy

        return policy

    async def generate_from_observations(
        self,
        namespace: str,
        pod_labels: dict[str, str],
        observations: list[TrafficObservation],
    ) -> NetworkPolicySpec:
        """Generate policy from provided observations.

        Args:
            namespace: Target namespace
            pod_labels: Target pod labels
            observations: Traffic observations

        Returns:
            Generated NetworkPolicy
        """
        policy = await self.policy_generator.generate_from_observations(
            namespace, pod_labels, observations
        )

        self._update_stats(policies_generated=1, traffic_rules_observed=len(observations))

        return policy

    async def generate_default_deny(self, namespace: str) -> NetworkPolicySpec:
        """Generate a default-deny policy.

        Args:
            namespace: Target namespace

        Returns:
            Default deny NetworkPolicy
        """
        policy = await self.policy_generator.generate_default_deny(namespace)
        self._update_stats(policies_generated=1)
        return policy

    def validate(self, policy: NetworkPolicySpec) -> PolicyValidationResult:
        """Validate a NetworkPolicy.

        Args:
            policy: Policy to validate

        Returns:
            Validation result
        """
        result = self.policy_validator.validate(policy)
        self._update_stats(policies_validated=1)

        if not result.is_valid:
            self._update_stats(validation_errors=len(result.errors))

        return result

    def validate_yaml(self, yaml_content: str) -> PolicyValidationResult:
        """Validate a policy from YAML.

        Args:
            yaml_content: YAML policy content

        Returns:
            Validation result
        """
        result = self.policy_validator.validate_yaml(yaml_content)
        self._update_stats(policies_validated=1)

        if not result.is_valid:
            self._update_stats(validation_errors=len(result.errors))

        return result

    def evaluate(self, policy: NetworkPolicySpec) -> PolicyEvaluation:
        """Evaluate a policy using DeepEval-style metrics.

        Args:
            policy: Policy to evaluate

        Returns:
            Policy evaluation
        """
        return self.policy_validator.evaluate(policy)

    async def apply_policy(
        self,
        policy: NetworkPolicySpec,
        commit_message: str | None = None,
    ) -> GitOpsCommit:
        """Apply a policy via GitOps.

        Args:
            policy: Policy to apply
            commit_message: Optional commit message

        Returns:
            GitOps commit information
        """
        # Validate first
        validation = self.validate(policy)

        if not validation.is_valid:
            raise ValueError(f"Policy validation failed: {validation.errors}")

        # Evaluate
        evaluation = self.evaluate(policy)

        if evaluation.score < 0.5:
            logger.warning(
                "low_evaluation_score",
                policy=policy.name,
                score=evaluation.score,
            )

            if not self.config.auto_approve:
                raise ValueError(f"Policy evaluation score too low: {evaluation.score:.2f}")

        # Commit to GitOps repo
        commit = await self.gitops_manager.commit_policy(policy, commit_message)

        # Push if not dry run
        if not self.config.dry_run:
            pushed = await self.gitops_manager.push()
            if not pushed:
                logger.warning("push_failed", commit=commit.commit_hash)

        self._update_stats(policies_applied=1, gitops_commits=1)

        return commit

    async def apply_policies(
        self,
        policies: list[NetworkPolicySpec],
        commit_message: str | None = None,
    ) -> GitOpsCommit:
        """Apply multiple policies via GitOps.

        Args:
            policies: Policies to apply
            commit_message: Optional commit message

        Returns:
            GitOps commit information
        """
        # Validate all policies first
        for policy in policies:
            validation = self.validate(policy)
            if not validation.is_valid:
                raise ValueError(f"Policy {policy.name} validation failed: {validation.errors}")

        # Commit all policies
        commit = await self.gitops_manager.commit_policies(policies, commit_message)

        # Push if not dry run
        if not self.config.dry_run:
            await self.gitops_manager.push()

        self._update_stats(
            policies_applied=len(policies),
            gitops_commits=1,
        )

        return commit

    async def full_pipeline(
        self,
        namespace: str,
        pod_labels: dict[str, str] | None = None,
        auto_apply: bool = False,
    ) -> dict[str, Any]:
        """Run the full pipeline: analyze -> generate -> validate -> (optionally) apply.

        Args:
            namespace: Target namespace
            pod_labels: Optional pod label selectors
            auto_apply: Whether to apply the policy automatically

        Returns:
            Pipeline results including policy, validation, and evaluation
        """
        logger.info(
            "starting_full_pipeline",
            namespace=namespace,
            pod_labels=pod_labels,
            auto_apply=auto_apply,
        )

        # Step 1: Analyze and generate
        policy = await self.analyze_and_generate(namespace, pod_labels)

        # Step 2: Validate
        validation = self.validate(policy)

        # Step 3: Evaluate
        evaluation = self.evaluate(policy)

        result: dict[str, Any] = {
            "policy": policy,
            "policy_yaml": self.policy_generator.policy_to_yaml(policy),
            "validation": validation,
            "evaluation": evaluation,
            "applied": False,
            "commit": None,
        }

        # Step 4: Apply if requested and valid
        if auto_apply and validation.is_valid:
            try:
                commit = await self.apply_policy(policy)
                result["applied"] = True
                result["commit"] = commit
            except ValueError as e:
                logger.warning("auto_apply_failed", error=str(e))
                result["apply_error"] = str(e)

        return result

    async def cleanup(self) -> None:
        """Clean up resources."""
        self.gitops_manager.cleanup()

    def get_cached_policy(self, namespace: str, name: str) -> NetworkPolicySpec | None:
        """Get a cached policy.

        Args:
            namespace: Policy namespace
            name: Policy name

        Returns:
            Cached policy or None
        """
        cache_key = f"{namespace}/{name}"
        return self._policies_cache.get(cache_key)

    def clear_cache(self) -> None:
        """Clear the policy cache."""
        self._policies_cache.clear()

    def _update_stats(
        self,
        policies_generated: int = 0,
        policies_validated: int = 0,
        policies_applied: int = 0,
        traffic_rules_observed: int = 0,
        gitops_commits: int = 0,
        validation_errors: int = 0,
    ) -> None:
        """Update agent statistics.

        Args:
            policies_generated: Number of policies generated
            policies_validated: Number of policies validated
            policies_applied: Number of policies applied
            traffic_rules_observed: Number of traffic rules observed
            gitops_commits: Number of GitOps commits
            validation_errors: Number of validation errors
        """
        self._stats = AgentStats(
            policies_generated=self._stats.policies_generated + policies_generated,
            policies_validated=self._stats.policies_validated + policies_validated,
            policies_applied=self._stats.policies_applied + policies_applied,
            traffic_rules_observed=self._stats.traffic_rules_observed + traffic_rules_observed,
            gitops_commits=self._stats.gitops_commits + gitops_commits,
            validation_errors=self._stats.validation_errors + validation_errors,
        )

    def get_stats(self) -> AgentStats:
        """Get agent statistics.

        Returns:
            Agent statistics
        """
        return self._stats

    def get_full_stats(self) -> dict[str, Any]:
        """Get full statistics from all components.

        Returns:
            Full statistics dictionary
        """
        return {
            "agent": self._stats.model_dump(),
            "traffic_analyzer": self.traffic_analyzer.get_stats(),
            "gitops": self.gitops_manager.get_stats(),
            "cached_policies": len(self._policies_cache),
        }


def create_policy_agent(config: PolicyConfig | None = None) -> PolicyAgent:
    """Factory function to create PolicyAgent.

    Args:
        config: Optional policy configuration

    Returns:
        Configured PolicyAgent instance
    """
    if config is None:
        config = PolicyConfig()

    return PolicyAgent(config)
