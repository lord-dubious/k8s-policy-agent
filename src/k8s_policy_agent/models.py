"""Data models for Kubernetes Policy Agent."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TrafficDirection(StrEnum):
    """Network traffic direction."""

    INGRESS = "ingress"
    EGRESS = "egress"
    BOTH = "both"


class PolicyAction(StrEnum):
    """Policy action type."""

    ALLOW = "allow"
    DENY = "deny"


class Protocol(StrEnum):
    """Network protocol."""

    TCP = "TCP"
    UDP = "UDP"
    SCTP = "SCTP"


class PolicyGenerationSource(StrEnum):
    """Source used to generate a NetworkPolicy."""

    GEMINI = "gemini"
    MOCK = "mock"
    FALLBACK = "fallback"
    MANUAL = "manual"


class PolicyGenerationMetadata(BaseModel):
    """Metadata describing how a NetworkPolicy was generated."""

    model_config = ConfigDict(frozen=True)

    source: PolicyGenerationSource = Field(
        default=PolicyGenerationSource.MANUAL,
        description="Generation source used for this policy",
    )
    degraded: bool = Field(
        default=False,
        description="Whether generation used degraded fallback behavior",
    )
    model: str = Field(default="", description="External model name, when used")
    error: str = Field(default="", description="Generation error that caused degradation")


class PolicyConfig(BaseSettings):
    """Configuration for the Kubernetes Policy Agent."""

    model_config = SettingsConfigDict(
        env_prefix="K8S_POLICY_",
        env_file=".env",
        extra="ignore",
    )

    # Gemini settings
    gemini_api_key: str = Field(default="", description="Gemini API key")
    gemini_model: str = Field(default="gemini-2.0-flash", description="Gemini model")

    # Kubernetes settings
    kubeconfig: str = Field(default="", description="Path to kubeconfig")
    namespace: str = Field(default="default", description="Default namespace")

    # GitOps settings
    git_repo_url: str = Field(default="", description="Git repository URL")
    git_branch: str = Field(default="main", description="Git branch")
    git_policies_path: str = Field(default="policies/", description="Path for policies")

    # Policy settings
    default_deny_all: bool = Field(default=True, description="Default deny all traffic")
    auto_approve: bool = Field(default=False, description="Auto-approve policies")
    dry_run: bool = Field(default=True, description="Dry run mode")
    mock_mode: bool = Field(default=False, description="Mock mode for testing")


def create_config(**kwargs: Any) -> PolicyConfig:
    """Factory function to create PolicyConfig."""
    return PolicyConfig(**kwargs)


class PortSpec(BaseModel):
    """Port specification for network policy."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(description="Port number")
    protocol: Protocol = Field(default=Protocol.TCP, description="Protocol")
    end_port: int | None = Field(default=None, description="End port for range")


class PodSelector(BaseModel):
    """Pod selector for network policy."""

    model_config = ConfigDict(frozen=True)

    match_labels: dict[str, str] = Field(default_factory=dict, description="Label selectors")
    match_expressions: list[dict[str, Any]] = Field(
        default_factory=list, description="Expression selectors"
    )


class NamespaceSelector(BaseModel):
    """Namespace selector for network policy."""

    model_config = ConfigDict(frozen=True)

    match_labels: dict[str, str] = Field(default_factory=dict, description="Label selectors")
    match_expressions: list[dict[str, Any]] = Field(
        default_factory=list, description="Expression selectors"
    )


class IPBlock(BaseModel):
    """IP block for network policy."""

    model_config = ConfigDict(frozen=True)

    cidr: str = Field(description="CIDR block")
    except_cidrs: list[str] = Field(default_factory=list, description="Except CIDRs")


class NetworkPeer(BaseModel):
    """Network peer (source or destination) for traffic rule."""

    model_config = ConfigDict(frozen=True)

    pod_selector: PodSelector | None = Field(default=None, description="Pod selector")
    namespace_selector: NamespaceSelector | None = Field(
        default=None, description="Namespace selector"
    )
    ip_block: IPBlock | None = Field(default=None, description="IP block")


class TrafficRule(BaseModel):
    """A traffic rule observed or to be applied."""

    model_config = ConfigDict(frozen=True)

    direction: TrafficDirection = Field(description="Traffic direction")
    source_namespace: str = Field(default="", description="Source namespace")
    source_pod: str = Field(default="", description="Source pod name/pattern")
    source_labels: dict[str, str] = Field(default_factory=dict, description="Source labels")
    dest_namespace: str = Field(default="", description="Destination namespace")
    dest_pod: str = Field(default="", description="Destination pod name/pattern")
    dest_labels: dict[str, str] = Field(default_factory=dict, description="Dest labels")
    port: int | None = Field(default=None, description="Port number")
    protocol: Protocol = Field(default=Protocol.TCP, description="Protocol")
    count: int = Field(default=1, description="Observation count")
    last_seen: datetime = Field(default_factory=datetime.now, description="Last seen time")


class IngressRule(BaseModel):
    """Ingress rule for NetworkPolicy."""

    model_config = ConfigDict(frozen=True)

    from_peers: list[NetworkPeer] = Field(default_factory=list, description="Source peers")
    ports: list[PortSpec] = Field(default_factory=list, description="Allowed ports")


class EgressRule(BaseModel):
    """Egress rule for NetworkPolicy."""

    model_config = ConfigDict(frozen=True)

    to_peers: list[NetworkPeer] = Field(default_factory=list, description="Destination peers")
    ports: list[PortSpec] = Field(default_factory=list, description="Allowed ports")


class NetworkPolicySpec(BaseModel):
    """Kubernetes NetworkPolicy specification."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Policy name")
    namespace: str = Field(default="default", description="Policy namespace")
    pod_selector: PodSelector = Field(
        default_factory=lambda: PodSelector(), description="Target pods"
    )
    policy_types: list[str] = Field(
        default_factory=lambda: ["Ingress", "Egress"], description="Policy types"
    )
    ingress_rules: list[IngressRule] = Field(default_factory=list, description="Ingress rules")
    egress_rules: list[EgressRule] = Field(default_factory=list, description="Egress rules")

    # Metadata
    description: str = Field(default="", description="Policy description")
    generated_at: datetime = Field(default_factory=datetime.now, description="Generation time")
    generation: PolicyGenerationMetadata = Field(
        default_factory=PolicyGenerationMetadata,
        description="Generation source and degradation metadata",
    )

    def to_k8s_manifest(self) -> dict[str, Any]:
        """Convert to Kubernetes manifest format."""
        manifest: dict[str, Any] = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
                "labels": {
                    "generated-by": "k8s-policy-agent",
                },
                "annotations": {
                    "description": self.description,
                    "generated-at": self.generated_at.isoformat(),
                    "generation-source": self.generation.source.value,
                    "generation-degraded": str(self.generation.degraded).lower(),
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": self.pod_selector.match_labels,
                },
                "policyTypes": self.policy_types,
            },
        }

        if self.generation.model:
            manifest["metadata"]["annotations"]["generation-model"] = self.generation.model

        if self.generation.error:
            manifest["metadata"]["annotations"]["generation-error"] = self.generation.error

        if self.ingress_rules:
            manifest["spec"]["ingress"] = [
                self._ingress_rule_to_dict(rule) for rule in self.ingress_rules
            ]

        if self.egress_rules:
            manifest["spec"]["egress"] = [
                self._egress_rule_to_dict(rule) for rule in self.egress_rules
            ]

        return manifest

    def _ingress_rule_to_dict(self, rule: IngressRule) -> dict[str, Any]:
        """Convert ingress rule to dict."""
        result: dict[str, Any] = {}

        if rule.from_peers:
            result["from"] = [self._peer_to_dict(p) for p in rule.from_peers]

        if rule.ports:
            result["ports"] = [{"port": p.port, "protocol": p.protocol.value} for p in rule.ports]

        return result

    def _egress_rule_to_dict(self, rule: EgressRule) -> dict[str, Any]:
        """Convert egress rule to dict."""
        result: dict[str, Any] = {}

        if rule.to_peers:
            result["to"] = [self._peer_to_dict(p) for p in rule.to_peers]

        if rule.ports:
            result["ports"] = [{"port": p.port, "protocol": p.protocol.value} for p in rule.ports]

        return result

    def _peer_to_dict(self, peer: NetworkPeer) -> dict[str, Any]:
        """Convert peer to dict."""
        result: dict[str, Any] = {}

        if peer.pod_selector:
            result["podSelector"] = {"matchLabels": peer.pod_selector.match_labels}

        if peer.namespace_selector:
            result["namespaceSelector"] = {"matchLabels": peer.namespace_selector.match_labels}

        if peer.ip_block:
            ip_block: dict[str, str | list[str]] = {"cidr": peer.ip_block.cidr}
            if peer.ip_block.except_cidrs:
                ip_block["except"] = peer.ip_block.except_cidrs
            result["ipBlock"] = ip_block

        return result

    def compute_hash(self) -> str:
        """Compute hash of the policy spec."""
        content = f"{self.name}:{self.namespace}:{self.pod_selector.match_labels}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]


class PolicyValidationResult(BaseModel):
    """Result of policy validation."""

    model_config = ConfigDict(frozen=True)

    policy_name: str = Field(description="Validated policy name")
    is_valid: bool = Field(description="Whether policy is valid")
    errors: list[str] = Field(default_factory=list, description="Validation errors")
    warnings: list[str] = Field(default_factory=list, description="Validation warnings")

    # Security checks
    allows_dns: bool = Field(default=True, description="Allows DNS egress")
    allows_api_server: bool = Field(default=True, description="Allows API server access")
    blocks_external: bool = Field(default=False, description="Blocks external traffic")

    # Recommendations
    recommendations: list[str] = Field(
        default_factory=list, description="Improvement recommendations"
    )


class PolicyEvaluation(BaseModel):
    """DeepEval evaluation result for a policy."""

    model_config = ConfigDict(frozen=True)

    policy_name: str = Field(description="Evaluated policy name")
    score: float = Field(description="Overall evaluation score (0-1)")

    # Evaluation dimensions
    security_score: float = Field(default=0.0, description="Security score")
    completeness_score: float = Field(default=0.0, description="Completeness score")
    least_privilege_score: float = Field(default=0.0, description="Least privilege score")

    # Test results
    tests_passed: int = Field(default=0, description="Tests passed")
    tests_failed: int = Field(default=0, description="Tests failed")
    test_details: list[dict[str, Any]] = Field(
        default_factory=list, description="Individual test results"
    )

    # Metadata
    evaluated_at: datetime = Field(default_factory=datetime.now, description="Evaluation timestamp")


class TrafficObservation(BaseModel):
    """Observed traffic flow in the cluster."""

    model_config = ConfigDict(frozen=True)

    source_namespace: str = Field(description="Source namespace")
    source_pod: str = Field(description="Source pod")
    source_labels: dict[str, str] = Field(default_factory=dict, description="Source labels")
    dest_namespace: str = Field(description="Destination namespace")
    dest_pod: str = Field(description="Destination pod")
    dest_labels: dict[str, str] = Field(default_factory=dict, description="Dest labels")
    dest_port: int = Field(description="Destination port")
    protocol: Protocol = Field(default=Protocol.TCP, description="Protocol")
    count: int = Field(default=1, description="Observation count")
    first_seen: datetime = Field(default_factory=datetime.now, description="First seen")
    last_seen: datetime = Field(default_factory=datetime.now, description="Last seen")


class PolicyGenerationRequest(BaseModel):
    """Request to generate a NetworkPolicy."""

    model_config = ConfigDict(frozen=True)

    target_namespace: str = Field(description="Target namespace")
    target_pod_labels: dict[str, str] = Field(default_factory=dict, description="Target pod labels")
    traffic_observations: list[TrafficObservation] = Field(
        default_factory=list, description="Observed traffic"
    )
    additional_rules: list[TrafficRule] = Field(
        default_factory=list, description="Additional rules to include"
    )
    description: str = Field(default="", description="Policy description")


class GitOpsCommit(BaseModel):
    """GitOps commit information."""

    model_config = ConfigDict(frozen=True)

    commit_hash: str = Field(description="Commit hash")
    message: str = Field(description="Commit message")
    author: str = Field(description="Commit author")
    timestamp: datetime = Field(default_factory=datetime.now, description="Commit time")
    files_changed: list[str] = Field(default_factory=list, description="Changed files")
    policy_names: list[str] = Field(default_factory=list, description="Affected policies")
    operation_mode: str = Field(default="real", description="GitOps operation mode")
    dry_run: bool = Field(default=False, description="Whether dry-run mode was enabled")
    mock_mode: bool = Field(default=False, description="Whether mock mode was enabled")
    failure_reason: str = Field(default="", description="Failure context, if operation failed")


class AgentStats(BaseModel):
    """Statistics from the policy agent."""

    model_config = ConfigDict(frozen=True)

    policies_generated: int = Field(default=0, description="Total policies generated")
    policies_validated: int = Field(default=0, description="Total policies validated")
    policies_applied: int = Field(default=0, description="Total policies applied")
    traffic_rules_observed: int = Field(default=0, description="Traffic rules observed")
    gitops_commits: int = Field(default=0, description="GitOps commits made")
    validation_errors: int = Field(default=0, description="Validation errors found")
