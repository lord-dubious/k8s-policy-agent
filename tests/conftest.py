"""Pytest configuration for Kubernetes Policy Agent tests."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Generator

import pytest

from k8s_policy_agent.models import (
    PolicyConfig,
    NetworkPolicySpec,
    PodSelector,
    IngressRule,
    EgressRule,
    NetworkPeer,
    PortSpec,
    NamespaceSelector,
    Protocol,
    TrafficObservation,
    PolicyGenerationRequest,
    TrafficRule,
    TrafficDirection,
)


@pytest.fixture(autouse=True)
def mock_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables for testing."""
    monkeypatch.setenv("K8S_POLICY_GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("K8S_POLICY_MOCK_MODE", "true")
    monkeypatch.setenv("K8S_POLICY_DRY_RUN", "true")


@pytest.fixture
def mock_config() -> PolicyConfig:
    """Create a mock configuration for testing."""
    return PolicyConfig(
        gemini_api_key="test-api-key",
        gemini_model="gemini-2.0-flash",
        kubeconfig="",
        namespace="default",
        git_repo_url="https://github.com/test/policies.git",
        git_branch="main",
        git_policies_path="policies/",
        default_deny_all=True,
        auto_approve=False,
        dry_run=True,
        mock_mode=True,
    )


@pytest.fixture
def sample_pod_selector() -> PodSelector:
    """Create a sample pod selector."""
    return PodSelector(match_labels={"app": "backend", "tier": "api"})


@pytest.fixture
def sample_namespace_selector() -> NamespaceSelector:
    """Create a sample namespace selector."""
    return NamespaceSelector(match_labels={"kubernetes.io/metadata.name": "default"})


@pytest.fixture
def sample_port_spec() -> PortSpec:
    """Create a sample port specification."""
    return PortSpec(port=8080, protocol=Protocol.TCP)


@pytest.fixture
def sample_network_peer(
    sample_pod_selector: PodSelector, sample_namespace_selector: NamespaceSelector
) -> NetworkPeer:
    """Create a sample network peer."""
    return NetworkPeer(
        pod_selector=sample_pod_selector,
        namespace_selector=sample_namespace_selector,
    )


@pytest.fixture
def sample_ingress_rule(
    sample_network_peer: NetworkPeer, sample_port_spec: PortSpec
) -> IngressRule:
    """Create a sample ingress rule."""
    return IngressRule(
        from_peers=[sample_network_peer],
        ports=[sample_port_spec],
    )


@pytest.fixture
def sample_egress_rule(sample_network_peer: NetworkPeer, sample_port_spec: PortSpec) -> EgressRule:
    """Create a sample egress rule."""
    return EgressRule(
        to_peers=[sample_network_peer],
        ports=[sample_port_spec],
    )


@pytest.fixture
def dns_egress_rule() -> EgressRule:
    """Create DNS egress rule."""
    return EgressRule(
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


@pytest.fixture
def sample_network_policy(
    sample_pod_selector: PodSelector,
    sample_ingress_rule: IngressRule,
    dns_egress_rule: EgressRule,
) -> NetworkPolicySpec:
    """Create a sample NetworkPolicy specification."""
    return NetworkPolicySpec(
        name="allow-backend",
        namespace="default",
        pod_selector=sample_pod_selector,
        policy_types=["Ingress", "Egress"],
        ingress_rules=[sample_ingress_rule],
        egress_rules=[dns_egress_rule],
        description="Allow traffic to backend pods",
    )


@pytest.fixture
def default_deny_policy() -> NetworkPolicySpec:
    """Create a default-deny policy."""
    return NetworkPolicySpec(
        name="default-deny",
        namespace="default",
        pod_selector=PodSelector(),
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
        description="Default deny all traffic except DNS",
    )


@pytest.fixture
def sample_traffic_observation() -> TrafficObservation:
    """Create a sample traffic observation."""
    return TrafficObservation(
        source_namespace="default",
        source_pod="frontend-abc123",
        source_labels={"app": "frontend", "tier": "web"},
        dest_namespace="default",
        dest_pod="backend-def456",
        dest_labels={"app": "backend", "tier": "api"},
        dest_port=8080,
        protocol=Protocol.TCP,
        count=1500,
    )


@pytest.fixture
def sample_traffic_observations() -> list[TrafficObservation]:
    """Create a list of sample traffic observations."""
    return [
        TrafficObservation(
            source_namespace="default",
            source_pod="frontend-abc123",
            source_labels={"app": "frontend"},
            dest_namespace="default",
            dest_pod="backend-def456",
            dest_labels={"app": "backend"},
            dest_port=8080,
            protocol=Protocol.TCP,
            count=1500,
        ),
        TrafficObservation(
            source_namespace="default",
            source_pod="backend-def456",
            source_labels={"app": "backend"},
            dest_namespace="default",
            dest_pod="database-ghi789",
            dest_labels={"app": "postgres"},
            dest_port=5432,
            protocol=Protocol.TCP,
            count=3000,
        ),
        TrafficObservation(
            source_namespace="default",
            source_pod="backend-def456",
            source_labels={"app": "backend"},
            dest_namespace="kube-system",
            dest_pod="coredns-xxx",
            dest_labels={"k8s-app": "kube-dns"},
            dest_port=53,
            protocol=Protocol.UDP,
            count=5000,
        ),
    ]


@pytest.fixture
def sample_policy_generation_request(
    sample_traffic_observations: list[TrafficObservation],
) -> PolicyGenerationRequest:
    """Create a sample policy generation request."""
    return PolicyGenerationRequest(
        target_namespace="default",
        target_pod_labels={"app": "backend"},
        traffic_observations=sample_traffic_observations,
        description="Policy for backend service",
    )


@pytest.fixture
def sample_traffic_rule() -> TrafficRule:
    """Create a sample traffic rule."""
    return TrafficRule(
        direction=TrafficDirection.EGRESS,
        source_namespace="default",
        source_pod="frontend",
        source_labels={"app": "frontend"},
        dest_namespace="default",
        dest_pod="backend",
        dest_labels={"app": "backend"},
        port=8080,
        protocol=Protocol.TCP,
        count=100,
    )


@pytest.fixture
def valid_policy_yaml() -> str:
    """Create a valid NetworkPolicy YAML."""
    return """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-backend
  namespace: default
  labels:
    generated-by: k8s-policy-agent
  annotations:
    description: Allow traffic to backend
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - port: 8080
          protocol: TCP
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
"""


@pytest.fixture
def invalid_policy_yaml() -> str:
    """Create an invalid policy YAML."""
    return """
apiVersion: networking.k8s.io/v1
kind: ConfigMap
metadata:
  name: not-a-policy
data:
  key: value
"""


@pytest.fixture
def overly_permissive_policy() -> NetworkPolicySpec:
    """Create an overly permissive policy."""
    return NetworkPolicySpec(
        name="allow-all",
        namespace="default",
        pod_selector=PodSelector(),
        policy_types=["Ingress", "Egress"],
        ingress_rules=[
            IngressRule(from_peers=[], ports=[]),  # Empty = allow all
        ],
        egress_rules=[
            EgressRule(to_peers=[], ports=[]),  # Empty = allow all
        ],
        description="Allow all traffic",
    )


@pytest.fixture
def sample_mock_observations() -> list[dict[str, Any]]:
    """Create mock observation dictionaries."""
    return [
        {
            "source_namespace": "default",
            "source_pod": "web-server",
            "source_labels": {"app": "web"},
            "dest_namespace": "default",
            "dest_pod": "api-server",
            "dest_labels": {"app": "api"},
            "dest_port": 3000,
            "protocol": "TCP",
            "count": 500,
        },
        {
            "source_namespace": "default",
            "source_pod": "api-server",
            "source_labels": {"app": "api"},
            "dest_namespace": "default",
            "dest_pod": "redis",
            "dest_labels": {"app": "redis"},
            "dest_port": 6379,
            "protocol": "TCP",
            "count": 1000,
        },
    ]


@pytest.fixture
def policy_with_no_pod_selector() -> NetworkPolicySpec:
    """Create a policy without pod selector labels."""
    return NetworkPolicySpec(
        name="no-selector",
        namespace="default",
        pod_selector=PodSelector(match_labels={}),
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
        description="Policy without specific pod selector",
    )


@pytest.fixture
def policy_without_dns() -> NetworkPolicySpec:
    """Create a policy that doesn't allow DNS."""
    return NetworkPolicySpec(
        name="no-dns",
        namespace="default",
        pod_selector=PodSelector(match_labels={"app": "isolated"}),
        policy_types=["Ingress", "Egress"],
        ingress_rules=[],
        egress_rules=[
            EgressRule(
                to_peers=[
                    NetworkPeer(
                        pod_selector=PodSelector(match_labels={"app": "database"}),
                    )
                ],
                ports=[PortSpec(port=5432, protocol=Protocol.TCP)],
            )
        ],
        description="Policy without DNS egress",
    )
