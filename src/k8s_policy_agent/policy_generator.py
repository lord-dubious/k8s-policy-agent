"""AI-powered NetworkPolicy generator using Gemini."""

from __future__ import annotations

import json
import re
from typing import Any

import google.generativeai as genai
import structlog
import yaml

from k8s_policy_agent.models import (
    PolicyConfig,
    NetworkPolicySpec,
    TrafficObservation,
    PolicyGenerationRequest,
    PodSelector,
    IngressRule,
    EgressRule,
    NetworkPeer,
    PortSpec,
    NamespaceSelector,
    Protocol,
)

logger = structlog.get_logger()


POLICY_GENERATION_PROMPT = """You are a Kubernetes security expert. Generate a NetworkPolicy based on the observed traffic patterns.

## Target Information
- Namespace: {namespace}
- Target Pod Labels: {pod_labels}

## Observed Traffic Patterns
{traffic_patterns}

## Requirements
1. Generate a least-privilege NetworkPolicy
2. Allow only the observed traffic patterns
3. Allow DNS egress (port 53 UDP to kube-system)
4. Include appropriate labels and annotations

## Output Format
Respond with a JSON object containing:
```json
{{
    "name": "policy-name",
    "description": "Policy description",
    "ingress_rules": [
        {{
            "from_labels": {{"app": "frontend"}},
            "from_namespace": "default",
            "ports": [8080]
        }}
    ],
    "egress_rules": [
        {{
            "to_labels": {{"app": "database"}},
            "to_namespace": "default", 
            "ports": [5432]
        }}
    ]
}}
```

Respond with only the JSON, no additional text.
"""


class PolicyGenerator:
    """AI-powered NetworkPolicy generator."""

    def __init__(self, config: PolicyConfig) -> None:
        """Initialize the policy generator.

        Args:
            config: Policy configuration
        """
        self.config = config
        self._model: Any = None

        if not config.mock_mode and config.gemini_api_key:
            genai.configure(api_key=config.gemini_api_key)
            self._model = genai.GenerativeModel(config.gemini_model)

    async def generate(self, request: PolicyGenerationRequest) -> NetworkPolicySpec:
        """Generate a NetworkPolicy from a request.

        Args:
            request: Policy generation request

        Returns:
            Generated NetworkPolicy specification
        """
        if self.config.mock_mode:
            return self._generate_mock_policy(request)

        return await self._generate_with_ai(request)

    async def generate_from_observations(
        self,
        namespace: str,
        pod_labels: dict[str, str],
        observations: list[TrafficObservation],
    ) -> NetworkPolicySpec:
        """Generate policy from traffic observations.

        Args:
            namespace: Target namespace
            pod_labels: Target pod labels
            observations: Traffic observations

        Returns:
            Generated NetworkPolicy
        """
        request = PolicyGenerationRequest(
            target_namespace=namespace,
            target_pod_labels=pod_labels,
            traffic_observations=observations,
        )

        return await self.generate(request)

    async def generate_default_deny(self, namespace: str) -> NetworkPolicySpec:
        """Generate a default-deny policy for a namespace.

        Args:
            namespace: Target namespace

        Returns:
            Default deny policy
        """
        return NetworkPolicySpec(
            name=f"default-deny-{namespace}",
            namespace=namespace,
            pod_selector=PodSelector(),  # Empty = all pods
            policy_types=["Ingress", "Egress"],
            ingress_rules=[],  # No ingress allowed
            egress_rules=[
                # Allow DNS
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
            description=f"Default deny policy for {namespace} namespace",
        )

    async def _generate_with_ai(self, request: PolicyGenerationRequest) -> NetworkPolicySpec:
        """Use AI to generate the policy.

        Args:
            request: Generation request

        Returns:
            Generated policy
        """
        logger.info(
            "generating_policy_with_ai",
            namespace=request.target_namespace,
            observations=len(request.traffic_observations),
        )

        # Format traffic patterns
        traffic_patterns = self._format_traffic_patterns(request.traffic_observations)

        prompt = POLICY_GENERATION_PROMPT.format(
            namespace=request.target_namespace,
            pod_labels=json.dumps(request.target_pod_labels),
            traffic_patterns=traffic_patterns,
        )

        try:
            response = self._model.generate_content(prompt)
            policy_data = self._extract_json(response.text)

            return self._build_policy_from_ai(request, policy_data)

        except Exception as e:
            logger.error("ai_generation_error", error=str(e))
            return self._generate_mock_policy(request)

    def _format_traffic_patterns(self, observations: list[TrafficObservation]) -> str:
        """Format traffic observations for the prompt.

        Args:
            observations: Traffic observations

        Returns:
            Formatted string
        """
        lines = []
        for obs in observations:
            lines.append(
                f"- {obs.source_namespace}/{obs.source_pod} -> "
                f"{obs.dest_namespace}/{obs.dest_pod}:{obs.dest_port}/{obs.protocol.value} "
                f"({obs.count} connections)"
            )

        return "\n".join(lines) if lines else "No traffic observed"

    def _extract_json(self, text: str) -> dict[str, Any]:
        """Extract JSON from AI response.

        Args:
            text: AI response text

        Returns:
            Parsed JSON
        """
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        return {}

    def _build_policy_from_ai(
        self, request: PolicyGenerationRequest, data: dict[str, Any]
    ) -> NetworkPolicySpec:
        """Build policy from AI response.

        Args:
            request: Original request
            data: AI response data

        Returns:
            NetworkPolicy specification
        """
        ingress_rules = []
        for rule in data.get("ingress_rules", []):
            ingress_rules.append(
                IngressRule(
                    from_peers=[
                        NetworkPeer(
                            pod_selector=PodSelector(match_labels=rule.get("from_labels", {})),
                            namespace_selector=NamespaceSelector(
                                match_labels={
                                    "kubernetes.io/metadata.name": rule.get(
                                        "from_namespace", request.target_namespace
                                    )
                                }
                            )
                            if rule.get("from_namespace")
                            else None,
                        )
                    ],
                    ports=[PortSpec(port=p, protocol=Protocol.TCP) for p in rule.get("ports", [])],
                )
            )

        egress_rules = []
        for rule in data.get("egress_rules", []):
            egress_rules.append(
                EgressRule(
                    to_peers=[
                        NetworkPeer(
                            pod_selector=PodSelector(match_labels=rule.get("to_labels", {})),
                            namespace_selector=NamespaceSelector(
                                match_labels={
                                    "kubernetes.io/metadata.name": rule.get(
                                        "to_namespace", request.target_namespace
                                    )
                                }
                            )
                            if rule.get("to_namespace")
                            else None,
                        )
                    ],
                    ports=[PortSpec(port=p, protocol=Protocol.TCP) for p in rule.get("ports", [])],
                )
            )

        # Always add DNS egress
        egress_rules.append(
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
        )

        return NetworkPolicySpec(
            name=data.get("name", f"policy-{request.target_namespace}"),
            namespace=request.target_namespace,
            pod_selector=PodSelector(match_labels=request.target_pod_labels),
            policy_types=["Ingress", "Egress"],
            ingress_rules=ingress_rules,
            egress_rules=egress_rules,
            description=data.get("description", request.description),
        )

    def _generate_mock_policy(self, request: PolicyGenerationRequest) -> NetworkPolicySpec:
        """Generate mock policy for testing.

        Args:
            request: Generation request

        Returns:
            Mock NetworkPolicy
        """
        # Build rules from observations
        ingress_rules = []
        egress_rules = []

        for obs in request.traffic_observations:
            if obs.dest_labels == request.target_pod_labels:
                # This is ingress traffic
                ingress_rules.append(
                    IngressRule(
                        from_peers=[
                            NetworkPeer(
                                pod_selector=PodSelector(match_labels=obs.source_labels),
                                namespace_selector=NamespaceSelector(
                                    match_labels={
                                        "kubernetes.io/metadata.name": obs.source_namespace
                                    }
                                )
                                if obs.source_namespace
                                else None,
                            )
                        ],
                        ports=[PortSpec(port=obs.dest_port, protocol=obs.protocol)],
                    )
                )
            else:
                # This is egress traffic
                egress_rules.append(
                    EgressRule(
                        to_peers=[
                            NetworkPeer(
                                pod_selector=PodSelector(match_labels=obs.dest_labels),
                                namespace_selector=NamespaceSelector(
                                    match_labels={"kubernetes.io/metadata.name": obs.dest_namespace}
                                )
                                if obs.dest_namespace
                                else None,
                            )
                        ],
                        ports=[PortSpec(port=obs.dest_port, protocol=obs.protocol)],
                    )
                )

        # Add DNS egress
        egress_rules.append(
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
        )

        # Generate policy name from labels
        label_str = "-".join(f"{k}-{v}" for k, v in sorted(request.target_pod_labels.items()))[:30]
        policy_name = f"allow-{label_str}" if label_str else "allow-all"

        return NetworkPolicySpec(
            name=policy_name,
            namespace=request.target_namespace,
            pod_selector=PodSelector(match_labels=request.target_pod_labels),
            policy_types=["Ingress", "Egress"],
            ingress_rules=ingress_rules,
            egress_rules=egress_rules,
            description=f"Auto-generated policy for {request.target_pod_labels}",
        )

    def policy_to_yaml(self, policy: NetworkPolicySpec) -> str:
        """Convert policy to YAML string.

        Args:
            policy: NetworkPolicy specification

        Returns:
            YAML string
        """
        manifest = policy.to_k8s_manifest()
        return yaml.dump(manifest, default_flow_style=False, sort_keys=False)


def create_policy_generator(config: PolicyConfig | None = None) -> PolicyGenerator:
    """Factory function to create PolicyGenerator.

    Args:
        config: Optional policy configuration

    Returns:
        Configured PolicyGenerator instance
    """
    if config is None:
        config = PolicyConfig()

    return PolicyGenerator(config)
