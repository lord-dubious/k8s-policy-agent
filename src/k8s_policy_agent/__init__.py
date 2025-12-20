"""Kubernetes Policy Agent - AI-powered NetworkPolicy generation and validation.

This package provides tools for generating, validating, and applying Kubernetes
NetworkPolicy resources using Gemini AI and DeepEval for policy evaluation.
"""

from k8s_policy_agent.models import (
    PolicyConfig,
    TrafficRule,
    NetworkPolicySpec,
    PolicyValidationResult,
    PolicyEvaluation,
    TrafficDirection,
    PolicyAction,
    create_config,
)
from k8s_policy_agent.traffic_analyzer import TrafficAnalyzer, create_traffic_analyzer
from k8s_policy_agent.policy_generator import PolicyGenerator, create_policy_generator
from k8s_policy_agent.policy_validator import PolicyValidator, create_policy_validator
from k8s_policy_agent.gitops import GitOpsManager, create_gitops_manager
from k8s_policy_agent.agent import PolicyAgent, create_policy_agent

__version__ = "0.1.0"

__all__ = [
    # Config
    "PolicyConfig",
    "create_config",
    # Models
    "TrafficRule",
    "NetworkPolicySpec",
    "PolicyValidationResult",
    "PolicyEvaluation",
    "TrafficDirection",
    "PolicyAction",
    # Traffic Analyzer
    "TrafficAnalyzer",
    "create_traffic_analyzer",
    # Policy Generator
    "PolicyGenerator",
    "create_policy_generator",
    # Policy Validator
    "PolicyValidator",
    "create_policy_validator",
    # GitOps
    "GitOpsManager",
    "create_gitops_manager",
    # Agent
    "PolicyAgent",
    "create_policy_agent",
]
