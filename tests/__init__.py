"""Tests for k8s_policy_agent package initialization."""


def test_package_version() -> None:
    """Test package version is defined."""
    from k8s_policy_agent import __version__

    assert __version__ == "0.1.0"


def test_package_exports() -> None:
    """Test package exports all expected components."""
    import k8s_policy_agent

    # Config
    assert hasattr(k8s_policy_agent, "PolicyConfig")
    assert hasattr(k8s_policy_agent, "create_config")

    # Models
    assert hasattr(k8s_policy_agent, "TrafficRule")
    assert hasattr(k8s_policy_agent, "NetworkPolicySpec")
    assert hasattr(k8s_policy_agent, "PolicyValidationResult")
    assert hasattr(k8s_policy_agent, "PolicyEvaluation")
    assert hasattr(k8s_policy_agent, "TrafficDirection")
    assert hasattr(k8s_policy_agent, "PolicyAction")

    # Components
    assert hasattr(k8s_policy_agent, "TrafficAnalyzer")
    assert hasattr(k8s_policy_agent, "create_traffic_analyzer")
    assert hasattr(k8s_policy_agent, "PolicyGenerator")
    assert hasattr(k8s_policy_agent, "create_policy_generator")
    assert hasattr(k8s_policy_agent, "PolicyValidator")
    assert hasattr(k8s_policy_agent, "create_policy_validator")
    assert hasattr(k8s_policy_agent, "GitOpsManager")
    assert hasattr(k8s_policy_agent, "create_gitops_manager")
    assert hasattr(k8s_policy_agent, "PolicyAgent")
    assert hasattr(k8s_policy_agent, "create_policy_agent")


def test_factory_functions() -> None:
    """Test factory functions create instances."""
    from k8s_policy_agent import (
        PolicyConfig,
        create_config,
        create_gitops_manager,
        create_policy_agent,
        create_policy_generator,
        create_policy_validator,
        create_traffic_analyzer,
    )

    config = create_config(mock_mode=True)
    assert isinstance(config, PolicyConfig)

    analyzer = create_traffic_analyzer(config)
    assert analyzer is not None

    generator = create_policy_generator(config)
    assert generator is not None

    validator = create_policy_validator(config)
    assert validator is not None

    gitops = create_gitops_manager(config)
    assert gitops is not None

    agent = create_policy_agent(config)
    assert agent is not None
