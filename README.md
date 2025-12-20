# Kubernetes Policy Agent

AI-powered Kubernetes NetworkPolicy generator and validator using Gemini and DeepEval-style evaluation.

## Features

- **Traffic Analysis**: Analyze CNI (Cilium/Calico) logs to understand actual traffic patterns
- **AI Policy Generation**: Use Gemini 3.0 Flash to generate least-privilege NetworkPolicies
- **Policy Validation**: Validate policies against security best practices
- **DeepEval Scoring**: Evaluate policies on security, completeness, and least-privilege metrics
- **GitOps Integration**: Automatically commit and push policies to Git repositories

## Installation

```bash
# Clone the repository
git clone https://github.com/lord-dubious/k8s-policy-agent.git
cd k8s-policy-agent

# Create virtual environment and install
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Quick Start

### Analyze Traffic

```bash
# Analyze traffic in a namespace (mock mode for demo)
k8s-policy analyze default --mock

# Analyze specific pods
k8s-policy analyze production --labels app=backend --mock
```

### Generate Policies

```bash
# Generate policy based on traffic analysis
k8s-policy generate --mock

# Generate with pod labels
k8s-policy generate --labels app=backend,tier=api --mock

# Generate default-deny policy
k8s-policy generate --default-deny --mock

# Save to file
k8s-policy generate --output policy.yaml --mock
```

### Validate Policies

```bash
# Validate a policy file
k8s-policy validate policy.yaml

# Shows validation errors, warnings, and security checks
```

### Evaluate Policies

```bash
# Evaluate policy with DeepEval-style metrics
k8s-policy evaluate policy.yaml

# Shows:
# - Security Score
# - Completeness Score  
# - Least Privilege Score
# - Individual test results
```

### Full Pipeline

```bash
# Run full pipeline: analyze -> generate -> validate
k8s-policy pipeline default --mock

# With auto-apply to GitOps repo
k8s-policy pipeline default --apply --mock --dry-run
```

## Configuration

Set environment variables or use `.env` file:

```bash
# Gemini API
K8S_POLICY_GEMINI_API_KEY=your-api-key
K8S_POLICY_GEMINI_MODEL=gemini-2.0-flash

# Kubernetes
K8S_POLICY_KUBECONFIG=/path/to/kubeconfig
K8S_POLICY_NAMESPACE=default

# GitOps
K8S_POLICY_GIT_REPO_URL=https://github.com/org/policies.git
K8S_POLICY_GIT_BRANCH=main
K8S_POLICY_GIT_POLICIES_PATH=policies/

# Behavior
K8S_POLICY_DRY_RUN=true
K8S_POLICY_MOCK_MODE=false
K8S_POLICY_AUTO_APPROVE=false
```

## Python API

```python
import asyncio
from k8s_policy_agent import create_policy_agent, create_config

async def main():
    # Create agent with config
    config = create_config(
        gemini_api_key="your-key",
        mock_mode=True,
    )
    agent = create_policy_agent(config)
    
    # Analyze and generate policy
    policy = await agent.analyze_and_generate(
        namespace="production",
        pod_labels={"app": "backend"},
    )
    
    # Validate
    validation = agent.validate(policy)
    print(f"Valid: {validation.is_valid}")
    
    # Evaluate
    evaluation = agent.evaluate(policy)
    print(f"Score: {evaluation.score:.2%}")
    
    # Get YAML
    yaml_content = agent.policy_generator.policy_to_yaml(policy)
    print(yaml_content)
    
    await agent.cleanup()

asyncio.run(main())
```

## Security Tests

The evaluator runs these security tests on each policy:

| Test | Description |
|------|-------------|
| `dns_egress` | Policy allows DNS egress to kube-system |
| `no_allow_all_ingress` | Policy doesn't allow all ingress traffic |
| `no_allow_all_egress` | Policy doesn't allow all egress traffic |
| `has_pod_selector` | Policy targets specific pods |
| `has_policy_types` | Policy specifies Ingress/Egress types |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Policy Agent                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Traffic    │  │   Policy     │  │   Policy     │          │
│  │   Analyzer   │─▶│   Generator  │─▶│   Validator  │          │
│  │              │  │   (Gemini)   │  │  (DeepEval)  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                              │                   │
│                                              ▼                   │
│                                     ┌──────────────┐            │
│                                     │    GitOps    │            │
│                                     │   Manager    │            │
│                                     └──────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
                                     ┌──────────────┐
                                     │  Git Repo    │
                                     │  (ArgoCD)    │
                                     └──────────────┘
```

## Development

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=k8s_policy_agent

# Type checking
mypy src/

# Linting
ruff check src/ tests/
ruff format src/ tests/
```

## License

MIT License - see [LICENSE](LICENSE) for details.
