## Summary

- 

## Verification

- [ ] `ruff check src/ tests/`
- [ ] `mypy src/ --ignore-missing-imports`
- [ ] `pytest --cov=k8s_policy_agent --cov-report=xml -v`
- [ ] Generated policy YAML was reviewed by a human before any cluster use.

## Review Questions

- Do generated policies clearly show their source, degradation status, and any external generation error?
- Were external dependencies such as Gemini API access, network availability, kubeconfig, and Git credentials considered?
- Are GitOps side effects understood, including target repository/branch, dry-run behavior, push behavior, and downstream controllers?
