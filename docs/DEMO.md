# Demo Guide

This guide gives a safe way to evaluate **Kubernetes Policy Agent** locally. The commands favor help screens, mock/dry-run paths, or clearly labeled local execution so the demo stays honest.

## Quick Orientation

Start with the CLI help and README sections before running any external-service path.

```bash
k8s-policy --help
```
```bash
k8s-policy generate --help
```
```bash
k8s-policy validate --help
```

If a command needs live services or credentials, run the help command first and configure only the services you actually intend to test.

## Portfolio Walkthrough

Use this sequence in an interview or portfolio review:

1. Open the README and explain the problem the project solves in one sentence.
2. Open [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) and walk through the data flow.
3. Show the relevant model fields or tests that label mock, fallback, degraded, or warning states.
4. Run the local test suite or the project CI page to show the implementation is maintained.
5. Explain one tradeoff or limitation from the README instead of overselling the project.

## Suggested Demo Script

- **Problem**: NetworkPolicy generation and validation workflow for Kubernetes traffic observations, with Gemini-assisted drafts, deterministic mock mode, and GitOps safety metadata.
- **Engineering signal**: the project models external-service failure instead of hiding it.
- **Safety signal**: generated or assisted outputs are explicitly marked for human review.
- **Portfolio signal**: the Git history includes focused maintenance PRs, CI fixes, and docs polish.

## Screenshots And Videos

No generated screenshot or video is included here because a fake recording would weaken the portfolio. If you add one later, capture it from a real local run with sanitized sample data and include the exact command/config used to produce it.

## Demo Boundaries

- Generated policies need human review before applying to a cluster.
- Observed traffic can be incomplete and may produce overly narrow policies.
- Gemini assistance is optional and failures degrade visibly.
