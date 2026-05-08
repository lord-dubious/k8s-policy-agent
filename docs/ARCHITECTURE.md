# Architecture

NetworkPolicy generation and validation workflow for Kubernetes traffic observations, with Gemini-assisted drafts, deterministic mock mode, and GitOps safety metadata.

This document is written for reviewers who want to understand how the project is shaped before reading the code. It emphasizes boundaries, dependencies, and degraded paths rather than marketing claims.

## Data Flow

1. Traffic logs or policy request
2. Traffic analyzer
3. Policy generator
4. Policy validator/evaluator
5. GitOps writer with mock/dry-run/real modes
6. Manifest review

```mermaid
flowchart TB
    classDef input fill:#ecfeff,stroke:#0891b2,stroke-width:2px,color:#164e63
    classDef core fill:#eef2ff,stroke:#4f46e5,stroke-width:2px,color:#312e81
    classDef external fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#7c2d12
    classDef metadata fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d
    classDef review fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d

    Request[/Policy request or traffic logs/]:::input
    Reviewer[/Platform engineer review/]:::review

    subgraph Observation["Traffic Observation"]
        Parser[Traffic analyzer]:::core
        Flows[Observed service flows]:::metadata
    end

    subgraph Generation["Policy Drafting"]
        Generator[NetworkPolicy generator]:::core
        Gemini{{Gemini API optional}}:::external
        Mock[Deterministic mock policy]:::metadata
        Metadata[Generation metadata and annotations]:::metadata
    end

    subgraph Validation["Safety Checks"]
        Validator[Policy validator]:::core
        Evaluator[Security and least-privilege scoring]:::core
    end

    subgraph GitOps["GitOps Boundary"]
        Writer[Policy file writer]:::core
        Git[(Policy repository)]:::external
        Mode[Mock dry-run or real operation state]:::metadata
    end

    Request --> Parser --> Flows --> Generator
    Generator <-->|optional model assist| Gemini
    Generator -. unavailable or malformed .-> Mock
    Generator --> Metadata
    Generator --> Validator --> Evaluator
    Evaluator --> Reviewer
    Metadata --> Reviewer
    Reviewer -->|approved manifest only| Writer
    Writer --> Mode
    Writer <-->|real mode only| Git
    Mode --> Reviewer
```

## Main Components

- **Traffic analyzer**: Normalizes observed service-to-service flows.
- **Policy generator**: Builds NetworkPolicy YAML and annotates generation source/degraded state.
- **Policy validator**: Checks generated or provided policies against common safety expectations.
- **GitOps manager**: Writes policy manifests while reporting dry-run, mock, and real operation state.

## External Dependencies

- Python 3.11+
- Optional Gemini API key
- Optional Git repository for GitOps output
- Kubernetes cluster knowledge for production review

The project is intentionally explicit about optional services. Mock, fallback, and degraded paths are labeled in result metadata so a demo cannot be mistaken for a successful production integration.

## Failure And Degraded Modes

- External-service failures are captured as warnings, status fields, or source metadata where the domain model supports it.
- Mock/demo behavior is opt-in or explicitly labeled.
- Generated outputs are treated as review candidates, not authoritative decisions.
- CLI output remains user-facing; library internals use logging or structured metadata.

## What To Review In Code

- Generated manifests include generation-source and degraded annotations.
- GitOps push behavior is explicit about mock, dry-run, and real side effects.
- Tests cover fallback metadata and policy safety checks.

## Current Limits

- Generated policies need human review before applying to a cluster.
- Observed traffic can be incomplete and may produce overly narrow policies.
- Gemini assistance is optional and failures degrade visibly.
