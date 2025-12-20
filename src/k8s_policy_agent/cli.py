"""CLI interface for Kubernetes Policy Agent."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from k8s_policy_agent.models import PolicyConfig
from k8s_policy_agent.agent import PolicyAgent

app = typer.Typer(
    name="k8s-policy",
    help="AI-powered Kubernetes NetworkPolicy generator and validator",
    add_completion=False,
)
console = Console()


def get_config(
    mock: bool = False,
    dry_run: bool = True,
    namespace: str = "default",
) -> PolicyConfig:
    """Get configuration from environment and CLI options."""
    return PolicyConfig(
        mock_mode=mock,
        dry_run=dry_run,
        namespace=namespace,
    )


@app.command()
def analyze(
    namespace: Annotated[str, typer.Argument(help="Namespace to analyze")] = "default",
    labels: Annotated[
        str | None, typer.Option("--labels", "-l", help="Pod labels (key=value,key2=value2)")
    ] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use mock mode for testing")] = False,
) -> None:
    """Analyze traffic patterns in a namespace."""
    config = get_config(mock=mock, namespace=namespace)
    agent = PolicyAgent(config)

    pod_labels = {}
    if labels:
        for pair in labels.split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                pod_labels[key.strip()] = value.strip()

    async def run_analysis() -> None:
        if pod_labels:
            observations = await agent.traffic_analyzer.analyze_pod(namespace, pod_labels)
        else:
            observations = await agent.traffic_analyzer.analyze_namespace(namespace)

        table = Table(title=f"Traffic Observations in {namespace}")
        table.add_column("Source", style="cyan")
        table.add_column("Destination", style="green")
        table.add_column("Port", style="yellow")
        table.add_column("Protocol", style="blue")
        table.add_column("Count", style="magenta")

        for obs in observations:
            table.add_row(
                f"{obs.source_namespace}/{obs.source_pod}",
                f"{obs.dest_namespace}/{obs.dest_pod}",
                str(obs.dest_port),
                obs.protocol.value,
                str(obs.count),
            )

        console.print(table)
        console.print(f"\n[bold]Total observations:[/bold] {len(observations)}")

    asyncio.run(run_analysis())


@app.command()
def generate(
    namespace: Annotated[str, typer.Argument(help="Target namespace")] = "default",
    labels: Annotated[
        str | None, typer.Option("--labels", "-l", help="Pod labels (key=value,key2=value2)")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use mock mode for testing")] = False,
    default_deny: Annotated[
        bool, typer.Option("--default-deny", help="Generate default-deny policy")
    ] = False,
) -> None:
    """Generate a NetworkPolicy based on traffic analysis."""
    config = get_config(mock=mock, namespace=namespace)
    agent = PolicyAgent(config)

    pod_labels = {}
    if labels:
        for pair in labels.split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                pod_labels[key.strip()] = value.strip()

    async def run_generate() -> None:
        if default_deny:
            policy = await agent.generate_default_deny(namespace)
        else:
            policy = await agent.analyze_and_generate(namespace, pod_labels if pod_labels else None)

        yaml_content = agent.policy_generator.policy_to_yaml(policy)

        if output:
            output.write_text(yaml_content)
            console.print(f"[green]Policy written to {output}[/green]")
        else:
            console.print(
                Panel(
                    Syntax(yaml_content, "yaml", theme="monokai"),
                    title=f"NetworkPolicy: {policy.name}",
                )
            )

        # Show validation summary
        validation = agent.validate(policy)
        if validation.is_valid:
            console.print("[green]Validation: PASSED[/green]")
        else:
            console.print("[red]Validation: FAILED[/red]")
            for error in validation.errors:
                console.print(f"  [red]- {error}[/red]")

        for warning in validation.warnings:
            console.print(f"  [yellow]Warning: {warning}[/yellow]")

    asyncio.run(run_generate())


@app.command()
def validate(
    file: Annotated[Path, typer.Argument(help="YAML file to validate")],
) -> None:
    """Validate a NetworkPolicy YAML file."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    config = get_config()
    agent = PolicyAgent(config)

    yaml_content = file.read_text()
    result = agent.validate_yaml(yaml_content)

    # Display result
    if result.is_valid:
        console.print(
            Panel(
                f"[green]Policy '{result.policy_name}' is VALID[/green]",
                title="Validation Result",
            )
        )
    else:
        console.print(
            Panel(
                f"[red]Policy '{result.policy_name}' is INVALID[/red]",
                title="Validation Result",
            )
        )

    if result.errors:
        console.print("\n[red]Errors:[/red]")
        for error in result.errors:
            console.print(f"  - {error}")

    if result.warnings:
        console.print("\n[yellow]Warnings:[/yellow]")
        for warning in result.warnings:
            console.print(f"  - {warning}")

    if result.recommendations:
        console.print("\n[blue]Recommendations:[/blue]")
        for rec in result.recommendations:
            console.print(f"  - {rec}")

    # Security checks
    table = Table(title="Security Checks")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green")

    table.add_row("Allows DNS", "[green]Yes[/green]" if result.allows_dns else "[red]No[/red]")
    table.add_row(
        "Allows API Server",
        "[green]Yes[/green]" if result.allows_api_server else "[yellow]No[/yellow]",
    )
    table.add_row(
        "Blocks External", "[green]Yes[/green]" if result.blocks_external else "[yellow]No[/yellow]"
    )

    console.print(table)

    if not result.is_valid:
        raise typer.Exit(1)


@app.command()
def evaluate(
    file: Annotated[Path, typer.Argument(help="YAML file to evaluate")],
) -> None:
    """Evaluate a NetworkPolicy using DeepEval-style metrics."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    config = get_config()
    agent = PolicyAgent(config)

    yaml_content = file.read_text()

    # First validate to get the spec
    validation = agent.validate_yaml(yaml_content)

    if not validation.is_valid:
        console.print(f"[red]Cannot evaluate invalid policy: {validation.errors}[/red]")
        raise typer.Exit(1)

    # Parse YAML and evaluate
    import yaml as yaml_lib
    from k8s_policy_agent.models import NetworkPolicySpec, PodSelector

    data = yaml_lib.safe_load(yaml_content)
    metadata = data.get("metadata", {})
    spec = data.get("spec", {})

    policy = NetworkPolicySpec(
        name=metadata.get("name", "unknown"),
        namespace=metadata.get("namespace", "default"),
        pod_selector=PodSelector(match_labels=spec.get("podSelector", {}).get("matchLabels", {})),
        policy_types=spec.get("policyTypes", []),
    )

    evaluation = agent.evaluate(policy)

    # Display results
    console.print(
        Panel(
            f"Overall Score: [bold]{evaluation.score:.2%}[/bold]",
            title=f"Policy Evaluation: {evaluation.policy_name}",
        )
    )

    # Scores table
    scores_table = Table(title="Evaluation Scores")
    scores_table.add_column("Metric", style="cyan")
    scores_table.add_column("Score", style="green")

    def score_color(score: float) -> str:
        if score >= 0.8:
            return "green"
        elif score >= 0.5:
            return "yellow"
        return "red"

    scores_table.add_row(
        "Security Score",
        f"[{score_color(evaluation.security_score)}]{evaluation.security_score:.2%}[/]",
    )
    scores_table.add_row(
        "Completeness Score",
        f"[{score_color(evaluation.completeness_score)}]{evaluation.completeness_score:.2%}[/]",
    )
    scores_table.add_row(
        "Least Privilege Score",
        f"[{score_color(evaluation.least_privilege_score)}]{evaluation.least_privilege_score:.2%}[/]",
    )

    console.print(scores_table)

    # Test results
    console.print(
        f"\n[bold]Tests: {evaluation.tests_passed} passed, {evaluation.tests_failed} failed[/bold]"
    )

    if evaluation.test_details:
        tests_table = Table(title="Test Details")
        tests_table.add_column("Test", style="cyan")
        tests_table.add_column("Description", style="white")
        tests_table.add_column("Result", style="green")

        for test in evaluation.test_details:
            result = "[green]PASS[/green]" if test["passed"] else "[red]FAIL[/red]"
            tests_table.add_row(test["test"], test["description"], result)

        console.print(tests_table)


@app.command()
def apply(
    file: Annotated[Path, typer.Argument(help="YAML file to apply")],
    message: Annotated[str | None, typer.Option("--message", "-m", help="Commit message")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Dry run (don't push)")] = True,
    mock: Annotated[bool, typer.Option("--mock", help="Use mock mode for testing")] = False,
) -> None:
    """Apply a NetworkPolicy via GitOps."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    config = get_config(mock=mock, dry_run=dry_run)
    agent = PolicyAgent(config)

    yaml_content = file.read_text()

    # Parse and create policy spec
    import yaml as yaml_lib
    from k8s_policy_agent.models import NetworkPolicySpec, PodSelector

    data = yaml_lib.safe_load(yaml_content)
    metadata = data.get("metadata", {})
    spec = data.get("spec", {})

    policy = NetworkPolicySpec(
        name=metadata.get("name", "unknown"),
        namespace=metadata.get("namespace", "default"),
        pod_selector=PodSelector(match_labels=spec.get("podSelector", {}).get("matchLabels", {})),
        policy_types=spec.get("policyTypes", []),
        description=metadata.get("annotations", {}).get("description", ""),
    )

    async def run_apply() -> None:
        try:
            commit = await agent.apply_policy(policy, message)

            console.print(
                Panel(
                    f"[green]Policy applied successfully![/green]\n\n"
                    f"Commit: {commit.commit_hash}\n"
                    f"Message: {commit.message}\n"
                    f"Files: {', '.join(commit.files_changed)}",
                    title="GitOps Commit",
                )
            )

            if dry_run:
                console.print("[yellow]Note: This was a dry run. No changes were pushed.[/yellow]")

        except ValueError as e:
            console.print(f"[red]Failed to apply policy: {e}[/red]")
            raise typer.Exit(1)
        finally:
            await agent.cleanup()

    asyncio.run(run_apply())


@app.command()
def pipeline(
    namespace: Annotated[str, typer.Argument(help="Target namespace")] = "default",
    labels: Annotated[str | None, typer.Option("--labels", "-l", help="Pod labels")] = None,
    apply: Annotated[bool, typer.Option("--apply", help="Apply the generated policy")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file")] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use mock mode")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Dry run (don't push)")] = True,
) -> None:
    """Run the full pipeline: analyze -> generate -> validate -> (optionally) apply."""
    config = get_config(mock=mock, dry_run=dry_run, namespace=namespace)
    agent = PolicyAgent(config)

    pod_labels = {}
    if labels:
        for pair in labels.split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                pod_labels[key.strip()] = value.strip()

    async def run_pipeline() -> None:
        result = await agent.full_pipeline(
            namespace=namespace,
            pod_labels=pod_labels if pod_labels else None,
            auto_apply=apply,
        )

        policy = result["policy"]
        yaml_content = result["policy_yaml"]
        validation = result["validation"]
        evaluation = result["evaluation"]

        # Display policy
        if output:
            output.write_text(yaml_content)
            console.print(f"[green]Policy written to {output}[/green]")
        else:
            console.print(
                Panel(
                    Syntax(yaml_content, "yaml", theme="monokai"),
                    title=f"NetworkPolicy: {policy.name}",
                )
            )

        # Validation result
        if validation.is_valid:
            console.print("[green]Validation: PASSED[/green]")
        else:
            console.print("[red]Validation: FAILED[/red]")
            for error in validation.errors:
                console.print(f"  [red]- {error}[/red]")

        # Evaluation summary
        console.print(f"\n[bold]Evaluation Score: {evaluation.score:.2%}[/bold]")

        # Apply result
        if result.get("applied"):
            commit = result["commit"]
            console.print(f"\n[green]Applied via GitOps: {commit.commit_hash}[/green]")
        elif result.get("apply_error"):
            console.print(f"\n[yellow]Apply skipped: {result['apply_error']}[/yellow]")

        await agent.cleanup()

    asyncio.run(run_pipeline())


@app.command()
def stats() -> None:
    """Show agent statistics."""
    config = get_config()
    agent = PolicyAgent(config)

    stats = agent.get_full_stats()

    console.print(
        Panel(
            f"[bold]Agent Statistics[/bold]\n\n"
            f"Policies Generated: {stats['agent']['policies_generated']}\n"
            f"Policies Validated: {stats['agent']['policies_validated']}\n"
            f"Policies Applied: {stats['agent']['policies_applied']}\n"
            f"Traffic Rules Observed: {stats['agent']['traffic_rules_observed']}\n"
            f"GitOps Commits: {stats['agent']['gitops_commits']}\n"
            f"Validation Errors: {stats['agent']['validation_errors']}",
            title="K8s Policy Agent",
        )
    )


@app.command()
def version() -> None:
    """Show version information."""
    from k8s_policy_agent import __version__

    console.print(f"k8s-policy-agent version {__version__}")


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
