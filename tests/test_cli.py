"""Tests for CLI interface."""

import tempfile
from pathlib import Path

from typer.testing import CliRunner

from k8s_policy_agent.cli import app

runner = CliRunner()


class TestVersionCommand:
    """Tests for version command."""

    def test_version_shows_version(self) -> None:
        """Test version command shows version."""
        result = runner.invoke(app, ["version"])

        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestStatsCommand:
    """Tests for stats command."""

    def test_stats_shows_statistics(self) -> None:
        """Test stats command shows statistics."""
        result = runner.invoke(app, ["stats"])

        assert result.exit_code == 0
        assert "Policies Generated" in result.output


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_default_namespace(self) -> None:
        """Test analyze with default namespace."""
        result = runner.invoke(app, ["analyze", "--mock"])

        assert result.exit_code == 0
        assert "Traffic Observations" in result.output

    def test_analyze_custom_namespace(self) -> None:
        """Test analyze with custom namespace."""
        result = runner.invoke(app, ["analyze", "production", "--mock"])

        assert result.exit_code == 0
        assert "production" in result.output

    def test_analyze_with_labels(self) -> None:
        """Test analyze with labels."""
        result = runner.invoke(app, ["analyze", "--labels", "app=backend", "--mock"])

        assert result.exit_code == 0


class TestGenerateCommand:
    """Tests for generate command."""

    def test_generate_default_namespace(self) -> None:
        """Test generate with default namespace."""
        result = runner.invoke(app, ["generate", "--mock"])

        assert result.exit_code == 0
        assert "NetworkPolicy" in result.output

    def test_generate_with_labels(self) -> None:
        """Test generate with pod labels."""
        result = runner.invoke(app, ["generate", "--labels", "app=web", "--mock"])

        assert result.exit_code == 0
        assert "NetworkPolicy" in result.output

    def test_generate_default_deny(self) -> None:
        """Test generate default-deny policy."""
        result = runner.invoke(app, ["generate", "--default-deny", "--mock"])

        assert result.exit_code == 0
        assert "default-deny" in result.output

    def test_generate_to_file(self) -> None:
        """Test generate to output file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(app, ["generate", "--output", output_path, "--mock"])

            assert result.exit_code == 0
            assert Path(output_path).exists()
            content = Path(output_path).read_text()
            assert "apiVersion" in content
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestValidateCommand:
    """Tests for validate command."""

    def test_validate_valid_file(self, valid_policy_yaml: str) -> None:
        """Test validate with valid policy file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["validate", policy_path])

            assert result.exit_code == 0
            assert "VALID" in result.output
        finally:
            Path(policy_path).unlink(missing_ok=True)

    def test_validate_invalid_file(self, invalid_policy_yaml: str) -> None:
        """Test validate with invalid policy file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(invalid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["validate", policy_path])

            assert result.exit_code == 1
            assert "INVALID" in result.output
        finally:
            Path(policy_path).unlink(missing_ok=True)

    def test_validate_nonexistent_file(self) -> None:
        """Test validate with nonexistent file."""
        result = runner.invoke(app, ["validate", "/nonexistent/path.yaml"])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_validate_shows_security_checks(self, valid_policy_yaml: str) -> None:
        """Test validate shows security checks."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["validate", policy_path])

            assert "Security Checks" in result.output
            assert "DNS" in result.output
        finally:
            Path(policy_path).unlink(missing_ok=True)


class TestEvaluateCommand:
    """Tests for evaluate command."""

    def test_evaluate_valid_file(self, valid_policy_yaml: str) -> None:
        """Test evaluate with valid policy file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["evaluate", policy_path])

            assert result.exit_code == 0
            assert "Score" in result.output
        finally:
            Path(policy_path).unlink(missing_ok=True)

    def test_evaluate_shows_metrics(self, valid_policy_yaml: str) -> None:
        """Test evaluate shows evaluation metrics."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["evaluate", policy_path])

            assert "Security Score" in result.output
            assert "Completeness Score" in result.output
            assert "Least Privilege Score" in result.output
        finally:
            Path(policy_path).unlink(missing_ok=True)

    def test_evaluate_shows_test_details(self, valid_policy_yaml: str) -> None:
        """Test evaluate shows test details."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["evaluate", policy_path])

            assert "Test Details" in result.output or "Tests" in result.output
        finally:
            Path(policy_path).unlink(missing_ok=True)


class TestApplyCommand:
    """Tests for apply command."""

    def test_apply_valid_file(self, valid_policy_yaml: str) -> None:
        """Test apply with valid policy file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["apply", policy_path, "--mock"])

            assert result.exit_code == 0
            assert "applied" in result.output.lower() or "GitOps" in result.output
        finally:
            Path(policy_path).unlink(missing_ok=True)

    def test_apply_dry_run(self, valid_policy_yaml: str) -> None:
        """Test apply with dry run."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(app, ["apply", policy_path, "--dry-run", "--mock"])

            assert result.exit_code == 0
            # In dry-run mode, the apply still succeeds but note is shown
            assert "applied" in result.output.lower() or "gitops" in result.output.lower()
        finally:
            Path(policy_path).unlink(missing_ok=True)

    def test_apply_custom_message(self, valid_policy_yaml: str) -> None:
        """Test apply with custom commit message."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            f.write(valid_policy_yaml)
            policy_path = f.name

        try:
            result = runner.invoke(
                app, ["apply", policy_path, "--message", "Custom message", "--mock"]
            )

            assert result.exit_code == 0
        finally:
            Path(policy_path).unlink(missing_ok=True)


class TestPipelineCommand:
    """Tests for pipeline command."""

    def test_pipeline_default(self) -> None:
        """Test pipeline with defaults."""
        result = runner.invoke(app, ["pipeline", "--mock"])

        assert result.exit_code == 0
        assert "NetworkPolicy" in result.output
        assert "Validation" in result.output

    def test_pipeline_with_labels(self) -> None:
        """Test pipeline with pod labels."""
        result = runner.invoke(app, ["pipeline", "--labels", "app=backend", "--mock"])

        assert result.exit_code == 0

    def test_pipeline_to_file(self) -> None:
        """Test pipeline with output file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(app, ["pipeline", "--output", output_path, "--mock"])

            assert result.exit_code == 0
            assert Path(output_path).exists()
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_pipeline_with_apply(self) -> None:
        """Test pipeline with apply flag."""
        result = runner.invoke(app, ["pipeline", "--apply", "--mock", "--dry-run"])

        assert result.exit_code == 0

    def test_pipeline_shows_evaluation(self) -> None:
        """Test pipeline shows evaluation score."""
        result = runner.invoke(app, ["pipeline", "--mock"])

        assert "Evaluation Score" in result.output or "Score" in result.output


class TestHelpMessages:
    """Tests for help messages."""

    def test_main_help(self) -> None:
        """Test main help message."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "k8s-policy" in result.output.lower() or "kubernetes" in result.output.lower()

    def test_analyze_help(self) -> None:
        """Test analyze command help."""
        result = runner.invoke(app, ["analyze", "--help"])

        assert result.exit_code == 0
        assert "namespace" in result.output.lower()

    def test_generate_help(self) -> None:
        """Test generate command help."""
        result = runner.invoke(app, ["generate", "--help"])

        assert result.exit_code == 0
        assert "labels" in result.output.lower() or "output" in result.output.lower()

    def test_validate_help(self) -> None:
        """Test validate command help."""
        result = runner.invoke(app, ["validate", "--help"])

        assert result.exit_code == 0
        assert "file" in result.output.lower()

    def test_apply_help(self) -> None:
        """Test apply command help."""
        result = runner.invoke(app, ["apply", "--help"])

        assert result.exit_code == 0
        assert "gitops" in result.output.lower() or "file" in result.output.lower()

    def test_pipeline_help(self) -> None:
        """Test pipeline command help."""
        result = runner.invoke(app, ["pipeline", "--help"])

        assert result.exit_code == 0


class TestLabelsParsing:
    """Tests for labels parsing."""

    def test_single_label(self) -> None:
        """Test parsing single label."""
        result = runner.invoke(app, ["generate", "--labels", "app=backend", "--mock"])

        assert result.exit_code == 0

    def test_multiple_labels(self) -> None:
        """Test parsing multiple labels."""
        result = runner.invoke(app, ["generate", "--labels", "app=backend,tier=api", "--mock"])

        assert result.exit_code == 0

    def test_labels_with_spaces(self) -> None:
        """Test parsing labels with spaces after comma."""
        result = runner.invoke(app, ["generate", "--labels", "app=backend, tier=api", "--mock"])

        assert result.exit_code == 0
