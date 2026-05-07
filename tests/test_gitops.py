"""Tests for GitOps manager."""

import pytest

from k8s_policy_agent.gitops import GitOpsManager, create_gitops_manager
from k8s_policy_agent.models import NetworkPolicySpec, PolicyConfig


class TestGitOpsManagerInit:
    """Tests for GitOpsManager initialization."""

    def test_create_with_config(self, mock_config: PolicyConfig) -> None:
        """Test creating manager with config."""
        manager = GitOpsManager(mock_config)
        assert manager.config == mock_config

    def test_factory_function(self, mock_config: PolicyConfig) -> None:
        """Test factory function."""
        manager = create_gitops_manager(mock_config)
        assert manager is not None

    def test_factory_without_config(self) -> None:
        """Test factory function without config."""
        manager = create_gitops_manager()
        assert manager.config is not None


class TestProperties:
    """Tests for GitOpsManager properties."""

    def test_repo_url(self, mock_config: PolicyConfig) -> None:
        """Test repo_url property."""
        manager = GitOpsManager(mock_config)
        assert manager.repo_url == mock_config.git_repo_url

    def test_branch(self, mock_config: PolicyConfig) -> None:
        """Test branch property."""
        manager = GitOpsManager(mock_config)
        assert manager.branch == "main"

    def test_policies_path(self, mock_config: PolicyConfig) -> None:
        """Test policies_path property."""
        manager = GitOpsManager(mock_config)
        assert manager.policies_path == "policies/"


class TestCloneRepo:
    """Tests for repository cloning."""

    @pytest.mark.asyncio
    async def test_clone_repo_mock_mode(self, mock_config: PolicyConfig) -> None:
        """Test cloning in mock mode creates temp repo."""
        manager = GitOpsManager(mock_config)
        work_dir = await manager.clone_repo()

        assert work_dir.exists()
        assert (work_dir / ".git").exists()

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_clone_repo_creates_policies_dir(self, mock_config: PolicyConfig) -> None:
        """Test cloning creates policies directory."""
        manager = GitOpsManager(mock_config)
        work_dir = await manager.clone_repo()

        policies_dir = work_dir / mock_config.git_policies_path
        assert policies_dir.exists()

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_clone_repo_initializes_git(self, mock_config: PolicyConfig) -> None:
        """Test cloning initializes git repository."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        assert manager._repo is not None
        assert manager._work_dir is not None

        manager.cleanup()


class TestCommitPolicy:
    """Tests for committing policies."""

    @pytest.mark.asyncio
    async def test_commit_policy(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test committing a policy."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        commit = await manager.commit_policy(sample_network_policy)

        assert commit.commit_hash is not None
        assert len(commit.commit_hash) > 0
        assert sample_network_policy.name in commit.policy_names
        assert commit.operation_mode == "mock"
        assert commit.mock_mode is True
        assert commit.dry_run is True

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_commit_policy_creates_file(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test commit creates policy file."""
        manager = GitOpsManager(mock_config)
        work_dir = await manager.clone_repo()

        await manager.commit_policy(sample_network_policy)

        expected_file = (
            work_dir
            / mock_config.git_policies_path
            / f"{sample_network_policy.namespace}-{sample_network_policy.name}.yaml"
        )
        assert expected_file.exists()

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_commit_policy_custom_message(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test commit with custom message."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        commit = await manager.commit_policy(
            sample_network_policy,
            message="Custom commit message",
        )

        assert commit.message == "Custom commit message"

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_commit_policy_files_changed(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test commit records files changed."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        commit = await manager.commit_policy(sample_network_policy)

        assert len(commit.files_changed) == 1
        assert commit.files_changed[0].endswith(".yaml")

        manager.cleanup()


class TestCommitPolicies:
    """Tests for committing multiple policies."""

    @pytest.mark.asyncio
    async def test_commit_multiple_policies(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
        default_deny_policy: NetworkPolicySpec,
    ) -> None:
        """Test committing multiple policies."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        commit = await manager.commit_policies(
            [sample_network_policy, default_deny_policy],
        )

        assert len(commit.policy_names) == 2
        assert len(commit.files_changed) == 2

        manager.cleanup()


class TestPush:
    """Tests for pushing to remote."""

    @pytest.mark.asyncio
    async def test_push_mock_mode(self, mock_config: PolicyConfig) -> None:
        """Test push in mock mode succeeds."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        result = await manager.push()

        assert result is True
        assert manager.last_operation_mode == "mock"
        assert manager.last_failure_reason == ""

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_push_dry_run_skips_remote(self, mock_config: PolicyConfig) -> None:
        """Test dry-run push is visibly skipped without remote side effects."""
        config = mock_config.model_copy(update={"mock_mode": False, "dry_run": True})
        manager = GitOpsManager(config)

        result = await manager.push()

        assert result is True
        assert manager.last_operation_mode == "dry_run"
        assert manager.last_failure_reason == ""

    @pytest.mark.asyncio
    async def test_push_without_repo_records_failure(self, mock_config: PolicyConfig) -> None:
        """Test push failure state is exposed when no repository is initialized."""
        config = mock_config.model_copy(update={"mock_mode": False, "dry_run": False})
        manager = GitOpsManager(config)

        with pytest.raises(RuntimeError, match="Repository not initialized"):
            await manager.push()

        assert manager.last_failure_reason == "Repository not initialized"


class TestCreateBranch:
    """Tests for branch creation."""

    @pytest.mark.asyncio
    async def test_create_branch(self, mock_config: PolicyConfig) -> None:
        """Test creating a new branch."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        result = await manager.create_branch("feature/new-policy")

        assert result is True

        manager.cleanup()


class TestListPolicies:
    """Tests for listing policies."""

    @pytest.mark.asyncio
    async def test_list_policies_empty(self, mock_config: PolicyConfig) -> None:
        """Test listing policies in empty repo."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        policies = await manager.list_policies()

        assert policies == []

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_list_policies_after_commit(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test listing policies after committing."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()
        await manager.commit_policy(sample_network_policy)

        policies = await manager.list_policies()

        assert len(policies) == 1
        assert policies[0].endswith(".yaml")

        manager.cleanup()


class TestGetPolicy:
    """Tests for getting policy content."""

    @pytest.mark.asyncio
    async def test_get_policy_not_found(self, mock_config: PolicyConfig) -> None:
        """Test getting non-existent policy."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        content = await manager.get_policy("nonexistent")

        assert content is None

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_get_policy_after_commit(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test getting policy after committing."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()
        await manager.commit_policy(sample_network_policy)

        filename = f"{sample_network_policy.namespace}-{sample_network_policy.name}"
        content = await manager.get_policy(filename)

        assert content is not None
        assert "NetworkPolicy" in content

        manager.cleanup()


class TestDeletePolicy:
    """Tests for deleting policies."""

    @pytest.mark.asyncio
    async def test_delete_policy_not_found(self, mock_config: PolicyConfig) -> None:
        """Test deleting non-existent policy."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        commit = await manager.delete_policy("nonexistent")

        assert commit is None

        manager.cleanup()

    @pytest.mark.asyncio
    async def test_delete_policy_success(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test deleting existing policy."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()
        await manager.commit_policy(sample_network_policy)

        filename = f"{sample_network_policy.namespace}-{sample_network_policy.name}"
        commit = await manager.delete_policy(filename)

        assert commit is not None
        assert "Remove" in commit.message

        manager.cleanup()


class TestFilenameGeneration:
    """Tests for filename generation."""

    def test_generate_filename(
        self,
        mock_config: PolicyConfig,
        sample_network_policy: NetworkPolicySpec,
    ) -> None:
        """Test filename generation."""
        manager = GitOpsManager(mock_config)
        filename = manager._generate_filename(sample_network_policy)

        assert filename == "default-allow-backend.yaml"

    def test_generate_filename_different_namespace(self, mock_config: PolicyConfig) -> None:
        """Test filename with different namespace."""
        from k8s_policy_agent.models import PodSelector

        policy = NetworkPolicySpec(
            name="my-policy",
            namespace="production",
            pod_selector=PodSelector(match_labels={"app": "web"}),
        )

        manager = GitOpsManager(mock_config)
        filename = manager._generate_filename(policy)

        assert filename == "production-my-policy.yaml"


class TestCleanup:
    """Tests for cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_removes_temp_dir(self, mock_config: PolicyConfig) -> None:
        """Test cleanup removes temporary directory."""
        manager = GitOpsManager(mock_config)
        work_dir = await manager.clone_repo()

        assert work_dir.exists()

        manager.cleanup()

        assert not work_dir.exists()

    def test_cleanup_no_repo(self, mock_config: PolicyConfig) -> None:
        """Test cleanup with no repo doesn't fail."""
        manager = GitOpsManager(mock_config)
        manager.cleanup()  # Should not raise


class TestGetStats:
    """Tests for statistics."""

    def test_get_stats_initial(self, mock_config: PolicyConfig) -> None:
        """Test initial statistics."""
        manager = GitOpsManager(mock_config)
        stats = manager.get_stats()

        assert stats["initialized"] is False
        assert "repo_url" in stats
        assert "branch" in stats
        assert stats["operation_mode"] == "mock"
        assert stats["dry_run"] is True
        assert stats["mock_mode"] is True
        assert stats["last_failure_reason"] == ""

    @pytest.mark.asyncio
    async def test_get_stats_after_init(self, mock_config: PolicyConfig) -> None:
        """Test statistics after initialization."""
        manager = GitOpsManager(mock_config)
        await manager.clone_repo()

        stats = manager.get_stats()

        assert stats["initialized"] is True
        assert "commit_count" in stats

        manager.cleanup()
