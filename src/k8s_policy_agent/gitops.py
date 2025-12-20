"""GitOps manager for Kubernetes policies."""

from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog
from git import Repo
from git.exc import GitCommandError

from k8s_policy_agent.models import (
    PolicyConfig,
    NetworkPolicySpec,
    GitOpsCommit,
)

logger = structlog.get_logger()


class GitOpsManager:
    """Manages GitOps workflow for NetworkPolicy resources."""

    def __init__(self, config: PolicyConfig) -> None:
        """Initialize the GitOps manager.

        Args:
            config: Policy configuration
        """
        self.config = config
        self._repo: Repo | None = None
        self._work_dir: Path | None = None
        self._temp_dir: str | None = None

    @property
    def repo_url(self) -> str:
        """Get the repository URL."""
        return self.config.git_repo_url

    @property
    def branch(self) -> str:
        """Get the target branch."""
        return self.config.git_branch

    @property
    def policies_path(self) -> str:
        """Get the policies directory path."""
        return self.config.git_policies_path

    async def clone_repo(self) -> Path:
        """Clone the Git repository.

        Returns:
            Path to the cloned repository
        """
        if self.config.mock_mode:
            return self._create_mock_repo()

        if not self.config.git_repo_url:
            raise ValueError("Git repository URL not configured")

        self._temp_dir = tempfile.mkdtemp(prefix="k8s-policy-")
        work_dir = Path(self._temp_dir)

        logger.info("cloning_repository", url=self.config.git_repo_url, path=str(work_dir))

        try:
            self._repo = Repo.clone_from(
                self.config.git_repo_url,
                work_dir,
                branch=self.config.git_branch,
            )
            self._work_dir = work_dir
            return work_dir

        except GitCommandError as e:
            logger.error("clone_failed", error=str(e))
            raise

    def _create_mock_repo(self) -> Path:
        """Create a mock repository for testing.

        Returns:
            Path to mock repository
        """
        self._temp_dir = tempfile.mkdtemp(prefix="k8s-policy-mock-")
        work_dir = Path(self._temp_dir)

        # Initialize git repo
        self._repo = Repo.init(work_dir)

        # Create policies directory
        policies_dir = work_dir / self.config.git_policies_path
        policies_dir.mkdir(parents=True, exist_ok=True)

        # Create initial commit
        readme_path = work_dir / "README.md"
        readme_path.write_text("# Network Policies\n\nManaged by k8s-policy-agent.\n")

        self._repo.index.add([str(readme_path)])
        self._repo.index.commit("Initial commit")

        self._work_dir = work_dir
        return work_dir

    async def commit_policy(
        self,
        policy: NetworkPolicySpec,
        message: str | None = None,
    ) -> GitOpsCommit:
        """Commit a policy to the repository.

        Args:
            policy: NetworkPolicy to commit
            message: Optional commit message

        Returns:
            GitOps commit information
        """
        if self._repo is None or self._work_dir is None:
            await self.clone_repo()

        if self._work_dir is None:
            raise RuntimeError("Repository not initialized")

        # Ensure policies directory exists
        policies_dir = self._work_dir / self.config.git_policies_path
        policies_dir.mkdir(parents=True, exist_ok=True)

        # Generate policy filename
        filename = self._generate_filename(policy)
        policy_path = policies_dir / filename

        # Write policy YAML
        from k8s_policy_agent.policy_generator import PolicyGenerator

        generator = PolicyGenerator(self.config)
        yaml_content = generator.policy_to_yaml(policy)

        policy_path.write_text(yaml_content)
        relative_path = str(policy_path.relative_to(self._work_dir))

        logger.info("writing_policy", path=relative_path)

        # Stage and commit
        if self._repo is None:
            raise RuntimeError("Repository not initialized")

        self._repo.index.add([relative_path])

        commit_message = message or f"Add/update NetworkPolicy: {policy.name}"
        commit = self._repo.index.commit(commit_message)

        return GitOpsCommit(
            commit_hash=commit.hexsha,
            message=commit_message,
            author=str(commit.author),
            timestamp=datetime.now(),
            files_changed=[relative_path],
            policy_names=[policy.name],
        )

    async def commit_policies(
        self,
        policies: list[NetworkPolicySpec],
        message: str | None = None,
    ) -> GitOpsCommit:
        """Commit multiple policies to the repository.

        Args:
            policies: List of NetworkPolicies to commit
            message: Optional commit message

        Returns:
            GitOps commit information
        """
        if self._repo is None or self._work_dir is None:
            await self.clone_repo()

        if self._work_dir is None:
            raise RuntimeError("Repository not initialized")

        policies_dir = self._work_dir / self.config.git_policies_path
        policies_dir.mkdir(parents=True, exist_ok=True)

        from k8s_policy_agent.policy_generator import PolicyGenerator

        generator = PolicyGenerator(self.config)

        files_changed = []
        policy_names = []

        for policy in policies:
            filename = self._generate_filename(policy)
            policy_path = policies_dir / filename

            yaml_content = generator.policy_to_yaml(policy)
            policy_path.write_text(yaml_content)

            relative_path = str(policy_path.relative_to(self._work_dir))
            files_changed.append(relative_path)
            policy_names.append(policy.name)

        if self._repo is None:
            raise RuntimeError("Repository not initialized")

        self._repo.index.add(files_changed)

        commit_message = message or f"Add/update {len(policies)} NetworkPolicies"
        commit = self._repo.index.commit(commit_message)

        return GitOpsCommit(
            commit_hash=commit.hexsha,
            message=commit_message,
            author=str(commit.author),
            timestamp=datetime.now(),
            files_changed=files_changed,
            policy_names=policy_names,
        )

    async def push(self, remote: str = "origin") -> bool:
        """Push commits to remote repository.

        Args:
            remote: Remote name

        Returns:
            True if push succeeded
        """
        if self.config.mock_mode:
            logger.info("mock_push", remote=remote, branch=self.config.git_branch)
            return True

        if self._repo is None:
            raise RuntimeError("Repository not initialized")

        try:
            logger.info("pushing_to_remote", remote=remote, branch=self.config.git_branch)
            self._repo.remote(remote).push(self.config.git_branch)
            return True

        except GitCommandError as e:
            logger.error("push_failed", error=str(e))
            return False

    async def create_branch(self, branch_name: str) -> bool:
        """Create a new branch.

        Args:
            branch_name: Name for the new branch

        Returns:
            True if branch was created
        """
        if self._repo is None:
            raise RuntimeError("Repository not initialized")

        try:
            self._repo.create_head(branch_name)
            self._repo.heads[branch_name].checkout()
            logger.info("created_branch", branch=branch_name)
            return True

        except GitCommandError as e:
            logger.error("branch_creation_failed", error=str(e))
            return False

    async def list_policies(self) -> list[str]:
        """List all policy files in the repository.

        Returns:
            List of policy file paths
        """
        if self._work_dir is None:
            await self.clone_repo()

        if self._work_dir is None:
            return []

        policies_dir = self._work_dir / self.config.git_policies_path

        if not policies_dir.exists():
            return []

        return [str(f.relative_to(self._work_dir)) for f in policies_dir.glob("*.yaml")]

    async def get_policy(self, name: str) -> str | None:
        """Get policy content by name.

        Args:
            name: Policy name

        Returns:
            YAML content or None
        """
        if self._work_dir is None:
            await self.clone_repo()

        if self._work_dir is None:
            return None

        policies_dir = self._work_dir / self.config.git_policies_path
        policy_file = policies_dir / f"{name}.yaml"

        if policy_file.exists():
            return policy_file.read_text()

        return None

    async def delete_policy(self, name: str, message: str | None = None) -> GitOpsCommit | None:
        """Delete a policy from the repository.

        Args:
            name: Policy name to delete
            message: Optional commit message

        Returns:
            GitOps commit information or None if policy not found
        """
        if self._work_dir is None:
            await self.clone_repo()

        if self._work_dir is None or self._repo is None:
            return None

        policies_dir = self._work_dir / self.config.git_policies_path
        policy_file = policies_dir / f"{name}.yaml"

        if not policy_file.exists():
            return None

        relative_path = str(policy_file.relative_to(self._work_dir))
        self._repo.index.remove([relative_path])
        policy_file.unlink()

        commit_message = message or f"Remove NetworkPolicy: {name}"
        commit = self._repo.index.commit(commit_message)

        return GitOpsCommit(
            commit_hash=commit.hexsha,
            message=commit_message,
            author=str(commit.author),
            timestamp=datetime.now(),
            files_changed=[relative_path],
            policy_names=[name],
        )

    def _generate_filename(self, policy: NetworkPolicySpec) -> str:
        """Generate a filename for a policy.

        Args:
            policy: NetworkPolicy specification

        Returns:
            Filename
        """
        return f"{policy.namespace}-{policy.name}.yaml"

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir)
            self._temp_dir = None
            self._work_dir = None
            self._repo = None

    def get_stats(self) -> dict[str, Any]:
        """Get GitOps manager statistics.

        Returns:
            Statistics dictionary
        """
        stats = {
            "repo_url": self.config.git_repo_url,
            "branch": self.config.git_branch,
            "policies_path": self.config.git_policies_path,
            "initialized": self._repo is not None,
        }

        if self._repo is not None:
            try:
                stats["commit_count"] = len(list(self._repo.iter_commits()))
                stats["current_branch"] = str(self._repo.active_branch)
            except Exception:
                pass

        return stats


def create_gitops_manager(config: PolicyConfig | None = None) -> GitOpsManager:
    """Factory function to create GitOpsManager.

    Args:
        config: Optional policy configuration

    Returns:
        Configured GitOpsManager instance
    """
    if config is None:
        config = PolicyConfig()

    return GitOpsManager(config)
