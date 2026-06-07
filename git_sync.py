"""
git_sync.py — Optional Git auto-commit for time capsules.

Usage:
  capsule init --git <repo-url>   → stores the remote in ~/.timecapsule/config.json
  After every `capsule write`, auto_commit() is called if git is configured.

Security: master.key is NEVER committed. A .gitignore is written automatically.
"""

from __future__ import annotations

import logging
from pathlib import Path

from capsule.storage import CAPSULES_DIR, TIMECAPSULE_DIR, load_config, save_config

logger = logging.getLogger(__name__)

GITIGNORE_PATH = TIMECAPSULE_DIR / ".gitignore"
GITIGNORE_CONTENT = """# timecapsule — never commit the master key!
master.key
"""


def _get_repo():
    """Import and return the GitPython Repo object for ~/.timecapsule, or None."""
    try:
        import git
        return git.Repo(str(TIMECAPSULE_DIR))
    except Exception:
        return None


def init_git(repo_url: str) -> bool:
    """
    Initialize a git repo at ~/.timecapsule and set a remote.

    Args:
        repo_url: URL of the private remote git repository.

    Returns:
        True on success, False on failure.
    """
    try:
        import git

        TIMECAPSULE_DIR.mkdir(parents=True, exist_ok=True)

        # Write .gitignore protecting master.key
        GITIGNORE_PATH.write_text(GITIGNORE_CONTENT, encoding="utf-8")

        # Init or load repo
        try:
            repo = git.Repo(str(TIMECAPSULE_DIR))
        except git.InvalidGitRepositoryError:
            repo = git.Repo.init(str(TIMECAPSULE_DIR))

        # Set / update remote
        try:
            remote = repo.remote("origin")
            remote.set_url(repo_url)
        except ValueError:
            repo.create_remote("origin", repo_url)

        # Store config
        config = load_config()
        config["git_remote"] = repo_url
        save_config(config)

        logger.info("Git remote configured: %s", repo_url)
        return True

    except Exception as exc:
        logger.error("Git init failed: %s", exc)
        return False


def auto_commit(capsule_id: str, unlock_date: str) -> bool:
    """
    Stage the new .capsule file + index.json and commit.

    Args:
        capsule_id:  UUID of the newly created capsule.
        unlock_date: ISO date string for the commit message.

    Returns:
        True if committed (and pushed) successfully, False otherwise.
    """
    config = load_config()
    if "git_remote" not in config:
        return False  # Git not configured — silently skip

    repo = _get_repo()
    if repo is None:
        logger.warning("Git repo not found at %s", TIMECAPSULE_DIR)
        return False

    try:
        capsule_file = CAPSULES_DIR / f"{capsule_id}.capsule"
        index_file = TIMECAPSULE_DIR / "index.json"

        # Stage files
        files_to_stage = []
        if capsule_file.exists():
            files_to_stage.append(str(capsule_file))
        if index_file.exists():
            files_to_stage.append(str(index_file))
        if GITIGNORE_PATH.exists():
            files_to_stage.append(str(GITIGNORE_PATH))

        repo.index.add(files_to_stage)

        commit_msg = f"capsule: added {capsule_id} (unlocks {unlock_date})"
        repo.index.commit(commit_msg)

        # Push to remote
        try:
            origin = repo.remote("origin")
            origin.push()
            logger.info("Pushed capsule to remote.")
        except Exception as push_exc:
            logger.warning("Push failed (commit saved locally): %s", push_exc)

        return True

    except Exception as exc:
        logger.error("Git commit failed: %s", exc)
        return False
