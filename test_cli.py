"""
test_cli.py — Tests for the Click CLI commands.

RFC 3161 TSA calls are always mocked to avoid network dependency.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from capsule import CapsuleLockedError
from cli import cli


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_vault(tmp_path, monkeypatch):
    """Redirect all storage and encrypt paths to tmp_path."""
    capsules_dir = tmp_path / "capsules"
    capsules_dir.mkdir()

    monkeypatch.setattr("capsule.storage.TIMECAPSULE_DIR", tmp_path)
    monkeypatch.setattr("capsule.storage.CAPSULES_DIR", capsules_dir)
    monkeypatch.setattr("capsule.storage.INDEX_PATH", tmp_path / "index.json")
    monkeypatch.setattr("capsule.storage.CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr("capsule.encrypt.TIMECAPSULE_DIR", tmp_path)
    monkeypatch.setattr("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key")
    monkeypatch.setattr("capsule.git_sync.TIMECAPSULE_DIR", tmp_path)
    monkeypatch.setattr("capsule.git_sync.CAPSULES_DIR", capsules_dir)

    return tmp_path


@pytest.fixture
def mock_tsa(mocker):
    """Mock the RFC 3161 TSA request to avoid network calls."""
    return mocker.patch(
        "capsule.timestamp.request_timestamp",
        return_value=None,  # Simulate offline/no timestamp
    )


# ---------------------------------------------------------------------------
# `capsule write` tests
# ---------------------------------------------------------------------------

class TestWriteCommand:
    def test_write_basic_success(self, runner, temp_vault, mock_tsa):
        result = runner.invoke(cli, [
            "write", "Hello future me",
            "--unlock", "2099-01-01",
            "--mood", "hopeful",
            "--no-git",
        ])
        assert result.exit_code == 0
        assert "Capsule Sealed" in result.output

    def test_write_creates_capsule_file(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "Test message",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        capsule_files = list((temp_vault / "capsules").glob("*.capsule"))
        assert len(capsule_files) == 1

    def test_write_creates_index_entry(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "Another test",
            "--unlock", "2099-06-01",
            "--tag", "career",
            "--mood", "excited",
            "--no-git",
        ])
        index_path = temp_vault / "index.json"
        assert index_path.exists()
        entries = json.loads(index_path.read_text())
        assert len(entries) == 1
        assert entries[0]["mood"] == "excited"
        assert "career" in entries[0]["tags"]

    def test_write_invalid_date_fails(self, runner, temp_vault, mock_tsa):
        result = runner.invoke(cli, [
            "write", "Test",
            "--unlock", "not-a-date",
            "--no-git",
        ])
        assert result.exit_code != 0

    def test_write_shows_countdown(self, runner, temp_vault, mock_tsa):
        result = runner.invoke(cli, [
            "write", "Far future",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        assert result.exit_code == 0
        # Should show a countdown with "year" in it
        assert "year" in result.output.lower() or "Opens in" in result.output

    def test_write_multiple_tags(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "Tagged message",
            "--unlock", "2030-01-01",
            "--tag", "career",
            "--tag", "health",
            "--tag", "travel",
            "--no-git",
        ])
        index_path = temp_vault / "index.json"
        entries = json.loads(index_path.read_text())
        assert set(entries[0]["tags"]) == {"career", "health", "travel"}


# ---------------------------------------------------------------------------
# `capsule list` tests
# ---------------------------------------------------------------------------

class TestListCommand:
    def test_list_empty_vault(self, runner, temp_vault):
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0
        assert "No capsules" in result.output

    def test_list_shows_capsule_hint(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "Hello future self welcome here",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        # Check the title_hint was stored correctly in the index
        index_path = temp_vault / "index.json"
        entries = json.loads(index_path.read_text())
        assert entries[0]["title_hint"] == "Hello future self..."
        # Also check list runs without error
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0

    def test_list_shows_locked_status(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "Future message",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        result = runner.invoke(cli, ["list"])
        assert "LOCKED" in result.output

    def test_list_hides_message_content(self, runner, temp_vault, mock_tsa):
        secret_phrase = "THIS_IS_THE_SECRET_CONTENT_XYZ"
        runner.invoke(cli, [
            "write", f"{secret_phrase} and more text here",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        result = runner.invoke(cli, ["list"])
        # The full secret should NOT appear in list output
        assert secret_phrase not in result.output

    def test_list_multiple_capsules(self, runner, temp_vault, mock_tsa):
        for i in range(3):
            runner.invoke(cli, [
                "write", f"Capsule number {i} content",
                "--unlock", "2099-01-01",
                "--no-git",
            ])
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0
        assert "3" in result.output  # total count shown


# ---------------------------------------------------------------------------
# `capsule open` tests
# ---------------------------------------------------------------------------

class TestOpenCommand:
    def test_open_locked_shows_countdown(self, runner, temp_vault, mock_tsa):
        """Opening a locked capsule must show countdown, not an error."""
        runner.invoke(cli, [
            "write", "Locked message",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        # Get the capsule ID from index
        index_path = temp_vault / "index.json"
        entries = json.loads(index_path.read_text())
        capsule_id = entries[0]["id"]

        result = runner.invoke(cli, ["open", capsule_id])
        assert "LOCKED" in result.output or "sealed" in result.output.lower()
        assert "year" in result.output.lower() or "Opens in" in result.output

    def test_open_locked_exits_cleanly(self, runner, temp_vault, mock_tsa):
        """Opening a locked capsule must exit 0 (expected behavior, not error)."""
        runner.invoke(cli, [
            "write", "Sealed",
            "--unlock", "2099-06-01",
            "--no-git",
        ])
        index_path = temp_vault / "index.json"
        entries = json.loads(index_path.read_text())
        capsule_id = entries[0]["id"]

        result = runner.invoke(cli, ["open", capsule_id])
        assert result.exit_code == 0

    def test_open_nonexistent_id_fails(self, runner, temp_vault):
        result = runner.invoke(cli, ["open", "nonexistent-id"])
        assert result.exit_code != 0

    def test_open_unlocked_capsule_shows_message(self, runner, temp_vault, mock_tsa):
        """A past-unlock-date capsule must decrypt and show the message."""
        # Create a capsule with past date
        runner.invoke(cli, [
            "write", "Past message for testing decrypt",
            "--unlock", "2020-01-01",  # Past date
            "--no-git",
        ])
        index_path = temp_vault / "index.json"
        entries = json.loads(index_path.read_text())
        capsule_id = entries[0]["id"]

        result = runner.invoke(cli, ["open", capsule_id, "--skip-verify"])
        assert result.exit_code == 0
        assert "Past message for testing decrypt" in result.output

    def test_open_short_id_prefix(self, runner, temp_vault, mock_tsa):
        """Opening with first 8 chars of ID should work."""
        runner.invoke(cli, [
            "write", "Short ID test",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        index_path = temp_vault / "index.json"
        entries = json.loads(index_path.read_text())
        short_id = entries[0]["id"][:8]

        result = runner.invoke(cli, ["open", short_id])
        # Should find the capsule (may be locked, but not "not found")
        assert "not found" not in result.output.lower()


# ---------------------------------------------------------------------------
# `capsule stats` tests
# ---------------------------------------------------------------------------

class TestStatsCommand:
    def test_stats_empty_vault(self, runner, temp_vault):
        result = runner.invoke(cli, ["stats"])
        assert result.exit_code == 0

    def test_stats_shows_total(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "First",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        runner.invoke(cli, [
            "write", "Second",
            "--unlock", "2030-01-01",
            "--mood", "excited",
            "--no-git",
        ])
        result = runner.invoke(cli, ["stats"])
        assert result.exit_code == 0
        assert "2" in result.output  # 2 total

    def test_stats_shows_mood_chart(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "Happy test",
            "--unlock", "2099-01-01",
            "--mood", "happy",
            "--no-git",
        ])
        result = runner.invoke(cli, ["stats"])
        assert "happy" in result.output.lower()


# ---------------------------------------------------------------------------
# `capsule export` tests
# ---------------------------------------------------------------------------

class TestExportCommand:
    def test_export_empty_vault(self, runner, temp_vault):
        result = runner.invoke(cli, ["export", "--output", str(temp_vault / "out.zip")])
        assert result.exit_code == 0

    def test_export_creates_zip(self, runner, temp_vault, mock_tsa):
        runner.invoke(cli, [
            "write", "Export test message",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        out_path = temp_vault / "backup.zip"
        runner.invoke(cli, ["export", "--output", str(out_path)])
        assert out_path.exists()

    def test_export_zip_contains_capsule(self, runner, temp_vault, mock_tsa):
        import zipfile
        runner.invoke(cli, [
            "write", "Zip content test",
            "--unlock", "2099-01-01",
            "--no-git",
        ])
        # Verify capsule file was created in temp_vault
        capsule_files = list((temp_vault / "capsules").glob("*.capsule"))
        assert len(capsule_files) >= 1, "Capsule file not created in temp vault"
        
        out_path = temp_vault / "backup.zip"
        result = runner.invoke(cli, ["export", "--output", str(out_path)])
        assert result.exit_code == 0
        assert out_path.exists(), "Zip file not created"
        
        with zipfile.ZipFile(out_path) as zf:
            names = zf.namelist()
        assert any(name.endswith(".capsule") for name in names)


# ---------------------------------------------------------------------------
# `capsule init` tests
# ---------------------------------------------------------------------------

class TestInitCommand:
    def test_init_runs_successfully(self, runner, temp_vault):
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0
        assert "initialized" in result.output.lower()

    def test_init_creates_master_key(self, runner, temp_vault):
        key_path = temp_vault / "master.key"
        assert not key_path.exists()
        runner.invoke(cli, ["init"])
        assert key_path.exists()
