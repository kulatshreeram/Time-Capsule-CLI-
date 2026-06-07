"""
test_storage.py — Tests for the storage layer (.capsule files + index.json).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from capsule.storage import (
    add_index_entry,
    create_capsule,
    get_index_entry,
    load_capsule,
    load_index,
    make_title_hint,
    save_capsule,
    save_index,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_vault(tmp_path, monkeypatch):
    """Redirect all storage paths to a temporary directory."""
    capsules_dir = tmp_path / "capsules"
    capsules_dir.mkdir()
    index_path = tmp_path / "index.json"
    config_path = tmp_path / "config.json"

    monkeypatch.setattr("capsule.storage.TIMECAPSULE_DIR", tmp_path)
    monkeypatch.setattr("capsule.storage.CAPSULES_DIR", capsules_dir)
    monkeypatch.setattr("capsule.storage.INDEX_PATH", index_path)
    monkeypatch.setattr("capsule.storage.CONFIG_PATH", config_path)

    return tmp_path


# ---------------------------------------------------------------------------
# Title hint
# ---------------------------------------------------------------------------

class TestTitleHint:
    def test_three_words(self):
        assert make_title_hint("Hello future me") == "Hello future me"

    def test_more_than_three_words(self):
        assert make_title_hint("Hello future me it's good") == "Hello future me..."

    def test_exactly_three_words(self):
        assert make_title_hint("one two three") == "one two three"

    def test_single_word(self):
        assert make_title_hint("Hello") == "Hello"

    def test_custom_n_words(self):
        assert make_title_hint("one two three four five", n_words=2) == "one two..."

    def test_empty_message(self):
        assert make_title_hint("") == ""


# ---------------------------------------------------------------------------
# Capsule file I/O
# ---------------------------------------------------------------------------

class TestCapsuleFileIO:
    def test_save_and_load_roundtrip(self, temp_vault):
        payload = {"nonce_hex": "aabb", "message": "test"}
        path = save_capsule("test-uuid-1234", payload)
        assert path.exists()
        loaded = load_capsule("test-uuid-1234")
        assert loaded == payload

    def test_capsule_file_is_valid_json(self, temp_vault):
        save_capsule("uuid-json-check", {"key": "value"})
        path = (temp_vault / "capsules" / "uuid-json-check.capsule")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data == {"key": "value"}

    def test_capsule_file_extension_is_capsule(self, temp_vault):
        save_capsule("uuid-ext", {"data": 1})
        path = temp_vault / "capsules" / "uuid-ext.capsule"
        assert path.exists()

    def test_load_nonexistent_capsule_raises(self, temp_vault):
        from capsule import CapsuleNotFoundError
        with pytest.raises(CapsuleNotFoundError):
            load_capsule("nonexistent-uuid")

    def test_overwrite_capsule(self, temp_vault):
        save_capsule("uuid-ow", {"v": 1})
        save_capsule("uuid-ow", {"v": 2})
        assert load_capsule("uuid-ow")["v"] == 2


# ---------------------------------------------------------------------------
# Index I/O
# ---------------------------------------------------------------------------

class TestIndexIO:
    def test_load_empty_index(self, temp_vault):
        assert load_index() == []

    def test_save_and_load_index(self, temp_vault):
        entries = [{"id": "aaa", "mood": "hopeful"}, {"id": "bbb", "mood": "sad"}]
        save_index(entries)
        loaded = load_index()
        assert len(loaded) == 2

    def test_add_entry(self, temp_vault):
        add_index_entry({"id": "new-id", "mood": "happy"})
        entries = load_index()
        assert any(e["id"] == "new-id" for e in entries)

    def test_add_entry_replaces_existing_id(self, temp_vault):
        add_index_entry({"id": "same-id", "mood": "hopeful"})
        add_index_entry({"id": "same-id", "mood": "excited"})
        entries = load_index()
        matching = [e for e in entries if e["id"] == "same-id"]
        assert len(matching) == 1
        assert matching[0]["mood"] == "excited"

    def test_get_index_entry_found(self, temp_vault):
        add_index_entry({"id": "find-me", "mood": "happy"})
        entry = get_index_entry("find-me")
        assert entry is not None
        assert entry["mood"] == "happy"

    def test_get_index_entry_not_found(self, temp_vault):
        assert get_index_entry("ghost-id") is None


# ---------------------------------------------------------------------------
# create_capsule (integration)
# ---------------------------------------------------------------------------

class TestCreateCapsule:
    def test_create_capsule_returns_uuid(self, temp_vault):
        encrypted = {
            "nonce_hex": "a" * 24,
            "ciphertext_hex": "b" * 32,
            "auth_tag_hex": "c" * 32,
            "unlock_timestamp": "2020-01-01T00:00:00+00:00",
        }
        capsule_id = create_capsule(
            message="Hello world from the past",
            mood="nostalgic",
            tags=["test"],
            unlock_date="2020-01-01",
            encrypted_payload=encrypted,
            rfc3161_token_hex=None,
            timestamp_verified=False,
        )
        assert len(capsule_id) == 36  # UUID format

    def test_create_capsule_saves_file(self, temp_vault):
        encrypted = {
            "nonce_hex": "a" * 24,
            "ciphertext_hex": "b" * 32,
            "auth_tag_hex": "c" * 32,
            "unlock_timestamp": "2020-01-01T00:00:00+00:00",
        }
        capsule_id = create_capsule(
            message="Test message",
            mood="happy",
            tags=[],
            unlock_date="2020-01-01",
            encrypted_payload=encrypted,
            rfc3161_token_hex=None,
            timestamp_verified=False,
        )
        path = temp_vault / "capsules" / f"{capsule_id}.capsule"
        assert path.exists()

    def test_create_capsule_adds_index_entry(self, temp_vault):
        encrypted = {
            "nonce_hex": "a" * 24,
            "ciphertext_hex": "b" * 32,
            "auth_tag_hex": "c" * 32,
            "unlock_timestamp": "2020-01-01T00:00:00+00:00",
        }
        capsule_id = create_capsule(
            message="Check the index entry",
            mood="grateful",
            tags=["index", "test"],
            unlock_date="2020-01-01",
            encrypted_payload=encrypted,
            rfc3161_token_hex=None,
            timestamp_verified=False,
        )
        entry = get_index_entry(capsule_id)
        assert entry is not None
        assert entry["mood"] == "grateful"
        assert "index" in entry["tags"]

    def test_create_capsule_past_date_is_unlocked(self, temp_vault):
        encrypted = {
            "nonce_hex": "a" * 24,
            "ciphertext_hex": "b" * 32,
            "auth_tag_hex": "c" * 32,
            "unlock_timestamp": "2020-01-01T00:00:00+00:00",
        }
        capsule_id = create_capsule(
            message="Past capsule",
            mood="nostalgic",
            tags=[],
            unlock_date="2020-01-01",
            encrypted_payload=encrypted,
            rfc3161_token_hex=None,
            timestamp_verified=False,
        )
        entry = get_index_entry(capsule_id)
        assert entry["is_unlocked"] is True

    def test_create_capsule_future_date_is_locked(self, temp_vault):
        encrypted = {
            "nonce_hex": "a" * 24,
            "ciphertext_hex": "b" * 32,
            "auth_tag_hex": "c" * 32,
            "unlock_timestamp": "2099-01-01T00:00:00+00:00",
        }
        capsule_id = create_capsule(
            message="Future capsule",
            mood="hopeful",
            tags=[],
            unlock_date="2099-01-01",
            encrypted_payload=encrypted,
            rfc3161_token_hex=None,
            timestamp_verified=False,
        )
        entry = get_index_entry(capsule_id)
        assert entry["is_unlocked"] is False

    def test_title_hint_in_index(self, temp_vault):
        encrypted = {
            "nonce_hex": "a" * 24,
            "ciphertext_hex": "b" * 32,
            "auth_tag_hex": "c" * 32,
            "unlock_timestamp": "2020-01-01T00:00:00+00:00",
        }
        capsule_id = create_capsule(
            message="Hello future me, how are you doing?",
            mood="happy",
            tags=[],
            unlock_date="2020-01-01",
            encrypted_payload=encrypted,
            rfc3161_token_hex=None,
            timestamp_verified=False,
        )
        entry = get_index_entry(capsule_id)
        assert entry["title_hint"] == "Hello future me..."
