"""
storage.py — Save/load .capsule files and manage the JSON index.

Layout:
  ~/.timecapsule/
    master.key          ← AES-256 master key (never committed to git)
    index.json          ← Metadata index (no encrypted content)
    capsules/
      <uuid>.capsule    ← JSON file containing encrypted payload
    config.json         ← Optional config (git remote, etc.)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from capsule import CapsuleNotFoundError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

TIMECAPSULE_DIR = Path.home() / ".timecapsule"
CAPSULES_DIR = TIMECAPSULE_DIR / "capsules"
INDEX_PATH = TIMECAPSULE_DIR / "index.json"
CONFIG_PATH = TIMECAPSULE_DIR / "config.json"


def _ensure_dirs() -> None:
    TIMECAPSULE_DIR.mkdir(parents=True, exist_ok=True)
    CAPSULES_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Title hint
# ---------------------------------------------------------------------------


def make_title_hint(message: str, n_words: int = 3) -> str:
    """Return the first `n_words` words of `message` followed by '...'.
    
    Trailing punctuation is stripped from each word so the hint reads cleanly.
    """
    words = message.split()
    clean_words = [w.rstrip(".,!?;:") for w in words[:n_words]]
    snippet = " ".join(clean_words)
    return f"{snippet}..." if len(words) > n_words else snippet


# ---------------------------------------------------------------------------
# Capsule file I/O
# ---------------------------------------------------------------------------


def save_capsule(capsule_id: str, payload: dict) -> Path:
    """
    Serialize `payload` to ~/.timecapsule/capsules/<capsule_id>.capsule.

    Args:
        capsule_id: UUID string.
        payload:    Encrypted capsule data dict (from encrypt.py + timestamp token).

    Returns:
        Path to the saved .capsule file.
    """
    _ensure_dirs()
    path = CAPSULES_DIR / f"{capsule_id}.capsule"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_capsule(capsule_id: str) -> dict:
    """
    Load a .capsule file by ID.

    Raises:
        CapsuleNotFoundError: If the file does not exist.
    """
    _ensure_dirs()
    path = CAPSULES_DIR / f"{capsule_id}.capsule"
    if not path.exists():
        raise CapsuleNotFoundError(f"Capsule '{capsule_id}' not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Index I/O
# ---------------------------------------------------------------------------


def load_index() -> list[dict]:
    """Load the index.json, returning an empty list if it doesn't exist."""
    _ensure_dirs()
    if not INDEX_PATH.exists():
        return []
    try:
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def save_index(entries: list[dict]) -> None:
    """Write the full index list to index.json."""
    _ensure_dirs()
    INDEX_PATH.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")


def add_index_entry(entry: dict) -> None:
    """Append a new entry to the index, replacing any existing entry with the same id."""
    entries = load_index()
    entries = [e for e in entries if e.get("id") != entry.get("id")]
    entries.append(entry)
    save_index(entries)


def update_index_entry(capsule_id: str, updates: dict) -> None:
    """Patch fields on an existing index entry."""
    entries = load_index()
    for entry in entries:
        if entry.get("id") == capsule_id:
            entry.update(updates)
            break
    save_index(entries)


def get_index_entry(capsule_id: str) -> dict | None:
    """Find and return an index entry by id, or None if not found."""
    for entry in load_index():
        if entry.get("id") == capsule_id:
            return entry
    return None


# ---------------------------------------------------------------------------
# High-level write
# ---------------------------------------------------------------------------


def create_capsule(
    message: str,
    mood: str,
    tags: list[str],
    unlock_date: str,
    encrypted_payload: dict,
    rfc3161_token_hex: str | None,
    timestamp_verified: bool,
) -> str:
    """
    Save an encrypted capsule and update the index.

    Args:
        message:              Original plaintext message (used only for title_hint).
        mood:                 Mood string.
        tags:                 List of tag strings.
        unlock_date:          ISO date string "YYYY-MM-DD".
        encrypted_payload:    Dict from encrypt.encrypt().
        rfc3161_token_hex:    Hex-encoded RFC 3161 token, or None.
        timestamp_verified:   Whether TSA returned a valid token.

    Returns:
        The new capsule UUID string.
    """
    capsule_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    # Build .capsule file payload
    file_payload = {
        **encrypted_payload,
        "rfc3161_token_hex": rfc3161_token_hex,
        "timestamp_verified": timestamp_verified,
        "created_at": now_iso,
    }
    save_capsule(capsule_id, file_payload)

    # Build index entry (no encrypted content!)
    title_hint = make_title_hint(message)
    unlock_dt = datetime.fromisoformat(f"{unlock_date}T00:00:00+00:00")
    is_unlocked = datetime.now(timezone.utc) >= unlock_dt

    index_entry = {
        "id": capsule_id,
        "title_hint": title_hint,
        "unlock_date": unlock_date,
        "mood": mood,
        "tags": tags,
        "created_at": now_iso,
        "is_unlocked": is_unlocked,
        "timestamp_verified": timestamp_verified,
    }
    add_index_entry(index_entry)

    return capsule_id


def refresh_unlock_statuses() -> None:
    """Update is_unlocked flags in the index based on current time."""
    entries = load_index()
    now = datetime.now(timezone.utc)
    changed = False
    for entry in entries:
        try:
            unlock_dt = datetime.fromisoformat(f"{entry['unlock_date']}T00:00:00+00:00")
            new_status = now >= unlock_dt
            if entry.get("is_unlocked") != new_status:
                entry["is_unlocked"] = new_status
                changed = True
        except (KeyError, ValueError):
            pass
    if changed:
        save_index(entries)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_config(config: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
