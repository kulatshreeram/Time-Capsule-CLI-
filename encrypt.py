"""
encrypt.py — AES-256-GCM encryption/decryption for time capsules.

Key lifecycle:
  - On first run, a 32-byte random master key is generated and stored at
    ~/.timecapsule/master.key with restrictive file permissions (600 on Unix,
    icacls restricted on Windows).
  - Each capsule gets its own unique 12-byte nonce.
  - The plaintext is a JSON blob: {message, mood, tags, unlock_timestamp}.
  - The encrypted blob stores: nonce, ciphertext, auth_tag, unlock_timestamp,
    and optionally an rfc3161_token.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from capsule import CapsuleLockedError, CorruptedCapsuleError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

TIMECAPSULE_DIR = Path.home() / ".timecapsule"
MASTER_KEY_PATH = TIMECAPSULE_DIR / "master.key"


# ---------------------------------------------------------------------------
# Master key management
# ---------------------------------------------------------------------------


def _ensure_dir() -> None:
    """Create ~/.timecapsule directory if it doesn't exist."""
    TIMECAPSULE_DIR.mkdir(parents=True, exist_ok=True)
    capsules_dir = TIMECAPSULE_DIR / "capsules"
    capsules_dir.mkdir(exist_ok=True)


def _set_key_permissions(path: Path) -> None:
    """Set restrictive permissions on the master key file."""
    if platform.system() == "Windows":
        try:
            username = os.environ.get("USERNAME", "")
            if username:
                # Remove all inherited permissions, grant current user full control only
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r", "/grant:r", f"{username}:F"],
                    check=True,
                    capture_output=True,
                )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # icacls not available or failed — warn but continue
            pass
    else:
        os.chmod(path, 0o600)


def get_master_key() -> bytes:
    """
    Load the master key from disk, generating it on first run.

    Returns:
        32-byte AES-256 key as bytes.
    """
    _ensure_dir()
    if not MASTER_KEY_PATH.exists():
        key = AESGCM.generate_key(bit_length=256)
        MASTER_KEY_PATH.write_bytes(key)
        _set_key_permissions(MASTER_KEY_PATH)
    return MASTER_KEY_PATH.read_bytes()


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _compute_time_remaining(unlock_dt: datetime) -> dict:
    """Return a human-friendly breakdown of time remaining until unlock."""
    now = _now_utc()
    if unlock_dt.tzinfo is None:
        unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)

    delta = unlock_dt - now
    if delta.total_seconds() <= 0:
        return {"years": 0, "months": 0, "days": 0, "hours": 0, "minutes": 0}

    total_seconds = int(delta.total_seconds())
    minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    # Rough month/year breakdown
    years, remainder_days = divmod(days, 365)
    months, days = divmod(remainder_days, 30)

    return {
        "years": years,
        "months": months,
        "days": days,
        "hours": hours,
        "minutes": minutes,
        "seconds": seconds,
        "total_seconds": delta.total_seconds(),
    }


def format_countdown(unlock_date_str: str) -> str:
    """Return a human-readable countdown string for a locked capsule."""
    unlock_dt = datetime.fromisoformat(unlock_date_str)
    if unlock_dt.tzinfo is None:
        unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)

    remaining = _compute_time_remaining(unlock_dt)

    parts = []
    if remaining["years"]:
        parts.append(f"{remaining['years']} year{'s' if remaining['years'] != 1 else ''}")
    if remaining["months"]:
        parts.append(f"{remaining['months']} month{'s' if remaining['months'] != 1 else ''}")
    if remaining["days"]:
        parts.append(f"{remaining['days']} day{'s' if remaining['days'] != 1 else ''}")
    if not parts:
        if remaining["hours"]:
            parts.append(f"{remaining['hours']} hour{'s' if remaining['hours'] != 1 else ''}")
        if remaining["minutes"]:
            parts.append(f"{remaining['minutes']} minute{'s' if remaining['minutes'] != 1 else ''}")

    return ", ".join(parts) if parts else "less than a minute"


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------


def encrypt(
    message: str,
    mood: str,
    tags: list[str],
    unlock_dt: datetime,
) -> dict:
    """
    Encrypt a message + metadata as an AES-256-GCM blob.

    Args:
        message:    The plaintext message body.
        mood:       Mood tag string (e.g. "hopeful").
        tags:       List of category tags.
        unlock_dt:  The datetime after which decryption is allowed.

    Returns:
        dict with keys: nonce_hex, ciphertext_hex, auth_tag_hex,
        unlock_timestamp (ISO string).
    """
    if unlock_dt.tzinfo is None:
        unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)

    # Build plaintext JSON blob
    plaintext = json.dumps(
        {
            "message": message,
            "mood": mood,
            "tags": tags,
            "unlock_timestamp": unlock_dt.isoformat(),
        },
        ensure_ascii=False,
    ).encode("utf-8")

    key = get_master_key()
    aesgcm = AESGCM(key)

    # Generate a unique 12-byte nonce (96-bit, recommended for GCM)
    nonce = os.urandom(12)

    # AESGCM.encrypt returns ciphertext + 16-byte GCM tag appended
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # Split ciphertext and tag
    ciphertext = ct_with_tag[:-16]
    auth_tag = ct_with_tag[-16:]

    return {
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "auth_tag_hex": auth_tag.hex(),
        "unlock_timestamp": unlock_dt.isoformat(),
    }


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------


def decrypt(capsule_data: dict) -> dict:
    """
    Decrypt a capsule payload after verifying the time-lock.

    Args:
        capsule_data: The dict stored in the .capsule file.

    Returns:
        Decrypted payload dict: {message, mood, tags, unlock_timestamp}.

    Raises:
        CapsuleLockedError: If unlock_timestamp has not been reached.
        CorruptedCapsuleError: If AES-GCM tag verification fails.
    """
    unlock_ts_str = capsule_data["unlock_timestamp"]
    unlock_dt = datetime.fromisoformat(unlock_ts_str)
    if unlock_dt.tzinfo is None:
        unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)

    now = _now_utc()

    if now < unlock_dt:
        remaining = _compute_time_remaining(unlock_dt)
        countdown = format_countdown(unlock_ts_str)
        raise CapsuleLockedError(
            f"This capsule is still sealed. Opens in {countdown}.",
            time_remaining=remaining,
        )

    key = get_master_key()
    aesgcm = AESGCM(key)

    nonce = bytes.fromhex(capsule_data["nonce_hex"])
    ciphertext = bytes.fromhex(capsule_data["ciphertext_hex"])
    auth_tag = bytes.fromhex(capsule_data["auth_tag_hex"])

    # Recombine ciphertext + tag for decryption
    ct_with_tag = ciphertext + auth_tag

    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
    except Exception as exc:
        raise CorruptedCapsuleError(
            "Decryption failed — the capsule data may be corrupted or tampered with."
        ) from exc

    return json.loads(plaintext.decode("utf-8"))
