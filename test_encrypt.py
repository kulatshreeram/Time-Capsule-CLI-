"""
test_encrypt.py — Tests for AES-256-GCM encrypt/decrypt logic.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from capsule import CapsuleLockedError, CorruptedCapsuleError
from capsule.encrypt import decrypt, encrypt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _past_dt() -> datetime:
    """A datetime clearly in the past."""
    return datetime(2020, 1, 1, tzinfo=timezone.utc)


def _future_dt() -> datetime:
    """A datetime far in the future (2099)."""
    return datetime(2099, 6, 1, tzinfo=timezone.utc)


def _near_future_dt() -> datetime:
    """A datetime 1 second in the future."""
    return datetime.now(timezone.utc) + timedelta(seconds=1)


# ---------------------------------------------------------------------------
# Encrypt / decrypt round-trip
# ---------------------------------------------------------------------------

class TestEncryptDecryptRoundTrip:
    """Encrypt then decrypt with a past unlock date — should succeed."""

    def test_roundtrip_returns_original_message(self, tmp_path):
        """Encrypted then decrypted message must match original."""
        message = "Hello, future me!"
        mood = "hopeful"
        tags = ["career", "personal"]
        unlock_dt = _past_dt()

        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt(message, mood, tags, unlock_dt)
            result = decrypt(encrypted)

        assert result["message"] == message

    def test_roundtrip_preserves_mood(self, tmp_path):
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("test", "excited", [], _past_dt())
            result = decrypt(encrypted)
        assert result["mood"] == "excited"

    def test_roundtrip_preserves_tags(self, tmp_path):
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("test", "hopeful", ["tag1", "tag2"], _past_dt())
            result = decrypt(encrypted)
        assert result["tags"] == ["tag1", "tag2"]

    def test_roundtrip_unicode_message(self, tmp_path):
        """Encryption must handle unicode characters correctly."""
        message = "こんにちは未来の私へ 🌸 मेरे भविष्य को"
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt(message, "peaceful", [], _past_dt())
            result = decrypt(encrypted)
        assert result["message"] == message

    def test_roundtrip_long_message(self, tmp_path):
        """Encryption must handle very long messages."""
        message = "A" * 100_000
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt(message, "determined", [], _past_dt())
            result = decrypt(encrypted)
        assert result["message"] == message

    def test_each_encrypt_produces_unique_nonce(self, tmp_path):
        """Two encryptions of the same message must produce different nonces."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            e1 = encrypt("same message", "happy", [], _past_dt())
            e2 = encrypt("same message", "happy", [], _past_dt())
        assert e1["nonce_hex"] != e2["nonce_hex"]

    def test_each_encrypt_produces_unique_ciphertext(self, tmp_path):
        """Due to unique nonces, ciphertexts must differ even for identical inputs."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            e1 = encrypt("same", "hopeful", [], _past_dt())
            e2 = encrypt("same", "hopeful", [], _past_dt())
        assert e1["ciphertext_hex"] != e2["ciphertext_hex"]


# ---------------------------------------------------------------------------
# Time-lock enforcement
# ---------------------------------------------------------------------------

class TestTimeLock:
    """CapsuleLockedError must be raised when unlock date is in the future."""

    def test_locked_capsule_raises_error(self, tmp_path):
        """Decrypt must raise CapsuleLockedError for a 2099 unlock date."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("future message", "hopeful", [], _future_dt())
            with pytest.raises(CapsuleLockedError):
                decrypt(encrypted)

    def test_locked_error_contains_time_remaining(self, tmp_path):
        """CapsuleLockedError must include time_remaining breakdown."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("message", "hopeful", [], _future_dt())
            with pytest.raises(CapsuleLockedError) as exc_info:
                decrypt(encrypted)
        assert exc_info.value.time_remaining is not None
        assert "years" in exc_info.value.time_remaining

    def test_locked_error_years_in_future(self, tmp_path):
        """For 2099, the remaining years must be > 0."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("message", "hopeful", [], _future_dt())
            with pytest.raises(CapsuleLockedError) as exc_info:
                decrypt(encrypted)
        assert exc_info.value.time_remaining["years"] > 0

    def test_past_unlock_does_not_raise(self, tmp_path):
        """A capsule with past unlock date must decrypt without raising."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("past message", "nostalgic", [], _past_dt())
            result = decrypt(encrypted)
        assert result is not None


# ---------------------------------------------------------------------------
# Corruption / tampering
# ---------------------------------------------------------------------------

class TestCorruption:
    """CorruptedCapsuleError must be raised when ciphertext is tampered with."""

    def test_tampered_ciphertext_raises_error(self, tmp_path):
        """Flipping a byte in the ciphertext must trigger CorruptedCapsuleError."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("secret", "hopeful", [], _past_dt())

        # Tamper with ciphertext
        ct_bytes = bytearray(bytes.fromhex(encrypted["ciphertext_hex"]))
        ct_bytes[0] ^= 0xFF  # Flip all bits in first byte
        encrypted["ciphertext_hex"] = ct_bytes.hex()

        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            with pytest.raises(CorruptedCapsuleError):
                decrypt(encrypted)

    def test_tampered_auth_tag_raises_error(self, tmp_path):
        """A wrong auth_tag must trigger CorruptedCapsuleError."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            encrypted = encrypt("secret", "hopeful", [], _past_dt())

        # Corrupt the auth tag
        tag_bytes = bytearray(bytes.fromhex(encrypted["auth_tag_hex"]))
        tag_bytes[0] ^= 0xFF
        encrypted["auth_tag_hex"] = tag_bytes.hex()

        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            with pytest.raises(CorruptedCapsuleError):
                decrypt(encrypted)

    def test_wrong_key_raises_error(self, tmp_path):
        """Decrypting with a different key must raise CorruptedCapsuleError."""
        key_file = tmp_path / "master.key"

        with patch("capsule.encrypt.MASTER_KEY_PATH", key_file):
            encrypted = encrypt("secret", "hopeful", [], _past_dt())

        # Replace master key with a new one
        key_file.unlink()

        with patch("capsule.encrypt.MASTER_KEY_PATH", key_file):
            with pytest.raises(CorruptedCapsuleError):
                decrypt(encrypted)


# ---------------------------------------------------------------------------
# Encrypt output structure
# ---------------------------------------------------------------------------

class TestEncryptStructure:
    """The encrypted payload must contain all required fields."""

    def test_encrypted_has_nonce_hex(self, tmp_path):
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            result = encrypt("msg", "hopeful", [], _past_dt())
        assert "nonce_hex" in result

    def test_encrypted_has_ciphertext_hex(self, tmp_path):
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            result = encrypt("msg", "hopeful", [], _past_dt())
        assert "ciphertext_hex" in result

    def test_encrypted_has_auth_tag_hex(self, tmp_path):
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            result = encrypt("msg", "hopeful", [], _past_dt())
        assert "auth_tag_hex" in result

    def test_encrypted_has_unlock_timestamp(self, tmp_path):
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            result = encrypt("msg", "hopeful", [], _past_dt())
        assert "unlock_timestamp" in result

    def test_nonce_is_24_hex_chars(self, tmp_path):
        """12-byte nonce = 24 hex chars."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            result = encrypt("msg", "hopeful", [], _past_dt())
        assert len(result["nonce_hex"]) == 24

    def test_auth_tag_is_32_hex_chars(self, tmp_path):
        """16-byte GCM tag = 32 hex chars."""
        with patch("capsule.encrypt.MASTER_KEY_PATH", tmp_path / "master.key"):
            result = encrypt("msg", "hopeful", [], _past_dt())
        assert len(result["auth_tag_hex"]) == 32
