"""
timestamp.py — RFC 3161 trusted timestamping for time capsules.

On every `capsule write`, a SHA-256 hash of the encrypted blob is submitted
to a public TSA (DigiCert). The returned DER-encoded token is stored inside
the .capsule file. On `capsule open`, the token is verified, making backdating
detectable.

If the TSA is unreachable (offline / CI), the write still succeeds but a warning
is stored — the capsule is marked timestamp_verified=False in the index.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

import requests

try:
    import rfc3161ng
    RFC3161_AVAILABLE = True
except ImportError:
    RFC3161_AVAILABLE = False

from capsule import TamperedCapsuleError

logger = logging.getLogger(__name__)

# Free public TSA endpoints (tried in order)
TSA_URLS = [
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://tsa.starfieldtech.com",
]

TIMEOUT_SECONDS = 10


# ---------------------------------------------------------------------------
# Hashing helper
# ---------------------------------------------------------------------------


def hash_blob(data: bytes) -> bytes:
    """Return SHA-256 digest of the given bytes."""
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Request a timestamp token
# ---------------------------------------------------------------------------


def request_timestamp(data: bytes) -> Optional[bytes]:
    """
    Submit a SHA-256 hash of `data` to a public RFC 3161 TSA.

    Args:
        data: The raw bytes to timestamp (typically the serialized capsule blob).

    Returns:
        DER-encoded RFC 3161 TimeStampToken bytes, or None if unavailable.
    """
    if not RFC3161_AVAILABLE:
        logger.warning("rfc3161ng not installed — skipping trusted timestamp.")
        return None

    digest = hash_blob(data)

    for tsa_url in TSA_URLS:
        try:
            # Build a RFC 3161 timestamp request
            request = rfc3161ng.make_timestamp_request(
                data=digest,
                hashname="sha256",
                nonce=True,
                cert=True,
            )
            der = rfc3161ng.encode_timestamp_request(request)

            response = requests.post(
                tsa_url,
                data=der,
                headers={"Content-Type": "application/timestamp-query"},
                timeout=TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            tst = rfc3161ng.decode_timestamp_response(response.content)
            token = rfc3161ng.get_timestamp_token(tst)
            return rfc3161ng.encode_timestamp_token(token)

        except Exception as exc:
            logger.debug("TSA %s failed: %s", tsa_url, exc)
            continue

    logger.warning("All TSA endpoints unreachable — capsule saved without trusted timestamp.")
    return None


# ---------------------------------------------------------------------------
# Verify a timestamp token
# ---------------------------------------------------------------------------


def verify_timestamp(token_bytes: bytes, data: bytes) -> bool:
    """
    Verify an RFC 3161 token against the given data blob.

    Args:
        token_bytes: DER-encoded RFC 3161 TimeStampToken.
        data:        The original bytes that were timestamped.

    Returns:
        True if valid.

    Raises:
        TamperedCapsuleError: If verification fails.
    """
    if not RFC3161_AVAILABLE:
        logger.warning("rfc3161ng not installed — cannot verify timestamp.")
        return False

    if not token_bytes:
        return False

    digest = hash_blob(data)

    try:
        token = rfc3161ng.decode_timestamp_token(token_bytes)
        rfc3161ng.check_timestamp(
            token,
            hashname="sha256",
            data=digest,
        )
        return True
    except Exception as exc:
        raise TamperedCapsuleError(
            f"RFC 3161 timestamp verification failed — the capsule may have been backdated or tampered with. Detail: {exc}"
        ) from exc
