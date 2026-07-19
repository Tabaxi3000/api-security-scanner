"""
HMAC-SHA256 signing and verification for outgoing webhook payloads.

When scan results are delivered to a webhook, the payload is signed so the
receiver can confirm it came from this scanner and was not tampered with in
transit. Verification uses a constant-time comparison to avoid timing
side-channels.
"""

from __future__ import annotations

import hashlib
import hmac

SIGNATURE_PREFIX = "sha256="


class WebhookSigner:
    """
    Signs and verifies webhook payloads with a shared secret.
    """

    def __init__(self, secret: str):
        """
        Args:
            secret: Shared secret known to both sender and receiver.
        """
        if not secret:
            raise ValueError("webhook secret must not be empty")
        self._secret = secret.encode("utf-8")

    def sign(self, payload: str) -> str:
        """
        Return the ``sha256=<hex>`` signature for a payload.
        """
        digest = hmac.new(
            self._secret,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{SIGNATURE_PREFIX}{digest}"

    def verify(self, payload: str, signature: str) -> bool:
        """
        Verify a signature against a payload in constant time.

        Accepts signatures with or without the ``sha256=`` prefix.
        """
        if not signature:
            return False
        expected = self.sign(payload)
        # Normalize: allow callers to pass the bare hex digest too.
        candidate = (
            signature
            if signature.startswith(SIGNATURE_PREFIX)
            else f"{SIGNATURE_PREFIX}{signature}"
        )
        return hmac.compare_digest(expected, candidate)
