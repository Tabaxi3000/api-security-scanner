"""
Tests for webhook payload signing and verification.
"""

import pytest

from core.webhook import WebhookSigner


class TestWebhookSigner:
    def test_sign_is_deterministic_and_prefixed(self):
        signer = WebhookSigner("shared-secret")
        sig = signer.sign('{"scan":1}')
        assert sig.startswith("sha256=")
        assert sig == signer.sign('{"scan":1}')

    def test_verify_roundtrip(self):
        signer = WebhookSigner("shared-secret")
        payload = '{"scan":1,"vulns":3}'
        assert signer.verify(payload, signer.sign(payload)) is True

    def test_verify_accepts_bare_hex(self):
        signer = WebhookSigner("shared-secret")
        payload = "hello"
        full = signer.sign(payload)
        bare = full.removeprefix("sha256=")
        assert signer.verify(payload, bare) is True

    def test_tampered_payload_rejected(self):
        signer = WebhookSigner("shared-secret")
        sig = signer.sign('{"amount":1}')
        assert signer.verify('{"amount":1000}', sig) is False

    def test_wrong_secret_rejected(self):
        payload = "data"
        good = WebhookSigner("secret-a").sign(payload)
        assert WebhookSigner("secret-b").verify(payload, good) is False

    def test_empty_signature_rejected(self):
        assert WebhookSigner("secret").verify("data", "") is False

    def test_empty_secret_raises(self):
        with pytest.raises(ValueError):
            WebhookSigner("")
