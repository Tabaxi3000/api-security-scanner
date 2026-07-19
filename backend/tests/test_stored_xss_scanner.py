"""
Tests for the stored XSS scanner (make_request stubbed).
"""

from conftest import FakeResponse

from core.enums import ScanStatus, Severity
from scanners.stored_xss_scanner import StoredXSSScanner


class StoreStub:
    """
    Emulates a backend that stores POSTed content and serves it back.
    """

    def __init__(self, encode: bool = False, csp: str | None = None):
        self.encode = encode
        self.csp = csp
        self.stored = ""

    def __call__(self, method, endpoint, **kwargs):
        if method == "POST":
            self.stored = kwargs.get("json", {}).get("content", "")
            return FakeResponse(status_code=201)
        # GET: serve stored content, optionally encoded / with a CSP
        body = self.stored
        if self.encode:
            body = (
                body.replace("<", "&lt;").replace(">", "&gt;")
            )
        headers = {"Content-Security-Policy": self.csp} if self.csp else {}
        return FakeResponse(text=f"<html>{body}</html>", headers=headers)


def _scanner(stub):
    scanner = StoredXSSScanner(target_url="http://target.test")
    scanner.make_request = stub
    return scanner


def test_persisted_unescaped_is_vulnerable():
    result = _scanner(StoreStub()).scan()
    assert result.status == ScanStatus.VULNERABLE
    assert result.severity == Severity.HIGH


def test_html_encoded_is_safe():
    result = _scanner(StoreStub(encode=True)).scan()
    assert result.status == ScanStatus.SAFE


def test_csp_protected_is_safe():
    result = _scanner(StoreStub(csp="script-src 'none'")).scan()
    assert result.status == ScanStatus.SAFE


def test_cannot_submit_is_safe():
    def stub(method, endpoint, **kwargs):
        return FakeResponse(status_code=404)

    result = _scanner(stub).scan()
    assert result.status == ScanStatus.SAFE
