"""
Tests for the XXE scanner (make_request stubbed).
"""

from conftest import FakeResponse

from core.enums import ScanStatus, Severity
from scanners.xxe_scanner import XXEScanner


def _scanner(stub):
    scanner = XXEScanner(target_url="http://target.test")
    scanner.make_request = stub
    return scanner


def test_file_disclosure_is_critical():
    def stub(method, endpoint, **kwargs):
        data = kwargs.get("data", "")
        if "/etc/passwd" in data:
            return FakeResponse(text="<data>root:x:0:0:root:/root:/bin/bash</data>")
        return FakeResponse(text="ok")

    result = _scanner(stub).scan()
    assert result.test_name.value == "xxe"
    assert result.status == ScanStatus.VULNERABLE
    assert result.severity == Severity.CRITICAL
    assert result.evidence_json["marker"].startswith("root")


def test_billion_laughs_is_high():
    def stub(method, endpoint, **kwargs):
        data = kwargs.get("data", "")
        if "/etc/passwd" in data:
            return FakeResponse(text="no file here")
        if "lolz" in data:
            # a vulnerable parser expands the entities
            return FakeResponse(text="lol" * 500)
        return FakeResponse(text="")

    result = _scanner(stub).scan()
    assert result.status == ScanStatus.VULNERABLE
    assert result.severity == Severity.HIGH


def test_hardened_parser_is_safe():
    def stub(method, endpoint, **kwargs):
        # parser rejects DTDs, leaks nothing, expands nothing
        return FakeResponse(status_code=400, text="XML parse error: DTD forbidden")

    result = _scanner(stub).scan()
    assert result.status == ScanStatus.SAFE
    assert result.severity == Severity.INFO
