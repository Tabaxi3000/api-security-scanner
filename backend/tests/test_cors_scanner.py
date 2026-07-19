"""
Tests for the CORS misconfiguration scanner (make_request stubbed).
"""

from conftest import FakeResponse

from core.enums import ScanStatus, Severity
from scanners.cors_scanner import CORSScanner


def _scanner(stub):
    scanner = CORSScanner(target_url="http://target.test")
    scanner.make_request = stub
    return scanner


def test_reflected_origin_with_credentials_is_high():
    def stub(method, endpoint, **kwargs):
        origin = kwargs["headers"]["Origin"]
        return FakeResponse(
            headers={
                "Access-Control-Allow-Origin": origin,  # reflects any origin
                "Access-Control-Allow-Credentials": "true",
            }
        )

    result = _scanner(stub).scan()
    assert result.test_name.value == "cors"
    assert result.status == ScanStatus.VULNERABLE
    assert result.severity == Severity.HIGH
    assert result.evidence_json["findings"]


def test_wildcard_origin_is_low():
    def stub(method, endpoint, **kwargs):
        return FakeResponse(headers={"Access-Control-Allow-Origin": "*"})

    result = _scanner(stub).scan()
    assert result.status == ScanStatus.VULNERABLE
    assert result.severity == Severity.LOW


def test_strict_allowlist_is_safe():
    def stub(method, endpoint, **kwargs):
        # server always answers with its own fixed origin, never reflecting
        return FakeResponse(
            headers={"Access-Control-Allow-Origin": "https://trusted.example"}
        )

    result = _scanner(stub).scan()
    assert result.status == ScanStatus.SAFE
    assert result.severity == Severity.INFO


def test_no_cors_headers_is_safe():
    def stub(method, endpoint, **kwargs):
        return FakeResponse(headers={})

    assert _scanner(stub).scan().status == ScanStatus.SAFE
