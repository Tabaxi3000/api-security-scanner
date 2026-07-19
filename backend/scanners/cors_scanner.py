"""
CORS (Cross-Origin Resource Sharing) misconfiguration scanner

Tests whether the target reflects arbitrary Origin headers, allows a
wildcard origin, trusts the ``null`` origin, or combines a permissive
origin with ``Access-Control-Allow-Credentials: true`` - the combination
that lets a malicious site read authenticated responses.
"""

from typing import Any

from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from schemas.test_result_schemas import TestResultCreate

from .payloads import CORSPayloads
from .base_scanner import BaseScanner


class CORSScanner(BaseScanner):
    """
    Detects overly permissive CORS policies.
    """

    def scan(self) -> TestResultCreate:
        """
        Execute CORS misconfiguration tests.

        Returns:
            TestResultCreate: Scan result with findings
        """
        findings: list[dict[str, Any]] = []

        for origin in CORSPayloads.get_test_origins():
            result = self._test_origin(origin)
            if result is not None:
                findings.append(result)

        if findings:
            worst = max(findings, key=lambda f: f["_severity_rank"])
            severity = worst["severity"]
            for f in findings:
                f.pop("_severity_rank", None)

            return TestResultCreate(
                test_name=TestType.CORS,
                status=ScanStatus.VULNERABLE,
                severity=severity,
                details=(
                    f"CORS misconfiguration detected "
                    f"({len(findings)} permissive origin(s))"
                ),
                evidence_json={"findings": findings},
                recommendations_json=[
                    "Validate the Origin header against an explicit allowlist",
                    "Never reflect arbitrary Origin values",
                    "Do not combine Access-Control-Allow-Credentials: true "
                    "with a wildcard or reflected origin",
                    "Reject the 'null' origin",
                ],
            )

        return TestResultCreate(
            test_name=TestType.CORS,
            status=ScanStatus.SAFE,
            severity=Severity.INFO,
            details="No CORS misconfiguration detected",
            evidence_json={"origins_tested": CORSPayloads.get_test_origins()},
            recommendations_json=[
                "Continue enforcing a strict origin allowlist",
            ],
        )

    def _test_origin(self, origin: str) -> dict[str, Any] | None:
        """
        Send a request with a spoofed Origin and inspect the ACAO/ACAC
        response headers.

        Returns:
            dict describing the finding, or None if the origin is not trusted.
        """
        try:
            response = self.make_request(
                "GET", "/", headers={"Origin": origin}
            )
        except Exception:
            return None

        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_creds = response.headers.get(
            "Access-Control-Allow-Credentials", ""
        )
        credentials_allowed = allow_creds.strip().lower() == "true"

        if allow_origin is None:
            return None

        reflected = allow_origin == origin
        wildcard = allow_origin == "*"

        if not (reflected or wildcard):
            return None

        # Reflected origin + credentials is the dangerous combination.
        if reflected and credentials_allowed:
            severity, rank = Severity.HIGH, 3
            issue = "Reflected origin with credentials allowed"
        elif reflected:
            severity, rank = Severity.MEDIUM, 2
            issue = "Origin header reflected in Access-Control-Allow-Origin"
        elif wildcard and credentials_allowed:
            # Browsers reject *,+creds, but it signals a broken config.
            severity, rank = Severity.MEDIUM, 2
            issue = "Wildcard origin combined with credentials"
        else:
            severity, rank = Severity.LOW, 1
            issue = "Wildcard Access-Control-Allow-Origin"

        return {
            "origin": origin,
            "allow_origin": allow_origin,
            "credentials_allowed": credentials_allowed,
            "issue": issue,
            "severity": severity,
            "_severity_rank": rank,
        }
