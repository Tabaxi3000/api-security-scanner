"""
XML External Entity (XXE) detection scanner

Submits XML payloads with external entity references to endpoints that
accept XML and checks whether the parser resolves them. Detects file
disclosure (reading /etc/passwd), reports an SSRF test vector, and probes
for entity-expansion (billion laughs) denial of service.
"""

from typing import Any

from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from schemas.test_result_schemas import TestResultCreate

from .payloads import XXEPayloads
from .base_scanner import BaseScanner


class XXEScanner(BaseScanner):
    """
    Tests XML-accepting endpoints for XXE vulnerabilities.
    """

    XML_HEADERS = {"Content-Type": "application/xml"}

    def scan(self) -> TestResultCreate:
        """
        Execute XXE tests in impact order (file disclosure first).

        Returns:
            TestResultCreate: Scan result with findings
        """
        file_disclosure = self._test_file_disclosure()
        if file_disclosure["vulnerable"]:
            return self._vulnerable_result(
                details="XXE file disclosure detected (read /etc/passwd)",
                evidence=file_disclosure,
                severity=Severity.CRITICAL,
                recommendations=[
                    "Disable external entity resolution in the XML parser",
                    "Set resolve_entities=False (lxml) or "
                    "FEATURE_SECURE_PROCESSING (Java)",
                    "Prefer JSON over XML where possible",
                    "Validate and whitelist accepted content types",
                ],
            )

        dos = self._test_billion_laughs()
        if dos["vulnerable"]:
            return self._vulnerable_result(
                details="XXE entity-expansion (billion laughs) DoS possible",
                evidence=dos,
                severity=Severity.HIGH,
                recommendations=[
                    "Disable DTD processing entirely",
                    "Limit entity expansion depth and total nodes",
                ],
            )

        return TestResultCreate(
            test_name=TestType.XXE,
            status=ScanStatus.SAFE,
            severity=Severity.INFO,
            details="No XXE vulnerability detected",
            evidence_json={
                "file_disclosure_test": file_disclosure,
                "dos_test": dos,
                "note": "SSRF-via-XXE requires out-of-band verification",
            },
            recommendations_json=[
                "Keep external entity resolution disabled",
            ],
        )

    def _test_file_disclosure(self) -> dict[str, Any]:
        """
        Submit a file:// XXE payload and look for leaked passwd content.
        """
        try:
            response = self.make_request(
                "POST",
                "/",
                data=XXEPayloads.FILE_DISCLOSURE,
                headers=self.XML_HEADERS,
            )
        except Exception as exc:
            return {"vulnerable": False, "error": str(exc)}

        body = response.text
        for marker in XXEPayloads.FILE_DISCLOSURE_MARKERS:
            if marker in body:
                return {
                    "vulnerable": True,
                    "marker": marker,
                    "status_code": response.status_code,
                    "leaked_excerpt": body[:200],
                }

        return {
            "vulnerable": False,
            "status_code": response.status_code,
            "description": "No file contents reflected",
        }

    def _test_billion_laughs(self) -> dict[str, Any]:
        """
        Submit an entity-expansion payload; a parser that expands it
        (reflecting many 'lol' tokens or erroring on limits) is affected.
        """
        try:
            response = self.make_request(
                "POST",
                "/",
                data=XXEPayloads.BILLION_LAUGHS,
                headers=self.XML_HEADERS,
            )
        except Exception as exc:
            return {"vulnerable": False, "error": str(exc)}

        # A hardened parser rejects the DTD outright; a vulnerable one
        # expands the entities, so the token count balloons.
        lol_count = response.text.count("lol")
        if lol_count >= 100:
            return {
                "vulnerable": True,
                "expanded_tokens": lol_count,
                "status_code": response.status_code,
            }

        return {
            "vulnerable": False,
            "expanded_tokens": lol_count,
            "status_code": response.status_code,
        }

    def _vulnerable_result(
        self,
        details: str,
        evidence: dict[str, Any],
        severity: Severity,
        recommendations: list[str],
    ) -> TestResultCreate:
        """
        Build a vulnerable TestResultCreate for XXE findings.
        """
        return TestResultCreate(
            test_name=TestType.XXE,
            status=ScanStatus.VULNERABLE,
            severity=severity,
            details=details,
            evidence_json=evidence,
            recommendations_json=recommendations,
        )
