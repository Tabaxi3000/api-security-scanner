"""
Stored (persistent) XSS detection scanner

Unlike reflected XSS, stored XSS persists on the server and executes for
every user who views the affected resource. This scanner submits a
uniquely-marked payload via POST to common content endpoints, then
retrieves content via GET to see whether the payload was stored
unescaped. It accounts for HTML-encoding and a restrictive CSP, which
neutralize the payload even when it persists.
"""

import uuid
from typing import Any

from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from schemas.test_result_schemas import TestResultCreate

from .base_scanner import BaseScanner


class StoredXSSScanner(BaseScanner):
    """
    Two-step (submit then retrieve) stored XSS detector.
    """

    SUBMIT_ENDPOINTS = ["/comments", "/api/posts", "/api/profile", "/"]
    RETRIEVE_ENDPOINTS = ["/", "/comments", "/api/posts"]

    def scan(self) -> TestResultCreate:
        """
        Submit a marked payload, then check whether it persists unescaped.

        Returns:
            TestResultCreate: Scan result with findings
        """
        marker = f"XSS{uuid.uuid4().hex[:8]}"
        payload = f"<script>alert('{marker}')</script>"

        submit = self._submit_payload(payload)
        if not submit["submitted"]:
            return TestResultCreate(
                test_name=TestType.STORED_XSS,
                status=ScanStatus.SAFE,
                severity=Severity.INFO,
                details="Could not submit a stored-XSS test payload",
                evidence_json=submit,
                recommendations_json=[
                    "Manually verify user-content endpoints for stored XSS",
                ],
            )

        retrieve = self._retrieve_and_check(marker)

        if retrieve["vulnerable"]:
            return TestResultCreate(
                test_name=TestType.STORED_XSS,
                status=ScanStatus.VULNERABLE,
                severity=Severity.HIGH,
                details="Stored XSS detected: payload persisted unescaped",
                evidence_json={"submit": submit, "retrieve": retrieve,
                               "payload": payload},
                recommendations_json=[
                    "Output-encode user content for its rendering context",
                    "Apply a strict Content-Security-Policy",
                    "Validate and sanitize input on write",
                    "Use frameworks that auto-escape by default",
                ],
            )

        return TestResultCreate(
            test_name=TestType.STORED_XSS,
            status=ScanStatus.SAFE,
            severity=Severity.INFO,
            details="No stored XSS detected",
            evidence_json={"submit": submit, "retrieve": retrieve},
            recommendations_json=[
                "Continue output-encoding stored content",
            ],
        )

    def _submit_payload(self, payload: str) -> dict[str, Any]:
        """
        Try to store the payload via several common content endpoints.
        """
        for endpoint in self.SUBMIT_ENDPOINTS:
            try:
                response = self.make_request(
                    "POST",
                    endpoint,
                    json={"content": payload, "text": payload, "bio": payload},
                )
            except Exception:
                continue

            if response.status_code in (200, 201):
                return {"submitted": True, "endpoint": endpoint,
                        "status_code": response.status_code}

        return {"submitted": False}

    def _retrieve_and_check(self, marker: str) -> dict[str, Any]:
        """
        Retrieve content and determine whether the payload executes.
        """
        for endpoint in self.RETRIEVE_ENDPOINTS:
            try:
                response = self.make_request("GET", endpoint)
            except Exception:
                continue

            body = response.text
            if marker not in body:
                continue

            # Present but HTML-encoded -> not executable.
            if f"&lt;script&gt;alert('{marker}')" in body or (
                "&lt;script&gt;" in body and f"<script>alert('{marker}')" not in body
            ):
                return {"vulnerable": False, "encoded": True, "endpoint": endpoint}

            # A restrictive CSP blocks inline script execution.
            csp = response.headers.get("Content-Security-Policy", "")
            if "script-src 'none'" in csp or "script-src 'self'" in csp:
                return {"vulnerable": False, "csp_protected": True,
                        "csp": csp, "endpoint": endpoint}

            if f"<script>alert('{marker}')</script>" in body:
                return {"vulnerable": True, "marker": marker,
                        "endpoint": endpoint}

        return {"vulnerable": False}
