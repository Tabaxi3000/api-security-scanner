"""
Example scanner plugin. Copy this file to build your own.
"""

from typing import Any

from scanners.plugin_interface import ScannerPlugin


class ExampleScanner(ScannerPlugin):
    """
    Flags responses that expose a Server header (information disclosure).
    """

    @property
    def name(self) -> str:
        return "example_server_header"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def test_type(self) -> str:
        return "example"

    def scan(self, target_url: str, **kwargs: Any) -> dict[str, Any]:
        # A real plugin would issue HTTP requests here; kept dependency-free
        # so the example is trivially importable.
        headers = kwargs.get("headers", {})
        server = headers.get("Server")
        vulnerable = server is not None

        return {
            "vulnerable": vulnerable,
            "details": (
                f"Server header exposed: {server}"
                if vulnerable
                else "No Server header exposed"
            ),
            "evidence": {"server": server},
            "recommendations": (
                ["Suppress the Server response header"] if vulnerable else []
            ),
        }
