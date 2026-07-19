"""
Test configuration.

Sets the environment variables that config.Settings requires before any
backend module is imported, and puts the backend package root on sys.path
so tests can import modules the same way the app does (``from core...``).
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-in-prod")

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


class FakeResponse:
    """
    Minimal stand-in for requests.Response for scanner unit tests.
    """

    def __init__(
        self,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        text: str = "",
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.request_time = 0.0
