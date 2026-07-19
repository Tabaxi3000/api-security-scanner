"""
Plugin interface for third-party scanners

Lets users add custom scanners without modifying core code. A plugin
subclasses ScannerPlugin, declares an identity (name/version/test_type),
and implements scan(). Plugins are discovered and loaded at runtime by
plugin_loader.PluginLoader.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ScannerPlugin(ABC):
    """
    Base class every scanner plugin must inherit from.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique, human-readable scanner name (e.g. 'custom_graphql')."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version, semver recommended (e.g. '1.0.0')."""

    @property
    @abstractmethod
    def test_type(self) -> str:
        """Unique test-type identifier used for registration/dedup."""

    @abstractmethod
    def scan(self, target_url: str, **kwargs: Any) -> dict[str, Any]:
        """
        Execute the scan and return a result dict.

        Returns:
            dict with at least the keys: ``vulnerable`` (bool),
            ``details`` (str), ``evidence`` (dict), ``recommendations`` (list).
        """

    def validate(self) -> bool:
        """
        Validate plugin configuration before registration.

        Override to add custom checks. The default requires a non-empty
        name, version, and test_type.
        """
        return bool(self.name and self.version and self.test_type)
