"""
Plugin discovery and registration

Dynamically loads ScannerPlugin subclasses from a plugins directory. A
broken or malicious plugin is isolated: it is logged and skipped rather
than crashing the scanner. Discovered plugins are held in a PluginRegistry
that resolves test_type conflicts on a first-come, first-served basis.
"""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path

from .plugin_interface import ScannerPlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Holds discovered plugin classes keyed by their test_type.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, type[ScannerPlugin]] = {}

    def register(self, plugin_cls: type[ScannerPlugin]) -> bool:
        """
        Register a plugin class. Returns False (and warns) on a test_type
        conflict; the first registration wins.
        """
        instance = plugin_cls()
        test_type = instance.test_type

        if test_type in self._plugins:
            logger.warning(
                "plugin test_type conflict for %r: keeping %s, ignoring %s",
                test_type,
                self._plugins[test_type].__name__,
                plugin_cls.__name__,
            )
            return False

        self._plugins[test_type] = plugin_cls
        return True

    def get(self, test_type: str) -> type[ScannerPlugin] | None:
        """Return the plugin class for a test_type, or None."""
        return self._plugins.get(test_type)

    def all(self) -> dict[str, type[ScannerPlugin]]:
        """Return a copy of the registered plugins by test_type."""
        return dict(self._plugins)


class PluginLoader:
    """
    Discovers ScannerPlugin subclasses from a directory of .py files.
    """

    def __init__(self, plugin_dir: str | Path = "plugins") -> None:
        self.plugin_dir = Path(plugin_dir)
        self.registry = PluginRegistry()

    def discover_plugins(self) -> list[type[ScannerPlugin]]:
        """
        Load every valid plugin from the plugin directory.

        Files whose names start with ``_`` are skipped. Any error while
        importing or validating a single plugin is logged and that plugin
        is skipped, so one broken plugin never aborts discovery.

        Returns:
            list of validated plugin classes (also added to self.registry).
        """
        if not self.plugin_dir.exists():
            return []

        discovered: list[type[ScannerPlugin]] = []

        for file in sorted(self.plugin_dir.glob("*.py")):
            if file.stem.startswith("_"):
                continue
            try:
                plugin_cls = self._load_plugin_from_file(file)
            except Exception as exc:  # isolate broken plugins
                logger.warning("failed to load plugin %s: %s", file, exc)
                continue

            if plugin_cls is None:
                continue

            discovered.append(plugin_cls)
            self.registry.register(plugin_cls)

        return discovered

    def _load_plugin_from_file(
        self, filepath: Path
    ) -> type[ScannerPlugin] | None:
        """
        Import a file and return its first valid ScannerPlugin subclass.
        """
        spec = importlib.util.spec_from_file_location(
            f"sentinel_plugins.{filepath.stem}", filepath
        )
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, ScannerPlugin)
                and attr is not ScannerPlugin
            ):
                instance = attr()
                if instance.validate():
                    return attr

        return None
