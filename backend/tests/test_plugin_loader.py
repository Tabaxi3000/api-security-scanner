"""
Tests for the scanner plugin discovery system.
"""

from scanners.plugin_loader import PluginLoader, PluginRegistry
from scanners.plugin_interface import ScannerPlugin

VALID_PLUGIN = '''
from scanners.plugin_interface import ScannerPlugin

class GoodPlugin(ScannerPlugin):
    @property
    def name(self): return "good"
    @property
    def version(self): return "1.0.0"
    @property
    def test_type(self): return "good_type"
    def scan(self, target_url, **kwargs):
        return {"vulnerable": False, "details": "", "evidence": {}, "recommendations": []}
'''

BROKEN_PLUGIN = '''
import this_module_does_not_exist_zzz  # import error at load time

from scanners.plugin_interface import ScannerPlugin

class BrokenPlugin(ScannerPlugin):
    @property
    def name(self): return "broken"
    @property
    def version(self): return "1.0.0"
    @property
    def test_type(self): return "broken_type"
    def scan(self, target_url, **kwargs): return {}
'''

INVALID_PLUGIN = '''
from scanners.plugin_interface import ScannerPlugin

class EmptyNamePlugin(ScannerPlugin):
    @property
    def name(self): return ""          # fails default validate()
    @property
    def version(self): return "1.0.0"
    @property
    def test_type(self): return "empty_type"
    def scan(self, target_url, **kwargs): return {}
'''

CONFLICT_PLUGIN = '''
from scanners.plugin_interface import ScannerPlugin

class ConflictPlugin(ScannerPlugin):
    @property
    def name(self): return "conflict"
    @property
    def version(self): return "2.0.0"
    @property
    def test_type(self): return "good_type"   # same type as GoodPlugin
    def scan(self, target_url, **kwargs): return {}
'''


def _write(dir_path, name, src):
    (dir_path / name).write_text(src)


def test_discovers_valid_plugin(tmp_path):
    _write(tmp_path, "good.py", VALID_PLUGIN)
    loader = PluginLoader(tmp_path)
    discovered = loader.discover_plugins()

    assert len(discovered) == 1
    inst = discovered[0]()
    assert isinstance(inst, ScannerPlugin)
    assert inst.test_type == "good_type"
    assert loader.registry.get("good_type") is discovered[0]


def test_broken_plugin_is_isolated(tmp_path):
    _write(tmp_path, "good.py", VALID_PLUGIN)
    _write(tmp_path, "broken.py", BROKEN_PLUGIN)

    discovered = PluginLoader(tmp_path).discover_plugins()
    # broken one is skipped, good one still loads
    assert [p.__name__ for p in discovered] == ["GoodPlugin"]


def test_invalid_plugin_skipped(tmp_path):
    _write(tmp_path, "invalid.py", INVALID_PLUGIN)
    assert PluginLoader(tmp_path).discover_plugins() == []


def test_underscore_files_skipped(tmp_path):
    _write(tmp_path, "_template.py", VALID_PLUGIN)
    assert PluginLoader(tmp_path).discover_plugins() == []


def test_missing_dir_returns_empty(tmp_path):
    assert PluginLoader(tmp_path / "nope").discover_plugins() == []


def test_test_type_conflict_first_wins(tmp_path):
    _write(tmp_path, "a_good.py", VALID_PLUGIN)
    _write(tmp_path, "b_conflict.py", CONFLICT_PLUGIN)

    loader = PluginLoader(tmp_path)
    loader.discover_plugins()
    # sorted discovery: a_good.py registers first and keeps the type
    assert loader.registry.get("good_type").__name__ == "GoodPlugin"


def test_registry_register_returns_false_on_conflict():
    registry = PluginRegistry()

    class P1(ScannerPlugin):
        name = "p1"
        version = "1.0.0"
        test_type = "dup"
        def scan(self, target_url, **kwargs): return {}

    class P2(ScannerPlugin):
        name = "p2"
        version = "1.0.0"
        test_type = "dup"
        def scan(self, target_url, **kwargs): return {}

    assert registry.register(P1) is True
    assert registry.register(P2) is False
    assert registry.get("dup") is P1
