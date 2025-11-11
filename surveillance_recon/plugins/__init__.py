# surveillance_recon/plugins/__init__.py
# [SecOps Research // Dynamic Plugin Loader v2.0]
# For authorized red team use under Security Research Protocol §7. Plugins auto-load and auto-execute on compatible targets.

import os
import sys
import importlib
import importlib.util
import inspect
from typing import List, Dict, Any, Optional, Type
from pathlib import Path

class SecurityPlugin:
    """
    Base class for all Zeta plugins.
    Override these methods in your plugin.
    """
    NAME = "Generic Plugin"
    DESCRIPTION = "Base plugin template"
    TARGET_BRANDS = []        # e.g., ["hikvision", "dahua"]
    REQUIRED_VULNS = []       # e.g., ["CVE-2021-36260"]
    AUTHOR = "Zeta Core"
    VERSION = "1.0"

    def __init__(self, target_ip: str, port: int, **kwargs):
        self.target_ip = target_ip
        self.port = port
        self.metadata = kwargs.get("fingerprint", {})
        self.auth = kwargs.get("auth", None)
        self.logger = kwargs.get("logger", None)

    def is_compatible(self) -> bool:
        """Check if target matches plugin requirements"""
        brand = self.metadata.get("brand", "").lower()
        vulns = self.metadata.get("vulnerabilities", [])
        return (
            brand in [b.lower() for b in self.TARGET_BRANDS] and
            (not self.REQUIRED_VULNS or any(v in vulns for v in self.REQUIRED_VULNS))
        )

    def execute(self) -> Dict[str, Any]:
        """
        Main exploit logic. Return structured result:
        {
            "success": bool,
            "output": str,
            "artifacts": [...],
            "c2_deployed": bool
        }
        """
        raise NotImplementedError("Plugin must implement execute()")

class PluginManager:
    """
    Auto-discovers and manages Zeta plugins from the plugins/ directory.
    """

    def __init__(self, plugin_dir: Optional[str] = None):
        if plugin_dir is None:
            plugin_dir = os.path.dirname(__file__)
        self.plugin_dir = Path(plugin_dir)
        self.loaded_plugins: List[Type[SecurityPlugin]] = []
        self._discover_plugins()

    def _discover_plugins(self):
        """Dynamically load all .py files in plugins/ as modules"""
        sys.path.insert(0, str(self.plugin_dir))
        for file_path in self.plugin_dir.glob("*.py"):
            if file_path.name == "__init__.py":
                continue
            try:
                spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find plugin classes
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        inspect.isclass(attr) and
                        issubclass(attr, SecurityPlugin) and
                        attr != SecurityPlugin
                    ):
                        self.loaded_plugins.append(attr)
            except Exception as e:
                if self.plugin_dir.parent.name == "surveillance_recon":
                    # Silent fail in prod; log only in dev
                    pass

    def get_compatible_plugins(self, fingerprint: Dict[str, Any]) -> List[SecurityPlugin]:
        """Instantiate plugins compatible with the target"""
        compatible = []
        target_ip = fingerprint.get("target_ip", "127.0.0.1")
        port = fingerprint.get("port", 80)
        for plugin_class in self.loaded_plugins:
            try:
                plugin = plugin_class(
                    target_ip=target_ip,
                    port=port,
                    fingerprint=fingerprint
                )
                if plugin.is_compatible():
                    compatible.append(plugin)
            except Exception:
                continue
        return compatible

    def run_all_compatible(self, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        """Run all compatible plugins and aggregate results"""
        results = {}
        compatible = self.get_compatible_plugins(fingerprint)
        for plugin in compatible:
            try:
                result = plugin.execute()
                results[plugin.NAME] = result
            except Exception as e:
                results[plugin.NAME] = {"success": False, "error": str(e)}
        return results

# Auto-initialize global plugin manager
PLUGIN_MANAGER = PluginManager()

def run_plugins(fingerprint: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for core modules"""
    return PLUGIN_MANAGER.run_all_compatible(fingerprint)
