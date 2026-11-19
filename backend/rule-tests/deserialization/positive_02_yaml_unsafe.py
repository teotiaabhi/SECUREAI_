# =============================================================================
# Test:     positive_02_yaml_unsafe
# Expected: TRIGGER rule DESER-PY-002
# Category: Deserialization
# Language: Python
# Description: Python script using yaml.load() with yaml.UnsafeLoader,
#              allowing arbitrary Python object instantiation from YAML input.
# =============================================================================

import yaml
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages application configuration loaded from YAML files."""

    def __init__(self, config_dir: str = "/etc/myapp"):
        self.config_dir = Path(config_dir)
        self._config = {}

    def load_config(self, filename: str) -> dict:
        """
        Load a YAML configuration file.
        WARNING: Uses UnsafeLoader which can instantiate arbitrary Python objects.
        """
        config_path = self.config_dir / filename
        if not config_path.exists():
            logger.error("Configuration file not found: %s", config_path)
            return {}

        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                # VULNERABLE: UnsafeLoader allows arbitrary object instantiation
                data = yaml.load(fh, Loader=yaml.UnsafeLoader)

            if not isinstance(data, dict):
                logger.warning("Config file %s did not contain a mapping", filename)
                return {}

            self._config.update(data)
            logger.info("Loaded configuration from %s", filename)
            return data

        except yaml.YAMLError as exc:
            logger.exception("YAML parse error in %s", filename)
            return {}

    def load_user_config(self, raw_yaml: str) -> dict:
        """
        Parse user-supplied YAML string.
        WARNING: Uses yaml.load without SafeLoader.
        """
        try:
            # VULNERABLE: yaml.load without explicit SafeLoader
            data = yaml.load(raw_yaml, Loader=yaml.FullLoader)
            self._config.update(data or {})
            return data or {}
        except yaml.YAMLError:
            logger.exception("Failed to parse user YAML input")
            return {}


if __name__ == "__main__":
    manager = ConfigManager()
    if len(sys.argv) > 1:
        result = manager.load_config(sys.argv[1])
        print(f"Loaded keys: {list(result.keys())}")
