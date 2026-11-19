"""Configuration module for the rule validation test framework.

Provides centralized configuration with defaults, environment variable
overrides, and optional YAML config file loading.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"
_DEFAULT_TESTS_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
_DEFAULT_BASELINES_DIR = Path(__file__).resolve().parent.parent / "baselines"


@dataclass
class RuleTestConfig:
    """Configuration for the rule test runner.

    Attributes:
        rules_dir: Path to the directory containing YAML rule definitions.
        tests_dir: Path to the directory containing test sample files.
        reports_dir: Path where test reports will be written.
        baselines_dir: Path where performance baselines are stored.
        parallel_workers: Number of threads for parallel test execution.
        confidence_threshold: Minimum confidence score to consider a match valid.
        timeout_per_rule_ms: Maximum time in milliseconds allowed per rule execution.
        verbose: Whether to enable verbose logging output.
    """

    rules_dir: Path = field(default_factory=lambda: _DEFAULT_RULES_DIR)
    tests_dir: Path = field(default_factory=lambda: _DEFAULT_TESTS_DIR)
    reports_dir: Path = field(default_factory=lambda: _DEFAULT_REPORTS_DIR)
    baselines_dir: Path = field(default_factory=lambda: _DEFAULT_BASELINES_DIR)
    parallel_workers: int = 4
    confidence_threshold: float = 0.5
    timeout_per_rule_ms: int = 5000
    verbose: bool = False


def create_default_config() -> RuleTestConfig:
    """Create a configuration instance with all default values.

    Returns:
        A RuleTestConfig populated with sensible defaults.
    """
    return RuleTestConfig()


def _apply_env_overrides(config: RuleTestConfig) -> RuleTestConfig:
    """Apply environment variable overrides to an existing configuration.

    Recognized environment variables:
        RULE_TEST_RULES_DIR, RULE_TEST_TESTS_DIR, RULE_TEST_REPORTS_DIR,
        RULE_TEST_BASELINES_DIR, RULE_TEST_PARALLEL_WORKERS,
        RULE_TEST_CONFIDENCE_THRESHOLD, RULE_TEST_TIMEOUT_PER_RULE_MS,
        RULE_TEST_VERBOSE

    Args:
        config: The base configuration to override.

    Returns:
        The configuration with environment overrides applied in place.
    """
    env_map = {
        "RULE_TEST_RULES_DIR": ("rules_dir", Path),
        "RULE_TEST_TESTS_DIR": ("tests_dir", Path),
        "RULE_TEST_REPORTS_DIR": ("reports_dir", Path),
        "RULE_TEST_BASELINES_DIR": ("baselines_dir", Path),
        "RULE_TEST_PARALLEL_WORKERS": ("parallel_workers", int),
        "RULE_TEST_CONFIDENCE_THRESHOLD": ("confidence_threshold", float),
        "RULE_TEST_TIMEOUT_PER_RULE_MS": ("timeout_per_rule_ms", int),
        "RULE_TEST_VERBOSE": ("verbose", lambda v: v.lower() in ("1", "true", "yes")),
    }

    for env_var, (attr, converter) in env_map.items():
        value = os.environ.get(env_var)
        if value is not None:
            try:
                setattr(config, attr, converter(value))
                logger.debug("Config override from env %s: %s = %s", env_var, attr, value)
            except (ValueError, TypeError) as exc:
                logger.warning("Invalid value for %s='%s': %s", env_var, value, exc)

    return config


def load_config(config_path: Optional[Path] = None) -> RuleTestConfig:
    """Load configuration from a YAML file, with environment variable overrides.

    Resolution order (later sources win):
        1. Built-in defaults
        2. YAML config file (if found)
        3. Environment variables

    Args:
        config_path: Explicit path to a YAML config file.  When *None* the
            loader looks for ``rule-tests/config.yaml`` relative to this
            module.

    Returns:
        A fully resolved RuleTestConfig instance.
    """
    config = create_default_config()

    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent / "config.yaml"

    if config_path.is_file():
        logger.info("Loading config from %s", config_path)
        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                raw: dict = yaml.safe_load(fh) or {}

            field_types = {
                "rules_dir": Path,
                "tests_dir": Path,
                "reports_dir": Path,
                "baselines_dir": Path,
                "parallel_workers": int,
                "confidence_threshold": float,
                "timeout_per_rule_ms": int,
                "verbose": bool,
            }

            for key, converter in field_types.items():
                if key in raw:
                    try:
                        setattr(config, key, converter(raw[key]))
                    except (ValueError, TypeError) as exc:
                        logger.warning("Invalid config value for %s: %s", key, exc)
        except yaml.YAMLError as exc:
            logger.error("Failed to parse config file %s: %s", config_path, exc)
    else:
        logger.debug("No config file found at %s; using defaults.", config_path)

    config = _apply_env_overrides(config)

    return config
