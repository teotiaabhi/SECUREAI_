"""Setup script for SecureAI Code Analyzer CLI.

Install in development mode:
    cd backend
    pip install -e .

This registers the `secureai` console command and auto-installs
the OpenAI Codex CLI (requires Node.js 22+).
"""

import shutil
import subprocess
import sys

from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop


def _install_codex_cli():
    """Post-install: attempt to install @openai/codex via npm."""
    npm = shutil.which("npm")
    if npm is None:
        print(
            "\n"
            "  ⚠  Node.js / npm not found on PATH.\n"
            "     To enable AI-powered scanning (secureai scan --ai),\n"
            "     install Node.js 22+ and then run:\n"
            "       npm install -g @openai/codex\n"
        )
        return

    print("\n  Installing OpenAI Codex CLI (@openai/codex)...")
    try:
        result = subprocess.run(
            [npm, "install", "-g", "@openai/codex"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print("  ✓ OpenAI Codex CLI installed successfully.\n")
        else:
            print(
                f"  ⚠  Codex CLI install failed (non-critical):\n"
                f"     {result.stderr.strip()[:200]}\n"
                f"     You can install it manually: npm install -g @openai/codex\n"
            )
    except subprocess.TimeoutExpired:
        print("  ⚠  Codex CLI install timed out. Install manually: npm install -g @openai/codex\n")
    except OSError as exc:
        print(f"  ⚠  Could not run npm: {exc}\n")


class PostInstallCommand(install):
    """Post-installation: install Codex CLI after pip install."""

    def run(self):
        install.run(self)
        _install_codex_cli()


class PostDevelopCommand(develop):
    """Post-installation for dev mode: install Codex CLI after pip install -e ."""

    def run(self):
        develop.run(self)
        _install_codex_cli()


setup(
    name="secureai-cli",
    version="1.0.0",
    description="SecureAI Code Analyzer — Production SAST CLI with AI-powered false-positive removal",
    author="SecureAI Team",
    python_requires=">=3.9",
    packages=find_packages(include=["cli", "cli.*", "engine", "engine.*"]),
    install_requires=[
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "secureai=cli.cli:main",
        ],
    },
    cmdclass={
        "install": PostInstallCommand,
        "develop": PostDevelopCommand,
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
