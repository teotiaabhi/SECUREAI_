# Test: negative for rule PY-INJ-002
# Expected: should_not_trigger
# Category: injection
# Language: python

"""
Safe Django management command demonstrating proper subprocess usage.
All shell commands are executed via subprocess.run() with list arguments,
preventing command injection by avoiding shell interpretation.
"""

import logging
import os
import re
import subprocess
from django.core.management.base import BaseCommand, CommandError

logger = logging.getLogger(__name__)

HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class Command(BaseCommand):
    help = "Export application logs for a given date range and hostname"

    def add_arguments(self, parser):
        parser.add_argument(
            "--hostname",
            type=str,
            required=True,
            help="Target hostname to collect logs from",
        )
        parser.add_argument(
            "--date",
            type=str,
            required=True,
            help="Date for log export in YYYY-MM-DD format",
        )
        parser.add_argument(
            "--output-dir",
            type=str,
            default="/tmp/log_exports",
            help="Directory to store exported log files",
        )

    def handle(self, *args, **options):
        hostname = options["hostname"]
        log_date = options["date"]
        output_dir = options["output_dir"]

        # SAFE: Input validation before use
        if not HOSTNAME_PATTERN.match(hostname):
            raise CommandError(f"Invalid hostname format: {hostname}")

        if not DATE_PATTERN.match(log_date):
            raise CommandError(f"Invalid date format: {log_date}. Expected YYYY-MM-DD")

        self.stdout.write(f"Starting log export for {hostname} on {log_date}")

        # SAFE: Using os.makedirs instead of shell command
        export_path = os.path.join(output_dir, hostname)
        os.makedirs(export_path, exist_ok=True)

        # SAFE: subprocess.run with list arguments (no shell=True)
        source_dir = os.path.join("/var/log/remote", hostname)
        archive_path = os.path.join(export_path, f"logs_{log_date}.tar.gz")

        result = subprocess.run(
            ["tar", "czf", archive_path, source_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            logger.error("tar stderr: %s", result.stderr)
            raise CommandError(f"Log archive failed with exit code {result.returncode}")

        # SAFE: subprocess.run with list arguments for find command
        cleanup_result = subprocess.run(
            ["find", source_dir, "-name", "*.log", "-mtime", "+30", "-delete"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if cleanup_result.returncode != 0:
            logger.warning("Cleanup had warnings: %s", cleanup_result.stderr)

        logger.info("Log export completed for host=%s date=%s", hostname, log_date)
        self.stdout.write(self.style.SUCCESS(f"Successfully exported logs to {export_path}"))
