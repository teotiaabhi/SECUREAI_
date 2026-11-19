# Test: positive for rule PY-INJ-002
# Expected: should_trigger
# Category: injection
# Language: python

"""
Vulnerable Django management command demonstrating OS command injection.
User-supplied arguments are concatenated directly into shell commands
executed via os.system() and subprocess.call() with shell=True.
"""

import os
import subprocess
import logging
from django.core.management.base import BaseCommand, CommandError

logger = logging.getLogger(__name__)


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

        self.stdout.write(f"Starting log export for {hostname} on {log_date}")

        # VULNERABLE: os.system with string concatenation of user input
        os.system("mkdir -p " + output_dir + "/" + hostname)

        # VULNERABLE: subprocess.call with shell=True and user input
        archive_cmd = f"tar czf {output_dir}/{hostname}/logs_{log_date}.tar.gz /var/log/remote/{hostname}/"
        exit_code = subprocess.call(archive_cmd, shell=True)

        if exit_code != 0:
            raise CommandError(f"Log archive failed for {hostname} with exit code {exit_code}")

        # VULNERABLE: os.system with format string and user input
        cleanup_command = "find /var/log/remote/{host}/ -name '*.log' -mtime +30 -delete".format(
            host=hostname
        )
        os.system(cleanup_command)

        logger.info("Log export completed for host=%s date=%s", hostname, log_date)
        self.stdout.write(self.style.SUCCESS(f"Successfully exported logs to {output_dir}/{hostname}/"))
