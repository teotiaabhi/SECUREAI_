"""
Shared fixtures for CI/CD integration lifecycle tests.

Provides mock database sessions, model factories, and test helpers
that let us exercise the full webhook → scan → baseline → delta chain
without a live database or GitHub API.
"""

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Deterministic UUIDs for predictable test assertions ─────

USER_ID_A = uuid.UUID("aaaa0000-0000-0000-0000-000000000001")
USER_ID_B = uuid.UUID("bbbb0000-0000-0000-0000-000000000002")
REPO_ID = uuid.UUID("cccc0000-0000-0000-0000-000000000001")
SCAN_ID_FULL = uuid.UUID("dddd0000-0000-0000-0000-000000000001")
SCAN_ID_DIFF = uuid.UUID("dddd0000-0000-0000-0000-000000000002")
SCAN_ID_DIFF2 = uuid.UUID("dddd0000-0000-0000-0000-000000000003")

WEBHOOK_SECRET = "test_webhook_secret_value_for_hmac"
GITHUB_REPO_ID = 999888777


# ── Lightweight ORM-like objects used in place of real models ─

class FakeUser:
    def __init__(self, user_id=USER_ID_A, email="test@test.com"):
        self.id = user_id
        self.email = email
        self.name = "Test User"
        self.github_token_encrypted = "encrypted_token_blob"
        self.is_paid = False


class FakeRepository:
    def __init__(self, user_id=USER_ID_A, repo_id=REPO_ID):
        self.id = repo_id
        self.user_id = user_id
        self.github_repo_id = GITHUB_REPO_ID
        self.full_name = "testowner/testrepo"
        self.default_branch = "main"
        self.webhook_secret = WEBHOOK_SECRET
        self.is_active = True
        self.scan_config = {}
        self.installed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)


class FakeVulnerability:
    """Mimics Vulnerability ORM object with the fields used by compute_detection_id."""
    def __init__(self, file_name, vulnerability_type, severity, line_reference=1, confidence=0.85, scan_id=None):
        self.id = uuid.uuid4()
        self.scan_id = scan_id or SCAN_ID_FULL
        self.file_name = file_name
        self.vulnerability_type = vulnerability_type
        self.severity = severity
        self.confidence = confidence
        self.line_reference = line_reference
        self.impact = "Test impact"
        self.owasp_mapping = ""
        self.category = ""


class FakeBaselineFinding:
    """Mimics BaselineFinding ORM object."""
    def __init__(self, detection_id, file_name, vulnerability_type, severity,
                 line_reference=1, scan_id=None, repo_id=REPO_ID):
        self.id = uuid.uuid4()
        self.repository_id = repo_id
        self.scan_id = scan_id or SCAN_ID_FULL
        self.detection_id = detection_id
        self.file_name = file_name
        self.vulnerability_type = vulnerability_type
        self.severity = severity
        self.line_reference = line_reference
        self.commit_sha = "abc123"
        self.is_active = True
        self.first_seen_at = datetime.now(timezone.utc)
        self.last_seen_at = datetime.now(timezone.utc)


# ── Helper: build GitHub webhook payloads ───────────────────

def build_push_payload(
    repo_id: int = GITHUB_REPO_ID,
    repo_name: str = "testowner/testrepo",
    branch: str = "main",
    head_sha: str = "a" * 40,
) -> dict:
    return {
        "ref": f"refs/heads/{branch}",
        "before": "0" * 40,
        "after": head_sha,
        "repository": {
            "id": repo_id,
            "full_name": repo_name,
            "default_branch": "main",
        },
        "head_commit": {
            "id": head_sha,
            "message": "Test commit",
            "author": {"username": "testuser"},
        },
    }


def build_pr_payload(
    repo_id: int = GITHUB_REPO_ID,
    repo_name: str = "testowner/testrepo",
    action: str = "opened",
    pr_number: int = 42,
    base_sha: str = "b" * 40,
    head_sha: str = "c" * 40,
) -> dict:
    return {
        "action": action,
        "number": pr_number,
        "repository": {
            "id": repo_id,
            "full_name": repo_name,
            "default_branch": "main",
        },
        "pull_request": {
            "number": pr_number,
            "title": "Test PR",
            "base": {"sha": base_sha},
            "head": {"sha": head_sha, "ref": "feature/test"},
            "user": {"login": "testuser"},
        },
    }


def sign_payload(body: bytes, secret: str) -> str:
    """Generate a valid HMAC-SHA256 signature for a webhook payload."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


# ── Settings stub ───────────────────────────────────────────

def make_fake_settings(**overrides):
    """Create a mock Settings object with all CI/CD fields."""
    defaults = {
        "DEBUG": False,
        "APP_NAME": "TestApp",
        "APP_VERSION": "1.0.0-test",
        "API_PREFIX": "/api/v1",
        "GITHUB_APP_WEBHOOK_SECRET": "",
        "GITHUB_APP_ID": "",
        "GITHUB_APP_PRIVATE_KEY": "",
        "GITHUB_API_BASE": "https://api.github.com",
        "DIFF_SCAN_MAX_FILES": 200,
        "DIFF_SCAN_FALLBACK_ENABLED": True,
        "DIFF_FALLBACK_TO_FULL_THRESHOLD": 300,
        "PR_COMMENT_ENABLED": True,
        "PR_COMMENT_MIN_SEVERITY": "medium",
        "GITHUB_COMMENT_TIMEOUT_SECONDS": 10,
        "BASELINE_RETENTION_COUNT": 10,
        "AI_REQUEST_TIMEOUT": 30,
        "CORS_ORIGINS": ["http://localhost:3000"],
        "WORKER_TASK_TIMEOUT": 600,
        "SCAN_TEMP_DIR": "",
        "MAX_CONCURRENT_SCANS_PER_USER": 3,
        "MAX_GLOBAL_CONCURRENT_SCANS": 20,
    }
    defaults.update(overrides)
    settings = MagicMock()
    for k, v in defaults.items():
        setattr(settings, k, v)
    return settings


# ── Mock DB session factory ─────────────────────────────────

class FakeScalarResult:
    """Result from db.execute() that supports .scalar_one_or_none() and .scalars().all()."""
    def __init__(self, rows=None, scalar_value=None):
        self._rows = rows or []
        self._scalar = scalar_value

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        return self

    def all(self):
        return self._rows


class FakeDBSession:
    """Async DB session stub that tracks operations for assertion."""
    def __init__(self):
        self.added: list = []
        self.executed: list = []
        self.committed = 0
        self.flushed = 0
        self._query_responses: Dict[str, Any] = {}

    def set_query_response(self, key: str, result):
        """Pre-configure a response for queries matching a key pattern."""
        self._query_responses[key] = result

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flushed += 1
        # Assign IDs to objects that need them
        for obj in self.added:
            if hasattr(obj, 'id') and obj.id is None:
                obj.id = uuid.uuid4()

    async def commit(self):
        self.committed += 1

    async def rollback(self):
        pass

    async def close(self):
        pass

    async def execute(self, statement, *args, **kwargs):
        self.executed.append(statement)
        # Return empty result by default
        return FakeScalarResult()
