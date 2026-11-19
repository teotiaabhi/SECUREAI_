from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SecureAI Code Analyzer"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"

    # Database — Supabase PostgreSQL (set DATABASE_URL in .env)
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/postgres"
    DB_ECHO: bool = False

    # JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Google OAuth
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:5000/auth/google/callback"

    # GitHub OAuth
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:5000/auth/github/callback"

    # AI Providers — Required for production
    PPLX_API_KEY: str
    PPLX_API_URL: str = "https://api.perplexity.ai/chat/completions"
    PHI3_API_URL: str = "https://router.huggingface.co/hf-inference/models/microsoft/Phi-3-mini-4k-instruct"
    GEMMA_API_URL: str = "https://router.huggingface.co/hf-inference/models/google/gemma-2-2b-it"
    HF_API_TOKEN: str = ""

    # Encryption
    ENCRYPTION_KEY: str

    # Limits
    MAX_FILE_SIZE_MB: int = 1
    MAX_FILES_PER_SCAN: int = 100
    MAX_CHUNK_TOKENS: int = 3000
    SCAN_TIMEOUT_SECONDS: int = 300
    AI_REQUEST_TIMEOUT: int = 30
    AI_RETRY_ATTEMPTS: int = 2
    RATE_LIMIT: str = "60/minute"

    # Engine
    ENGINE_WORKER_COUNT: int = 0          # 0 = auto (cpu_count, max 8)
    ENGINE_STREAM_THRESHOLD: int = 262144 # 256 KB — files below scanned whole
    ENGINE_MAX_FINDINGS_PER_FILE: int = 100
    ENGINE_RULES_DIR: str = ""            # empty = default backend/rules/
    ENGINE_PER_FILE_TIMEOUT: int = 10     # seconds per file — skip + continue if exceeded
    ENGINE_MAX_FILE_SIZE_BYTES: int = 1_048_576  # 1 MB — skip files larger than this

    # Orchestration
    MAX_CONCURRENT_SCANS_PER_USER: int = 3
    MAX_GLOBAL_CONCURRENT_SCANS: int = 20
    MAX_FILES_PER_SCAN_LARGE: int = 20000
    SCAN_TEMP_DIR: str = ""               # empty = system temp

    # Git cloning
    GIT_CLONE_TIMEOUT: int = 120          # seconds
    GIT_CLONE_MAX_SIZE_MB: int = 1024
    CLONE_CACHE_DIR: str = ""             # Per-repo commit-based cache (empty = disabled)

    # ZIP extraction
    ZIP_MAX_EXTRACTED_SIZE_MB: int = 200
    ZIP_MAX_FILE_COUNT: int = 20000
    ZIP_MAX_COMPRESSION_RATIO: int = 100

    # Batch scanning
    BATCH_MAX_SIZE_MB: int = 10
    BATCH_MAX_FILES: int = 50

    # AI validation (orchestration layer)
    AI_VALIDATION_ENABLED: bool = False
    AI_MAX_CONCURRENT_VALIDATIONS: int = 5
    AI_MAX_TOKENS_PER_SCAN: int = 50000

    # Cleanup
    DATA_RETENTION_DAYS: int = 90
    STALE_SCAN_TIMEOUT: int = 3600        # 1 hour
    CLEANUP_INTERVAL_HOURS: int = 6

    # Rate limiting (per-user per-endpoint)
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_SCAN_START: str = "5/minute"
    RATE_LIMIT_UPLOAD: str = "3/minute"
    RATE_LIMIT_STATUS: str = "120/minute"

    # Request body limit
    MAX_REQUEST_BODY_MB: int = 512

    # Worker control
    MEMORY_PRESSURE_THRESHOLD: float = 85.0
    MAX_WORKER_PROCESSES: int = 4
    WORKER_TASK_TIMEOUT: int = 600        # seconds — overall scan pipeline timeout

    # AI safety
    AI_SNIPPET_MAX_CHARS: int = 4000
    AI_TOTAL_TIMEOUT_PER_SCAN: int = 300  # seconds
    AI_TOKENS_PER_DAY_FREE: int = 10000
    AI_TOKENS_PER_DAY_PRO: int = 100000
    AI_TOKENS_PER_DAY_ENTERPRISE: int = 500000

    # Cookie / HTTPS
    COOKIE_SECURE: bool = True            # Override to False only in dev

    # GitHub App / Webhook
    GITHUB_APP_WEBHOOK_SECRET: str = ""   # Global webhook HMAC secret
    GITHUB_APP_ID: str = ""               # GitHub App ID (optional)
    GITHUB_APP_PRIVATE_KEY: str = ""      # PEM private key for GitHub App JWT auth
    GITHUB_API_BASE: str = "https://api.github.com"  # Override for GitHub Enterprise

    # Diff scanning
    DIFF_SCAN_MAX_FILES: int = 200                  # Max changed files for diff scan
    DIFF_SCAN_FALLBACK_ENABLED: bool = True
    DIFF_FALLBACK_TO_FULL_THRESHOLD: int = 300      # Beyond this, always fallback to full

    # PR Comments
    PR_COMMENT_ENABLED: bool = False                # Explicitly opt-in in production
    PR_COMMENT_MIN_SEVERITY: str = "medium"
    GITHUB_COMMENT_TIMEOUT_SECONDS: int = 10        # Timeout for PR comment API calls

    # Baseline
    BASELINE_RETENTION_COUNT: int = 10    # Keep last N baselines per repo

    # Webhook rate limiting
    RATE_LIMIT_WEBHOOK: str = "60/minute"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # Deployment / runtime hardening
    GRACEFUL_SHUTDOWN_TIMEOUT: int = 30        # seconds to wait for in-flight work
    HEALTH_CHECK_TIMEOUT: int = 5              # timeout for individual health checks
    SATURATION_MEMORY_THRESHOLD: float = 90.0  # % memory for saturation guard
    SATURATION_MAX_QUEUE_DEPTH: int = 50       # max queue depth before rejecting

    # Distributed queue / worker
    QUEUE_BACKEND: str = "memory"              # "memory" or "redis"
    QUEUE_REDIS_URL: str = ""                  # redis://host:6379/0
    WORKER_MODE: str = "embedded"              # "embedded" or "standalone"
    WORKER_ID: str = ""                        # auto-generated if empty
    WORKER_HEARTBEAT_INTERVAL: int = 30        # seconds
    DLQ_MAX_RETRIES: int = 3
    DLQ_RETRY_DELAY: int = 60                 # seconds

    # KMS / key management
    KMS_BACKEND: str = "local"                 # "local" or "aws"
    KMS_AWS_KEY_ID: str = ""                   # AWS KMS key ARN
    KMS_KEY_ROTATION_DAYS: int = 90

    # Compliance
    AUDIT_CHAIN_ENABLED: bool = True
    GDPR_DELETION_ENABLED: bool = True
    COMPLIANCE_REPORT_CACHE_TTL: int = 300     # seconds

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if not v or len(v) < 16:
            raise ValueError("JWT_SECRET_KEY must be at least 16 characters")
        return v

    @field_validator("PPLX_API_KEY")
    @classmethod
    def validate_pplx_key(cls, v: str) -> str:
        if not v:
            raise ValueError("PPLX_API_KEY is required — set it in .env")
        return v

    @field_validator("ENCRYPTION_KEY")
    @classmethod
    def validate_encryption_key(cls, v: str) -> str:
        if not v or len(v) < 16:
            raise ValueError("ENCRYPTION_KEY must be at least 16 characters")
        return v

    @field_validator("DIFF_SCAN_MAX_FILES", "DIFF_FALLBACK_TO_FULL_THRESHOLD",
                     "GITHUB_COMMENT_TIMEOUT_SECONDS", "BASELINE_RETENTION_COUNT")
    @classmethod
    def validate_positive_int(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Value must be a positive integer")
        return v

    @field_validator("PR_COMMENT_MIN_SEVERITY")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        if v.lower() not in allowed:
            raise ValueError(f"PR_COMMENT_MIN_SEVERITY must be one of {allowed}")
        return v.lower()

    @field_validator("GITHUB_API_BASE")
    @classmethod
    def validate_api_base(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError("GITHUB_API_BASE must use HTTPS")
        return v.rstrip("/")

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
