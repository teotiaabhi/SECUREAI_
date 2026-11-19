# SecureAI Code Analyzer

Production-grade, AI-powered Static Application Security Testing (SAST) platform. Multi-tenant SaaS architecture with real-time vulnerability scanning, CI/CD integration, and SOC2-ready compliance controls.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Configuration Reference](#configuration-reference)
- [API Reference](#api-reference)
- [Static Analysis Engine](#static-analysis-engine)
- [Accuracy Engine & False Positive Control](#accuracy-engine--false-positive-control)
- [VS Code Extension](#vs-code-extension)
- [CLI Tool](#cli-tool)
- [Orchestration Layer](#orchestration-layer)
- [Distributed Worker Architecture](#distributed-worker-architecture)
- [CI/CD Integration](#cicd-integration)
- [Security & Compliance](#security--compliance)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Monitoring & Observability](#monitoring--observability)
- [Testing](#testing)
- [Frontend](#frontend)
- [Development Guide](#development-guide)


---

## Architecture Overview

```
                    +-------------------+
                    |   Next.js 16      |
                    |   React 19 SPA    |
                    +--------+----------+
                             |
                       HTTPS / WSS
                             |
                    +--------v----------+
                    |    FastAPI         |
                    |  API Gateway       |
                    | (Auth, Rate Limit, |
                    |  CORS, Security)   |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v--------+
     | Scan API   |  | Compliance  |  | Webhooks    |
     | CI/CD API  |  | GDPR API    |  | (GitHub)    |
     | Usage API  |  | Audit API   |  |             |
     +--------+---+  +------+------+  +----+--------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------v----------+
                    |   Orchestration    |
                    | - SessionManager  |
                    | - ProgressTracker |
                    | - QueueBackend    |
                    | - CleanupService  |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v--------+
     | Rule Engine |  | AI Validate |  | Git Cloner  |
     | 450 Rules   |  | Perplexity  |  | ZIP Extract |
     | 12 Languages|  | Phi-3 / Gemma| | Diff Detect |
     +--------+---+  +------+------+  +----+--------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------v----------+
                    |   PostgreSQL      |
                    |   (Supabase)      |
                    +-------------------+
```

### Core Capabilities

- **Multi-language SAST**: 1,014 detection rules across 38 programming languages
- **Delivery Modes**: Full-stack SaaS Web application, standalone Python CLI, and real-time VS Code Extension
- **Accuracy Engine**: 8-stage False Positive (FP) suppression pipeline achieving 0.0% FP rate on production codebase audits
- **AI-powered validation**: LLM-based vulnerability confirmation to reduce false positives
- **Multi-tenant isolation**: Row-level security, per-user resource quotas, tiered access
- **CI/CD native**: GitHub webhook integration, PR commenting, diff-aware scanning
- **Enterprise compliance**: SOC2 hash-chain audit logging, RBAC, GDPR data lifecycle
- **Production resilient**: Circuit breakers, saturation guards, graceful shutdown, distributed locking

---

## Technology Stack

### Backend

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | FastAPI | 0.115 |
| Runtime | Python | 3.12+ |
| Database | PostgreSQL (Supabase) | 15+ |
| ORM | SQLAlchemy 2.0 (async) | 2.0.35 |
| Auth | JWT (python-jose) | HS256 |
| Encryption | cryptography (Fernet + PBKDF2) | 43.0 |
| Queue | asyncio.PriorityQueue / Redis | - |
| Rate Limiting | SlowAPI | 0.1.9 |
| HTTP Client | httpx (async) | 0.27 |
| Metrics | Custom Prometheus exporter | - |
| Process Init | tini (PID 1 in Docker) | - |

### Frontend

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Next.js (App Router) | 16.1 |
| UI | React | 19.2 |
| State | Zustand | 5.0 |
| Charts | Recharts | 3.7 |
| Styling | Tailwind CSS | 4.0 |
| Language | TypeScript | 5.x |

### Infrastructure

| Component | Technology |
|-----------|-----------|
| Container | Docker (multi-stage, non-root) |
| Orchestration | Kubernetes + Helm |
| Monitoring | Prometheus + Grafana |
| CI/CD | GitHub Actions / Webhooks |

---

## Project Structure

```
security/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI application + lifespan
│   │   ├── api/                    # Route handlers
│   │   │   ├── auth.py             #   OAuth (Google, GitHub)
│   │   │   ├── scans.py            #   Scan CRUD + lifecycle
│   │   │   ├── repos.py            #   Repository management
│   │   │   ├── cicd.py             #   CI/CD pipeline management
│   │   │   ├── webhooks.py         #   GitHub webhook receiver
│   │   │   ├── usage.py            #   Usage & billing metrics
│   │   │   ├── compliance.py       #   SOC2 + GDPR endpoints
│   │   │   └── metrics.py          #   Prometheus /metrics
│   │   ├── auth/
│   │   │   ├── jwt_handler.py      #   Token create / decode / revoke
│   │   │   ├── permissions.py      #   RBAC permission system
│   │   │   ├── oauth_google.py     #   Google OAuth flow
│   │   │   └── oauth_github.py     #   GitHub OAuth flow
│   │   ├── core/
│   │   │   ├── config.py           #   Pydantic BaseSettings (100+ vars)
│   │   │   ├── security.py         #   Fernet encryption
│   │   │   ├── kms.py              #   KMS abstraction (local / AWS)
│   │   │   └── logging.py          #   Structured logging setup
│   │   ├── models/                 #   SQLAlchemy ORM models
│   │   │   ├── user.py             #   User (roles, tiers, quotas)
│   │   │   ├── scan.py             #   Scan lifecycle
│   │   │   ├── vulnerability.py    #   Vulnerability findings
│   │   │   ├── audit_log.py        #   Audit trail (hash-chained)
│   │   │   ├── cicd.py             #   CI/CD pipeline configs
│   │   │   ├── scan_session.py     #   Session tracking
│   │   │   ├── chunk.py            #   Code chunks
│   │   │   └── token_blacklist.py  #   JWT revocation
│   │   ├── middleware/
│   │   │   ├── security_headers.py #   CSP, HSTS, X-Frame
│   │   │   ├── saturation_guard.py #   Memory + queue pressure
│   │   │   ├── request_size_limit.py#  Body size enforcement
│   │   │   ├── abuse_detector.py   #   Behavioral anomaly detection
│   │   │   ├── tier_limits.py      #   Per-tier quota enforcement
│   │   │   ├── rate_limiter.py     #   Per-endpoint rate limits
│   │   │   └── tenant_context.py   #   Request-scoped user context
│   │   ├── orchestration/
│   │   │   ├── session_manager.py  #   Scan queue + concurrency
│   │   │   ├── scan_orchestrator.py#   Full scan pipeline
│   │   │   ├── progress_tracker.py #   DB-persisted progress
│   │   │   ├── report_aggregator.py#   Report generation
│   │   │   ├── parallel_controller.py# Multi-file parallel scan
│   │   │   ├── chunk_dispatcher.py #   Code chunking
│   │   │   ├── ai_validation_queue.py# AI validation pipeline
│   │   │   ├── git_cloner.py       #   Authenticated git clone
│   │   │   ├── zip_extractor.py    #   Safe ZIP extraction
│   │   │   └── cleanup_service.py  #   Stale data cleanup
│   │   ├── queue/
│   │   │   ├── base.py             #   ScanTask + QueueBackend ABC
│   │   │   ├── memory_backend.py   #   In-memory priority queue
│   │   │   ├── redis_backend.py    #   Redis sorted set backend
│   │   │   ├── factory.py          #   Backend factory
│   │   │   └── dead_letter.py      #   Failed task DLQ
│   │   ├── worker/
│   │   │   ├── scan_worker.py      #   Scan worker (embedded/standalone)
│   │   │   └── run.py              #   Standalone worker entrypoint
│   │   ├── services/
│   │   │   ├── audit_chain.py      #   SHA-256 hash-chain audit
│   │   │   ├── audit_service.py    #   Centralized audit logging
│   │   │   ├── data_retention.py   #   GDPR data lifecycle
│   │   │   ├── metrics.py          #   Prometheus metrics
│   │   │   ├── diff_detector.py    #   Git diff detection
│   │   │   ├── delta_engine.py     #   New/fixed finding diff
│   │   │   ├── baseline_service.py #   Baseline management
│   │   │   ├── distributed_lock.py #   Distributed lock (memory/Redis)
│   │   │   ├── circuit_breaker.py  #   Circuit breaker pattern
│   │   │   ├── cache_service.py    #   Result caching
│   │   │   ├── cost_estimator.py   #   AI token cost estimation
│   │   │   ├── usage_aggregator.py #   Usage tracking
│   │   │   ├── github_webhook.py   #   Webhook processing
│   │   │   ├── pr_comment_service.py#  PR comment formatting
│   │   │   └── ingestion.py        #   Code ingestion
│   │   ├── scanner/                #   Legacy scanner bridge
│   │   ├── ai/                     #   AI provider integrations
│   │   │   └── providers/          #   Perplexity, Phi-3, Gemma
│   │   ├── schemas/                #   Pydantic request/response
│   │   └── db/                     #   Database session factory
│   │
│   ├── engine/                     # Static analysis engine
│   │   ├── detection_engine.py     #   Core pattern matching
│   │   ├── rule_loader.py          #   YAML rule index
│   │   ├── pipeline.py             #   Scan pipeline
│   │   ├── streaming_scanner.py    #   Large file streaming
│   │   ├── file_classifier.py      #   Language detection
│   │   ├── severity.py             #   CVSS-aligned scoring
│   │   ├── deduplication.py        #   Finding dedup
│   │   ├── ai_validation.py        #   AI confidence
│   │   ├── worker.py               #   Multi-process workers
│   │   └── models.py               #   Finding dataclasses
│   │
│   ├── rules/                      # 450+ YAML detection rules
│   │   ├── injection/              #   SQL, command, NoSQL, SSTI, XXE
│   │   ├── xss/                    #   Reflected, stored, DOM
│   │   ├── auth/                   #   Broken authentication
│   │   ├── crypto/                 #   Weak crypto, hardcoded keys
│   │   ├── secrets/                #   API keys, passwords, tokens
│   │   ├── ssrf/                   #   Server-side request forgery
│   │   ├── rce/                    #   Remote code execution
│   │   ├── path_traversal/         #   Directory traversal
│   │   ├── deserialization/        #   Unsafe deserialization
│   │   ├── framework_misuse/       #   Framework-specific misuse
│   │   └── devops/                 #   Kubernetes, Docker misconfig
│   │
│   ├── k8s/                        # Kubernetes deployment
│   │   ├── helm/                   #   Helm chart
│   │   │   ├── Chart.yaml
│   │   │   ├── values.yaml
│   │   │   └── templates/          #   API + Worker deployments
│   │   └── monitoring/
│   │       ├── grafana-dashboard.json
│   │       └── alerting-rules.yaml
│   │
│   ├── tests/                      # Integration test suite
│   ├── rule-tests/                 # Rule validation framework
│   ├── Dockerfile                  # Multi-stage, non-root, tini
│   ├── docker-compose.yml
│   └── requirements.txt
│
└── src/                            # Next.js frontend
    ├── app/
    │   ├── layout.tsx              #   Root layout
    │   ├── page.tsx                #   Landing page
    │   ├── login/                  #   OAuth login
    │   ├── dashboard/              #   Dashboard
    │   ├── scan/                   #   New scan
    │   ├── results/                #   Scan results
    │   ├── history/                #   Scan history
    │   └── settings/               #   User settings
    ├── components/
    │   ├── auth/                   #   AuthGuard, LogoutModal
    │   ├── layout/                 #   AppShell, Header
    │   ├── results/                #   Charts, Tables, Modals
    │   ├── scan/                   #   Editor, Uploader, Progress
    │   └── ui/                     #   Badge, Modal, Tabs, Skeleton
    ├── lib/
    │   ├── api.ts                  #   HTTP client
    │   └── errors.ts               #   Error handling
    └── store/
        ├── authStore.ts            #   Auth state (Zustand)
        ├── scanStore.ts            #   Scan state
        └── historyStore.ts         #   History state
```

---

## Getting Started

### Prerequisites

- Python 3.12+
- Node.js 20+
- PostgreSQL 15+ (or Supabase project)
- Git

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your values (see Configuration Reference)

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
# From project root
npm install
npm run dev
```

### Docker

```bash
cd backend
docker build -t secureai-analyzer .
docker run -p 8000:8000 --env-file .env secureai-analyzer
```

### Docker Compose

```bash
cd backend
docker-compose up -d
```

---

## Configuration Reference

All configuration is managed via environment variables, loaded through Pydantic BaseSettings. See `app/core/config.py` for the complete list.

### Required Variables

| Variable | Description |
|----------|-------------|
| `JWT_SECRET_KEY` | JWT signing key (min 16 chars) |
| `PPLX_API_KEY` | Perplexity AI API key |
| `ENCRYPTION_KEY` | Data encryption key (min 16 chars) |
| `DATABASE_URL` | PostgreSQL connection string |

### Key Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode (docs, verbose logging) |
| `API_PREFIX` | `/api/v1` | API route prefix |
| `MAX_CONCURRENT_SCANS_PER_USER` | `3` | Per-user scan concurrency limit |
| `MAX_GLOBAL_CONCURRENT_SCANS` | `20` | System-wide scan concurrency |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed CORS origins |
| `QUEUE_BACKEND` | `memory` | Queue backend (`memory` or `redis`) |
| `QUEUE_REDIS_URL` | _(empty)_ | Redis URL for distributed queue |
| `WORKER_MODE` | `embedded` | Worker mode (`embedded` or `standalone`) |
| `KMS_BACKEND` | `local` | KMS backend (`local` or `aws`) |
| `AUDIT_CHAIN_ENABLED` | `true` | Enable hash-chain audit logging |
| `GDPR_DELETION_ENABLED` | `true` | Enable self-service GDPR deletion |
| `GRACEFUL_SHUTDOWN_TIMEOUT` | `30` | Seconds to drain in-flight scans |
| `SATURATION_MEMORY_THRESHOLD` | `90.0` | Memory % to trigger saturation guard |
| `DATA_RETENTION_DAYS` | `90` | Automatic data retention period |

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/google` | Google OAuth redirect |
| `GET` | `/auth/github` | GitHub OAuth redirect |
| `GET` | `/api/v1/auth/me` | Current user profile |
| `POST` | `/api/v1/auth/refresh` | Refresh access token |
| `POST` | `/api/v1/auth/logout` | Revoke tokens |

### Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan/start` | Start a new scan |
| `POST` | `/api/v1/scan/upload` | Upload files for scanning |
| `GET` | `/api/v1/scan/{id}/status` | Scan progress |
| `GET` | `/api/v1/scan/{id}/result` | Scan results |
| `GET` | `/api/v1/scan/{id}/report` | Structured report |
| `POST` | `/api/v1/scan/compare` | Compare two scans |
| `GET` | `/api/v1/scan/history` | Scan history |
| `DELETE` | `/api/v1/scan/{id}` | Delete scan |
| `POST` | `/api/v1/scan/{id}/cancel` | Cancel running scan |

### CI/CD

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/cicd/pipelines` | Create pipeline config |
| `GET` | `/api/v1/cicd/pipelines` | List pipelines |
| `POST` | `/api/v1/cicd/pipelines/{id}/connect` | Connect with webhook |
| `GET` | `/api/v1/cicd/baselines/{repo}` | Get repo baseline |
| `GET` | `/api/v1/cicd/timeline/{repo}` | Risk score timeline |
| `GET` | `/api/v1/cicd/delta/{scan_id}` | Delta report |

### Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/compliance/status` | SOC2 readiness report |
| `GET` | `/api/v1/compliance/audit-log` | Query audit log |
| `POST` | `/api/v1/compliance/audit-verify` | Verify hash-chain integrity |
| `POST` | `/api/v1/compliance/gdpr/delete-my-data` | GDPR right-to-be-forgotten |
| `GET` | `/api/v1/compliance/gdpr/export-my-data` | GDPR data portability |

### Usage & Billing

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/usage/current` | Current period usage |
| `GET` | `/api/v1/usage/cost-estimate` | Scan cost estimate |

### Health & Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/health/ready` | Readiness probe |
| `GET` | `/health/deep` | Deep dependency check |
| `GET` | `/health/db` | Database connectivity |
| `GET` | `/metrics` | Prometheus metrics |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/webhooks/github` | GitHub event receiver |

---

## Static Analysis Engine

### Rule Engine Architecture

The detection engine processes source code through a multi-stage pipeline:

1. **File Classification** (`engine/file_classifier.py`): Detects language by extension and shebang
2. **Rule Loading** (`engine/rule_loader.py`): Indexes 1,014 YAML rules by language and category
3. **Pattern Matching** (`engine/detection_engine.py`): Regex-based detection with context extraction and string-literal/docstring suppression
4. **Streaming Scanner** (`engine/streaming_scanner.py`): Handles large files without full memory load
5. **Deduplication** (`engine/deduplication.py`): Eliminates duplicate findings using exact and line-proximity merges
6. **Severity Scoring** (`engine/severity.py`): CVSS-aligned severity classification
7. **AI Validation** (`engine/ai_validation.py`): LLM-based confidence scoring

### Supported Languages

| Language | Categories | Rule Count |
|----------|-----------|------------|
| Python | injection, xss, auth, crypto, secrets, ssrf, rce, path_traversal, deserialization | 50+ |
| JavaScript/TypeScript | injection, xss, secrets, ssrf, rce, framework_misuse | 45+ |
| Java | injection, crypto, deserialization, ssrf, rce, framework_misuse | 40+ |
| Go | injection, crypto, ssrf, rce, path_traversal, auth | 30+ |
| PHP | injection, xss, path_traversal, deserialization, framework_misuse | 30+ |
| C# | injection, crypto, deserialization, framework_misuse | 25+ |
| Ruby | injection | 10+ |
| C/C++ | injection | 10+ |
| Rust, Kotlin, Swift | injection | 10+ |
| Shell | injection | 5+ |
| SQL | injection | 5+ |
| YAML | devops (K8s/Docker misconfig) | 15+ |

### Rule Format

Rules are defined in YAML with regex patterns, severity levels, and remediation guidance:

```yaml
- id: SQLI-PY-001
  name: SQL Injection via f-string
  description: User input interpolated directly into SQL query
  severity: critical
  category: injection
  languages: [python]
  patterns:
    - 'execute\(f["\'].*\{.*\}.*["\']'
  cwe: CWE-89
  owasp: A03:2021
  remediation: Use parameterized queries with placeholders
```

---

## Accuracy Engine & False Positive Control

SecureAI's Static Analysis Accuracy Engine features a custom context-aware gating layer, a string-literal bypass mechanism, and a multi-stage False Positive (FP) suppression system. These systems work in concert to drastically minimize noise and target only developer-actionable security issues.

### Real-World Audit Benchmark
During a comprehensive accuracy audit scanning **140 Python source code files** inside this repository, the engine achieved a **0.0% False Positive Rate** and collapsed overlapping findings down to single occurrences.

| Audit Metric | Before Improvements | After Improvements | Change / Impact |
| :--- | :---: | :---: | :---: |
| **Total Findings** | 91 | **16** | -82.4% (Noise Filtered) |
| **False Positive Rate** | 48.4% | **0.0%** | Zero false alarms in source code |
| **Duplicate Findings** | 17 | **1** | Only 1 duplicate remained |
| **Noisy Rules Triggered** | 2 | **0** | Tightened rules no longer trigger FPs |
| **High-Confidence FPs** | 35 | **0** | Erroneous high-conf findings eliminated |

### Key Improvements & Mitigations

#### 1. String-Literal & Docstring Suppression
* **Problem:** Security scanners frequently match pattern matches inside comments, docstrings, unit tests, code examples, or log statements (Root Cause #1 — responsible for 48.4% of all False Positives).
* **Fix:** The engine pre-computes an $O(1)$ string-literal map (`_build_string_line_map` in `detection_engine.py`) for every file prior to scanning. Any regex match falling on a line inside double/single triple-quotes (`"""` / `'''`), string assignments, or multiline comments is automatically skipped.

#### 2. Deduplication Key Standardization
* **Problem:** The previous engine tracked finding uniqueness using `(rule_id, file, line, matched_text)`, which caused duplicate reports on the same line if different branches of the same rule pattern fired (Root Cause #2).
* **Fix:** Standardized the unique dedup key to `(rule_id, file, line)` across both the Python engine and the TypeScript extension scanner. Only the highest-severity and highest-confidence finding is kept.

#### 3. Proximity-Based Related Rule Merging
* **Problem:** Related rules matching the same CWE vulnerability family (e.g., different rules for Pickle deserialization) would produce multiple distinct findings on adjacent lines.
* **Fix:** Modified `merge_category_hits()` in `deduplication.py` to cluster findings by `file_name` and `CWE` within a **$\pm$5 line proximity window** rather than requiring exact line matches. 

#### 4. Scoped Anti-Pattern Validation
* **Problem:** Global anti-pattern suppression completely disables a rule for a file if a sanitizer is found anywhere, which can cause false negatives if the sanitizer is in an unrelated function.
* **Fix:** Added `check_anti_patterns_scoped()` to check anti-patterns within a **$\pm$30 line window** surrounding the match location, preventing broad sanitization flags from suppressing valid findings in other scopes.

#### 5. Additional False Positive Gating Stages
The False Positive Reduction Engine (`engine/false_positive_control.py`) applies 8 independent contextual stages:
1. **Framework Context Validation:** Confirms frameworks are imported (e.g. Django, Flask, Express) before firing framework-specific rules.
2. **Sanitization Detection:** Lowers confidence when sanitizers/escape functions are found adjacent to the match.
3. **Test File Suppression:** Downgrades severity and flags test configurations/directories.
4. **Safe Pattern Detection:** Suppresses warnings when safe database constructs (e.g., ORM, parameterized queries) are present.
5. **Commented Code Detection:** Ignores matches on single-line comment lines.
6. **Web-CWE Gating (Stage 6):** Penalizes web-only CWEs (e.g., XSS, CSRF, SSRF) by 35% in non-web files (files lacking HTTP routing, web packages, or request context).
7. **Import-Line Suppression (Stage 7):** Deducts 55% confidence for findings on import/require statement lines.
8. **Multi-line Comment/Docstring Detection (Stage 8):** Checks and suppresses findings located inside C-style multi-line comments (`/* ... */`) and Python triple-quote blocks across 12 languages.

---

## VS Code Extension

SecureAI includes a premium, real-time VS Code / Antigravity IDE Extension (`backend/extension/`) that brings the power of our SAST engine directly into the editor workspace.

### Key Features
* **Real-time Scanning:** Scans your open files instantly as you type (debounced) or when files are saved.
* **Inline Diagnostics:** Highlights vulnerabilities using grey squiggly underlines.
* **Hover Tooltips:** Hovering over underlined code shows detailed vulnerability details, severity, confidence, CWE, and remediation tips.
* **Local Scan Execution:** Runs a TypeScript-ported scanner utilizing the exact same 1,014 YAML security rules fully offline. No external API calls are made.

### Setup and Packaging
To build and package the extension locally:
```bash
# Navigate to the extension folder
cd backend/extension

# Install dependencies
npm install

# Compile TypeScript and bundle security rules
npm run build

# Package into a VSIX file
npm run package
```

---

## CLI Tool

The `secureai` CLI tool provides a production-grade local SAST scanner that can be run on directories or integrated directly into local build steps.

### Setup and Installation
Install the CLI in editable development mode from the backend folder:
```bash
cd backend
pip install -e .
```

### Command Usage
```bash
# Scan a directory or file
secureai scan <path> [options]

# Run an AI-assisted scan using OpenAI Codex validation
secureai scan <path> --ai

# List all loaded security rules
secureai rules [options]

# Show tool version
secureai version
```

---

## Orchestration Layer

The orchestration layer manages the complete scan lifecycle:

### Session Manager (`orchestration/session_manager.py`)

- Priority queue with per-user and global concurrency controls
- Queue backend abstraction (in-memory or Redis)
- Automatic scan cancellation and timeout enforcement
- Active count tracking for graceful shutdown

### Scan Pipeline

```
enqueue_scan() → _queue_consumer() → _run_scan_pipeline()
    │                                        │
    │                                  ┌─────┴──────┐
    │                                  │             │
    │                            git_clone()    ingest_upload()
    │                                  │             │
    │                                  └─────┬──────┘
    │                                        │
    │                              parallel_scan_files()
    │                                        │
    │                              ai_validate_findings()
    │                                        │
    │                              aggregate_report()
    │                                        │
    │                              store_results_to_db()
    │                                        │
    └────────── update_progress() ◄──────────┘
```

### Key Features

- **Parallel file scanning**: Multi-worker process pool for CPU-intensive pattern matching
- **AI validation queue**: Concurrent LLM calls with rate limiting and circuit breaking
- **Diff-aware scanning**: Only scan changed files in PRs for faster feedback
- **Baseline management**: Track vulnerability trends across commits
- **Crash recovery**: Recover stuck scans on restart

---

## Distributed Worker Architecture

### Queue Abstraction

Two interchangeable backends:

**Memory Backend** (default, single-process):
- Wraps `asyncio.PriorityQueue`
- O(1) lookup by scan_id via secondary dict
- Zero external dependencies

**Redis Backend** (multi-node):
- Sorted sets (ZADD) with composite score: `priority * 1e12 + enqueued_at`
- Blocking dequeue via BZPOPMIN
- Per-task hash with 24h TTL

### Worker Modes

**Embedded** (default): Worker runs as an asyncio task inside the API process. Identical to single-process behavior.

**Standalone**: Worker runs as a separate process via `python -m app.worker.run`. Pulls from queue, executes pipeline, reports metrics.

### Dead-Letter Queue

Failed scans are retried with exponential backoff. After `DLQ_MAX_RETRIES` (default 3) exhausted attempts, tasks move to the DLQ for investigation.

### Distributed Locking

Prevents duplicate processing when multiple workers run:

- **Memory backend**: `asyncio.Lock` per key with TTL tracking
- **Redis backend**: `SET NX EX` with Lua scripts for safe release (only the lock owner can release)

---

## CI/CD Integration

### GitHub Webhook Flow

```
GitHub Push/PR Event
        │
        ▼
  POST /webhooks/github
        │
  HMAC signature validation
        │
  Idempotency check (delivery ID)
        │
        ├── Push to default branch → Full scan + baseline update
        │
        └── Pull request opened/synchronized → Diff scan + delta report
                                                      │
                                              PR comment (opt-in)
```

### Diff Scanning

- Detects changed files between PR head and base via `git diff`
- Classifies files by language, filters binaries
- Falls back to full scan when diff exceeds `DIFF_SCAN_MAX_FILES`
- Delta engine compares current findings against baseline to identify new/fixed vulnerabilities

### PR Comments

When `PR_COMMENT_ENABLED=true`, the system posts structured vulnerability reports directly on PRs:
- New findings with severity badges
- Fixed findings acknowledged
- Risk score comparison vs. baseline
- Configurable minimum severity threshold

---

## Security & Compliance

### Authentication & Authorization

- **OAuth 2.0**: Google and GitHub provider support
- **JWT tokens**: Access (30min) + Refresh (7 days) with JTI-based revocation
- **Token blacklist**: Database-backed revocation list
- **RBAC**: Four roles with granular permissions:

| Role | Permissions |
|------|------------|
| `admin` | All operations |
| `auditor` | Read scans, read/export audit logs, compliance reports |
| `developer` | Create/read/delete scans, export data |
| `user` | Create/read/delete scans, export data |

### Multi-Tenant Isolation

- Request-scoped tenant context via middleware
- All database queries filtered by `user_id`
- Per-user resource quotas (scans/day, AI tokens, storage)
- Tiered access (Free / Pro / Enterprise) with separate limits

### SOC2 Controls

| Control | Implementation |
|---------|---------------|
| Audit Logging | Hash-chain linked entries with SHA-256   |
| Encryption at Rest | Fernet AES-128-CBC with PBKDF2 key derivation |
| Access Control | RBAC + JWT + token revocation |
| Data Retention | Configurable auto-purge (default 90 days) |
| Availability | Health probes, circuit breaker, saturation guard |
| Integrity | Tamper-evident audit chain verification |

### GDPR Compliance

- **Right to be forgotten**: `POST /api/v1/compliance/gdpr/delete-my-data` — deletes all user data, anonymizes audit logs
- **Data portability**: `GET /api/v1/compliance/gdpr/export-my-data` — exports complete user data as JSON
- **Data retention**: Automatic purge of data older than configured retention period

### Middleware Security Stack

Applied on every request (outermost to innermost):

1. **Request Size Limit** — Reject bodies exceeding `MAX_REQUEST_BODY_MB`
2. **Saturation Guard** — 503 when memory or queue pressure exceeds thresholds
3. **Security Headers** — CSP, HSTS, X-Content-Type-Options, X-Frame-Options
4. **CORS** — Strict origin allowlist (no wildcards in production)
5. **Rate Limiting** — Per-endpoint, per-user rate limits
6. **Abuse Detection** — Behavioral anomaly detection

---

## Kubernetes Deployment

### Helm Chart

```bash
cd backend/k8s/helm

# Install
helm install secureai . -n secureai --create-namespace \
  --set secrets.jwtSecret=<...> \
  --set secrets.encryptionKey=<...> \
  --set secrets.pplxApiKey=<...> \
  --set postgresql.host=<db-host>

# Upgrade
helm upgrade secureai . -n secureai

# Template (dry run)
helm template secureai .
```

### Architecture

- **API Deployment**: FastAPI servers behind a ClusterIP Service
  - Rolling update: `maxSurge: 1`, `maxUnavailable: 0`
  - Startup/readiness/liveness probes
  - Pod anti-affinity for HA
  - Security context: non-root, read-only rootfs, drop all capabilities

- **Worker Deployment**: Standalone scan workers
  - Separate resource limits tuned for CPU-intensive scanning
  - No service/ingress (internal only)

- **HPA**: Horizontal Pod Autoscaler
  - API: scale on CPU (70%) and memory (80%)
  - Worker: scale on custom metrics (queue depth)

- **PDB**: Pod Disruption Budget with `minAvailable: 1`

### Monitoring Stack

- **ServiceMonitor**: Prometheus scrape config for `/metrics`
- **Grafana Dashboard**: Pre-built JSON dashboard with panels for throughput, latency, queue depth, memory, error rates
- **Alert Rules**: PrometheusRule CRD with alerts for high error rate, memory pressure, queue backlog, worker down, DLQ growth

---

## Monitoring & Observability

### Prometheus Metrics

Exposed at `GET /metrics` in Prometheus text exposition format:

| Metric | Type | Description |
|--------|------|-------------|
| `secureai_scans_started_total` | Counter | Total scans initiated |
| `secureai_scans_completed_total` | Counter | Total scans completed (by status) |
| `secureai_scan_duration_seconds` | Histogram | Scan duration distribution |
| `secureai_active_scans` | Gauge | Currently running scans |
| `secureai_queued_scans` | Gauge | Scans waiting in queue |
| `secureai_vulnerabilities_found_total` | Counter | Vulnerabilities discovered |
| `secureai_ai_requests_total` | Counter | AI validation API calls |
| `secureai_memory_usage_percent` | Gauge | System memory utilization |
| `secureai_worker_tasks_processed_total` | Counter | Tasks processed by workers |
| `secureai_worker_heartbeat_age_seconds` | Gauge | Time since last worker heartbeat |
| `secureai_dlq_size` | Gauge | Dead-letter queue depth |

### Health Probes

| Endpoint | Purpose | Use Case |
|----------|---------|----------|
| `/health` | Liveness | K8s liveness probe, always returns 200 |
| `/health/ready` | Readiness | K8s readiness probe, checks app state + memory + disk |
| `/health/deep` | Deep check | Monitoring dashboard, checks DB + engine + encryption |
| `/health/db` | Database | Database connectivity check |

### Structured Logging

All log output is structured JSON via `structlog`:

```json
{
  "event": "scan_completed",
  "scan_id": "abc-123",
  "duration_ms": 4500,
  "findings": 12,
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

## Testing

### Integration Tests

```bash
cd backend
python -m pytest tests/ -x -v
```

58 integration tests covering:
- CI/CD lifecycle scenarios (push → scan → baseline → PR → diff)
- Webhook validation (HMAC signatures, replay protection)
- Security surface audit (no hardcoded secrets, no wildcard CORS, docs disabled in prod)
- Response shape validation (backward compatibility)
- Multi-tenant isolation
- Middleware stack integrity

### CLI Tool Tests
Verify command registration and rules engine logic locally:
```bash
cd backend
secureai version
secureai rules --lang python
secureai scan cli/ --severity medium
```

### VS Code Extension Tests
Run TS-based extension unit/integration suite:
```bash
cd backend/extension
npm test
```

### Rule Validation Tests

```bash
cd backend/rule-tests
python run_tests.py
```

Tests every detection rule against positive (should detect) and negative (should not detect) code samples.

---

## Frontend

### Pages

| Route | Description |
|-------|-------------|
| `/` | Landing page with feature overview |
| `/login` | OAuth login (Google / GitHub) |
| `/dashboard` | Overview with scan stats and recent activity |
| `/scan` | Start new scan (paste, upload, or GitHub repo) |
| `/results` | Detailed scan results with charts and vulnerability table |
| `/history` | Scan history with filtering and search |
| `/settings` | User settings and preferences |

### State Management

Zustand stores with persistent state:
- `authStore`: User session, tokens, login/logout
- `scanStore`: Current scan state, progress, results
- `historyStore`: Scan history list, pagination

### Components

- **AuthGuard**: Route protection with token validation
- **ScanConfigPanel**: Scan depth, categories, AI settings
- **ProgressTracker**: Real-time scan progress with stage indicators
- **VulnerabilityTable**: Sortable, filterable vulnerability list
- **ChartsSection**: Severity distribution, trend charts (Recharts)
- **ExecutiveSummary**: High-level security posture overview
- **RepoRiskIntelligence**: Repository-level risk aggregation

---

## Development Guide

### Adding a New Detection Rule

1. Create a YAML file in the appropriate `rules/<category>/` directory
2. Define pattern, severity, CWE mapping, and remediation
3. Add positive/negative test cases in `rule-tests/<category>/`
4. Run `python rule-tests/run_tests.py` to validate

### Adding a New API Endpoint

1. Create or extend a router in `app/api/`
2. Add Pydantic schemas in `app/schemas/`
3. Wire the router in `app/main.py`
4. Add audit logging via `AuditService.log()`
5. Apply appropriate permission checks via `require_permission()`

### Adding a New AI Provider

1. Create a provider module in `app/ai/providers/`
2. Implement the provider interface with `analyze()` method
3. Register in `app/ai/router.py`
4. Add configuration variables in `app/core/config.py`

### Running the Standalone Worker

```bash
cd backend
python -m app.worker.run
```

Requires `QUEUE_BACKEND=redis` and `QUEUE_REDIS_URL` to be set for cross-process queue transport.

---

## License

Proprietary. All rights reserved.
